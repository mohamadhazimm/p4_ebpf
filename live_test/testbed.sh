#!/usr/bin/env bash
# Local testbed for the P4 (tofino-model) + eBPF monitor.
#
#   sudo live_test/testbed.sh up            veths, Tofino model, bf_switchd, forwarding + mirror
#   sudo live_test/testbed.sh mode replay   host ends of the switch ports in the root ns, no IPs
#   sudo live_test/testbed.sh mode live     client/server namespaces with IPs and benign servers
#   sudo live_test/testbed.sh status
#   sudo live_test/testbed.sh down          stop everything, remove namespaces and veths
#
# Switch ports (thesis-hybrid-ebpf-p4/ports.json): the model is attached to
# veth1 (port 0, internal), veth3 (port 1, external) and veth5 (port 2, CPU
# reports). Their peers veth0/veth2/veth4 are the host ends.
#
# replay: frames sent on veth0 enter port 0, frames sent on veth2 enter port 1.
#         The host ends have no IP address, so no daemon talks on them.
# live:   veth0 is 10.0.0.1/24 in netns p4int (where workloads run, via
#         "ip netns exec p4int"), veth2 is 10.0.0.2/24 in netns p4ext, which
#         runs live_test/servers.py (HTTP 8088, TCP sink 9099). Traffic
#         between them crosses the P4 pipeline in both directions; root-ns
#         daemons (avahi, resolved) do not see these links.
#
# MTU is 1500 on the switch links (veth_setup.sh sets 10240), so packet sizes
# match an Ethernet LAN. By default bf_switchd starts with --skip-port-add and
# only ports 0-2 are added through BFRT (~1 minute; p4_known_answer.py passes
# 19/19 so). P4_FAST=0 lets bf_switchd add all 288 model ports instead, which
# took 35 minutes on this VM.
set -euo pipefail

SDE=${SDE_INSTALL:-/home/ubuntu/open-p4studio/install}
REPO=$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)
LT=$REPO/live_test
RUN=$LT/run
BUILD=$REPO/thesis-hybrid-ebpf-p4/basic.tofino
CONF=$BUILD/basic.conf
PORTS=$REPO/thesis-hybrid-ebpf-p4/ports.json
PYDIR=$REPO/thesis-hybrid-ebpf-p4/python
OWNER=${SUDO_USER:-root}
NVETH=6

log() { echo "[testbed] $*"; }
die() { echo "[testbed] ERROR: $*" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || die "run as root (sudo)"

# No "| grep -q" under pipefail: grep exiting early can SIGPIPE the producer.
listening() { [ -n "$(ss -Hlnt "sport = :$1" 2>/dev/null)" ]; }
ns_listening() { [ -n "$(ip netns exec "$1" ss -Hlnt "src $2" 2>/dev/null)" ]; }
ns_exists() { [ -e "/run/netns/$1" ]; }

write_conf() {
    [ -f "$BUILD/pipe/tofino.bin" ] || die "no compiled program in $BUILD (compile basic.p4 first)"
    cat > "$CONF" <<EOF
{
    "chip_list": [
        {
            "chip_family": "tofino",
            "instance": 0,
            "pcie_sysfs_prefix": "/sys/devices/pci0000:00/0000:00:03.0/0000:05:00.0",
            "sds_fw_path": "share/tofino_sds_fw/avago/firmware"
        }
    ],
    "p4_devices": [
        {
            "device-id": 0,
            "p4_programs": [
                {
                    "program-name": "basic",
                    "bfrt-config": "$BUILD/bf-rt.json",
                    "p4_pipelines": [
                        {
                            "p4_pipeline_name": "pipe",
                            "context": "$BUILD/pipe/context.json",
                            "config": "$BUILD/pipe/tofino.bin",
                            "pipe_scope": [0, 1, 2, 3],
                            "path": "$BUILD"
                        }
                    ]
                }
            ],
            "agent0": "lib/libpltfm_mgr.so"
        }
    ],
    "switch_options": [
        {
            "device-id": 0
        }
    ]
}
EOF
}

quiet_link() {   # quiet_link IFACE [netns]
    local ns=() ; [ $# -ge 2 ] && ns=(ip netns exec "$2")
    "${ns[@]}" ip link set dev "$1" mtu 1500 up
    for opt in rx tx sg tso gso gro lro rxvlan txvlan rxhash; do
        "${ns[@]}" ethtool --offload "$1" "$opt" off >/dev/null 2>&1 || true
    done
    "${ns[@]}" sysctl -qw "net.ipv6.conf.$1.disable_ipv6=1" >/dev/null 2>&1 || true
}

make_veths() {
    if ! ip link show veth1 >/dev/null 2>&1; then
        "$SDE/bin/veth_setup.sh" "$NVETH" >/dev/null
    fi
    for i in 1 3 4 5; do quiet_link "veth$i"; done
    ip link show veth0 >/dev/null 2>&1 && quiet_link veth0
    ip link show veth2 >/dev/null 2>&1 && quiet_link veth2
    return 0
}

start_model() {
    if pgrep -x tofino-model >/dev/null; then log "tofino-model already running"; return; fi
    mkdir -p "$RUN/model"
    # exec: no shell stays behind holding the caller's stdout open
    (cd "$RUN/model" && exec env "LD_LIBRARY_PATH=$SDE/lib" setsid nohup "$SDE/bin/tofino-model" \
        --no-cli --logs-disable -f "$PORTS" --install-dir "$SDE" \
        > "$RUN/model/tofino-model.out" 2>&1 < /dev/null) &
    for _ in $(seq 60); do listening 8001 && break; sleep 1; done
    listening 8001 || die "tofino-model did not start (see $RUN/model/tofino-model.out)"
    log "tofino-model up"
}

start_switchd() {
    if pgrep -x bf_switchd >/dev/null; then log "bf_switchd already running"; else
        mkdir -p "$RUN/switchd"
        local extra=()
        [ "${P4_FAST:-1}" = 1 ] && extra=(--skip-port-add)
        (cd "$RUN/switchd" && exec env "SDE=$SDE/.." "SDE_INSTALL=$SDE" "LD_LIBRARY_PATH=$SDE/lib:/usr/local/lib" \
            "PATH=$SDE/bin:/usr/sbin:/usr/bin:/sbin:/bin" setsid nohup "$SDE/bin/bf_switchd" --background \
            --install-dir "$SDE" --conf-file "$CONF" "${extra[@]}" \
            > "$RUN/switchd/bf_switchd.out" 2>&1 < /dev/null) &
        log "bf_switchd started${extra:+ (${extra[*]})}; waiting for BFRT (port 9999)"
    fi
    local t0=$SECONDS
    until listening 9999; do
        pgrep -x bf_switchd >/dev/null || die "bf_switchd exited (see $RUN/switchd/bf_switchd.out)"
        if (( (SECONDS - t0) % 60 == 0 && SECONDS > t0 )); then
            log "  ... $(( (SECONDS - t0) / 60 )) min, $(grep -c mc_mgr_add_port "$RUN/switchd/bf_drivers.log" 2>/dev/null || echo 0) ports added"
        fi
        (( SECONDS - t0 > 3600 )) && die "BFRT not up after an hour"
        sleep 1
    done
    log "BFRT up after $(( SECONDS - t0 )) s"
    sleep 3   # let the CLI server settle before the first session
}

add_fast_ports() {
    [ "${P4_FAST:-1}" = 1 ] || return 0
    python3 - "$PYDIR" <<'PY'
import sys
sys.path.insert(0, sys.argv[1])
from bfshell_run import run_bfshell_script
out = run_bfshell_script("""
for dp in (0, 1, 2):
    try:
        bfrt.port.port.add(DEV_PORT=dp, SPEED="BF_SPEED_10G", FEC="BF_FEC_TYP_NONE", PORT_ENABLE=True)
        print("[OK] port", dp)
    except Exception as error:
        print("[INFO] port", dp, error)
bfrt.complete_operations()
""", timeout=300)
print("\n".join(l for l in out.splitlines() if "port" in l and ("[OK]" in l or "[INFO]" in l)))
PY
}

program() {
    # The first bfshell session right after BFRT starts listening can fail
    # ("Can't startup clish"), so retry.
    for attempt in 1 2 3; do
        if python3 "$PYDIR/program_forwarding.py" --int-port 0 --ext-port 1 --report-port 2 --mirror-sid 1 \
            > "$RUN/program_forwarding.out" 2>&1; then
            log "forwarding 0<->1 and mirror sid 1 -> port 2 programmed"
            return 0
        fi
        log "programming attempt $attempt failed, retrying"
        sleep 5
    done
    cat "$RUN/program_forwarding.out"
    die "programming failed"
}

make_www() {
    local www=$LT/www
    [ -f "$www/.ready" ] && return
    mkdir -p "$www"
    python3 - "$www" <<'PY'
import random, sys
from pathlib import Path
d = Path(sys.argv[1]); rng = random.Random(1)
text = lambda n: "".join(rng.choice("abcdefghijklmnopqrstuvwxyz ABCDEFGHIJ\n") for _ in range(n))
(d / "index.html").write_text("<html><body><h1>Test Page</h1></body></html>\n")
(d / "about.html").write_text("<html><body><p>Benign local page.</p></body></html>\n")
(d / "data.json").write_text('{"status":"ok","source":"local-test"}\n')
(d / "image.txt").write_text(text(2048))
(d / "notes.txt").write_text(text(4096))
(d / "test.txt").write_text(text(1024))
for name, size in (("test.bin", 16384), ("payload.bin", 4096), ("file_100k.bin", 102400), ("file_1m.bin", 1048576)):
    (d / name).write_bytes(bytes(rng.getrandbits(8) for _ in range(size)))
(d / ".ready").write_text("ok\n")
PY
    chown -R "$OWNER" "$www"
}

stop_servers() {
    if [ -f "$RUN/servers.pid" ]; then
        kill "$(cat "$RUN/servers.pid")" 2>/dev/null || true
        : > "$RUN/servers.pid"
    fi
}

mode_replay() {
    stop_servers
    for pair in "p4int veth0" "p4ext veth2"; do
        set -- $pair
        if ns_exists "$1"; then
            ip -n "$1" link set "$2" netns 1 2>/dev/null || true
            ip netns del "$1"
        fi
    done
    for i in 0 2; do ip addr flush dev "veth$i"; quiet_link "veth$i"; done
    log "mode replay: inject on veth0 (port 0) and veth2 (port 1), no IPs on the host ends"
}

mode_live() {
    make_www
    ns_exists p4int || ip netns add p4int
    ns_exists p4ext || ip netns add p4ext
    ip link show veth0 >/dev/null 2>&1 && ip link set veth0 netns p4int
    ip link show veth2 >/dev/null 2>&1 && ip link set veth2 netns p4ext
    for pair in "p4int veth0 10.0.0.1" "p4ext veth2 10.0.0.2"; do
        set -- $pair
        ip netns exec "$1" sysctl -qw net.ipv6.conf.all.disable_ipv6=1 net.ipv6.conf.default.disable_ipv6=1
        ip -n "$1" link set lo up
        quiet_link "$2" "$1"
        ip -n "$1" addr flush dev "$2"
        ip -n "$1" addr add "$3/24" dev "$2"
    done
    local mac0 mac2
    mac0=$(ip -n p4int -br link show veth0 | awk '{print $3}')
    mac2=$(ip -n p4ext -br link show veth2 | awk '{print $3}')
    ip -n p4int neigh replace 10.0.0.2 lladdr "$mac2" dev veth0 nud permanent
    ip -n p4ext neigh replace 10.0.0.1 lladdr "$mac0" dev veth2 nud permanent
    stop_servers
    # setsid, ip netns exec and setpriv all exec in place: $! is the server's PID.
    (setsid ip netns exec p4ext setpriv --reuid="$OWNER" --regid="$OWNER" --init-groups \
        python3 "$LT/servers.py" --bind 10.0.0.2 --www "$LT/www" \
        > "$RUN/servers.out" 2>&1 < /dev/null & echo $! > "$RUN/servers.pid")
    for _ in $(seq 20); do ns_listening p4ext 10.0.0.2:9099 && break; sleep 0.5; done
    ns_listening p4ext 10.0.0.2:8088 || die "servers did not start (see $RUN/servers.out)"
    log "mode live: p4int 10.0.0.1 (veth0) <-> P4 <-> p4ext 10.0.0.2 (veth2), servers on 8088/9099"
}

status() {
    echo "processes:"
    pgrep -a -x tofino-model | cut -c1-120 || echo "  tofino-model not running"
    pgrep -a -x bf_switchd | cut -c1-120 || echo "  bf_switchd not running"
    [ -s "$RUN/servers.pid" ] && ps -o pid=,comm=,args= -p "$(cat "$RUN/servers.pid")" 2>/dev/null | cut -c1-120 || true
    echo "listening: $(for p in 8001 9090 9999 50052; do listening $p && printf '%s ' $p; done)"
    echo "namespaces: $(ip netns list | awk '{print $1}' | tr '\n' ' ')"
    ip -br link | grep -E '^veth[0-5]' || true
    for ns in p4int p4ext; do ns_exists $ns && ip -n $ns -br addr | grep veth | sed "s/^/  $ns: /"; done
    if ns_exists p4int; then
        if ip netns exec p4int timeout 5 python3 -c "import urllib.request as u; print(len(u.urlopen('http://10.0.0.2:8088/index.html', timeout=4).read()))" >/dev/null 2>&1; then
            echo "data path: HTTP 10.0.0.1 -> 10.0.0.2:8088 through P4 OK"
        else
            echo "data path: HTTP 10.0.0.1 -> 10.0.0.2:8088 FAILED"
        fi
    fi
}

down() {
    stop_servers
    pkill -x bf_switchd 2>/dev/null || true
    for _ in $(seq 20); do pgrep -x bf_switchd >/dev/null || break; sleep 0.5; done
    pkill -9 -x bf_switchd 2>/dev/null || true
    pkill -x tofino-model 2>/dev/null || true
    for _ in $(seq 20); do pgrep -x tofino-model >/dev/null || break; sleep 0.5; done
    pkill -9 -x tofino-model 2>/dev/null || true
    for ns in p4int p4ext; do ns_exists $ns && ip netns del $ns; done
    "$SDE/bin/veth_teardown.sh" "$NVETH" >/dev/null 2>&1 || true
    log "down"
}

case "${1:-}" in
    up)
        mkdir -p "$RUN"
        write_conf
        make_veths
        start_model
        start_switchd
        add_fast_ports
        program
        mode_replay
        chown -R "$OWNER" "$RUN" 2>/dev/null || true
        ;;
    mode)
        case "${2:-}" in
            replay) mode_replay ;;
            live) mode_live ;;
            *) die "mode replay|live" ;;
        esac
        chown -R "$OWNER" "$RUN" 2>/dev/null || true
        ;;
    status) status ;;
    down) down ;;
    *) echo "usage: $0 up|mode replay|mode live|status|down" >&2; exit 2 ;;
esac
