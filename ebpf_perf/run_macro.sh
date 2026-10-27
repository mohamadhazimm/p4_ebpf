#!/usr/bin/env bash
# Run an arbitrary benchmark command under the same three conditions as run_bench.sh:
#   base     no HostMon; command in the dedicated cgroup
#   mon_in   HostMon attached; command (and all children) in the monitored cgroup
#   mon_out  HostMon attached; command outside the cgroup
#
# Usage (as root):
#   sudo ./run_macro.sh NAME REPS [--setup 'cmd'] -- COMMAND [ARGS...]
# The command runs as the invoking user (SUDO_UID), from the current directory.
# --setup runs (as that user, unmonitored, untimed) before every repetition,
# e.g. 'make clean'. Results: results/macro-NAME-<UTC timestamp>/.
# Env: WARMUP=1 runs one unrecorded round of all conditions first (runs/warmup_*);
# BENCH_CPUS=0-11 pins the benchmark (taskset list); HM_CPU pins HostMon;
# HOSTMON_BIN selects the collector (default build/hostmon; build/hostmon_agg is the
# in-kernel aggregating version).
# BPF_STATS=1 enables kernel.bpf_stats_enabled for per-program ns/run. It is off by
# default because it adds two clock reads to every BPF program run, which inflates
# the measured overhead; the papers we compare against measure with it off.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
BUILD="$HERE/build"
WINDOW="${WINDOW:-1}"
HM_CPU="${HM_CPU:-4}"
BENCH_CPUS="${BENCH_CPUS:-}"
WARMUP="${WARMUP:-0}"
BPF_STATS="${BPF_STATS:-0}"
export HOSTMON_BIN="${HOSTMON_BIN:-$BUILD/hostmon}"
PY=/usr/bin/python3

[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }
[[ $# -ge 4 ]] || { sed -n 2,13p "$0" >&2; exit 1; }
NAME=$1 REPS=$2; shift 2
SETUP=""
if [[ $1 == --setup ]]; then SETUP=$2; shift 2; fi
[[ $1 == -- ]] || { echo "expected -- before the command" >&2; exit 1; }
shift
[[ $NAME =~ ^[A-Za-z0-9._-]+$ ]] || { echo "bad NAME" >&2; exit 1; }
CMD=("$@")
[[ -x $HOSTMON_BIN ]] || { echo "run ./build.sh first ($HOSTMON_BIN missing)" >&2; exit 1; }
RUN_UID="${SUDO_UID:-0}" RUN_GID="${SUDO_GID:-0}"
AS_USER=(setpriv --reuid="$RUN_UID" --regid="$RUN_GID" --init-groups --reset-env)
USER_HOME="$(getent passwd "$RUN_UID" | cut -d: -f6)"

TS="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="$HERE/results/macro-$NAME-$TS"
CG="/sys/fs/cgroup/hostmon-macro-$TS"
mkdir -p "$OUT/runs"
mkdir "$CG"
OLD_STATS="$(cat /proc/sys/kernel/bpf_stats_enabled)"
HM_PID=""

cleanup() {
  if [[ -n $HM_PID ]] && kill -0 "$HM_PID" 2>/dev/null; then
    kill -INT "$HM_PID" 2>/dev/null || true; wait "$HM_PID" 2>/dev/null || true
  fi
  if [[ -d $CG ]]; then
    while read -r p; do echo "$p" > /sys/fs/cgroup/cgroup.procs 2>/dev/null || true; done < "$CG/cgroup.procs"
    rmdir "$CG" 2>/dev/null || echo "WARNING: could not remove $CG" >&2
  fi
  echo "$OLD_STATS" > /proc/sys/kernel/bpf_stats_enabled
  chown "$RUN_UID:$RUN_GID" "$HERE/results" 2>/dev/null || true
  chown -R "$RUN_UID:$RUN_GID" "$OUT" 2>/dev/null || true
}
trap cleanup EXIT
[[ $BPF_STATS == 1 ]] && echo 1 > /proc/sys/kernel/bpf_stats_enabled

$PY - "$OUT/environment.json" "$NAME" "$REPS" "$SETUP" "$PWD" "$@" <<'EOF'
import json, os, platform, subprocess, sys
out, name, reps, setup, cwd, *cmd = sys.argv[1:]
cpu = subprocess.run(["lscpu"], capture_output=True, text=True).stdout
model = next((l.split(":", 1)[1].strip() for l in cpu.splitlines() if l.startswith("Model name")), "")
json.dump({"name": name, "reps": int(reps), "setup": setup, "cwd": cwd, "command": cmd,
           "kernel": platform.release(), "cpu": model, "window_sec": float(os.environ.get("WINDOW", 1)),
           "hostmon_cpu": int(os.environ.get("HM_CPU", 4)), "bench_cpus": os.environ.get("BENCH_CPUS", ""),
           "warmup": os.environ.get("WARMUP", "0"), "bpf_stats": os.environ.get("BPF_STATS", "0"),
           "hostmon_bin": os.environ.get("HOSTMON_BIN", ""),
           "governor": open("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor").read().strip()},
          open(out, "w"), indent=2)
EOF
cp "$BUILD/sha256.txt" "$OUT/build-sha256.txt"

start_hostmon() {
  local d=$1
  mkfifo "$d/start.fifo"
  taskset -c "$HM_CPU" "$HOSTMON_BIN" "$WINDOW" "$CG" < "$d/start.fifo" > "$d/hostmon.out" 2> "$d/hostmon.err" &
  HM_PID=$!
  exec 9> "$d/start.fifo"
  for _ in $(seq 150); do
    grep -q '^HOSTMON_READY' "$d/hostmon.out" 2>/dev/null && break
    kill -0 "$HM_PID" 2>/dev/null || break
    sleep 0.1
  done
  grep -q '^HOSTMON_READY' "$d/hostmon.out" 2>/dev/null || { exec 9>&-; cat "$d/hostmon.err" >&2; exit 1; }
  $PY -c 'import time; print(f"{time.monotonic() + 0.3:.9f}")' >&9
  exec 9>&-
  sleep 0.5
}

run_one() {
  local cond=$1 rep=$2 d="$OUT/runs/${cond}_$2" rc=0 t0 t1 hm_rc=0 hm_before=0 hm_after=0
  local pin=()
  [[ -n $BENCH_CPUS ]] && pin=(taskset -c "$BENCH_CPUS")
  mkdir -p "$d"
  if [[ -n $SETUP ]]; then
    "${AS_USER[@]}" env HOME="$USER_HOME" PATH="$PATH" bash -c "$SETUP" > "$d/setup.log" 2>&1
  fi
  if [[ $cond != base ]]; then
    start_hostmon "$d"
    bpftool prog show --json > "$d/progs_before.json"
    hm_before=$(awk '{print $1}' "/proc/$HM_PID/schedstat")
  fi
  local join="$CG/cgroup.procs"
  [[ $cond == mon_out ]] && join=/dev/null
  t0=$(date +%s%N)
  bash -c 'echo $$ > "$1"; shift; exec "$@"' _ "$join" "${pin[@]}" \
    /usr/bin/time -o "$d/rusage.txt" -f '%e %U %S %M' \
    "${AS_USER[@]}" env HOME="$USER_HOME" PATH="$PATH" "${CMD[@]}" > "$d/stdout.txt" 2> "$d/stderr.txt" || rc=$?
  t1=$(date +%s%N)
  if [[ $cond != base ]]; then
    sleep "$($PY -c "print($WINDOW + 0.5)")"
    bpftool prog show --json > "$d/progs_after.json"
    hm_after=$(awk '{print $1}' "/proc/$HM_PID/schedstat")
    grep -E '^(VmHWM|VmRSS)' "/proc/$HM_PID/status" > "$d/hostmon.mem" || true
    kill -INT "$HM_PID"; wait "$HM_PID" || hm_rc=$?
    HM_PID=""
  fi
  printf '{"cond":"%s","rep":"%s","rc":%s,"wall_ns":%s,"hostmon_rc":%s,"hostmon_cpu_ns":%s}\n' \
    "$cond" "$rep" "$rc" "$((t1 - t0))" "$hm_rc" "$((hm_after - hm_before))" > "$d/meta.json"
  printf '%-8s rep=%s rc=%s wall=%.3fs\n' "$cond" "$rep" "$rc" "$($PY -c "print($((t1 - t0))/1e9)")"
}

ORDERS=("base mon_in mon_out" "mon_in mon_out base" "mon_out base mon_in")
if [[ $WARMUP == 1 ]]; then
  for cond in base mon_in mon_out; do run_one "$cond" warmup; done
  for d in "$OUT"/runs/*_warmup; do mv "$d" "$OUT/runs/warmup_$(basename "$d" _warmup)"; done
fi
for rep in $(seq "$REPS"); do
  for cond in ${ORDERS[$(( (rep - 1) % 3 ))]}; do
    run_one "$cond" "$rep"
  done
done
echo "results: $OUT"
