#!/usr/bin/env bash
# Generate a bfrt_python script, run it on the switch with run_bfshell.sh -b,
# and keep the script, the bfshell output and the parsed results.
#
#   perf/tools/run_bfrt.sh RUN_DIR LABEL BFRT_GEN_ARGS...
#
# The script goes to RUN_DIR/bfrt/LABEL.py (and to the switch's run
# directory), the bfshell session is logged by swrun.sh as RUN_DIR/NNN_LABEL.txt,
# and the "HZJSON" result lines are saved as RUN_DIR/bfrt/LABEL.json. bfshell
# is only started if sw_switchd.sh confirms that switchd ignores SIGHUP and is
# not a session leader.
#
# The device-ready check is done over 127.0.0.1:7777 (sw_switchd.sh ready):
# run_bfshell.sh's own check asks "localhost", which does not resolve on this
# switch (/etc/hosts has only "127.0.0.1 tofino-switch"), so it always waited
# out its 300 s timeout. bfshell itself is started by sw_bfshell_b.py, which
# keeps its stdin open until the session ends (see there).
set -u
if [ $# -lt 3 ]; then
    echo "usage: $0 RUN_DIR LABEL BFRT_GEN_ARGS..." >&2
    exit 2
fi
run_dir=$1; label=$2; shift 2
here=$(cd "$(dirname "$0")" && pwd)
rid=$(basename "$run_dir")
mkdir -p "$run_dir/bfrt"
python3 "$here/bfrt_gen.py" "$@" > "$run_dir/bfrt/$label.py" || exit 1
remote=/root/hazim_perf/runs/$rid/$label.py
if ! scp -q -o BatchMode=yes "$run_dir/bfrt/$label.py" "root@172.168.1.2:$remote" 2> /dev/null; then
    ssh -o BatchMode=yes root@172.168.1.2 "mkdir -p /root/hazim_perf/runs/$rid" &&
        scp -q -o BatchMode=yes "$run_dir/bfrt/$label.py" "root@172.168.1.2:$remote" || exit 1
fi
SHOW_LINES=${SHOW_LINES:-60} "$here/swrun.sh" "$run_dir" "$label" \
    "bash /root/hazim_perf/tools/sw_switchd.sh safety || { echo 'refusing to run bfshell'; exit 1; }; bash /root/hazim_perf/tools/sw_switchd.sh ready || exit 1; python3 /root/hazim_perf/tools/sw_bfshell_b.py $remote ${BFRT_TIMEOUT:-600}"
rc=$?
log=$(ls -t "$run_dir"/[0-9][0-9][0-9]_"$label".txt | head -1)
grep -ao 'HZJSON {.*}' "$log" | sed 's/^HZJSON //; s/\r$//' > "$run_dir/bfrt/$label.json"
echo "# results: $(wc -l < "$run_dir/bfrt/$label.json") HZJSON line(s) -> $run_dir/bfrt/$label.json"
exit $rc
