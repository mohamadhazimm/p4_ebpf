#!/usr/bin/env bash
# Run one shell command on the Tofino switch over the management network
# (root@172.168.1.2 via ma1) and keep a verbatim record of it on PC1.
#
#   perf/tools/swrun.sh RUN_DIR LABEL 'remote shell command'
#
# Same log format as logrun.sh; the switch's own UTC clock is printed first so
# switch-side timestamps can be related to PC1 time. The remote command runs
# under a non-login bash; source the SDE environment explicitly when needed.
set -u
SWITCH=${SWITCH:-root@172.168.1.2}
if [ $# -ne 3 ]; then
    echo "usage: $0 RUN_DIR LABEL 'remote command'" >&2
    exit 2
fi
run_dir=$1; label=$2; cmd=$3
mkdir -p "$run_dir"
n=$(printf '%03d' $(( $(ls "$run_dir" | grep -cE '^[0-9]{3}_') + 1 )))
out="$run_dir/${n}_${label}.txt"
start=$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)
t0=$(date +%s.%N)
{
    echo "# host: $SWITCH (switch, via ssh from $(hostname))"
    echo "# start_utc (PC1 clock): $start"
    echo "# cmd: $cmd"
    echo "# ---- output (stdout+stderr) ----"
} > "$out"
remote="echo \"# switch_utc: \$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)\"; $cmd"
ssh -o BatchMode=yes -o ConnectTimeout=10 "$SWITCH" "bash -c $(printf '%q' "$remote")" < /dev/null >> "$out" 2>&1
rc=$?
t1=$(date +%s.%N)
dur=$(awk -v a="$t0" -v b="$t1" 'BEGIN { printf "%.3f", b - a }')
echo "# ---- exit_code: $rc  wall_s: $dur" >> "$out"
cmd_1line=${cmd//$'\n'/\\n}; cmd_1line=${cmd_1line//$'\t'/\\t}
printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$n" "$start" "switch" "$rc" "$dur" "$cmd_1line" >> "$run_dir/INDEX.tsv"
if [ -n "${SHOW_LINES:-}" ]; then
    head -n "$SHOW_LINES" "$out"
    echo "# [display truncated to $SHOW_LINES lines; full log: $out]"
else
    cat "$out"
fi
exit $rc
