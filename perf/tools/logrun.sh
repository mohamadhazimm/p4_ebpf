#!/usr/bin/env bash
# Run one shell command on PC1 and keep a verbatim record of it.
#
#   perf/tools/logrun.sh RUN_DIR LABEL 'shell command'
#
# Output (stdout+stderr) goes to RUN_DIR/NNN_LABEL.txt between a header
# (host, UTC start, cwd, exact command) and a footer (exit code, wall time).
# One summary line is appended to RUN_DIR/INDEX.tsv. The log is echoed back
# (only the first SHOW_LINES lines if that variable is set). The exit code of
# the command is preserved.
set -u
if [ $# -ne 3 ]; then
    echo "usage: $0 RUN_DIR LABEL 'command'" >&2
    exit 2
fi
run_dir=$1; label=$2; cmd=$3
mkdir -p "$run_dir"
n=$(printf '%03d' $(( $(ls "$run_dir" | grep -cE '^[0-9]{3}_') + 1 )))
out="$run_dir/${n}_${label}.txt"
start=$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)
t0=$(date +%s.%N)
{
    echo "# host: $(hostname) (PC1, local)"
    echo "# start_utc: $start"
    echo "# cwd: $PWD"
    echo "# cmd: $cmd"
    echo "# ---- output (stdout+stderr) ----"
} > "$out"
bash -c "$cmd" >> "$out" 2>&1
rc=$?
t1=$(date +%s.%N)
dur=$(awk -v a="$t0" -v b="$t1" 'BEGIN { printf "%.3f", b - a }')
echo "# ---- exit_code: $rc  wall_s: $dur" >> "$out"
cmd_1line=${cmd//$'\n'/\\n}; cmd_1line=${cmd_1line//$'\t'/\\t}
printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$n" "$start" "PC1" "$rc" "$dur" "$cmd_1line" >> "$run_dir/INDEX.tsv"
if [ -n "${SHOW_LINES:-}" ]; then
    head -n "$SHOW_LINES" "$out"
    echo "# [display truncated to $SHOW_LINES lines; full log: $out]"
else
    cat "$out"
fi
exit $rc
