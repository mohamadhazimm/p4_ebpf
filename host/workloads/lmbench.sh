#!/usr/bin/env bash
# LMbench-style microbenchmarks (the suite used by CamFlow, LPM, Hi-Fi, LSM papers).
# Uses the Ubuntu lmbench 3.0-a9 binaries where they work on this host; open/close
# and fstat come from bench_load because this lat_syscall build stalls in its timing
# calibration for those two tests. Prints "RESULT <name> <microseconds>" lines.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$HERE")"
L="$ROOT/tools/root/usr/lib/lmbench/bin/x86_64-linux-gnu"
WORK="${EAUDIT_WORKDIR:-${XDG_CACHE_HOME:-$HOME/.cache}/hostmon-bench}/lmbench"
REPS="${LM_REPS:-5}"
mkdir -p "$WORK/fs"
FILE="$WORK/statfile"
echo x > "$FILE"

us() { awk '{for (i = 1; i <= NF; i++) if ($i ~ /^[0-9.]+$/) v = $i} END {print v}'; }
run() { local name=$1; shift; printf 'RESULT %s %s\n' "$name" "$("$@" 2>&1 | tail -1 | us)"; }

run null_syscall "$L/lat_syscall" -N "$REPS" null
run read         "$L/lat_syscall" -N "$REPS" read
run write        "$L/lat_syscall" -N "$REPS" write
run stat         "$L/lat_syscall" -N "$REPS" stat "$FILE"
for mode in openonly fstat; do
  n=2000000
  ns=$("$ROOT/build/bench_load" - "$mode" "$n" 0 "$FILE" | sed 's/.*"elapsed_ns":\([0-9]*\).*/\1/')
  printf 'RESULT %s %s\n' "$( [[ $mode == openonly ]] && echo open_close || echo fstat )" "$(awk -v ns="$ns" -v n="$n" 'BEGIN {printf "%.4f", ns / n / 1000}')"
done
(cd "$L" && run fork  ./lat_proc -N "$REPS" fork)
(cd "$L" && run exec  ./lat_proc -N "$REPS" exec)
(cd "$L" && run shell ./lat_proc -N "$REPS" shell)
run af_unix "$L/lat_unix" -N "$REPS"
run pipe    "$L/lat_pipe" -N "$REPS"
# lat_fs -s 0 runs 0k/1k/4k/10k files; columns: size files creates/s deletes/s.
# (-N and -n make this build stall in calibration, so defaults are used.)
"$L/lat_fs" -s 0 "$WORK/fs" 2>&1 | while read -r size _ creates deletes; do
  [[ $size == 0k || $size == 10k ]] || continue
  printf 'RESULT fs_create_%s %s\nRESULT fs_delete_%s %s\n' "$size" "$(awk -v r="$creates" 'BEGIN {printf "%.3f", 1e6 / r}')" \
    "$size" "$(awk -v r="$deletes" 'BEGIN {printf "%.3f", 1e6 / r}')"
done
