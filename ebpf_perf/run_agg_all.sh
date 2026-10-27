#!/usr/bin/env bash
# Evaluate hostmon_agg in one command (run as root from a terminal):
#   sudo ./run_agg_all.sh
#  1. check_agg.sh: hostmon_agg against hostmon side by side (about 30 s). Stops if they differ.
#  2. run_bench.sh quick, once with hostmon and once with hostmon_agg, bpf_stats on:
#     BPF ns per syscall and syscall coverage, same session (about 10 min).
#  3. run_literature.sh with hostmon_agg, TUNE=1, TAG=agg: the same suite and settings
#     as the 2026-10-26 hostmon run (about 2.5 h). Results in results/macro-lit-agg-*.
# Extra arguments are passed to run_literature.sh (phase names, e.g. "lmbench kernel").
# Progress goes to results/agg-all-<UTC timestamp>.log; results/agg-all.status says
# which step is running and, at the end, the exit status.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"
[[ $EUID -eq 0 ]] || { echo "run as root: sudo $0" >&2; exit 1; }
TS="$(date -u +%Y%m%dT%H%M%SZ)"
LOG="results/agg-all-$TS.log"
STATUS="results/agg-all.status"
mkdir -p results
owner() { chown "${SUDO_UID:-0}:${SUDO_GID:-0}" results "$LOG" "$STATUS" 2>/dev/null || true; }
step() {
  echo "$1 $TS $(date -u +%FT%TZ)" > "$STATUS"
  owner
  echo "=== $1 $(date -u +%FT%TZ)"
}

{
  step check && ./check_agg.sh &&
  step micro-hostmon && ./run_bench.sh quick &&
  step micro-hostmon_agg && HOSTMON_BIN="$HERE/build/hostmon_agg" ./run_bench.sh quick &&
  step literature && TUNE=1 TAG=agg HOSTMON_BIN="$HERE/build/hostmon_agg" ./run_literature.sh "$@"
} 2>&1 | tee -a "$LOG"
rc=${PIPESTATUS[0]}
echo "finished $TS rc=$rc log=$LOG" > "$STATUS"
owner
echo "finished rc=$rc, log: $HERE/$LOG"
exit "$rc"
