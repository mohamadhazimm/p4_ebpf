#!/usr/bin/env bash
# Live check of hostmon_agg against hostmon. Run as root:  sudo ./check_agg.sh
#
# Starts both collectors on the same dedicated cgroup with the same window and
# start time, runs hostmon_agg/check_workload.sh inside the cgroup as the
# invoking user, stops both, and compares their per-window rows with
# hostmon_agg/compare_agg.py. Exit status 0 = equivalent.
# Results: results/agg-check-<UTC timestamp>/.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
BUILD="$HERE/build"
WINDOW="${WINDOW:-1}"
PY=/usr/bin/python3

[[ $EUID -eq 0 ]] || { echo "run as root: sudo $0" >&2; exit 1; }
for b in hostmon hostmon_agg bench_load; do
  [[ -x $BUILD/$b ]] || { echo "run ./build.sh first ($b missing)" >&2; exit 1; }
done
RUN_UID="${SUDO_UID:-0}" RUN_GID="${SUDO_GID:-0}"
AS_USER=(setpriv --reuid="$RUN_UID" --regid="$RUN_GID" --init-groups --reset-env)
USER_HOME="$(getent passwd "$RUN_UID" | cut -d: -f6)"

TS="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="$HERE/results/agg-check-$TS"
CG="/sys/fs/cgroup/hostmon-aggcheck-$TS"
mkdir -p "$OUT"
chown "$RUN_UID:$RUN_GID" "$HERE/results" "$OUT"
mkdir "$CG"
PIDS=()

cleanup() {
  local p
  for p in "${PIDS[@]}"; do kill -INT "$p" 2>/dev/null || true; done
  for p in "${PIDS[@]}"; do wait "$p" 2>/dev/null || true; done
  if [[ -d $CG ]]; then
    while read -r p; do echo "$p" > /sys/fs/cgroup/cgroup.procs 2>/dev/null || true; done < "$CG/cgroup.procs"
    rmdir "$CG" 2>/dev/null || echo "WARNING: could not remove $CG" >&2
  fi
  chown -R "$RUN_UID:$RUN_GID" "$OUT" 2>/dev/null || true
}
trap cleanup EXIT

cp "$BUILD/sha256.txt" "$OUT/build-sha256.txt"
mkfifo "$OUT/hostmon.fifo" "$OUT/hostmon_agg.fifo"
"$BUILD/hostmon" "$WINDOW" "$CG" < "$OUT/hostmon.fifo" > "$OUT/hostmon.out" 2> "$OUT/hostmon.err" &
PIDS+=($!)
"$BUILD/hostmon_agg" "$WINDOW" "$CG" < "$OUT/hostmon_agg.fifo" > "$OUT/hostmon_agg.out" 2> "$OUT/hostmon_agg.err" &
PIDS+=($!)
exec 8> "$OUT/hostmon.fifo" 9> "$OUT/hostmon_agg.fifo"

ready() { grep -q '^HOSTMON_READY' "$OUT/hostmon.out" 2>/dev/null && grep -q '^HOSTMON_READY' "$OUT/hostmon_agg.out" 2>/dev/null; }
for _ in $(seq 150); do
  ready && break
  kill -0 "${PIDS[0]}" 2>/dev/null && kill -0 "${PIDS[1]}" 2>/dev/null || break
  sleep 0.1
done
if ! ready; then
  exec 8>&- 9>&-
  echo "a collector failed to load/attach:" >&2
  for f in hostmon hostmon_agg; do echo "--- $f.err" >&2; cat "$OUT/$f.err" >&2; done
  exit 1
fi
START="$($PY -c 'import time; print(f"{time.monotonic() + 0.3:.9f}")')"
echo "$START" >&8
echo "$START" >&9
exec 8>&- 9>&-
sleep 0.5

echo "workload running (about 15 s)..."
bash -c 'echo $$ > "$1"; shift; exec "$@"' _ "$CG/cgroup.procs" \
  "${AS_USER[@]}" env HOME="$USER_HOME" PATH="$PATH" \
  bash "$HERE/hostmon_agg/check_workload.sh" "$BUILD" "$OUT" > "$OUT/workload.log" 2>&1 || echo "workload exited $?" >&2
sleep "$($PY -c "print($WINDOW + 0.5)")"

kill -INT "${PIDS[@]}"
RC=()
for p in "${PIDS[@]}"; do
  rc=0
  wait "$p" || rc=$?
  RC+=("$rc")
done
PIDS=()
echo "collector exit codes: hostmon=${RC[0]} hostmon_agg=${RC[1]}"
for f in hostmon hostmon_agg; do [[ -s $OUT/$f.err ]] && { echo "--- $f.err"; cat "$OUT/$f.err"; }; done

status=0
$PY "$HERE/hostmon_agg/compare_agg.py" "$OUT/hostmon.out" "$OUT/hostmon_agg.out" \
  --threaded-pids "$OUT/threaded.pid" --json "$OUT/compare.json" | tee "$OUT/compare.txt" || status=$?
echo "results: $OUT"
exit "$status"
