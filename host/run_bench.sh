#!/usr/bin/env bash
# HostMon (ADFA-feature eBPF collector) performance benchmark. Run as root:
#   sudo ./run_bench.sh            # full matrix, 5 repeats (~15 min)
#   sudo ./run_bench.sh quick      # reduced matrix, 2 repeats (~3 min)
#
# Config fields: MODE COUNT RATE [PROCS]. PROCS > 1 runs that many copies in
# parallel (COUNT and RATE are per copy), each pinned to its own core.
#
# Conditions per workload, counterbalanced per repeat:
#   base     no HostMon; workload in the dedicated cgroup
#   mon_in   HostMon attached; workload in the monitored cgroup
#   mon_out  HostMon attached; workload outside the cgroup (filter-only cost)
#
# Temporarily enables kernel.bpf_stats_enabled and creates one cgroup; both are
# restored/removed on exit. Results go to results/<UTC timestamp>/.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
BUILD="$HERE/build"
PROFILE="${1:-full}"
WINDOW="${WINDOW:-1}"
BENCH_CPUS=(${BENCH_CPUS:-2 6 8 10 3 7 9 11})
HM_CPU="${HM_CPU:-4}"
HOSTMON_BIN="${HOSTMON_BIN:-$BUILD/hostmon}"  # or build/hostmon_agg
PY=/usr/bin/python3

[[ $EUID -eq 0 ]] || { echo "run as root: sudo $0 $PROFILE" >&2; exit 1; }
[[ -x $HOSTMON_BIN && -x $BUILD/bench_load ]] || { echo "run ./build.sh first" >&2; exit 1; }

case "$PROFILE" in
  full)  REPS="${REPS:-5}"
         CONFIGS=("getppid 5000000 0" "getppid 150000 50000" "getppid 600000 200000"
                  "getppid 1500000 500000" "getppid 3000000 1000000" "getppid 6000000 2000000"
                  "getppid 3000000 0 2" "getppid 3000000 0 4" "getppid 3000000 0 8"
                  "openclose 500000 0" "openclose 300000 100000" "openclose 300000 0 4" "forkexec 2000 0") ;;
  quick) REPS="${REPS:-2}"
         CONFIGS=("getppid 5000000 0" "getppid 600000 200000" "getppid 3000000 1000000" "getppid 3000000 0 4"
                  "openclose 500000 0" "forkexec 1000 0") ;;
  *) echo "profile must be full or quick" >&2; exit 1 ;;
esac

TS="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="$HERE/results/$TS"
CG="/sys/fs/cgroup/hostmon-bench-$TS"
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
  [[ -n ${SUDO_UID:-} ]] && chown "$SUDO_UID:$SUDO_GID" "$HERE/results" && chown -R "$SUDO_UID:$SUDO_GID" "$OUT" || true
}
trap cleanup EXIT
echo 1 > /proc/sys/kernel/bpf_stats_enabled

# Environment record.
{
  echo "{\"profile\":\"$PROFILE\",\"reps\":$REPS,\"window_sec\":$WINDOW,"
  echo "\"bench_cpus\":\"${BENCH_CPUS[*]}\",\"hostmon_cpu\":$HM_CPU,\"kernel\":\"$(uname -r)\","
  echo "\"cpu\":\"$(lscpu | sed -n 's/^Model name: *//p')\","
  echo "\"governor\":\"$(cat /sys/devices/system/cpu/cpu${BENCH_CPUS[0]}/cpufreq/scaling_governor 2>/dev/null || echo unknown)\","
  echo "\"bpf_stats_enabled_before\":$OLD_STATS,\"cgroup\":\"$CG\",\"hostmon_bin\":\"$HOSTMON_BIN\","
  echo "\"configs\":$(printf '%s\n' "${CONFIGS[@]}" | $PY -c 'import json,sys;print(json.dumps([l.strip() for l in sys.stdin if l.strip()]))')}"
} > "$OUT/environment.json"
cp "$BUILD/sha256.txt" "$OUT/build-sha256.txt"
grep -r . /sys/devices/system/cpu/vulnerabilities/ > "$OUT/cpu-vulnerabilities.txt" 2>/dev/null || true

hm_runtime_ns() { awk '{print $1}' "/proc/$1/schedstat"; }

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
  if ! grep -q '^HOSTMON_READY' "$d/hostmon.out" 2>/dev/null; then
    exec 9>&-
    echo "HostMon failed to load/attach; see $d/hostmon.err:" >&2
    cat "$d/hostmon.err" >&2
    exit 1
  fi
  $PY -c 'import time; print(f"{time.monotonic() + 0.3:.9f}")' >&9
  exec 9>&-
  sleep 0.5
}

run_one() {
  local mode=$1 count=$2 rate=$3 cond=$4 rep=$5 nproc=$6 i
  local d="$OUT/runs/${mode}_r${rate}_p${nproc}_${cond}_${rep}"
  (( nproc <= ${#BENCH_CPUS[@]} )) || { echo "PROCS $nproc exceeds BENCH_CPUS" >&2; exit 1; }
  local procs="$CG/cgroup.procs" hm_rc=0 hm_before=0 hm_after=0
  mkdir -p "$d"
  [[ $cond == mon_out ]] && procs="-"
  if [[ $cond != base ]]; then
    start_hostmon "$d"
    bpftool prog show --json > "$d/progs_before.json"
    hm_before=$(hm_runtime_ns "$HM_PID")
  fi
  local workers=()
  for (( i = 0; i < nproc; i++ )); do
    taskset -c "${BENCH_CPUS[$i]}" "$BUILD/bench_load" "$procs" "$mode" "$count" "$rate" > "$d/bench.$i.json" 2> "$d/bench.$i.err" &
    workers+=($!)
  done
  for i in "${workers[@]}"; do wait "$i" || true; done
  cat "$d"/bench.*.json > "$d/bench.json"
  if [[ $cond != base ]]; then
    sleep "$($PY -c "print($WINDOW + 0.5)")"
    bpftool prog show --json > "$d/progs_after.json"
    hm_after=$(hm_runtime_ns "$HM_PID")
    grep -E '^(VmHWM|VmRSS)' "/proc/$HM_PID/status" > "$d/hostmon.mem" || true
    kill -INT "$HM_PID"
    wait "$HM_PID" || hm_rc=$?
    HM_PID=""
  fi
  printf '{"mode":"%s","count":%s,"rate":%s,"procs":%s,"cond":"%s","rep":%s,"hostmon_rc":%s,"hostmon_cpu_ns":%s,"hostmon_pid_cpu":%s}\n' \
    "$mode" "$count" "$rate" "$nproc" "$cond" "$rep" "$hm_rc" "$((hm_after - hm_before))" "$HM_CPU" > "$d/meta.json"
  printf '%-10s rate=%-8s procs=%s %-8s rep=%s  %s\n' "$mode" "$rate" "$nproc" "$cond" "$rep" "$(head -1 "$d/bench.json" | cut -c1-80)"
}

ORDERS=("base mon_in mon_out" "mon_in mon_out base" "mon_out base mon_in")
for config in "${CONFIGS[@]}"; do
  read -r mode count rate nproc <<< "$config"
  nproc=${nproc:-1}
  for rep in $(seq "$REPS"); do
    for cond in ${ORDERS[$(( (rep - 1) % 3 ))]}; do
      run_one "$mode" "$count" "$rate" "$cond" "$rep" "$nproc"
    done
  done
done

$PY "$HERE/analyze_bench.py" "$OUT" || echo "analysis failed; raw results kept in $OUT" >&2
echo "results: $OUT"
