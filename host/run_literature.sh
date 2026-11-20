#!/usr/bin/env bash
# Replicate the benchmark methodology of the surveyed eBPF/audit/provenance papers
# against HostMon. Run as root:  sudo ./run_literature.sh [PHASE ...]
# Phases (default: all, in this order): lmbench eaudit1 eaudit12 kernel wrk redis eaudit4
#   lmbench   LMbench-style microbenchmarks (CamFlow, LPM, saBPF, ebpH)          5 reps
#   eauditN   eAudit's 7-benchmark suite minus kernel, N parallel tasks; N=1 uses
#             a quarter of eAudit's totals to keep runs ~25 s                     REPS reps
#   kernel    defconfig kernel build, make -j12 (ebpH, bpfbox, BPFContain, saBPF,
#             CamFlow, eAudit, Tetragon)                                          REPS reps
#   wrk       nginx + wrk -t4 -c64 -d15s (SysComb, BPFContain, saBPF)              REPS reps
#   redis     redis-benchmark SET/GET, 1M requests, 50 clients (CamFlow, saBPF)  REPS reps
# Every experiment runs base / mon_in / mon_out with one warm-up round first.
# HostMon is pinned to CPU 23 (SMT sibling of core 11); benchmarks with fewer than 12
# tasks are confined to cores 0-10 so they never share HostMon's physical core, and
# 12-task benchmarks use cores 0-11 (one hardware thread per core, like eAudit's
# HT-off 12-core machine). kernel.bpf_stats_enabled stays off (it inflates overhead).
# HOSTMON_BIN selects the collector (default build/hostmon); TAG=x names the result
# directories macro-lit-x-* so runs of different collectors stay apart.
# TUNE=1 additionally sets the performance governor on all CPUs and holds
# /dev/cpu_dma_latency at 2 us (no C6) for the whole run; both are restored on exit.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"
[[ $EUID -eq 0 ]] || { echo "run as root: sudo $0" >&2; exit 1; }
export HM_CPU="${HM_CPU:-23}" WARMUP="${WARMUP:-1}" BPF_STATS=0
REPS="${REPS:-5}" REPS_N4="${REPS_N4:-3}" LM_OUTER_REPS="${LM_OUTER_REPS:-3}" TUNE="${TUNE:-0}"
FEW=0-10 ALL=0-11
export HOSTMON_BIN="${HOSTMON_BIN:-$HERE/build/hostmon}"
L="lit${TAG:+-$TAG}"
PHASES=("$@")
[[ ${#PHASES[@]} -gt 0 ]] || PHASES=(lmbench eaudit1 eaudit12 kernel wrk redis eaudit4)
TS="$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p results
LOG="results/literature-$TS.log"
declare -A OLD_GOV=() OLD_EPP=()
DMA_PID=""
finish() {
  [[ -n $DMA_PID ]] && kill "$DMA_PID" 2>/dev/null || true
  local c
  for c in "${!OLD_GOV[@]}"; do
    echo "${OLD_GOV[$c]}" > "$c/cpufreq/scaling_governor" 2>/dev/null || true
    [[ -n ${OLD_EPP[$c]:-} ]] && echo "${OLD_EPP[$c]}" > "$c/cpufreq/energy_performance_preference" 2>/dev/null || true
  done
  chown "${SUDO_UID:-0}:${SUDO_GID:-0}" results "$LOG" 2>/dev/null || true
}
trap finish EXIT
if [[ $TUNE == 1 ]]; then
  for c in /sys/devices/system/cpu/cpu[0-9]*; do
    [[ -f $c/cpufreq/scaling_governor ]] || continue
    OLD_GOV[$c]=$(cat "$c/cpufreq/scaling_governor")
    OLD_EPP[$c]=$(cat "$c/cpufreq/energy_performance_preference" 2>/dev/null || true)
    echo performance > "$c/cpufreq/scaling_governor"
  done
  /usr/bin/python3 -c 'import os, signal, struct; fd = os.open("/dev/cpu_dma_latency", os.O_WRONLY); os.write(fd, struct.pack("i", 2)); signal.pause()' &
  DMA_PID=$!
fi

declare -A TOTAL=([shbm]=200000 [find]=288 [tar]=144 [rdwr]=100000000 [postmark]=24 [httperf]=3000)
KSETUP='source workloads/kernel_env.sh && cd "$KERNEL_TREE" && make clean >/dev/null 2>&1 && make mrproper >/dev/null 2>&1 && make defconfig >/dev/null 2>&1 && scripts/config --disable SECURITY_SELINUX_DISABLE && make olddefconfig >/dev/null 2>&1'

eaudit() {
  local n=$1 reps=$2 b total
  export BENCH_CPUS=$FEW
  (( n == 12 )) && export BENCH_CPUS=$ALL
  for b in shbm find tar rdwr postmark httperf; do
    total=${TOTAL[$b]}
    (( n == 1 )) && total=$(( total / 4 ))
    if [[ $b == rdwr ]]; then
      ./run_macro.sh "$L-eaudit-$b-N$n" "$reps" --setup "PREPARE_ONLY=1 workloads/eaudit.sh rdwr $n $total" -- workloads/eaudit.sh "$b" "$n" "$total"
    else
      ./run_macro.sh "$L-eaudit-$b-N$n" "$reps" -- workloads/eaudit.sh "$b" "$n" "$total"
    fi
  done
}

{
  echo "start $(date -u +%FT%TZ) phases=${PHASES[*]} reps=$REPS reps_n4=$REPS_N4 hostmon_bin=$HOSTMON_BIN hm_cpu=$HM_CPU warmup=$WARMUP tune=$TUNE governor=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor)"
  for phase in "${PHASES[@]}"; do
    echo "=== phase $phase $(date -u +%FT%TZ)"
    case $phase in
      lmbench)  BENCH_CPUS=$FEW ./run_macro.sh "$L-lmbench" "$LM_OUTER_REPS" -- env LM_REPS=3 workloads/lmbench.sh ;;
      eaudit1)  eaudit 1 "$REPS" ;;
      eaudit4)  eaudit 4 "$REPS_N4" ;;
      eaudit12) eaudit 12 "$REPS" ;;
      kernel)   BENCH_CPUS=$ALL ./run_macro.sh "$L-kernel-j12" "$REPS" --setup "$KSETUP" -- workloads/eaudit.sh kernel 12 ;;
      wrk)      BENCH_CPUS=$FEW ./run_macro.sh "$L-wrk" "$REPS" -- workloads/http_kv.sh wrk 4 64 15 ;;
      redis)    BENCH_CPUS=$FEW ./run_macro.sh "$L-redis" "$REPS" -- workloads/http_kv.sh redis 1000000 50 ;;
      *) echo "unknown phase $phase" >&2; exit 2 ;;
    esac
  done
  echo "done $(date -u +%FT%TZ)"
} 2>&1 | tee -a "$LOG"
