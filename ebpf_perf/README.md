# HostMon eBPF performance benchmark

Measures the cost of `libbpf-bootstrap/examples/c/hostmon` (the eBPF collector that
computes the ADFA syscall-sequence descriptors: total/unique syscalls, entropy,
top-syscall frequency, average/max run length, transition count, rare-syscall
ratio, first-50/100 unique) on the local machine.

```sh
./build.sh                 # no root; builds build/hostmon (static) and build/bench_load
sudo ./run_bench.sh quick  # ~3 min smoke run
sudo ./run_bench.sh        # full matrix, 5 repeats (~15 min)
```

`bench_load` issues a known number of syscalls (`getppid`, `openat+read+close`, or
`fork+exec /bin/true`), optionally paced to a target rate with a syscall-free busy wait.
Each workload runs in three counterbalanced conditions:

- `base`: HostMon not running
- `mon_in`: HostMon attached, workload inside the monitored cgroup
- `mon_out`: HostMon attached, workload outside the cgroup (cost of the filter alone)

Per run the harness records workload wall time, HostMon window output and its
`HOSTMON_HEALTH` line (ring-buffer loss, capacity errors, late events), BPF per-program
`run_time_ns`/`run_cnt` (via `kernel.bpf_stats_enabled`, restored afterwards),
collector CPU time and peak RSS. `analyze_bench.py` writes `summary.md`/`summary.json`
in `results/<timestamp>/`: overhead vs `base`, added ns per operation, ns per BPF
invocation, loss fraction, syscall coverage (recorded / issued), and the ADFA features
for one run.

Optional environment: `WINDOW` (s, default 1), `BENCH_CPU` (2), `HM_CPU` (4), `REPS`.
The CPU governor is recorded but not changed.

## hostmon_agg (optimized collector)

`build/hostmon_agg` computes the same features with in-kernel aggregation (one
`tp_btf/sys_enter` program, one map entry per process and window, no per-syscall
ring-buffer records); see [hostmon_agg/README.md](hostmon_agg/README.md). Every
runner takes `HOSTMON_BIN=build/hostmon_agg`; `run_literature.sh` also takes `TAG`
to keep result directories apart.

```sh
./build.sh && ./build/test_agg_equiv   # no root: offline equivalence with hostmon.c
sudo ./check_agg.sh                    # both collectors side by side on one workload
sudo ./run_agg_all.sh                  # check, micro A/B, full literature suite (~3 h)
```
