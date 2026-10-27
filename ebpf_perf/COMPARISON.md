# HostMon overhead compared with published eBPF and audit monitors

Measured 2026-10-26 on this host (Xeon w5-2455X, 12 cores / 24 threads, Linux 6.8.0-138),
against the published numbers collected in [LITERATURE.md](LITERATURE.md). Raw results are in
`results/macro-lit-*`; the combined summary is `results/literature-summary-20261026.{md,json}`
(produced by `analyze_macro.py`).

## Setup

- HostMon as built by `build.sh` from the unchanged `libbpf-bootstrap/examples/c/hostmon*`
  sources (hostmon `cfdb5296…`, hostmon.bpf.o `0d0eda52…`; full hashes in `build/sha256.txt`).
- Three conditions per experiment, counterbalanced, one warm-up round first:
  `base` (no HostMon), `mon_in` (HostMon attached, workload in the monitored cgroup),
  `mon_out` (HostMon attached, workload outside the cgroup).
- HostMon pinned to CPU 23 (SMT sibling of core 11). Benchmarks with fewer than 12 tasks run on
  cores 0–10; 12-task runs and the kernel build use cores 0–11, so there HostMon shares one
  physical core with the benchmark.
- Performance governor and `/dev/cpu_dma_latency` = 2 µs for the whole run (restored afterwards).
  `kernel.bpf_stats_enabled` off: an A/B test showed it adds ~50 ns per monitored syscall, so the
  earlier micro runs in `results/20261026T19*` (taken with it on) are superseded by these numbers.
- Repetitions: LMbench 3 outer × 3 inner, everything else 5 (eAudit N=4: 3). Medians reported.

## 1. Per-syscall microbenchmarks (LMbench-style), µs

| Test | HostMon base → monitored (added) | Unmonitored process | ebpH (added) | ProvBPF | CamFlow | SysComb |
|---|---|---|---|---|---|---|
| null syscall | 0.078 → 0.372 (+0.29, +379%) | +74% | +0.36 | 0% | 0% | +0.13 |
| read | 0.176 → 0.539 (+0.36, +206%) | +33% | +0.35 | +42% (+0.16) | – | – |
| write | 0.123 → 0.486 (+0.36, +294%) | +49% | +0.36 | +53% (+0.17) | – | – |
| stat | 0.437 → 0.975 (+0.54, +124%) | +20% | +0.39 | +35% (+0.36) | +100% (+0.39) | – |
| fstat | 0.178 → 0.528 (+0.35, +196%) | +34% | +0.36 | +28% (+0.14) | – | – |
| open/close | 0.953 → 2.628 (+1.68, +176%) | +24% | +0.79 | +46% (+0.82) | +80% (+0.71) | – |
| fork+exit | 152.9 → 149.0 (within noise) | – | +2.7% | +8% | +6% | – |
| fork+exec | 155.2 → 146.8 (within noise) | – | +8.1% | – | +3% | – |
| fork+/bin/sh | 501.7 → 624.9 (+123, +25%) | +11% | +153 (+10%) | – | +41 (+6%) | – |
| pipe | 4.05 → 6.24 (+2.2, +54%) | +6% | +1.26 (+28%) | +8% | – | – |
| AF_UNIX | 6.29 → 11.79 (+5.5, +87%) | +29% | +1.70 (+18%) | +47% | – | – |
| file create 0k | 6.26 → 7.65 (+22%) | +3% | – | +27% | +5% | – |
| file create 10k | 9.52 → 12.23 (+29%) | +5% | – | +25% | +16% | – |
| file delete 0k | 3.21 → 4.45 (+38%) | +3% | – | +14% | +11% | – |

fork and exec vary by about ±8% between repeats here, so their overhead is not resolved at 3 repeats.

## 2. Linux kernel build (defconfig, `make -j12`, wall time)

| System | Overhead |
|---|---|
| **HostMon** | **+6.4%** (74.08 → 78.84 s; unmonitored +0.6%; CPU time +4.6%) |
| ebpH | +0.97% |
| bpfbox passive / permissive | +1.33% / +13.85% |
| CamFlow | +2% |
| ProvBPF | +5% |

HostMon recorded 77% of the build's events as unattributed (`capacity_errors`): the consumer's
128-process table filled up, so those events are missing from the features.

## 3. eAudit benchmark suite

Wall-time overhead (HostMon monitored vs base):

| Benchmark | 1 task | 4 tasks | 12 tasks | events/s at 12 tasks |
|---|---|---|---|---|
| shbm | +12% | +9% | +24% | 1.47 M |
| httperf | +20% | +16% | +20% | 1.60 M |
| postmark | +51% | +39% | +83% | 2.68 M |
| find | +94% | +209% | +673% | 2.77 M |
| tar | +94% | +153% | +467% | 2.76 M |
| rdwr | +160% | +485% | +1561% | 2.80 M |

eAudit reports about +18% on average across benchmarks and core counts (+5.8% without find, tar
and rdwr), with no data loss up to ~17 M syscalls/s on 12 cores.

Agent CPU as a fraction of benchmark CPU (eAudit Fig. 20 metric), 1 task:

| | postmark | shbm |
|---|---|---|
| **HostMon** | **59%** | **21%** |
| eAudit | 4% | 5% |
| CamFlow | 50% | 39% |
| sysdig | 65% | 57% |
| Tracee | 270% | 184% |
| Tetragon | 694% | 615% |
| auditd | 900% | 118% |

HostMon's consumer spends 360–1,600 ns per event (eAudit Fig. 19: median 48 ns per syscall).
No ring-buffer loss in any run. shbm loses 72–76% of events to the 128-process table, as the
kernel build does.

## 4. Servers (client and server both monitored)

| System | Web server throughput | Redis SET / GET |
|---|---|---|
| **HostMon** | **nginx + wrk: −62%** (443,697 → 169,858 req/s; unmonitored +2%) | **−35% / −36%** (unmonitored −7% / −7%) |
| ProvBPF | Apache −8% | −10% / −11% |
| CamFlow | Apache −12% | −4% / −12% |
| bpfbox passive / permissive | Apache −5.6% / −8.4% | – |
| SysComb | nginx p90 latency +9.9% | p90 latency +3.8% |

Our nginx runs at ~444k req/s, 30–50× the Apache rates reported for ProvBPF and CamFlow, and
the monitored run reaches 2.53 M events/s, HostMon's throughput ceiling. The web result therefore
measures that ceiling more than a typical server load.

## 5. What the numbers show

- **Per-syscall cost matches ebpH**, the closest published design (every syscall, eBPF): about
  +0.30–0.36 µs per call, against ebpH's +0.36 µs and SysComb's +0.13 µs (which only updates a map).
- **open/close costs twice ebpH's**: each `openat` produces two ring-buffer records plus a
  256-byte path copy.
- **One shared ring buffer and one consumer thread cap HostMon at about 2.5–2.8 M events/s**
  in total. Syscall-heavy multi-task workloads (find, tar, rdwr, nginx) slow to that rate, which
  is where the 12-task results and the web result collapse. eAudit avoids this with per-CPU
  caches and ~17-byte batched records.
- **Collector CPU is between eAudit and sysdig/CamFlow**, far below Tracee, Tetragon and auditd.
- **Processes outside the monitored cgroup also pay** (+74% on a null syscall, +25% on rdwr,
  −7% Redis throughput), because the every-syscall tracepoint runs for every process and the
  cgroup check happens inside the BPF program.
- **The 128-process table drops 72–77% of events** in process-heavy workloads (shbm, kernel build).

## 6. Comparability limits

- Different hardware and kernels from every paper; compare relative overheads and added µs,
  not absolute times.
- Workloads were reimplemented from the papers' descriptions, not run from the authors' scripts.
  eAudit 1-task runs use a quarter of eAudit's totals to keep runs near 25 s. httperf replays 154
  of the 156 mirrored URIs (2 returned HTTP 401). The kernel tree is Ubuntu's 5.15 source with
  defconfig and `SECURITY_SELINUX_DISABLE` turned off so it builds.
- The tools trace different events. CamFlow and ProvBPF hook LSM operations, so they show 0% on
  syscalls they never see; an every-syscall monitor always pays something there. ebpH, SysComb
  and eAudit are the closer comparisons.
- In 12-task runs and the kernel build, HostMon shares a physical core with one benchmark thread.
- eAudit's Fig. 20 core count and configuration are not reproduced exactly.
