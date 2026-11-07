# HostMon overhead compared with published eBPF and audit monitors

Measured 2026-10-26 on this host (Xeon w5-2455X, 12 cores / 24 threads, Linux 6.8.0-138),
against the published numbers collected in [LITERATURE.md](LITERATURE.md). Raw results are in
`results/macro-lit-*`; the combined summary is `results/literature-summary-20261026.{md,json}`
(produced by `analyze_macro.py`).

Sections 1–6 are the original HostMon. Section 7 repeats the same suite with `hostmon_agg`
(in-kernel aggregation, [hostmon_agg/README.md](hostmon_agg/README.md)) on 2026-10-27.

## Setup

- HostMon as built by `build.sh` from the then-uncommitted, cgroup-scoped
  `libbpf-bootstrap/examples/c/hostmon*` sources (hostmon `cfdb5296…`, hostmon.bpf.o
  `0d0eda52…`; full hashes in `build/sha256.txt`). Those sources are committed as
  `hostmon_ref/` since 2026-11-07, and `build.sh` rebuilds the same bytes from them.
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

## 7. After optimization: hostmon_agg (2026-10-27)

Same suite, settings, cores and repetitions as sections 1–6 (`sudo ./run_agg_all.sh`, which runs
`TUNE=1 TAG=agg HOSTMON_BIN=build/hostmon_agg ./run_literature.sh`). Raw results are in
`results/macro-lit-agg-*`, the summary in `results/literature-agg-summary-20261027.{md,json}`.
All 354 runs exited 0 and every collector exited 0. All 192 monitored runs report
`HOSTMON_HEALTH,0,0,0,0`: no lost events, no capacity errors, no late events. The suite took
2 h 09 min, against 2 h 47 min for the original collector. Every overhead below is relative to
the same day's `base` runs.

### 7.1 Per-syscall microbenchmarks, µs added (base → monitored)

| Test | hostmon | hostmon_agg | Unmonitored process (hostmon → agg) | ebpH | SysComb |
|---|---|---|---|---|---|
| null syscall | +0.295 (+379%) | **+0.049 (+63%)** | +74% → +18% | +0.36 | +0.13 |
| read | +0.363 (+206%) | **+0.045 (+26%)** | +33% → +8% | +0.35 | – |
| write | +0.363 (+294%) | **+0.047 (+38%)** | +48% → +11% | +0.36 | – |
| stat | +0.539 (+123%) | **+0.074 (+17%)** | +20% → +5% | +0.39 | – |
| fstat | +0.350 (+196%) | **+0.050 (+28%)** | +34% → +9% | +0.36 | – |
| open/close | +1.675 (+176%) | **+0.136 (+16%)** | +24% → +5% | +0.79 | – |
| pipe | +2.20 (+54%) | **+0.14 (+3%)** | +6% → +5% | +1.26 | – |
| AF_UNIX | +5.50 (+87%) | **+0.62 (+8%)** | +29% → +8% | +1.70 | – |
| fork+/bin/sh | +123 (+25%) | **+13.9 (+3%)** | +11% → +5% | +153 | – |
| file create 0k / 10k | +22% / +28% | **+4% / +1%** | | | |
| file delete 0k / 10k | +38% / +21% | **+2% / −3%** | | | |

fork+exit and fork+exec stay within the ±8% repeat-to-repeat noise for both collectors.

### 7.2 Linux kernel build (defconfig, `make -j12`)

| | hostmon | hostmon_agg |
|---|---|---|
| Wall time, base → monitored | 74.08 → 78.84 s (**+6.4%**) | 73.66 → 74.13 s (**+0.6%**) |
| Unmonitored | +0.6% | +0.2% |
| Benchmark CPU time | +4.6% | +0.4% |
| Events not attributed to a process | 77% | **0%** |

The five hostmon_agg base builds range from 73.52 to 74.54 s. The 0.47 s difference is
inside that spread, so at 5 repeats hostmon_agg's kernel-build overhead is under 1% and not
resolved further. Published: ebpH +0.97%, bpfbox passive +1.33%, CamFlow +2%, ProvBPF +5%.

### 7.3 eAudit benchmark suite (wall time)

| Benchmark | 1 task | 4 tasks | 12 tasks | events/s at 12 tasks |
|---|---|---|---|---|
| shbm | +12.3% → **+1.8%** | +9.0% → **+1.8%** | +23.7% → **+3.6%** | 1.47 M → 1.71 M |
| httperf | +19.7% → **+1.2%** | +16.2% → **+1.7%** | +20.3% → **+1.1%** | 1.60 M → 2.27 M |
| postmark | +50.7% → **+4.0%** | +38.7% → **+3.1%** | +82.9% → **+1.3%** | 2.68 M → 4.88 M |
| find | +94.1% → **+11.1%** | +208.7% → **+10.3%** | +673.4% → **+10.0%** | 2.77 M → 19.8 M |
| tar | +93.7% → **+7.9%** | +153.4% → **+6.8%** | +467.0% → **+10.7%** | 2.76 M → 14.2 M |
| rdwr | +159.8% → **+22.3%** | +485.0% → **+21.7%** | +1561.3% → **+24.2%** | 2.80 M → 35.6 M |

Mean over the 18 cells: hostmon_agg **+8.0%**, or **+2.2%** without find, tar and rdwr.
eAudit reports about +18% and +5.8% respectively. The 12-task overhead is now about the same
as the 1-task overhead, because there is no shared ring buffer or consumer to saturate.

Agent CPU as a fraction of benchmark CPU, 1 task (eAudit Fig. 20 metric):

| | postmark | shbm |
|---|---|---|
| hostmon | 59% | 21% |
| **hostmon_agg** | **<0.1%** | **1.1%** |
| eAudit | 4% | 5% |

shbm's events not attributed to a process: 72–76% → 0% at 1, 4 and 12 tasks.

### 7.4 Servers

| | Web server throughput | Redis SET / GET |
|---|---|---|
| hostmon | nginx + wrk −62% | −35% / −36% |
| **hostmon_agg** | **nginx + wrk −6.8%** (504,105 → 469,635 req/s; unmonitored −1.3%) | **−5.2% / −4.8%** (unmonitored −1.5% / −1.4%) |
| ProvBPF | Apache −8% | −10% / −11% |
| CamFlow | Apache −12% | −4% / −12% |

The monitored nginx run recorded 6.93 M events/s, against hostmon's 2.53 M ceiling. The nginx
base rate was 443,697 req/s on 2026-10-26 and 504,105 req/s on 2026-10-27, although `base` loads
no collector. The cause was not investigated; each day's overhead uses that day's base.

### 7.5 What changed and what remains

- Per-syscall cost dropped from ~0.30–0.36 µs to ~0.045–0.050 µs, below ebpH (+0.36 µs) and
  SysComb (+0.13 µs). open/close costs a sixth of ebpH's.
- The ~2.5–2.8 M events/s ceiling is gone: find, tar, rdwr and nginx no longer collapse with
  more tasks (rdwr at 12 tasks: 35.6 M events/s, no loss).
- No events are dropped for lack of a process slot (kernel build and shbm: 77% → 0%).
- Collector CPU is near zero: user space wakes once per window. Its peak memory (VmHWM) is
  13.5 MiB in most runs (hostmon: 34.5 MiB) and grows with the number of processes per window
  (125.6 MiB in shbm at 12 tasks, 25.9 MiB in the kernel build).
- rdwr is still +22–24%. It is a loop of one-byte read/write pairs (25 M pairs in 12.8 s at
  1 task, about 250 ns per call including the loop), so the fixed ~50 ns per call is a large
  share. Lowering it further needs a cheaper per-call update, for
  example per-CPU entries without the per-process lock.
- Unmonitored processes still pay about 14 ns per syscall (+18% on a null syscall, +5.5–7% on
  rdwr): the hook runs for every process and the cgroup check is inside the program.
- The comparability limits of section 6 still apply.
