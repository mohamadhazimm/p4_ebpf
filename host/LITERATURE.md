# Published overhead numbers used for comparison

Every number below was read in the cited source (tables, text, or figure labels),
not taken from secondary summaries. Hardware and kernels differ between papers and
from this machine (Xeon w5-2455X, 12 cores / 24 threads, Linux 6.8), so compare
*relative* overheads and *added* microseconds, not absolute times.

## Systems

| System | What is monitored / data path | Source |
|---|---|---|
| **ebpH** | eBPF tracepoints on **every syscall**; in-kernel syscall-sequence (lookahead-pair) model updated on each syscall; maps + perf buffer polled 1/s. Closest design to HostMon. | W. Findlay, *Host-Based Anomaly Detection with Extended BPF*, Carleton honours thesis, 2020. Ryzen 7 1700 (16 thr), Linux 5.3 |
| **SysComb** | eBPF `raw_syscalls/sys_enter` raw tracepoint for tracees; per call: map lookups + set a bit in a bitmap. **No events sent to user space.** | Rossi et al., arXiv:2608.26871, 2026. Threadripper 2950X, **Linux 6.8.0** |
| **BCC `syscount`** | eBPF on every syscall, in-kernel counting only (or counts + latency). | BCC man page `syscount(8)`, OVERHEAD section |
| **CamFlow** | LSM hooks, whole-system provenance, relayfs to user space. | Pasquier et al., *Practical Whole-System Provenance Capture*, ACM SoCC 2017. i7-4510U, Linux 4.9.5 |
| **ProvBPF (saBPF)** | BPF-LSM hooks, provenance records through a ring buffer. | Lim et al., *Secure Namespaced Kernel Audit for Containers*, ACM SoCC 2021. Intel i7, Linux 5.11.2 |
| **bpfbox** | BPF-LSM + kprobes/uprobes/tracepoints; ring buffer logs. "Passive" = engine loaded, no profiles; "Permissive" = every operation logged. | Findlay, Somayaji, Barrera, ACM CCSW 2020. 8-vCPU VM, Linux 5.8 |
| **eAudit** | eBPF tracepoints (entry+exit) for 80 provenance syscalls; per-CPU caches batched into a 16 MB ring buffer; ~17 B/record. | Sekar, Kimm, Aich, IEEE S&P 2024. i7-12700 (12 cores, HT off), Linux 5.19/6.2 |
| **sysdig, auditd, CamFlow, Tracee, Tetragon** | Configured by the eAudit authors for full syscall logging (Tracee/Tetragon: "may not be their intended use"). | Same eAudit paper, Fig. 15, 16, 20 |
| **Houssel et al.** | eBPF tracepoint / kprobe / fentry / LSM programs capturing **one event type per workload** (accept, file create, clone); cgroup filter pre / in-program / post. | Houssel et al., *A Study of Kernel Telemetry Options for Security-Oriented Provenance*, arXiv:2608.11418, 2026. 24 cores, Linux 6.1 |

## 1. Per-syscall microbenchmarks (LMbench and syscall loops), µs

| Test | ebpH (base → ebpH) | CamFlow whole (vanilla → whole) | ProvBPF (vanilla → ProvBPF) | SysComb raw tp |
|---|---|---|---|---|
| null syscall | getppid 0.058 → 0.416 (+0.358, +615%) | 0.07 → 0.06 (0%) | 0.30 → 0.29 (0%) | getpid 0.166 → 0.297 (+0.131) |
| read | 0.187 → 0.540 (+189%) | – | 0.40 → 0.56 (+42%) | – |
| write | 0.111 → 0.469 (+321%) | – | 0.36 → 0.53 (+53%) | – |
| stat | 0.587 → 0.973 (+66%) | 0.39 → 0.78 (+100%) | 1.04 → 1.40 (+35%) | – |
| fstat | 0.194 → 0.552 (+184%) | – | 0.52 → 0.66 (+28%) | – |
| open/close | 1.043 → 1.830 (+75.5%) | 0.88 → 1.59 (+80%) | 1.80 → 2.62 (+46%) | – |
| fork+exit | 200.5 → 206.0 (+2.7%) | 110 → 116 (+6%) | 295.55 → 317.78 (+8%) | – |
| fork+exec | 536.9 → 580.5 (+8.1%) | 287 → 296 (+3%) | – | – |
| fork+/bin/sh | 1529 → 1682 (+10.0%) | 730 → 771 (+6%) | – | – |
| pipe | 4.510 → 5.768 (+27.9%) | – | 6.06 → 6.55 (+8%) | – |
| AF_UNIX | 9.367 → 11.067 (+18.1%) | – | 6.60 → 9.72 (+47%) | – |
| file create 0k | – | 5.05 → 5.32 (+5%) | 10.31 → 13.10 (+27%) | – |
| file delete 0k | – | 3.42 → 3.78 (+11%) | 11.25 → 12.80 (+14%) | – |
| file create 10k | – | 9.81 → 11.41 (+16%) | 16.55 → 20.65 (+25%) | – |

BCC `syscount`: a loop of 4 million `geteuid()` calls is slowed **1.85×** when tracing counts only and **>5×** with counts + latencies; ">3.5 million syscalls per second ... should not be typical".

## 2. Linux kernel build (elapsed time)

| System | Overhead | Notes |
|---|---|---|
| ebpH | **+0.97%** (system time +10.6%, user +0.3%) | Linux 5.6, all 16 threads |
| bpfbox passive / permissive | **+1.33% / +13.85%** | Linux 5.8.0-rc6, 6 runs |
| CamFlow whole | **+2%** (433 → 442 s) | |
| ProvBPF | **+5%** (194.26 → 203.70 s) | |

## 3. eAudit benchmark suite

eAudit Fig. 20, *runtime overhead* = agent CPU time / benchmark CPU time (postmark / shbm):

| eAudit | sysdig | CamFlow | auditd | Tracee | Tetragon |
|---|---|---|---|---|---|
| 4% / 5% | 65% / 57% | 50% / 39% | 900% / 118% | 270% / 184% | 694% / 615% |

* eAudit agent overhead averaged over all benchmarks and 1–12 cores: **3.1%** (Fig. 18); median per-syscall agent cost **48 ns** (Fig. 19).
* eAudit benchmark (wall-clock) overhead: about **18%** on average across benchmarks and core counts, **5.8%** excluding find, tar and rdwr (Fig. 21).
* Data loss: eAudit none on any benchmark (rdwr reached ~17 M syscalls/s on 12 cores); sysdig up to >95% on multicore; Tracee and Tetragon "drop about 90%" on postmark (Fig. 15, 16).

Houssel et al. 2026, CPU-time overhead of the traced workload (network / file / process workloads):

| Program at syscall entry | network | file | process |
|---|---|---|---|
| fentry ("tracing") | 0.76% | 8.12% | 1.15% |
| tracepoint | 1.43% | 8.63% | 1.22% |
| kprobe | 1.66% | 9.10% | 1.30% |

Cgroup filtering (LSM program, process workload): attach-time **0.45%**, in-program `bpf_get_current_cgroup_id` **0.85%**, user-space **1.66%**. Full systems: eAudit 5.9% (network) / 12% (file), no loss; CamFlow 55% / 45%, 95–96% loss; SPADE 13.4% (process), 91–99% loss.

## 4. Server throughput and latency

| System | Web server | Key-value store |
|---|---|---|
| SysComb raw tp (p90 latency) | nginx 7.407 → 8.138 ms (+9.9%); Apache 7.731 → 8.317 ms (+7.6%) | Redis 0.104 → 0.108 ms (+3.8%) |
| ProvBPF | Apache 14645 → 13487 req/s (−8%) | Redis SET 1873359 → 1690189 (−10%), GET 2360694 → 2102901 (−11%) |
| CamFlow | Apache 8235 → 7269 req/s (−12%) | Redis SET 1053978 → 1012158 (−4%), GET 1386329 → 1219830 (−12%) |
| bpfbox passive / permissive | Apache 14686.95 → 13887.59 (−5.6%) / 13504.23 (−8.4%) | – |
