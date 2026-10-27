# hostmon_agg: HostMon with in-kernel aggregation

`hostmon_agg` computes the same per-window, per-process ADFA features as
`libbpf-bootstrap/examples/c/hostmon` and prints them in the same format. The
command line, the `HOSTMON_READY` / stdin start-time handshake and the
`HOSTMON_HEALTH` line are the same, so it is a drop-in replacement in
`run_macro.sh`, `run_bench.sh` and `run_literature.sh` (set `HOSTMON_BIN`).

## Why

The 2026-10-26 benchmarks (`../COMPARISON.md`) traced HostMon's overhead to its
design, not to the eBPF hook itself:

| Bottleneck in hostmon | Effect measured | hostmon_agg |
|---|---|---|
| Every syscall becomes a 568-byte record in one shared 16 MiB ring buffer, read by one user-space thread | throughput ceiling of about 2.5-2.8 M events/s for the whole machine (find/tar/rdwr at 12 tasks, nginx) | no per-syscall records; each process updates its own map entry in the kernel |
| User space does the feature work per event (360-1,600 ns/event) | agent CPU 21-59% of the benchmark's | user space wakes once per window and reads one entry per process |
| 128-process table in user space | 72-77% of events unattributed in shbm and the kernel build | hash map with 65,536 live (process, window) entries |
| Classic tracepoint program (perf trace-buffer copy of all six arguments) plus five `syscalls:sys_enter_*` programs | about 58 ns added to every syscall of unmonitored processes | one BTF raw tracepoint (`tp_btf/sys_enter`); the five named counts come from the syscall id |
| `openat`, `execve`, `renameat`, `unlinkat` copy 256-byte paths the consumer never reads | `open/close` costs twice ebpH's | no path copies |

## Design

* Kernel (`hostmon_agg.bpf.c`): on `sys_enter`, if the caller is in the monitored
  cgroup, compute its window from `bpf_ktime_get_ns()` and update the
  `(tgid, window)` entry of a `BPF_F_NO_PREALLOC` hash map under the entry's
  `bpf_spin_lock`: syscall histogram (ids < 1024), current/longest run,
  transitions, the first 100 ids, the five named counts, unique connect
  IPv4 addresses and ports (64 each), and the last thread's `comm`. The lock
  gives a multi-threaded process one ordered syscall sequence, as hostmon's
  ring-buffer order did.
* User space (`hostmon_agg.c`): 50 ms after a window ends it marks the window
  closed, reads every entry of that window with `BPF_F_LOCK`, prints the rows
  and deletes them. The kernel rechecks the closed mark under the lock, so an
  update is either in the printed row or counted in `late_events`, never lost.
* The per-syscall update (`hostmon_agg_logic.h`) and the row output
  (`hostmon_agg_fmt.h`) follow hostmon.c's `record_syscall()`,
  `add_unique_ip/port()`, `handle_event()` and `print_and_reset()` line by line.

## Differences from hostmon output

* Rows within a window are sorted by PID (hostmon prints them in table-slot order).
* An event is timestamped when the syscall enters the kernel; hostmon stamps the
  ring-buffer record when it is submitted, slightly later. An event within a
  few hundred nanoseconds of a window boundary can therefore land in the
  neighbouring window.
* For multi-threaded processes the two collectors interleave concurrent threads
  independently, so order-dependent columns (run lengths, transitions, first-N
  unique, COMM) can differ for those processes; counts cannot.
* `HOSTMON_HEALTH` lost is always 0 (there is no ring buffer). Events that find no
  free map entry are counted as capacity errors, like hostmon's full table.
* No 128-process limit, so rows appear for processes hostmon dropped.

## Validation

* `build/test_agg_equiv` (built by `../build.sh`, no root): compiles the unchanged
  hostmon.c consumer next to `hostmon_agg_logic.h` and `hostmon_agg_fmt.h`, feeds
  both the same random event streams (3,006 scenarios, 6.1 M syscalls: runs, ids
  >= 1024, compat tasks, empty and quoted comms, overflowing connect sets) and
  requires byte-identical rows and equal capacity-error counts. It detects each
  of 11 deliberate one-line bugs in those two files.
* `../check_agg.sh` (root): runs hostmon and hostmon_agg at the same time on the
  same cgroup and workload (`check_workload.sh`) and compares the outputs with
  `compare_agg.py`, allowing only boundary shifts and multi-threaded ordering.
