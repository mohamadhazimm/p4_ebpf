# Live test results, 2026-11-03 (benign only)

Real components on this VM: `basic.p4` compiled with open-p4studio 9.13.4 on
`tofino-model` + `bf_switchd`, `hostmon`/`modelmon` built from this checkout,
`hybrid_collector.py` unchanged. Traffic: crafted packets, a synthetic benign
PCAP with exact ground truth (1,023 packets, 84 flows), and the repository's
`testers/` talking TCP through the switch. No malware was run. Evidence is in
`live_test/results/` (git-ignored).

## Correct

| Check | Result |
| --- | --- |
| Compiled hashes (`perf/tools/hash_block_identify.py`) | all 18 hash slices = `flow_index.py` (17 flow index, 1 `reg_newconn_dst`) |
| P4 known answer (`p4_known_answer.py`) | 19/19: forwarding both ways, one report per new bucket with the first packet's 5-tuple and the data plane's `flow_index`, all 14 registers + `reg_newconn_dst` exact (bytes = IPv4 totalLen), clear then re-report |
| Replay on a clean switch (`pcap_benign_mix_w60_*`) | 1,023/1,023 packets, 84/84 reports, 84/84 flows exact (pkts, bytes, ab/ba, SYN/ACK/RST, min/max length); CSV deltas equal the per-bucket read model in every window |
| Real traffic (`cmd_mixed_w40_*`) | 4,843/4,843 packets, 70 connections = 70 reports, CSV equals the read model |
| `live_feature_export.summarize_register_window` on real reads | packets and bytes equal the collector's in every window, 0 windows rejected |
| `modelmon` known answer | 11/11 operations as expected, 0 ring-buffer losses; tracks fork descendants |
| Python unit tests (`thesis-hybrid-ebpf-p4/python/tests`) | 31/31 |

## Fixed in the collector since (verified on the testbed)

| Problem | Fix | Live check |
| --- | --- | --- |
| 1, no reset between runs | every run clears the 15 registers first (`thesis-hybrid-ebpf-p4/python/reset_registers.py`, read-back of 4 cells each; `--no-register-reset` skips) | two replays back to back: 29/29 flows exact in both (before: 17/84 lost in the second) |
| 2, HostMon leak | HostMon in its own process group, started directly as root; SIGINT, SIGTERM, then SIGKILL to the group | no HostMon left after 6 runs; its last partial window is printed |
| 3, one failed read loses the run | reads retried (`--p4-read-timeout` 120 s, `--p4-read-retries` 2), the reader's error shown; rows written to `OUT.<run_id>.partial.csv` as they complete, a failed run keeps them as `.incomplete.csv` and leaves the output CSV untouched | injected failure retried (exit 0, 9 rows); permanent failure: exit 1, 2 rows kept; hung read stopped and retried; Ctrl+C: exit 130, 3 rows kept |

Rows now follow the register reads: host windows after the last read (they had
all-zero network features) get no row. The other problems below are unchanged.

## Problems found

1. **Registers are never reset between runs.** A bucket left from an earlier run
   keeps `dir_valid = 1`, so a new flow landing in it sends no CPU report and the
   collector never reads it. Second replay on the same switch: 17/84 flows and
   203/1,023 packets missing, their registers holding both runs' counts.
   `reg_newconn_dst` is never cleared, so a run's first read of a destination
   returns its count since the switch started (11/11 buckets above the replay's
   own SYN count). `reset_registers.py` clears all 15 registers (202 s here).
2. **The collector leaks hostmon.** `stop_hostmon()` signals the `sudo` wrapper;
   sudo does not relay a signal from its own process group, so after SIGINT and
   SIGTERM it is SIGKILLed and hostmon is orphaned at ~100% CPU, still writing
   the run's log. Seen in all 4 runs and reproduced in isolation. The last host
   window is never flushed; with the default relative `--hostmon-log`, the next
   run in the same directory writes into the same file as the orphan.
3. **One failed read loses the whole run.** A register read hung until bfshell's
   600 s timeout; `run_p4_reader_json` raised and the CSV (written only at the
   end) was never written: 11 windows lost. Separately, the first bfshell session
   right after BFRT starts listening can fail (`Can't startup clish`).
4. **hostmon misses common syscall variants** (`ebpf_known_answer.py`, 6/12):
   `open`/`creat` (OPEN = 0), `rename`/`renameat2` (REN = 0), `unlink` (DEL = 0),
   and every exec under `/usr/` (path filter). On this system Python's
   `os.rename`/`os.replace` use `rename(2)`, `os.remove`/`Path.unlink` use
   `unlink(2)`, `mv` uses `renameat2`: in the live run, `bulk_copy_cleanup.py`'s
   300 renames and 300 deletes gave REN = 0 and DEL = 0, and 60 `python3`
   spawns gave EXEC = 0.
5. **hostmon's host features describe the machine, not the workload.** The
   workload was 0.2-5% of hostmon's syscalls per window; the rest came from
   bf_switchd/tofino-model threads, VS Code's git and Copilot, the compositor.
   Its 128-slot process table was full in every busy window (further processes
   are silently ignored). The collector's own reader and bfshell are counted too.
6. **`modelmon` gaps:** `open(2)` is not hooked (statically linked musl/uClibc
   binaries open files with it on x86-64), writes through `mmap` are invisible,
   and `connect_count` counts every attempt of any family: 10 of 80 in the live
   run were glibc's failed `AF_UNIX` probes of `/var/run/nscd/socket`.
7. **Host and network windows are paired by index, not time.** hostmon windows
   follow the clock; P4 windows end when reads finish. Every completed run had one
   more host window than P4 windows, so the last CSV row has real host features and
   all-zero network features. When reads lag, row k pairs different times.
8. **This checkout is not the repaired one.** `tests/validation/REPAIRS.md` lists
   SHA-256 values for repaired `hybrid_collector.py`, `hostmon.c`,
   `hostmon.bpf.c` and the offline extractor; none matches these files.
   `tests/test_pcap_window_alignment.py` belongs to that repaired extractor
   (`derive_p4_features(..., byte_layer=...)`: TypeError here; 1 error, 1 failure).
9. Tooling: `perf/tools/hash_matrix_check.py` cannot parse 9.13.4's hash log
   (`exact hashtable N`) and its "collector" candidate is the pre-`@symmetric`
   blob, so it reports 0/20000 even though `flow_index.py` is right.

## Live features against the offline extractor

`analyze_p4_pcap_ablation.derive_p4_features` (the code that built the
dataset's P4 features) on a capture of the switch ingress, against the CSV,
clean replay run, 7 windows of 60 s:

| Feature group | Live vs offline |
| --- | --- |
| packets, SYN, ACK, RST | totals equal |
| bytes | offline counts frames (L2): +14 B/packet. bytes_total +2.6%, bytes_ab +17%, avg_pkt_size_ab +17%, min_len_min 40 vs 54 per window |
| flow duration | live: nanoseconds modulo 2^32 (wraps at 4.29 s); offline: seconds. ~1.6e9 vs ~3.6 per window |
| flow counts (`flow_count_seen`, `dir_valid_count`, `flows_with_ab/ba`) | offline TTL 3, collector TTL 5: 303 vs 377 (-20%); with TTL 5 offline 378 vs 377 |
| direction of equal-port flows (e.g. NTP 123 -> 123) | live: all packets "ab" (ports-only check); offline: split by IP |
| per window | live windows end when each bucket is read (1-11 s late here), so values shift by the read delay |

## Limits of the software model

Forwarding ~100-200 packets/s (1 MiB of HTTP in 8 s). Register sync 15 s idle and
25-45 s with traffic (the switch: 37-40 ms); direct reads ~0.27 s per bucket
(switch: 1.4 ms); a bucket clear ~3 s. Timestamps tick in 1.25 ms steps. On the
model one read takes longer than the default 10 s window; with sync reads, idle
clears and 30 s windows the reads fell up to 203 s behind. The clean runs used
40-60 s windows, `--p4-snapshot hw` and `--clear-idle-windows 0`. None of these
timings describe the ASIC.

## Not tested

The hardware switch; malware (waits for the isolated machine); the training
sensor that wrote `telemetry.csv` (not on this machine), so `modelmon`'s
`host__ebpf_*` fields could be checked against syscalls but not against the
training data.
