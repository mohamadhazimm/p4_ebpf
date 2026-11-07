# Live test results on this VM (benign only)

There were four rounds, with no malware:

- **2026-11-03:** this repo's collector (next section).
- **2026-11-04:** the validations of the release repo `~/Desktop/p4-ebpf-malware-detection`
  ([its section](#2026-11-04-the-release-repos-validations)).
- **2026-11-05:** the batched gRPC register reader
  ([its section](#2026-11-05-the-batched-grpc-register-reader-on-the-model)).
- **2026-11-07:** the collector's read-cadence profiles, read budget, report-only aggregates
  and `hostmon_agg` ([its section](#2026-11-07-read-cadence-profiles-read-budget-report-only-aggregates-hostmon_agg)).

## 2026-11-03: this repo's collector

Real components on this VM: `basic.p4` compiled with open-p4studio 9.13.4 on
`tofino-model` + `bf_switchd`, `hostmon`/`modelmon` built from this checkout,
`hybrid_collector.py` unchanged. Traffic: crafted packets, a synthetic benign
PCAP with exact ground truth (1,023 packets, 84 flows), and the repository's
`testers/` talking TCP through the switch. No malware was run. Evidence is in
`live_test/results/` (git-ignored).

### Correct

| Check | Result |
| --- | --- |
| Compiled hashes (`perf/tools/hash_block_identify.py`) | all 18 hash slices = `flow_index.py` (17 flow index, 1 `reg_newconn_dst`) |
| P4 known answer (`p4_known_answer.py`) | 19/19: forwarding both ways, one report per new bucket with the first packet's 5-tuple and the data plane's `flow_index`, all 14 registers + `reg_newconn_dst` exact (bytes = IPv4 totalLen), clear then re-report |
| Replay on a clean switch (`pcap_benign_mix_w60_*`) | 1,023/1,023 packets, 84/84 reports, 84/84 flows exact (pkts, bytes, ab/ba, SYN/ACK/RST, min/max length); CSV deltas equal the per-bucket read model in every window |
| Real traffic (`cmd_mixed_w40_*`) | 4,843/4,843 packets, 70 connections = 70 reports, CSV equals the read model |
| `live_feature_export.summarize_register_window` on real reads | packets and bytes equal the collector's in every window, 0 windows rejected |
| `modelmon` known answer | 11/11 operations as expected, 0 ring-buffer losses; tracks fork descendants |
| Python unit tests (`thesis-hybrid-ebpf-p4/python/tests`) | 31/31 |

### Fixed in the collector since (verified on the testbed)

| Problem | Fix | Live check |
| --- | --- | --- |
| 1, no reset between runs | every run clears the 15 registers first (`thesis-hybrid-ebpf-p4/python/reset_registers.py`, read-back of 4 cells each; `--no-register-reset` skips) | two replays back to back: 29/29 flows exact in both (before: 17/84 lost in the second) |
| 2, HostMon leak | HostMon in its own process group, started directly as root; SIGINT, SIGTERM, then SIGKILL to the group | no HostMon left after 6 runs; its last partial window is printed |
| 3, one failed read loses the run | reads retried (`--p4-read-timeout` 120 s, `--p4-read-retries` 2), the reader's error shown; rows written to `OUT.<run_id>.partial.csv` as they complete, a failed run keeps them as `.incomplete.csv` and leaves the output CSV untouched | injected failure retried (exit 0, 9 rows); permanent failure: exit 1, 2 rows kept; hung read stopped and retried; Ctrl+C: exit 130, 3 rows kept |

Rows now follow the register reads: host windows after the last read (they had
all-zero network features) get no row. The other problems below are unchanged.

### Problems found

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

### Live features against the offline extractor

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

## 2026-11-04: the release repo's validations

The release repo at `~/Desktop/p4-ebpf-malware-detection` checks its own sensors against the offline
code that built its `dataset/features.csv`. All three checks passed here with benign programs. The
results, and what was learned from them, are in its
[`validation/RESULTS.md`](../../p4-ebpf-malware-detection/validation/RESULTS.md). How the checks work
is in its `validation/README.md`. In short:

- **P4.** The release `p4/` build matched `features/switch_model.py` on all 13 count features of all 8
  bundled captures.
- **eBPF.** The release monitor `ebpf/hostmon_agg` matched `features/host_model.py` row for row, on a
  recording of every system call. Problems 4 to 6 above concern this repo's `hostmon` and `modelmon`,
  not `hostmon_agg`.
  - The earlier failures came from the comparison's 50 µs tolerance, not from the monitor.
  - On this VirtualBox VM, the recorder's ring-buffer wake-ups delayed the monitor's clock read by up
    to 3.3 ms.
- **Both at once.** 20 executions were collected the way the dataset's were (20 s, 40 windows of
  0.5 s), with the switch and `hostmon_agg` running together. Every flow and every host row was equal,
  and every row has all 235 dataset columns.
- **The rows differ from the dataset's.** The paper's detectors score most live benign rows as
  malicious (hybrid 0.54 to 0.82 in the main round). Three reasons:
  - Every dataset execution began with 178 calls of a fixed launcher in the monitored process, and its
    code is in neither repo.
  - The dataset's benign programs exited with 0.
  - They are far more repetitive than the live Python programs.

Commands used here, as root. The hybrid check needs cleared registers, so it starts from a fresh
testbed:

```sh
SDE=/home/ubuntu/open-p4studio/install
REL=$HOME/Desktop/p4-ebpf-malware-detection
LIBBPF=$HOME/Desktop/p4_ebpf/libbpf-bootstrap/libbpf/src    # the system libbpf 0.5 can't read this kernel's BTF

# P4: 8 captures, ~21 min
sudo env P4_BUILD=$REL/p4/basic.tofino live_test/testbed.sh up    # ~45 s
(cd $REL && sudo SDE_INSTALL=$SDE validation/run_validation.sh)

# eBPF: ~10 s, no switch needed; it also builds the monitor and the recorder
(cd $REL && sudo LIBBPF_SRC=$LIBBPF validation/host/run_host_validation.sh)

# both at once: 9 executions, ~45 s each
sudo live_test/testbed.sh down
sudo env P4_BUILD=$REL/p4/basic.tofino live_test/testbed.sh up
sudo live_test/testbed.sh mode live
(cd $REL && sudo python3 validation/hybrid/collect.py --sde-install $SDE)
sudo live_test/testbed.sh down

# scores: the system Python has no scikit-learn
python3 -m venv ~/venv-eval && ~/venv-eval/bin/pip install -r $REL/evaluation/requirements.txt
~/venv-eval/bin/python $REL/validation/hybrid/score.py $REL/validation/hybrid/results/<time>/features.csv
```

The results are git-ignored, under `$REL/validation/`:

| Check | Result folders |
|---|---|
| P4 | `results/20261104_111459` |
| eBPF | `host/results/20261104_122102`, `_122113`, `_122124` |
| Both at once | `hybrid/results/20261104_123550`, `_124249`, `_125003` (each with a `score.txt`) |

Open question for the user: whether to reproduce the dataset's launcher. That needs the original
collector's code.

## 2026-11-05: the batched gRPC register reader on the model

`hybrid_collector.py --reader batched` reads the registers with
`thesis-hybrid-ebpf-p4/python/batched_reader.py`: one BF Runtime gRPC client for the
whole run, one `Sync` per register table, one Read RPC per table with all active
buckets, one Write RPC for the idle clears, instead of a bfshell session per window
with one `get()` per register per bucket. Same rows by construction (its `combine()`
and row fields are copies of the legacy script's, checked by the tests). Checked on
the real components of this VM, benign traffic only:

| Check | Result |
| --- | --- |
| `p4_known_answer.py --reader batched` | 19/19 (all 14 registers + `reg_newconn_dst` exact, clear, zero read-back, re-report from 1) |
| `run_pcap_test.sh` with `EXTRA="--reader batched --reader-timing --clear-idle-windows 0"` (`pcap_benign_mix_w60_20261105_191620`) | 1,023/1,023 packets, 84/84 flows exact, CSV equals the per-bucket read model in all 7 windows |
| `tests/test_batched_reader.py` (bfrt_mock) | legacy and batched windows and CSV rows identical over 120 windows with clears, re-reports, two-pipe flows and counters wrapping mod 2^32 |
| per window on the model (`--reader-timing`) | 15 syncs 57-74 s, reads of 33-84 buckets 32-46 s, IPC overhead 3-8 ms; the legacy reader's session alone is 1.4-1.5 s on the switch |

The model's bf_switchd serves one register entry in milliseconds and one sync in seconds,
so these times say nothing about the switch; the switch commands are in
[`RUNBOOK.md`](../RUNBOOK.md). The run's windows are late by 55-268 s for the same reason
(sync reads, 60 s windows), which is why only the per-bucket read model matches per window.

## 2026-11-07: read cadence profiles, read budget, report-only aggregates, hostmon_agg

Commits 4980a04 (`--profile switch|model`, `--read-budget-frac` with the learned cost model,
the `rep_*` and `net_overload`/`net_buckets_*`/`net_read_overrun` columns, `--hostmon-cgroup`
with `ebpf_perf/build/hostmon_agg`) and 0b64bef (`derive_p4_features`'s `byte_layer` and
`rate_window`), checked with RUNBOOK sections 11.1 and 11.3 on the real components of this VM,
benign traffic only (section 11.2 needs the switch). Evidence: `live_test/results/cadence_20261107/`
(`runA`/`runB`/`runC` logs, CSVs and timing files; `run1*` are the attempts with the profile as
committed) and `live_test/results/ka_rawwire_20261107.json`.

| Check | Result |
| --- | --- |
| `tests.test_collector_cadence` / all of `thesis-hybrid-ebpf-p4/python/tests` | 17/17 / 93/93 |
| `tests/test_pcap_window_alignment.py` + `tests/validation` (venv: scikit-learn 1.3.2, NumPy 1.24.4) | the pull fixes 2 tests (`test_rate_window_convention_is_explicit`, `test_d10_offline_byte_unit_matches_p4`); the other 12 failures and 37 errors are the same at 9c109d1 (the 37 import `ReportCollector` from the lab machine's `listen_cpu_reports` layout; the failures are the suite's known-defect tests) |
| `p4_known_answer.py --reader batched --raw-wire` | 19/19 (in 696 s) |
| `DEP=/usr ./ebpf_perf/build.sh` | `hostmon` and `hostmon_agg` built; the last step, `test_agg_equiv.c`, does not compile against this repo's `hostmon.c` (it expects file-scope health counters; the same since 9a36b2b) |
| 11.1 command run (`model_cadence`, mixed workload, 4 x 60 s) | 70 CPU reports = sum of `rep_new_flows`, 0 index mismatches; active 19/70/70/70, all read; `net_overload` 0 in every row |
| 11.1 overload run (`model_overload`, `benign_mix.pcap`, budget 0.5) | 84 reports = sum of `rep_new_flows` = the capture's 84 flows; window 0 reads 17 of 17 (`net_overload` 0); windows 1-6 read 0 of 30-57 active buckets (`net_overload` 1, 280 skipped in all); learned cost 98.9 s fixed + 2.13 s per bucket |
| 11.3 host side (`host_agg`, `hostmon_agg` on `/sys/fs/cgroup/hazim_collect`, 2 x 120 s) | `HOSTMON_READY`; `HOSTMON_HEALTH` lost/capacity/late/failed 0/0/0/0; `host_window_start_sec` = `net_window_start_sec` in both rows; window 0: 71 processes, 81,349 syscalls, 259 execs, 85 connects, 70 reports; the cgroup removed afterwards; reads 95 s and 52 s, no overrun |

Per window with the batched reader and sync snapshots: 15 syncs 45-140 s, reads 7-121 s (when
flow buckets are read), 52-232 s in all, so `net_read_overrun` is 1 in every 60 s window of 11.1.

### Problems found

1. **`--profile model` as committed did not complete a run** (fixed). It set
   `--p4-snapshot hw` with the batched reader and kept the default `--p4-read-timeout 120`.
   The batched reader's hardware reads cost ~0.47 s per register entry here: window 0 of the
   command run (18 buckets, 253 entities) answered in 118 s on the third attempt after two
   attempts were cut off at 120 s, and window 1 (more buckets) timed out again. With sync
   snapshots and the 120 s timeout, window 0 timed out as well (sync plus read took 155-232 s
   today, 93-115 s on 2026-11-05). The profile now sets `p4_snapshot` `sync` and
   `p4_read_timeout` 600 (`PROFILES` in `hybrid_collector.py`, `test_collector_cadence`
   updated); the runs above gave these two as explicit options.
2. **RUNBOOK 11.1 and 11.3 commands** (fixed in `RUNBOOK.md`): `python3` on the bash script
   `benign_workload.sh`, with no scenario (it then only prints its usage); the known answer
   run in live mode, where `veth0` is inside netns `p4int`; the PCAP at `live_test/run/`
   instead of `live_test/data/`; PCAP mode without `--int-iface veth0 --ext-iface veth2` (the
   collector's defaults are the model's `veth1`/`veth3`).
3. **Not changed:** `derive_p4_features` gives `byte_layer` and `rate_window` defaults
   (`ipv4`, `recorded`) although 0b64bef's message says they must be selected explicitly. A
   caller that passes neither now gets IPv4 totalLen bytes (the data plane's convention, which
   `analyze_run.py` expects) instead of the earlier `len(packet)`, and recorded window
   durations (equal to the nominal ones for `analyze_run.py`, which passes nominal edges).
4. **Not changed:** when the budget fits no bucket, the reader still runs the 15 syncs and
   reads the `reg_newconn_dst` buckets (capped only by `--max-dst-reads`, no cap under the
   model profile). The skipped windows' register columns are 0 (`net_flow_count_seen` 0),
   not missing, so only `net_overload` tells an overloaded window from an idle one. On the
   switch the syncs cost ~70 ms.

## Limits of the software model

Forwarding ~100-200 packets/s (1 MiB of HTTP in 8 s). Register sync 15 s idle and
25-45 s with traffic (the switch: 37-40 ms); direct reads ~0.27 s per bucket with the
legacy reader (switch: 1.4 ms); with the batched reader ~0.47 s per register entry (18
buckets x 14 registers + 1 `reg_newconn_dst` entry in 118 s); a bucket clear ~3 s. Timestamps tick in 1.25 ms steps. On the
model one read takes longer than the default 10 s window; with sync reads, idle
clears and 30 s windows the reads fell up to 203 s behind. The clean runs used
40-60 s windows, `--p4-snapshot hw` and `--clear-idle-windows 0` with the legacy reader;
with the batched reader, `--p4-snapshot sync` and `--p4-read-timeout 600` (`--profile model`
since 2026-11-07). None of these timings describe the ASIC.

## Not tested

The hardware switch; malware (waits for the isolated machine); the training
sensor that wrote `telemetry.csv` (not on this machine), so `modelmon`'s
`host__ebpf_*` fields could be checked against syscalls but not against the
training data.
