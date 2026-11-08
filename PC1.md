# PC1: what to run now (2026-11-08)

**The decision.** The dataset was collected in windows of **0.5 s, 40 per run (20 s)**
(every run's `run.json`: `window_seconds` 0.5, `windows` 40, `timeout_seconds` 20). The live
system uses the same window and the published detectors, nothing else: `hybrid_collector.py
--profile dataset` (RUNBOOK 19.9.6). Closed: 1 s windows, retraining, the switch-exact
extractor, the cohort replays. RUNBOOK section 19 is the record of how we got here, not a to-do
list.

Three things are needed from PC1, in this order. Each takes a few minutes of switch time.

## 0. Before the runs

```sh
git pull                                                     # f073926 or later
python3 -m unittest discover -s thesis-hybrid-ebpf-p4/python/tests   # 139 OK, no SDE needed
git clone -b live-validation https://github.com/mohamadhazimm/p4-ebpf-malware-detection ../p4-ebpf-malware-detection
python3 -m venv --system-site-packages ../venv && ../venv/bin/pip install numpy==1.24.4 scikit-learn==1.3.2
mkdir -p perf/results/dataset_v1 && printf '#!/bin/sh\nexec sleep 86400\n' > perf/results/dataset_v1/hostmon_stub && chmod +x perf/results/dataset_v1/hostmon_stub
```

The switch runs `basic.p4` with the forwarding and the mirror of RUNBOOK sections 1-2 (ports
132 <-> 140, reports to 192, `enp5s0` up). `ebpf_perf/build/hostmon_agg` is the build of
2026-11-07. The common part of every collector command:

```sh
C="sudo python3 hybrid_collector.py --profile dataset --mode command \
    --switch-ssh root@172.168.1.2 --forward-int-port 132 --forward-ext-port 140 --cpu-iface enp5s0 \
    --p4-reader thesis-hybrid-ebpf-p4/python/read_registers_with_index.py \
    --p4-forwarder thesis-hybrid-ebpf-p4/python/program_forwarding.py"
OUT=perf/results/dataset_v1
```

`--profile dataset` already means: 0.5 s windows, exactly 40 of them, the program stopped after
the last read, the dataset's launcher, frame bytes, durations in seconds, dormant reads instead
of clears, the batched reader on the raw route, budget 0.7. Pass `--windows 0` only for a run
that should last as long as its command. **The dataset launcher runs the command from a private
working directory: every file path inside `--command` must be absolute.** The collector's first
line, `[INFO] profile dataset: ...`, must show `window_sec=0.5, windows=40, launcher=dataset,
byte_layer=frame, duration_unit=s, dormant_reads=1`.

## 1. Does the Wedge hold 0.5 s windows? (one run)

The heaviest benign capture at its own timing: 1,830 buckets, up to ~300 active per 0.5 s.

```sh
$C --scenario-name bulk2000 --label benign --hostmon $OUT/hostmon_stub --windows 0 \
    --command "tcpreplay -i eth1 $PWD/live_test/captures/bulk2000.pcap" \
    --out-csv $OUT/bulk2000.csv --reader-timing-file $OUT/bulk2000.timing.jsonl
python3 - <<'EOF'
import csv
rows = list(csv.DictReader(open("perf/results/dataset_v1/bulk2000.csv")))
print(len(rows), "windows; overruns", sum(int(float(r["net_read_overrun"])) for r in rows),
      "overloaded", sum(int(float(r["net_overload"])) for r in rows),
      "pkts", sum(int(float(r["net_pkts_total_delta"])) for r in rows),
      "bytes", sum(int(float(r["net_bytes_total_delta"])) for r in rows))
EOF
```

Pass: 0 overruns, 0 overloaded windows, pkts 24,008, bytes 2,520,560 (2,184,448 of IPv4 plus
14 B x 24,008 frames). If it does not pass, stop here and send the CSV and the timing log: the
window length is then the user's call.

Look for, in the collector's output and the timing log:
- `[WARN] window N: the read allowance ... fits X of Y active buckets` = overload; `[WARN] ...
  register reads ended after the next window boundary` = overrun. Neither should appear.
- `[TIMING]` lines: `parser=raw`, `wall_ms` under 350 every window; in the JSONL `active_read`,
  `dormant`, `dormant_read` per window (how many dormant buckets each window still re-reads).
- `[INFO] dormant buckets: N left the active set ..., at most M at a time; R dormant reads ...;
  S resumed` and `[INFO] end of run: cleared K of the K buckets still occupied`: K must equal the
  buckets used (1,830 to 2,002) with no `[WARN] end of run: clearing ... failed`.
- CPU reports between 1,830 and 2,002 (`cpu_index_count` summed over the rows).

## 2. Live benign executions scored by the published detectors (the point)

Each program runs on PC1 in the cgroup, 20 s, exactly as the dataset's collector ran its
programs; the row it produces is scored by the paper's detectors trained on the 240 rows. On
2026-11-04, with software windows and a different launcher, most live benign rows scored as
malicious; this is the test of whether the dataset profile fixes that.

Programs: the release's `validation/hybrid/workloads.py` (`NAME --server IP`). `files`, `fanout`
and `null` need no network path and can run first. The others need the program's connections to
leave on `eth1` (switch port 132) and reach `validation/hybrid/servers.py` behind port 140 (a
route, or a client namespace like the VM's `p4int` with `ip netns exec` in the command, which
adds its own few dozen calls to window 0: say so in the results). Benign programs only (no
malware on NETLAB).

```sh
REL=$(realpath ../p4-ebpf-malware-detection)
run() {   # run NAME CATEGORY SERVER
  $C --scenario-name $1 --label benign --hostmon ebpf_perf/build/hostmon_agg \
      --hostmon-cgroup /sys/fs/cgroup/unified/hazim_collect \
      --command "python3 $REL/validation/hybrid/workloads.py $1 --server $3" \
      --out-csv $OUT/$1.csv --reader-timing-file $OUT/$1.timing.jsonl
  python3 live_test/dataset_row.py $OUT/$1.csv --execution-id $1 --category $2 --label 0 \
      --release $REL --out $OUT/rows.csv
}
run null  null            10.0.0.2
run files benign          10.0.0.2
run fanout benign         10.0.0.2
run http_poll   network_benign SERVER_IP     # and http_bulk, tcp_beacon, interactive, threaded, mixed
../venv/bin/python3 ../p4-ebpf-malware-detection/validation/hybrid/score.py $OUT/rows.csv
```

`score.py` prints, per row, the probability of malicious from the host, network and hybrid
detectors (0.5 is the threshold) and how many of the 235 features lie inside the dataset range
of the row's category, with the three furthest outside. Send that table, plus `rows.csv`, the
per-run CSVs and timing logs. Expected: benign scores; whatever still falls outside the range
names the next difference to fix. The collector's cgroup path is the one of 12.3
(`/sys/fs/cgroup/unified/...` on PC1's hybrid layout).

Look for, per execution:
- `HOSTMON_READY`, then at the end `HOSTMON_HEALTH {'lost': 0, 'capacity_errors': 0,
  'late_events': 0, 'failed': 0}`; any other value makes the host row incomplete (the collector
  warns), and the run is redone.
- `[INFO] the command ended with code -15`: the program ran to the 20 s stop, as the dataset's
  did; 0 means it finished early (fine, 40 windows all the same); anything else is reported.
- Exactly 40 rows in the CSV, host and network window starts equal in every row;
  `dataset_row.py` says `40 windows -> 1 row with 90 host and 145 network columns`.
- Sanity of the dataset units: for a TCP program `net_min_len_min` is at least 54 (40 B of IPv4
  plus the 14 B header), never 40; `net_flow_duration_max` lies in 0-20 s, never ~4.29e9 and
  without jumps of 4.295 s between neighbouring windows.
- In `score.py`'s table: the three probabilities, the `in range` count, and the three features
  furthest outside, copied verbatim. Those features are the finding.

## 3. The launcher prologue (five minutes)

Every dataset row includes the launcher's startup: 178 calls in window 0 (RUNBOOK 19.5.6). The
live launcher is the same command; its count on PC1's bash:

```sh
$C --scenario-name prologue --label benign --hostmon ebpf_perf/build/hostmon_agg \
    --hostmon-cgroup /sys/fs/cgroup/unified/hazim_collect --command "sleep 20" --out-csv $OUT/prologue.csv
python3 -c "import csv; print(sum(int(float(r['host_total_syscalls_total'])) for r in csv.DictReader(open('perf/results/dataset_v1/prologue.csv'))))"
strace -f -c sleep 20 2>&1 | tail -1          # sleep's own calls
```

The first number minus strace's total is the live prologue. Send both numbers and `bash
--version | head -1` (the count depends on bash's startup); 178 means the rows match the
dataset's exactly on this point, another number is a constant offset to record.

## What comes back

`perf/results/dataset_v1/` stays on PC1 (git-ignored). Put the three results in a
`## Results (PC1, DATE)` section at the end of this file: the step 1 line, the `score.py` table,
the two prologue numbers, and anything that failed with its message. Commit that; nothing else is
needed.

## Results (PC1, 2026-11-08)

Run at commit 9066592 against the switch's `basic_fix` build (bf_switchd pid 19555 in tmux `hz_sw`;
`sw_switchd.sh safety` OK), `enp5s0` brought up for the runs and set down again afterwards. Step 0:
139 tests OK (6 skipped); release clone `3e7cb5f` (live-validation). Every CSV, timing log, collector
log, the hostmon logs, `rows.csv` and `score.txt` are in `perf/results/dataset_v1/` on PC1 (12 runs:
bulk2000, bulk2000_r2, the nine programs, prologue). The first line of every run was the expected one,
`[INFO] profile dataset: active_ttl_windows=3, byte_layer=frame, clear_budget_frac=0.5, clear_expired=0, clear_idle_windows=0, dormant_reads=1, duration_unit=s, forward_report_port=192, launcher=dataset, max_dst_reads=256, p4_snapshot=sync, read_budget_frac=0.7, reader=batched, reader_raw_wire=True, reader_sync_batched=True, window_sec=0.5, windows=40`
(`windows=0` for step 1).

### What was changed around the collector (its logic and the profile's defaults untouched)

- **Scoring Python.** The pinned venv could not be built: PC1's root filesystem is at 99 % (275 MB
  free), `python3 -m venv` has no `ensurepip` (`--without-pip` works around it), numpy 1.24.4 installed,
  then scipy stopped with `ERROR: Could not install packages due to an EnvironmentError: [Errno 28] No
  space left on device` (215 MB free at that point); the partial venv was removed. `score.py` ran with
  the dataset repository's existing `p4_ebpf-dataset-construction/.venv` (Python 3.11.17, NumPy 2.4.6,
  scikit-learn 1.9.1, SciPy 1.17.1); the release's README says tested with NumPy 2.2 and scikit-learn
  1.7, its requirements say `scikit-learn>=1.3`. Check: one dataset row per category scored as its label
  (malware 0.98/1.00/1.00, benign 0.21/0.00/0.08, network_attack 0.90/0.94/0.87, network_benign
  0.02/0.08/0.07, null 0.03/0.39/0.03; 235/235 in range each).
- **The server behind the switch.** PC2 (192.168.0.2, behind port 140) answers ping through the switch,
  but its sshd accepts public keys only (`admin@192.168.0.2: Permission denied (publickey).`, the same
  on 10.173.85.124), so `servers.py` could not be started there. Used instead: a hairpin on port 132.
  `servers.py --bind 192.168.0.22` ran in a network namespace `p4srv` on PC1 that holds a VEPA-mode
  macvlan on `eth1` (IPv6 off), and the switch's forwarding table was programmed 132 -> 132 (mirror
  sid 1 -> 192 as before) with `program_forwarding.py`'s bfshell runner; the seven runs that need the
  server passed `--skip-p4-forwarding`. Checked: `ping 192.168.0.22` fails under 132 <-> 140 and
  succeeds under 132 -> 132, so the frames leave `eth1`, cross the switch and come back to the
  macvlan's MAC. `forwarding` is the only P4 table keyed on the ingress port; the registers and the
  mirror do not use it, so every packet crosses the pipeline once, as with a server behind 140. The
  programs ran on the host itself, no `ip netns exec` in the command: window 0 holds the launcher only.
  132 <-> 140 was restored afterwards and the namespace removed. The alternative, with PC2 access:
  `python3 validation/hybrid/servers.py --bind 192.168.0.2 --www /tmp/www` on PC2 and `--server
  192.168.0.2` here, with the common command unchanged.
- `--server 192.168.0.22` for all nine programs: `fanout` fetches `page_4k.html` once per round, so it
  needs the server too (PC1.md lists it with the no-network programs). Categories from the release's
  `collect.py` (`CATEGORY`): null -> null; files, fanout, mixed -> benign; the other five ->
  network_benign.
- `--hostmon-log perf/results/dataset_v1/NAME.hostmon.log` per run (the default is one file, overwritten).
- The collector prints `the command ended with code N` only for N != 0; a program that finished early
  (code 0) leaves no line.
- Seen, not changed: the programs run as root (the collector runs under sudo and the dataset launcher
  keeps the user); the release's `collect.py` ran them as `$SUDO_USER`.

### 1. bulk2000 at 0.5 s: holds, one run 320 B short

| run | windows | overruns | overloaded | pkts | bytes | CPU reports | wall_ms max (windows over 350) | dormant reads | resumed | end of run |
|---|---|---|---|---|---|---|---|---|---|---|
| bulk2000 | 46 | 0 | 0 | 24,008 | **2,520,240** (320 short) | 1,830 | 375.1 (8 of 46) | 10,465 | 172 | cleared 1830 of 1830 in 209 ms |
| bulk2000_r2 (repeat, to tell a race from a constant loss) | 46 | 0 | 0 | 24,008 | 2,520,560 | 1,830 | 372.8 (8 of 46) | 9,844 | 172 | cleared 1830 of 1830 in 210 ms |

The first run fails the byte criterion; the repeat is exact on all four. In both: no `[WARN] window N`
line (no overload, no overrun), `parser=raw` in every `[TIMING]` line, `net_buckets_skipped` 0,
`tcpreplay`: 24,010 packets (2,520,662 bytes) in 22.32 s. The only `[WARN]` is `host_windows=0
net_windows=46; pairing by index` (the stub monitor). Verbatim:

```
[INFO] dormant buckets: 2001 left the active set and were kept, at most 1829 at a time; 10465 dormant reads over 46 windows; 172 resumed and counted again with their registers intact; all cleared at the end of the run
[INFO] end of run: cleared 1830 of the 1830 buckets still occupied (the last windows' active set, 1829 dormant, the clear backlog and 0 bucket(s) of the 0 report(s) that arrived after the last window) in 209 ms
[INFO] CPU reports: 1830 in 46 windows; index mismatches: 0; buckets cleared: 0 (0 of them expired, unconditionally); clear backlog after the last window: 0; cleared at the end of the run: 1830
```
(run 2: `9844 dormant reads over 46 windows`, `in 210 ms`, otherwise the same).

Per window: up to 509 buckets read (active up to 237; dormant up to 1,829 kept, up to 508 of them
re-read in one window); wall = 31 ms sync + 280-300 ms read + 17-23 ms overhead once 440-510 buckets
are read, so 350-375 ms in 8 windows per run (run 1: w11 352.7, w19 375.1, w20 370.8, w28 371.1, w30
364.4, w33 356.3, w37 359.8, w45 351.9; run 2: w11 359.7, w17 361.1, w20 372.8, w28 351.7, w32 353.1,
w34 350.4, w37 352.2, w38 353.3), never near the 500 ms boundary. The CPU reports are 1,830 = the
buckets, as the reused 5-tuples resume in dormant, uncleared buckets and send no second report.

**The 320 bytes of run 1** are exactly the first five packets of one bulk2000 connection: SYN 60,
SYN-ACK 60, ACK 52, GET 96, ACK 52 B of IPv4 (in the capture every one of the 172 reused 5-tuples has
its second connection's first five packets within 2 ms of its SYN, 153 of them within 1 ms). The
mechanism is in the collector and was not changed: the batched reader syncs the 14 registers one after
another inside one RPC (`reg_pkts` first, `reg_bytes` second, about 2 ms apart; 31 ms for all 14), and
`NetSummarizer.add` skips a dormant bucket's row as unchanged when its packet count did not move
(`pkts_delta == 0`) while still storing that row as the bucket's new baseline. A reused 5-tuple lands
in a dormant bucket (no second CPU report); when its first packets arrive between the two syncs, the
read shows the old packet count and the new byte count, the bytes are absorbed into the baseline, and
the next read counts the packets with zero bytes. Expected rate about 172 x 2 ms / 500 ms = 0.7 per
bulk2000 run; one hit in run 1, none in run 2. Packet totals and every other counter are exact. A fix
is the VM side's: treat a dormant row as changed when any summed register changed, not only `reg_pkts`.

### 2. The nine executions, scored

All nine: `HOSTMON_READY`, then `HOSTMON_HEALTH {'lost': 0, 'capacity_errors': 0, 'late_events': 0,
'failed': 0}`; exactly 40 rows with `host_window_start_sec` = `net_window_start_sec` in every row; 0
overruns, 0 overloaded; `dataset_row.py`: `40 windows -> 1 row with 90 host and 145 network columns`
each; register reads 48-80 ms per window at most. Units: `net_min_len_min` is 66 in every window with
packets of every TCP program (52 B pure ACKs + 14), never 40; `net_flow_duration_max` is 0-18.08 s with
no 4.295 s jump. CPU reports = buckets = connections in every run (no mismatch).

| program | category | command end | pkts | buckets | host calls (40 windows) | `net_flow_duration_max` |
|---|---|---|---|---|---|---|
| null | null | -15 (stopped at 20 s) | 0 | 0 | 1,871 | 0 |
| files | benign | 0 (ended in window 8) | 0 | 0 | 17,116 | 0 |
| fanout | benign | 0 (window 20) | 169 | 12 | 13,140 | 0.0041 s |
| http_poll | network_benign | -15 | 462 | 40 | 2,440 | 0.0048 s |
| http_bulk | network_benign | 0 (window 30) | 533 | 6 | 2,010 | 0.0050 s |
| tcp_beacon | network_benign | -15 | 200 | 20 | 2,120 | 0.0026 s |
| interactive | network_benign | 0 (window 36) | 277 | 1 | 2,366 | 18.08 s |
| threaded | network_benign | 0 (window 21) | 401 | 32 | 2,522 | 0.0056 s |
| mixed | benign | 0 (window 15) | 359 | 12 | 6,680 | 0.0041 s |

`score.py perf/results/dataset_v1/rows.csv`, verbatim:

```
execution                          category          host  network  hybrid  in range   furthest outside (value vs dataset range)
null                               null              0.40     0.39    0.32  163/235    host_total_syscalls_total__max 1871 vs [196, 196], host_total_syscalls_total__sum 1871 vs [196, 196], host_transition_count_total__max 1167 vs [93, 93]
files                              benign            0.80     0.39    0.58  224/235    host_first100_unique_mean__max 28 vs [15, 17.33], host_first100_unique_mean__std 4.826 vs [2.342, 2.788], host_first50_unique_mean__std 3.077 vs [0.7806, 1.873]
fanout                             benign            0.98     0.12    0.62   80/235    net_down_up_ratio_delta__sum 105.8 vs [0, 2.651], net_down_up_ratio_delta__mean 2.645 vs [0, 0.06627], net_bytes_ba_delta__sum 5.776e+04 vs [0, 2926]
http_poll                          network_benign    0.83     0.54    0.68  111/235    host_rare_syscall_ratio_mean__sum 25.15 vs [0.002564, 0.8299], host_rare_syscall_ratio_max__sum 25.15 vs [0.002564, 0.8299], host_rare_syscall_ratio_mean__mean 0.6288 vs [6.409e-05, 0.02075]
http_bulk                          network_benign    0.91     0.09    0.46  177/235    net_down_up_ratio_delta__max 115.4 vs [0.006492, 1.97], net_down_up_ratio_delta__std 38.55 vs [0.002198, 0.9128], host_first100_unique_mean__max 28 vs [15, 15]
tcp_beacon                         network_benign    0.90     0.72    0.81  155/235    host_rare_syscall_ratio_mean__mean 0.3457 vs [6.409e-05, 0.02075], host_rare_syscall_ratio_max__mean 0.3457 vs [6.409e-05, 0.02075], host_rare_syscall_ratio_mean__sum 13.83 vs [0.002564, 0.8299]
interactive                        network_benign    0.71     0.77    0.77  166/235    host_first100_unique_mean__max 28 vs [15, 15], host_first100_unique_max__max 28 vs [15, 15], net_flow_duration_mean__sum 397.9 vs [0.0974, 28.65]
threaded                           network_benign    0.89     0.13    0.50  182/235    host_first100_unique_max__max 28 vs [15, 15], host_first100_unique_mean__max 28 vs [15, 15], host_max_run_length_max__max 65 vs [54, 54]
mixed                              benign            0.92     0.24    0.54   74/235    net_bytes_ba_delta__mean 8135 vs [0, 73.15], net_bytes_ba_delta__sum 3.254e+05 vs [0, 2926], net_down_up_ratio_delta__mean 5.674 vs [0, 0.06627]
probability of malicious from detectors trained on all 240 dataset rows (0.5 = threshold)
```

Reading: the host detector gives 0.71-0.98 to eight of the nine benign programs (null 0.40); the
network detector is below 0.5 for six (above for http_poll 0.54, tcp_beacon 0.72, interactive 0.77);
the hybrid is at or above 0.5 for seven (null 0.32 and http_bulk 0.46 below). So the 2026-11-04
outcome stands with the dataset profile: the live benign rows still score as malicious, and the host
side carries it. The features furthest outside the category's range, as printed above, fall into five
groups:

- `host_first100_unique_*` 28 vs 15-17.33 (files, http_bulk, interactive, threaded): the first 100 calls
  of a Python process use 28 distinct syscalls; the dataset's programs' first 100 use 15-17.
- `host_total_syscalls_total__max/__sum` 1,871 vs [196, 196] and `host_transition_count_total__max`
  1,167 vs 93 (null): the dataset's null rows are a 196-call program (178 of them the launcher); the
  release's `workloads.py null` is a Python interpreter that sleeps.
- `host_rare_syscall_ratio_*` (http_poll, tcp_beacon): windows holding 10-15 calls of one short exchange
  are almost all "rare" calls (sum 25.15 and 13.83 vs [0.0026, 0.83]).
- `net_bytes_ba_delta__sum/__mean` and `net_down_up_ratio_delta__*` (fanout, mixed, http_bulk): the
  dataset's benign CLI rows carry at most 2,926 B of b->a bytes in 20 s; fanout downloads 57.8 kB,
  mixed 325 kB.
- `net_flow_duration_mean__sum` 397.9 vs [0.0974, 28.65] (interactive): one connection kept open for
  18 s is counted in every window; the dataset's network_benign flows are short.
- also `host_max_run_length_max__max` 65 vs [54, 54] (threaded).

### 3. The prologue: 134, not 178

- Collector host total over 40 windows for `sleep 20`: **172** (all in window 0; `HOSTMON_HEALTH` zeros;
  `the command ended with code -15`).
- `strace -f -c sleep 20 | tail -1`: `100.00    0.000000                    38         2 total`, i.e. **38**.
- Live prologue = 172 - 38 = **134**; the dataset's is 178: a constant offset of -44 in `syscall_count`
  and the window-0 host features of every live row.
- `bash --version | head -1`: `GNU bash, version 5.0.17(1)-release (x86_64-pc-linux-gnu)`.
- Cross-check: `strace -f -c /bin/bash -c 'exec "$@"' sample-launch sleep 1` as root counts 165 =
  127 + 38; the monitor's 134 also holds the outer shell's calls after the cgroup join.

### Failures, with their messages

- Step 1, run 1: `bytes 2520240` against the expected 2,520,560 (above). Everything else in all 12 runs
  passed its check; no `[ERROR]`, no `clearing ... failed`, no overload or overrun warning.
- `pip install scipy==1.10.1` in the pinned venv: `ERROR: Could not install packages due to an
  EnvironmentError: [Errno 28] No space left on device`.
- PC2: `admin@192.168.0.2: Permission denied (publickey).`
- Expected, in every step 2 and 3 run: `[WARN] host_windows=42 net_windows=40; pairing by index` with
  `[INFO] 2 host window(s) after the last register read have no network data and get no row`.

State left: the switch runs `basic_fix` with 132 <-> 140 and the mirror to 192, registers cleared at
the end of the last run, `enp5s0` down (it was down before; `ip link set enp5s0 up` before the next
runs). PC1: no namespace or macvlan, the cgroup removed by the collector, `../p4-ebpf-malware-detection`
at `3e7cb5f`, no `../venv`, 277 MB free on `/`.
