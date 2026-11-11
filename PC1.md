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

### 2b. The seven server programs again, with `servers.py` on PC2 behind port 140

Later the same day the user authorized PC1's key on PC2, so the drawn topology could be used: `servers.py
--bind 192.168.0.2 --www /tmp/www` on PC2 (eth1, switch port 140; Python 3.8.10; ufw active but 8089 and
9100 answer), the common command unchanged (the collector programs 132 <-> 140 itself), `--server
192.168.0.2`, execution ids `NAME_pc2`, files in `perf/results/dataset_v1/pc2/` (`rows_pc2.csv`,
`score_pc2.txt`). All seven: `HOSTMON_HEALTH` zeros, 40 rows with equal window starts, 0 overruns, 0
overloaded, CPU reports = buckets (12, 40, 6, 20, 1, 32, 12, as before), `net_min_len_min` 66, durations
0-18.08 s without jumps, reads at most 54-88 ms per window; http_poll and tcp_beacon ended with -15, the
others with 0. Packets: fanout 173, http_poll 480, http_bulk 533, tcp_beacon 200, interactive 277,
threaded 422, mixed 355 (hairpin: 169, 462, 533, 200, 277, 401, 359; the difference is the programs'
own variation, e.g. one more poll before the stop).

```
execution                          category          host  network  hybrid  in range   furthest outside (value vs dataset range)
fanout_pc2                         benign            0.98     0.11    0.62   80/235    net_down_up_ratio_delta__mean 2.579 vs [0, 0.06627], net_down_up_ratio_delta__sum 103.1 vs [0, 2.651], net_bytes_ba_delta__sum 5.783e+04 vs [0, 2926]
http_poll_pc2                      network_benign    0.82     0.55    0.69  111/235    host_rare_syscall_ratio_mean__sum 22.47 vs [0.002564, 0.8299], host_rare_syscall_ratio_max__sum 22.47 vs [0.002564, 0.8299], host_rare_syscall_ratio_max__mean 0.5618 vs [6.409e-05, 0.02075]
http_bulk_pc2                      network_benign    0.91     0.09    0.46  179/235    net_down_up_ratio_delta__max 115.4 vs [0.006492, 1.97], net_down_up_ratio_delta__std 38.27 vs [0.002198, 0.9128], host_first100_unique_mean__max 28 vs [15, 15]
tcp_beacon_pc2                     network_benign    0.90     0.70    0.80  155/235    host_rare_syscall_ratio_mean__mean 0.3457 vs [6.409e-05, 0.02075], host_rare_syscall_ratio_max__mean 0.3457 vs [6.409e-05, 0.02075], host_rare_syscall_ratio_mean__sum 13.83 vs [0.002564, 0.8299]
interactive_pc2                    network_benign    0.71     0.79    0.77  164/235    host_first100_unique_max__max 28 vs [15, 15], host_first100_unique_mean__max 28 vs [15, 15], net_flow_duration_mean__sum 397.8 vs [0.0974, 28.65]
threaded_pc2                       network_benign    0.90     0.13    0.51  180/235    host_first100_unique_mean__max 28 vs [15, 15], host_first100_unique_max__max 28 vs [15, 15], host_max_run_length_max__max 65 vs [54, 54]
mixed_pc2                          benign            0.92     0.21    0.54   74/235    net_bytes_ba_delta__mean 8133 vs [0, 73.15], net_bytes_ba_delta__sum 3.253e+05 vs [0, 2926], net_down_up_ratio_delta__mean 5.951 vs [0, 0.06627]
probability of malicious from detectors trained on all 240 dataset rows (0.5 = threshold)
```

Against the hairpin rows of section 2 every probability is within 0.02 and every `in range` count within
2 (http_bulk 179 vs 177, interactive 164 vs 166, threaded 180 vs 182), with the same features furthest
outside. So the hairpin and the two-port topology give the same rows, and the finding of section 2
stands. PC2 was left as found (server stopped, `/tmp/servers.py`, `/tmp/www` and `/tmp/servers.log`
removed); `ssh admin@192.168.0.2` from PC1 now works for the next runs.

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

## Results, part 2 (PC1, 2026-11-08): programs of the dataset's kind

**Why.** Section 2 scored the release's Python workloads. The dataset's 105 benign rows are one-shot CLI
tools (brotli, bzip2, coreutils b2sum/base32/base64/basenc/cksum/md5sum/od/sha256sum/sort/sum/wc, cpio,
curl, diffutils cmp, expat xmlwf, git, gzip, inetutils ftp/ping/telnet, jq, lz4, m4, ncompress, openssl,
rsync, sqlite3, tar, unzip, wget, xxhsum, xz, zip, zstd; 59 amd64_static, 28 i386_static, 18
amd64_dynamic), each at light/medium/heavy sizes, 24 to 40,117 calls. The generator of that revision is
not on PC1 (the construction repo holds the earlier bash-script workloads), so executions of the same kind
were rebuilt here from the rows' own numbers.

**What was generated** (`perf/results/dataset_v1/benign_cli/`, git-ignored: `scripts/`, `manifest.tsv`,
`runs/`, `rows_cli.csv`, `score_cli.txt`):

- Sizes: the rows' light/medium/heavy counts are reproduced by inputs of 1, 16 and 64 MiB of the dataset
  generator's periodic pattern `(i*37+1) % 256`, read in each tool's block size (strace on PC1: b2sum
  78/558/2094 against the rows' 62/542/2078, gzip 100/-/2116 against 66/547/2086, bzip2 336/4180 against
  300/4253, cksum 1070 against 1054, base64 463/6419 against 428/6383, cmp 8256/32832 against 8236/32814,
  xz 8342 against 8356, tar 13356 against 12670; `busybox sleep` 17 against the null rows' 18).
  `make_fixtures.py` writes them, plus a copy for cmp, a tree for tar/rsync/zip, a zip for unzip, a git
  repo and a 351-byte index page.
- `bin/null_static` (static C, does nothing for 30 s) and `busybox sleep 30` as the null program.
  `bin/outto FILE PROG ARGS` (static C: opens FILE as stdout and execs PROG; 3 calls plus the execve)
  stands in for the dataset runner's stdout redirection, since the launcher runs the command without a
  shell.
- The same programs as static binaries where busybox has them (md5sum, sha256sum, gzip, bzip2, wc, cmp,
  tar, wget), the dataset's amd64_static mode; everything else is Ubuntu 20.04's dynamic build.
- Services on PC2 behind port 140: `servers.py` (HTTP 8089, the 351 B page), `openssl s_server` on 8443
  (self-signed), and `scripts/banners.py` with an FTP-like banner on 8021 and a telnet-like one on 8023.
- 47 executions (`make_manifest.py` -> `manifest.tsv`; `run_cli.sh` drives the common collector command,
  one dataset row each): 2 null, 30 GNU file tools, 7 network clients (curl x2, wget, openssl s_client,
  telnet, ftp, ping), 8 busybox static.

**Checks.** All 47: `HOSTMON_HEALTH` zeros, 40 rows with equal window starts, 0 overruns, 0 overloaded,
CPU reports = connections. 42 ended with code 0; the null runs with -15 (they sleep 30 s); bzip2-heavy
with -15 (64 MiB took longer than 20 s on this VM, 13,371 of about 17,000 calls; the guest finished);
telnet with 1 (connection closed after EOF on stdin). Network rows against the dataset's: curl 12 pkts /
941 B b->a against 12 / 746, wget 12 / 941 against 12 / 746, openssl 14 / 2,223 against 13 / 2,293, telnet
7 / 219 against 7 / 206, ftp 11 / 443 against 13 / 488, ping 0 counted packets as in the dataset (ICMP).
cmp-heavy was first run against a hard link of its own file (GNU cmp returns at once, 167 calls) and
rerun against a copy; the table holds the rerun.

**The programs match the dataset's.** Live host total against the dataset row of the same program and
size (each includes its launcher: 134 calls here, 178 there):

| program | live | dataset |
|---|---|---|
| b2sum light / medium / heavy | 184 / 664 / 2,200 | 240 / 720 / 2,256 |
| gzip light / medium / heavy | 200 / 680 / 2,216 | 244 / 725 / 2,264 |
| bzip2 light / medium | 435 / 4,279 | 478 / 4,431 |
| base64 light / medium / heavy | 562 / 6,518 / 25,574 | 606 / 6,561 / 25,618 |
| cksum heavy, wc medium, sum light | 1,176 / 1,174 / 408 | 1,232 / 1,236 / 465 |
| cmp medium / heavy | 8,363 / 32,939 | 8,414 / 33,009 |
| xz heavy, tar heavy | 8,442 / 13,463 | 8,534 / 12,848 |
| curl / wget / openssl | 682 / 317 / 323 | 352 / 342 / 395 |
| telnet / ftp / ping | 283 / 320 / 257 | 235 / 251 / 215 |

The file tools differ by the prologue (44 calls) and the dynamic loader. zip, unzip, git-heavy, rsync and
sort were built here with other inputs than the dataset's and differ more (2,378 against 28,309; 1,324
against 20,454; 424 against 10,492; 14,076 against 33,001; 16,787 against 13,006).

**Scores** (`score.py perf/results/dataset_v1/benign_cli/rows_cli.csv`, verbatim):

```
execution                          category          host  network  hybrid  in range   furthest outside (value vs dataset range)
null-static-glibc-amd64_static     null              0.71     0.39    0.71  163/235    host_total_syscalls_total__max 117 vs [196, 196], host_total_syscalls_total__sum 117 vs [196, 196], host_max_run_length_max__sum 12 vs [54, 54]
null-busybox-sleep-amd64_static    null              0.71     0.39    0.71  163/235    host_total_syscalls_total__max 119 vs [196, 196], host_total_syscalls_total__sum 119 vs [196, 196], host_max_run_length_max__sum 12 vs [54, 54]
coreutils-b2sum-light-amd64_dynami benign            0.66     0.39    0.65  213/235    host_first100_unique_mean__max 28 vs [15, 17.33], host_first100_unique_mean__std 4.371 vs [2.342, 2.788], host_first100_unique_max__std 4.371 vs [2.342, 3.591]
coreutils-b2sum-medium-amd64_dynam benign            0.23     0.39    0.23  225/235    host_first100_unique_mean__max 28 vs [15, 17.33], host_first100_unique_mean__std 4.371 vs [2.342, 2.788], host_first100_unique_max__std 4.371 vs [2.342, 3.591]
coreutils-b2sum-heavy-amd64_dynami benign            0.23     0.39    0.22  225/235    host_first100_unique_mean__max 28 vs [15, 17.33], host_first100_unique_mean__std 4.371 vs [2.342, 2.788], host_first100_unique_max__std 4.371 vs [2.342, 3.591]
coreutils-md5sum-heavy-amd64_dynam benign            0.23     0.39    0.22  225/235    host_first100_unique_mean__max 28 vs [15, 17.33], host_first100_unique_mean__std 4.371 vs [2.342, 2.788], host_first100_unique_max__std 4.371 vs [2.342, 3.591]
coreutils-sha256sum-medium-amd64_d benign            0.23     0.39    0.23  225/235    host_first100_unique_mean__max 28 vs [15, 17.33], host_first100_unique_mean__std 4.371 vs [2.342, 2.788], host_first100_unique_max__std 4.371 vs [2.342, 3.591]
coreutils-cksum-heavy-amd64_dynami benign            0.22     0.39    0.23  225/235    host_first100_unique_mean__max 28 vs [15, 17.33], host_first100_unique_mean__std 4.371 vs [2.342, 2.788], host_first100_unique_max__std 4.371 vs [2.342, 3.591]
coreutils-sum-light-amd64_dynamic  benign            0.29     0.39    0.35  225/235    host_first100_unique_mean__max 28 vs [15, 17.33], host_first100_unique_mean__std 4.371 vs [2.342, 2.788], host_first100_unique_max__std 4.371 vs [2.342, 3.591]
coreutils-wc-medium-amd64_dynamic  benign            0.22     0.39    0.23  225/235    host_first100_unique_mean__max 28 vs [15, 17.33], host_first100_unique_mean__std 4.371 vs [2.342, 2.788], host_first100_unique_max__std 4.371 vs [2.342, 3.591]
coreutils-od-light-amd64_dynamic   benign            0.29     0.39    0.32  217/235    host_first100_unique_mean__max 28 vs [15, 17.33], host_first100_unique_mean__std 4.375 vs [2.342, 2.788], host_first100_unique_max__std 4.375 vs [2.342, 3.591]
coreutils-sort-heavy-amd64_dynamic benign            0.22     0.39    0.19  229/235    host_first100_unique_mean__max 28 vs [15, 17.33], host_first100_unique_mean__std 4.37 vs [2.342, 2.788], host_first100_unique_max__max 28 vs [15, 23]
coreutils-base64-light-amd64_dynam benign            0.29     0.39    0.32  218/235    host_first100_unique_mean__max 28 vs [15, 17.33], host_first100_unique_mean__std 4.371 vs [2.342, 2.788], host_first100_unique_max__std 4.371 vs [2.342, 3.591]
coreutils-base64-medium-amd64_dyna benign            0.27     0.39    0.30  218/235    host_first100_unique_mean__max 28 vs [15, 17.33], host_first100_unique_mean__std 4.371 vs [2.342, 2.788], host_first100_unique_max__std 4.371 vs [2.342, 3.591]
coreutils-base64-heavy-amd64_dynam benign            0.27     0.39    0.29  219/235    host_first100_unique_mean__max 28 vs [15, 17.33], host_first100_unique_mean__std 4.377 vs [2.342, 2.788], host_first100_unique_max__std 4.377 vs [2.342, 3.591]
gzip-light-amd64_dynamic           benign            0.60     0.39    0.62  215/235    host_first100_unique_mean__max 28 vs [15, 17.33], host_first100_unique_mean__std 4.371 vs [2.342, 2.788], host_first100_unique_max__std 4.371 vs [2.342, 3.591]
bzip2-light-amd64_dynamic          benign            0.27     0.39    0.25  225/235    host_first100_unique_mean__max 28 vs [15, 17.33], host_first100_unique_mean__std 4.371 vs [2.342, 2.788], host_first100_unique_max__std 4.371 vs [2.342, 3.591]
gzip-medium-amd64_dynamic          benign            0.22     0.39    0.23  225/235    host_first100_unique_mean__max 28 vs [15, 17.33], host_first100_unique_mean__std 4.371 vs [2.342, 2.788], host_first100_unique_max__std 4.371 vs [2.342, 3.591]
bzip2-medium-amd64_dynamic         benign            0.37     0.39    0.33  223/235    host_first100_unique_mean__max 28 vs [15, 17.33], host_first100_unique_mean__std 4.353 vs [2.342, 2.788], host_rare_syscall_ratio_max__active_windows 6 vs [1, 4]
gzip-heavy-amd64_dynamic           benign            0.25     0.39    0.25  223/235    host_first100_unique_mean__max 28 vs [15, 17.33], host_first100_unique_mean__std 4.37 vs [2.342, 2.788], host_first100_unique_max__max 28 vs [15, 23]
bzip2-heavy-amd64_dynamic          benign            0.43     0.39    0.38  198/235    host_first100_unique_mean__max 28 vs [15, 17.33], host_rare_syscall_ratio_mean__active_windows 16 vs [1, 4], host_rare_syscall_ratio_max__active_windows 16 vs [1, 4]
xz-utils-xz-heavy-amd64_dynamic    benign            0.25     0.39    0.22  228/235    host_first100_unique_mean__max 28 vs [15, 17.33], host_first100_unique_mean__std 4.366 vs [2.342, 2.788], host_first100_unique_max__max 28 vs [15, 23]
lz4-heavy-amd64_dynamic            benign            0.66     0.39    0.72  211/235    host_first100_unique_mean__max 28 vs [15, 17.33], host_first100_unique_mean__std 4.371 vs [2.342, 2.788], host_first100_unique_max__std 4.371 vs [2.342, 3.591]
diffutils-cmp-medium-amd64_dynamic benign            0.25     0.39    0.24  221/235    host_first100_unique_mean__max 28 vs [15, 17.33], host_first100_unique_mean__std 4.371 vs [2.342, 2.788], host_first100_unique_max__std 4.371 vs [2.342, 3.591]
tar-heavy-amd64_dynamic            benign            0.33     0.39    0.28  213/235    host_first100_unique_mean__max 28 vs [15, 17.33], host_first100_unique_mean__std 4.371 vs [2.342, 2.788], host_first100_unique_max__std 4.371 vs [2.342, 3.591]
zip-heavy-amd64_dynamic            benign            0.22     0.39    0.21  227/235    host_first100_unique_mean__max 28 vs [15, 17.33], host_first100_unique_mean__std 4.37 vs [2.342, 2.788], host_first100_unique_max__max 28 vs [15, 23]
unzip-heavy-amd64_dynamic          benign            0.22     0.39    0.26  221/235    host_first100_unique_mean__max 28 vs [15, 17.33], host_first100_unique_mean__std 4.371 vs [2.342, 2.788], host_first100_unique_max__std 4.371 vs [2.342, 3.591]
rsync-light-amd64_dynamic          benign            0.67     0.39    0.78  218/235    host_first100_unique_mean__max 19.33 vs [15, 17.33], host_first100_unique_max__std 4.371 vs [2.342, 3.591], host_first100_unique_max__max 28 vs [15, 23]
rsync-heavy-amd64_dynamic          benign            0.63     0.39    0.69  217/235    host_first100_unique_mean__max 20.33 vs [15, 17.33], host_first100_unique_mean__std 3.175 vs [2.342, 2.788], host_first100_unique_max__std 4.371 vs [2.342, 3.591]
git-light-amd64_dynamic            benign            0.66     0.39    0.70  213/235    host_first100_unique_mean__max 28 vs [15, 17.33], host_first100_unique_mean__std 4.371 vs [2.342, 2.788], host_first100_unique_max__std 4.371 vs [2.342, 3.591]
git-heavy-amd64_dynamic            benign            0.73     0.39    0.59  228/235    host_first100_unique_mean__std 4.928 vs [2.342, 2.788], host_first100_unique_mean__max 28 vs [15, 17.33], host_first50_unique_mean__std 3.216 vs [0.7806, 1.873]
curl-net-amd64_dynamic             benign            0.40     0.01    0.25  221/235    host_first100_unique_mean__max 28 vs [15, 17.33], host_first100_unique_mean__std 4.371 vs [2.342, 2.788], host_first100_unique_max__std 4.371 vs [2.342, 3.591]
curl-net-2-amd64_dynamic           benign            0.41     0.17    0.29  225/235    host_first100_unique_mean__max 28 vs [15, 17.33], host_first100_unique_mean__std 4.371 vs [2.342, 2.788], host_first100_unique_max__std 4.371 vs [2.342, 3.591]
wget-net-amd64_dynamic             benign            0.67     0.01    0.39  217/235    host_first100_unique_mean__max 28 vs [15, 17.33], host_first100_unique_mean__std 4.371 vs [2.342, 2.788], host_first100_unique_max__std 4.371 vs [2.342, 3.591]
openssl-net-amd64_dynamic          benign            0.66     0.00    0.40  213/235    host_first100_unique_mean__max 28 vs [15, 17.33], host_first100_unique_mean__std 4.371 vs [2.342, 2.788], host_first100_unique_max__std 4.371 vs [2.342, 3.591]
inetutils-telnet-net-amd64_dynamic benign            0.72     0.10    0.52  213/235    host_first100_unique_mean__max 28 vs [15, 17.33], host_first100_unique_mean__std 4.371 vs [2.342, 2.788], host_first100_unique_max__std 4.371 vs [2.342, 3.591]
inetutils-ftp-net-amd64_dynamic    benign            0.80     0.21    0.53  209/235    host_first100_unique_mean__max 28 vs [15, 17.33], host_first100_unique_mean__std 4.371 vs [2.342, 2.788], host_first100_unique_max__std 4.371 vs [2.342, 3.591]
inetutils-ping-net-amd64_dynamic   benign            0.68     0.39    0.75  221/235    host_first100_unique_mean__max 28 vs [15, 17.33], host_first100_unique_mean__std 4.371 vs [2.342, 2.788], host_first100_unique_max__std 4.371 vs [2.342, 3.591]
busybox-md5sum-light-amd64_static  benign            0.45     0.39    0.44  221/235    host_first100_unique_mean__max 28 vs [15, 17.33], host_first100_unique_mean__std 4.371 vs [2.342, 2.788], host_first100_unique_max__std 4.371 vs [2.342, 3.591]
busybox-sha256sum-medium-amd64_sta benign            0.37     0.39    0.29  221/235    host_first100_unique_mean__max 28 vs [15, 17.33], host_first100_unique_mean__std 4.371 vs [2.342, 2.788], host_first100_unique_max__std 4.371 vs [2.342, 3.591]
busybox-gzip-heavy-amd64_static    benign            0.22     0.39    0.22  227/235    host_first100_unique_mean__max 28 vs [15, 17.33], host_first100_unique_mean__std 4.37 vs [2.342, 2.788], host_first100_unique_max__max 28 vs [15, 23]
busybox-bzip2-medium-amd64_static  benign            0.70     0.39    0.52  224/235    host_first100_unique_mean__max 28 vs [15, 17.33], host_first100_unique_mean__std 4.386 vs [2.342, 2.788], host_rare_syscall_ratio_max__active_windows 9 vs [1, 4]
busybox-wc-heavy-amd64_static      benign            0.42     0.39    0.30  221/235    host_first100_unique_mean__max 28 vs [15, 17.33], host_first100_unique_mean__std 4.37 vs [2.342, 2.788], host_first100_unique_max__max 28 vs [15, 23]
busybox-cmp-medium-amd64_static    benign            0.37     0.39    0.28  221/235    host_first100_unique_mean__max 28 vs [15, 17.33], host_first100_unique_mean__std 4.371 vs [2.342, 2.788], host_first100_unique_max__std 4.371 vs [2.342, 3.591]
busybox-tar-heavy-amd64_static     benign            0.68     0.39    0.71  209/235    host_first100_unique_mean__max 28 vs [15, 17.33], host_first100_unique_mean__std 4.371 vs [2.342, 2.788], host_first100_unique_max__std 4.371 vs [2.342, 3.591]
busybox-wget-net-amd64_static      benign            0.65     0.00    0.42  203/235    host_first100_unique_mean__max 28 vs [15, 17.33], host_first100_unique_mean__std 4.371 vs [2.342, 2.788], host_first100_unique_max__std 4.371 vs [2.342, 3.591]
diffutils-cmp-heavy-amd64_dynamic  benign            0.31     0.39    0.25  213/235    host_first100_unique_mean__max 28 vs [15, 17.33], host_first100_unique_mean__std 4.371 vs [2.342, 2.788], host_first100_unique_max__std 4.371 vs [2.342, 3.591]
probability of malicious from detectors trained on all 240 dataset rows (0.5 = threshold)
```

Reading: the host detector is below 0.5 for 30 of the 47 rows, the hybrid for 33, the network detector
for all 47 (0.39 is its value for a row without traffic; the network clients get 0.00-0.21). Every medium
and heavy file tool scores 0.22-0.43 on the host side, curl 0.40 and 0.41, with 213-229 of the 235 features
inside the benign range. Still at or above 0.5 on the host side: the two null runs (0.71) and 15 short
executions of 117-682 calls: b2sum-light 0.66, gzip-light 0.60, lz4-heavy 0.66, git 0.66 and 0.73, rsync
0.67 and 0.63, wget 0.67, openssl 0.66, telnet 0.72, ftp 0.80, ping 0.68, busybox bzip2-medium 0.70, busybox
tar 0.68, busybox wget 0.65. On the hybrid side 14 remain (wget, openssl and busybox wget drop below 0.5;
telnet 0.52, ftp 0.53 and ping 0.75 stay above).

**What still differs: the launcher's own signature, on every row.** The features furthest outside are
the same for 45 of the 47 rows: `host_first100_unique_mean__max` 28 against [15, 17.33] and its std; the
null rows add `host_max_run_length_max__sum` 12 against 54. The first 100 calls of the cgroup are the
launcher's (`bash -c 'exec "$@"'`), not the program's. The guest's bash (Ubuntu 24.04) made 178 calls with
15 distinct syscalls among the first 100 and one run of 54 identical calls; PC1's bash 5.0.17 makes 134
with 28 distinct and a longest run of 12. Every dataset benign row carries 15 and 54 (the minimum of
`host_max_run_length_max__max` over the 105 rows is 54), every live row 28 and 12. A program of thousands
of calls dilutes that and scores benign; one of a few hundred does not, and forests that saw 15 and 54 on
every benign row lean to malware for it. The pairs in the table above show the programs themselves agree.

**What follows.** With programs of the dataset's population, the switch, the monitor and the dataset
profile produce rows the published detectors accept; the residual is the launch environment, not the
measurement. Options for the VM side, not done here: run the live launcher with the guest's bash and libc
(copy `/bin/bash`, its loader and libc from the Ubuntu 24.04 guest and start them through that loader), or
collect on an Ubuntu 24.04 host; or exclude the prologue on both sides (19.5.6 decided otherwise). The
Python workloads of section 2 are a different population and do not measure the detectors.

State after this part: the services on PC2 stopped and their files removed; `enp5s0` down; the fixture
files removed (`make_fixtures.py` regenerates them in seconds); scripts, manifest, per-run CSVs and logs,
`rows_cli.csv` and `score_cli.txt` stay in `perf/results/dataset_v1/benign_cli/`.

## Results, part 3 (PC1, 2026-11-11): the startup-free rows of 2f90549

**Why.** Commit 2f90549 added `live_test/prologuefree/features_05s_prologuefree.csv`: the 240 rows with
the 90 host columns recomputed without the launcher's 178 calls. PC1 trains the detectors on it and
scores the 47 executions of part 2, collected again without PC1's own launcher startup.

### The commit's tables on PC1

The CSV's SHA-256 matches the README. In all 240 rows the host total equals `syscall_count` (the
published rows: `syscall_count` + 178). The release's `evaluation/heldout.py` and `evaluation/combined.py`
ran unchanged, with `common.load()` pointed at each CSV (dataset repo `.venv`: Python 3.11, NumPy 2.4.6,
scikit-learn 1.9.1; disk too full for another venv):

| BA | host | network | hybrid |
|---|---|---|---|
| Table IV, published -> startup-free | 0.929 -> 0.929 | 0.750 -> 0.750 | 0.926 -> 0.946 |
| Table V, published -> startup-free | 0.796 -> 0.852 | 0.760 -> 0.760 | 0.828 -> 0.872 |

Table IV is the commit's to the third decimal. Table V's published row differs from the release README
(0.784 / 0.756 / 0.823, tested with scikit-learn 1.7), most likely through the fold assignments of
`StratifiedGroupKFold` in 1.9.1; the change from published to startup-free is the commit's (host +0.056
here against +0.048, hybrid +0.044 against +0.043).

### The live rows without the startup

- **Launch.** `live_test/prologuefree/pfexec.c` (static C), the rule of 19.5.6 ("the monitored process
  joins the cgroup immediately before it execs the target"), made exact: its child asks to be traced and
  execs the program; the successful exec stops it before its first instruction; `pfexec` moves it into
  the watched cgroup, detaches and waits, and exits like the program (code or signal). The first call
  counted is the program's first call after its execve, the dataset's cut. `-o FILE` opens stdout before
  the fork and replaces `bin/outto`. `hybrid_collector.py` is unchanged: `--hostmon-cgroup
  /sys/fs/cgroup/unified/hazim_launch` (the launcher's bash joins it; not watched) and `--hostmon` a
  two-line wrapper that runs `hostmon_agg "$1" /sys/fs/cgroup/unified/hazim_prog`; each command is
  `pfexec /sys/fs/cgroup/unified/hazim_prog [-o FILE] PROG ARGS` (part 2's manifest otherwise).
- **Exact.** Offline, `hostmon_agg` on the cgroup counts strace's total as root minus the execve:
  `/bin/true` 29, `busybox true` 12, `b2sum` 47, a PATH lookup 29. In the collector `b2sum` light 77 =
  78 - 1 (strace's extra `ioctl(TCGETS)` comes from its stdout on `/dev/null`). Part 2 minus now:
  **107** in 27 of the 32 direct runs (PC1's launcher with absolute paths; part 1's 134 for `sleep 20`
  probably adds bash's PATH search for `sleep`, not checked) and 120 = 107 + 13 (`outto`) in 13 of 15; the others are programs whose own
  count varies (rsync, git) and bzip2-heavy (stopped at 20 s both times). Null rows now 10 and 12 calls.
- **Checks.** All 47: `HOSTMON_HEALTH` zeros, 40 rows, 0 overruns, 0 overloaded windows, collector exit 0,
  nothing left in the watched cgroup after any run. Exit codes as in part 2 (null x2 and bzip2-heavy -15, telnet 1).
  Services on PC2 as in part 2 (`openssl s_server -www` with a new self-signed RSA-2048 certificate).

### Scores

`score.py` with the detectors and category ranges from the startup-free CSV, verbatim:

```
execution                          category          host  network  hybrid  in range   furthest outside (value vs dataset range)
null-static-glibc-amd64_static     null              0.98     0.39    0.97  169/235    host_first100_unique_mean__sum 6 vs [14, 14], host_first100_unique_mean__max 6 vs [14, 14], host_first50_unique_mean__max 6 vs [14, 14]
null-busybox-sleep-amd64_static    null              0.97     0.39    0.97  169/235    host_first100_unique_mean__max 8 vs [14, 14], host_first50_unique_mean__max 8 vs [14, 14], host_first50_unique_mean__sum 8 vs [14, 14]
coreutils-b2sum-light-amd64_dynami benign            0.73     0.39    0.53  229/235    host_unique_syscalls_mean__mean 0.375 vs [0.4, 1.95], host_unique_syscalls_max__mean 0.375 vs [0.4, 1.95], host_unique_syscalls_max__sum 15 vs [16, 78]
coreutils-b2sum-medium-amd64_dynam benign            0.27     0.39    0.24  229/235    host_unique_syscalls_mean__mean 0.375 vs [0.4, 1.95], host_unique_syscalls_max__mean 0.375 vs [0.4, 1.95], host_unique_syscalls_max__sum 15 vs [16, 78]
coreutils-b2sum-heavy-amd64_dynami benign            0.28     0.39    0.21  229/235    host_unique_syscalls_mean__mean 0.375 vs [0.4, 1.95], host_unique_syscalls_max__mean 0.375 vs [0.4, 1.95], host_unique_syscalls_max__sum 15 vs [16, 78]
coreutils-md5sum-heavy-amd64_dynam benign            0.28     0.39    0.21  229/235    host_unique_syscalls_mean__mean 0.375 vs [0.4, 1.95], host_unique_syscalls_max__mean 0.375 vs [0.4, 1.95], host_unique_syscalls_max__sum 15 vs [16, 78]
coreutils-sha256sum-medium-amd64_d benign            0.27     0.39    0.24  229/235    host_unique_syscalls_mean__mean 0.375 vs [0.4, 1.95], host_unique_syscalls_max__mean 0.375 vs [0.4, 1.95], host_unique_syscalls_max__sum 15 vs [16, 78]
coreutils-cksum-heavy-amd64_dynami benign            0.24     0.39    0.21  229/235    host_unique_syscalls_mean__mean 0.375 vs [0.4, 1.95], host_unique_syscalls_max__mean 0.375 vs [0.4, 1.95], host_unique_syscalls_max__sum 15 vs [16, 78]
coreutils-sum-light-amd64_dynamic  benign            0.34     0.39    0.29  229/235    host_unique_syscalls_mean__mean 0.375 vs [0.4, 1.95], host_unique_syscalls_max__mean 0.375 vs [0.4, 1.95], host_unique_syscalls_max__sum 15 vs [16, 78]
coreutils-wc-medium-amd64_dynamic  benign            0.34     0.39    0.23  227/235    host_unique_syscalls_mean__std 2.186 vs [2.376, 5.62], host_unique_syscalls_max__std 2.186 vs [2.376, 5.933], host_unique_syscalls_mean__max 14 vs [15, 36]
coreutils-od-light-amd64_dynamic   benign            0.38     0.39    0.28  231/235    host_unique_syscalls_mean__max 12 vs [15, 36], host_unique_syscalls_max__max 12 vs [15, 38], host_unique_syscalls_mean__std 2.011 vs [2.376, 5.62]
coreutils-sort-heavy-amd64_dynamic benign            0.02     0.39    0.02  235/235    
coreutils-base64-light-amd64_dynam benign            0.36     0.39    0.32  229/235    host_unique_syscalls_mean__mean 0.375 vs [0.4, 1.95], host_unique_syscalls_max__mean 0.375 vs [0.4, 1.95], host_unique_syscalls_max__sum 15 vs [16, 78]
coreutils-base64-medium-amd64_dyna benign            0.31     0.39    0.27  229/235    host_unique_syscalls_mean__mean 0.375 vs [0.4, 1.95], host_unique_syscalls_max__mean 0.375 vs [0.4, 1.95], host_unique_syscalls_max__sum 15 vs [16, 78]
coreutils-base64-heavy-amd64_dynam benign            0.32     0.39    0.27  221/235    host_unique_syscalls_mean__mean 0.375 vs [0.4, 1.95], host_unique_syscalls_max__mean 0.375 vs [0.4, 1.95], host_unique_syscalls_mean__sum 15 vs [16, 78]
gzip-light-amd64_dynamic           benign            0.76     0.39    0.55  227/235    host_unique_syscalls_mean__std 2.186 vs [2.376, 5.62], host_unique_syscalls_max__std 2.186 vs [2.376, 5.933], host_unique_syscalls_mean__max 14 vs [15, 36]
bzip2-light-amd64_dynamic          benign            0.05     0.39    0.05  235/235    
gzip-medium-amd64_dynamic          benign            0.34     0.39    0.26  227/235    host_unique_syscalls_mean__std 2.186 vs [2.376, 5.62], host_unique_syscalls_max__std 2.186 vs [2.376, 5.933], host_unique_syscalls_mean__max 14 vs [15, 36]
bzip2-medium-amd64_dynamic         benign            0.18     0.39    0.08  227/235    host_rare_syscall_ratio_mean__active_windows 6 vs [1, 4], host_rare_syscall_ratio_max__active_windows 6 vs [1, 4], host_unique_syscalls_mean__max 14 vs [15, 36]
gzip-heavy-amd64_dynamic           benign            0.48     0.39    0.22  231/235    host_unique_syscalls_mean__max 12 vs [15, 36], host_unique_syscalls_max__max 12 vs [15, 38], host_unique_syscalls_mean__std 1.96 vs [2.376, 5.62]
bzip2-heavy-amd64_dynamic          benign            0.43     0.39    0.25  210/235    host_rare_syscall_ratio_mean__active_windows 16 vs [1, 4], host_rare_syscall_ratio_max__active_windows 16 vs [1, 4], host_top_syscall_freq_mean__sum 39.85 vs [0.1351, 25.12]
xz-utils-xz-heavy-amd64_dynamic    benign            0.36     0.39    0.28  231/235    host_first50_unique_mean__max 10 vs [11, 24], host_first50_unique_max__max 10 vs [11, 24], host_first50_unique_mean__std 1.574 vs [1.717, 3.747]
lz4-heavy-amd64_dynamic            benign            0.37     0.39    0.41  235/235    
diffutils-cmp-medium-amd64_dynamic benign            0.33     0.39    0.18  229/235    host_unique_syscalls_mean__mean 0.375 vs [0.4, 1.95], host_unique_syscalls_max__mean 0.375 vs [0.4, 1.95], host_unique_syscalls_max__sum 15 vs [16, 78]
tar-heavy-amd64_dynamic            benign            0.38     0.39    0.50  227/235    host_first50_unique_max__std 1.561 vs [1.717, 3.747], host_first50_unique_mean__std 1.561 vs [1.717, 3.747], host_first50_unique_mean__max 10 vs [11, 24]
zip-heavy-amd64_dynamic            benign            0.36     0.39    0.23  235/235    
unzip-heavy-amd64_dynamic          benign            0.35     0.39    0.28  235/235    
rsync-light-amd64_dynamic          benign            0.75     0.39    0.83  234/235    host_entropy_max__max 4.348 vs [0.01763, 4.301]
rsync-heavy-amd64_dynamic          benign            0.63     0.39    0.62  234/235    host_entropy_max__max 4.315 vs [0.01763, 4.301]
git-light-amd64_dynamic            benign            0.55     0.39    0.72  227/235    host_first50_unique_max__std 1.561 vs [1.717, 3.747], host_first50_unique_mean__std 1.561 vs [1.717, 3.747], host_first50_unique_mean__max 10 vs [11, 24]
git-heavy-amd64_dynamic            benign            0.77     0.39    0.68  231/235    host_first50_unique_mean__max 10 vs [11, 24], host_first50_unique_max__max 10 vs [11, 24], host_first50_unique_mean__std 1.565 vs [1.717, 3.747]
curl-net-amd64_dynamic             benign            0.65     0.00    0.56  219/235    host_first50_unique_max__std 1.561 vs [1.717, 3.747], host_first50_unique_mean__std 1.561 vs [1.717, 3.747], host_first50_unique_max__max 10 vs [11, 24]
curl-net-2-amd64_dynamic           benign            0.65     0.21    0.60  219/235    host_first50_unique_max__std 1.561 vs [1.717, 3.747], host_first50_unique_mean__std 1.561 vs [1.717, 3.747], host_first50_unique_max__max 10 vs [11, 24]
wget-net-amd64_dynamic             benign            0.83     0.02    0.50  215/235    host_first50_unique_mean__std 1.405 vs [1.717, 3.747], host_first50_unique_max__std 1.405 vs [1.717, 3.747], host_first50_unique_mean__max 9 vs [11, 24]
openssl-net-amd64_dynamic          benign            0.74     0.00    0.34  219/235    host_first50_unique_mean__std 1.561 vs [1.717, 3.747], host_first50_unique_max__std 1.561 vs [1.717, 3.747], host_first50_unique_mean__max 10 vs [11, 24]
inetutils-telnet-net-amd64_dynamic benign            0.80     0.10    0.54  227/235    host_first50_unique_max__std 1.561 vs [1.717, 3.747], host_first50_unique_mean__std 1.561 vs [1.717, 3.747], host_first50_unique_max__max 10 vs [11, 24]
inetutils-ftp-net-amd64_dynamic    benign            0.71     0.00    0.42  229/235    net_ba_ratio_pkt_delta__std 0.08516 vs [0, 0.07206], net_ba_ratio_pkt_delta__mean 0.01364 vs [0, 0.01154], net_ba_ratio_pkt_delta__sum 0.5455 vs [0, 0.4615]
inetutils-ping-net-amd64_dynamic   benign            0.79     0.39    0.89  227/235    host_first50_unique_max__std 1.561 vs [1.717, 3.747], host_first50_unique_mean__std 1.561 vs [1.717, 3.747], host_first50_unique_mean__max 10 vs [11, 24]
busybox-md5sum-light-amd64_static  benign            0.67     0.39    0.69  207/235    host_first50_unique_mean__std 1.405 vs [1.717, 3.747], host_first50_unique_max__std 1.405 vs [1.717, 3.747], host_first50_unique_mean__max 9 vs [11, 24]
busybox-sha256sum-medium-amd64_sta benign            0.64     0.39    0.63  207/235    host_first50_unique_mean__std 1.405 vs [1.717, 3.747], host_first50_unique_max__std 1.405 vs [1.717, 3.747], host_first50_unique_mean__max 9 vs [11, 24]
busybox-gzip-heavy-amd64_static    benign            0.02     0.39    0.01  235/235    
busybox-bzip2-medium-amd64_static  benign            0.37     0.39    0.21  233/235    host_rare_syscall_ratio_max__active_windows 9 vs [1, 4], host_rare_syscall_ratio_mean__active_windows 9 vs [1, 4]
busybox-wc-heavy-amd64_static      benign            0.61     0.39    0.50  219/235    host_unique_syscalls_mean__max 10 vs [15, 36], host_unique_syscalls_max__max 10 vs [15, 38], host_unique_syscalls_mean__std 1.8 vs [2.376, 5.62]
busybox-cmp-medium-amd64_static    benign            0.66     0.39    0.63  207/235    host_unique_syscalls_mean__std 1.717 vs [2.376, 5.62], host_unique_syscalls_mean__max 11 vs [15, 36], host_unique_syscalls_max__std 1.717 vs [2.376, 5.933]
busybox-tar-heavy-amd64_static     benign            0.40     0.39    0.51  235/235    
busybox-wget-net-amd64_static      benign            0.23     0.01    0.12  231/235    net_ba_ratio_pkt_delta__std 0.07806 vs [0, 0.07206], net_ba_ratio_pkt_delta__mean 0.0125 vs [0, 0.01154], net_ba_ratio_pkt_delta__sum 0.5 vs [0, 0.4615]
diffutils-cmp-heavy-amd64_dynamic  benign            0.39     0.39    0.20  219/235    host_unique_syscalls_mean__mean 0.375 vs [0.4, 1.95], host_unique_syscalls_max__mean 0.375 vs [0.4, 1.95], host_unique_syscalls_max__sum 15 vs [16, 78]
probability of malicious from detectors trained on all 240 dataset rows (0.5 = threshold)
```

Against part 2 (launcher included, published detectors):

| below 0.5, of 47 | part 2 | startup-free |
|---|---|---|
| host | 30 | 28 |
| hybrid | 33 | 28 |
| network | 47 | 47 |

- The launcher's signature is gone: `in range` rises for 40 of the 47 rows, 8 rows lie fully inside
  (235/235), and `host_first100_unique` 28 against [15, 17.33] no longer appears. sort-heavy, bzip2-light
  and busybox gzip-heavy score 0.01-0.05; lz4-heavy 0.66 -> 0.37, busybox tar 0.68 -> 0.40, busybox wget
  0.65 -> 0.23, busybox bzip2-medium 0.70 -> 0.37 (host).
- Higher than before: the null rows 0.71 -> 0.98 (10 and 12 calls against the dataset's 18, three null
  rows in all), the network clients on the host side (curl 0.40 -> 0.65 twice, wget 0.67 -> 0.83, openssl
  0.66 -> 0.74, telnet 0.72 -> 0.80, ping 0.68 -> 0.79) and four busybox applets (md5sum 0.45 -> 0.67,
  sha256sum 0.37 -> 0.64, cmp 0.37 -> 0.66, wc 0.42 -> 0.61).

**What still differs: the program's own C library startup.** Without the launcher, the first calls of
every row are the program's loader and libc start. Distinct syscalls among the first 50
(`host_first50_unique_mean__max`), benign rows:

| build | dataset (n, min / median / max) | live (n, min / median / max) |
|---|---|---|
| amd64_dynamic | 18: 17 / 19 / 22 | 37: 9 / 12 / 16 |
| static | 87: 11 / 17 / 24 | 8 (busybox): 9 / 14 / 18 |

The dataset's malware median is 13. 14 of the 45 live benign rows fall below the dataset's benign
minimum. Where those first calls weigh most, the score stays high: 10 of the 13 executions under 300
calls are at or above 0.5 on the host side, against 4 of the 23 above 1,000 (busybox sha256sum, cmp and
wc, rsync-heavy). This fits PC1's Ubuntu 20.04 (glibc 2.31) starting a program with fewer distinct calls than the
guest's glibc 2.43 (2.43-2ubuntu2.4; the VM is named Ubuntu-Clean-24.04, but its libc is newer):
consistent with the counts, not shown call by call (the guest's raw `syscall_events.csv` are not on PC1).
The way to test it is the one part 2 named for the launcher: run the programs with the guest's loader
and libc, or collect on a host with a newer glibc.

**Checked on the lab workstation, 2026-11-11** (offline; study tree
`additional-study-review-20261022/pc1-part3-check-20261111/`): in the guest's raw runs, every one of the
18 dynamic benign programs starts with the loader and libc start-up including `set_tid_address`,
`set_robust_list`, `rseq`, `prlimit64` and `getrandom` (17-22 distinct calls in the first 50). So do 47 of
59 amd64-static and 21 of 28 i386-static programs, which were built with glibc 2.35 statically (the other
19 are musl builds). The workstation's glibc 2.35 `/usr/bin/b2sum` makes the same five calls (17 distinct
in its first 50). Not yet measured on PC1: `strace /usr/bin/b2sum /dev/null` there would show whether
glibc 2.31 leaves them out. The dataset's static benign builds carry their own C library, so running them
on PC1 would give the dataset's start-up exactly.

**Table V on PC1.** scikit-learn 1.8 changed how `StratifiedGroupKFold` shuffles the groups. With only
that change applied to 1.7 the published Table V becomes 0.795 / 0.759 / 0.834 (PC1, 1.9.1: 0.796 /
0.760 / 0.828), and stock 1.7 gives the paper's 0.784 / 0.756 / 0.823 exactly. The release now requires
scikit-learn older than 1.8 (release `ce7d51c`).

### Failures, with their messages

- cmp-heavy, first run: `/usr/bin/cmp: .../fx/heavy_copy.bin: No such file or directory` (exit 2): the
  manifest that ran in part 2 compares against `heavy_copy.bin`, and the fixture had been removed to save
  disk. Recreated and rerun; the table holds the rerun.

State after this part: services on PC2 stopped and their files removed; `enp5s0` down; our `basic_fix`
switchd untouched; both cgroups and the fixtures removed. Scripts, manifest, per-run CSVs and logs,
`rows_pf.csv`, `score_pf.txt`, `compare_parts.txt` and the two tables' outputs stay in
`perf/results/dataset_v1/prologuefree/` (git-ignored).
