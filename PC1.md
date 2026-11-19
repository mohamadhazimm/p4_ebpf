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

## Part 4 (ready, 2026-11-15): every capture through the Wedge, for the thesis committee

*Reopens the cohort replays closed on 2026-11-08, because the committee asks for detection measured on the
switch's own register reads.*

**Goal.** Replay every dataset capture that carries IPv4 TCP/UDP traffic through the Wedge into
`hybrid_collector.py --profile dataset` (0.5 s windows, the published detectors' window), turn each run into
a dataset row, and send the rows back. The VM side scores them against the software model
(`committee-eval-20261113/switchgap/score_switch_replay.py`: per-feature agreement, decision flips, balanced
accuracy with Table IV and Table V). Offline, with the switch rules emulated, the gap is at most 0.006 in
balanced accuracy and zero flips on the held-out split; the replay measures it on the hardware, including the
read budget under overload, which the offline emulation only approximates.

**Captures.** 110 in all (107 replayable), both sets sanitized (headers only, payload bytes zeroed):
- the 77 cohort captures in `live_test/captures/cohort/` (rows 0-203 with traffic; Chaos `d538053a...` last:
  it overloads the reader in every window);
- 33 new ones for the network attacks and network-benign rows (rows 204-239; the 3 null runs have no
  traffic): `live_test/captures/cohort-extra.tar.gz` (26 MB; 771 MB unpacked, git-ignored). Unpack first:

      tar xzf live_test/captures/cohort-extra.tar.gz -C live_test/captures
      (cd live_test/captures/cohort-extra && sha256sum -c SHA256SUMS)

  Its `manifest.csv` has the cohort's columns plus `attack_type`. Replay the 8 runs with `expect_overload` 1
  last (the fan-out floods, `slowloris_1000`, the two GoldenEye runs).
- **Skip `bulkup_200`, `bulkup_400`, `bulkup_700`** (found 2026-11-15): they hold 4,370, 8,824 and 15,072 frames
  larger than 1514 B (up to 65,226 B). The guest's capture took the upload's segments before the NIC split them
  (transmit segmentation offload), so these frames cannot go out on a 1500-byte wire as they are, and the
  dataset counted each as one packet where a switch would see up to ~45. Note them as not replayable; the other
  30 extra captures and all 77 cohort captures stay under 1514 B.

**The replay option (done, 2026-11-15).** `live_test/replay_capture.py --profile dataset` runs the collector
with `--profile dataset --launcher shell --windows K+40` and the replayer with 0.5 s windows, so that collector
windows K..K+39 are the dataset's 40 windows (`--profile switch`, the default, is unchanged).
`live_test/dataset_row.py --skip-windows K` takes those 40 windows. Tests:
`thesis-hybrid-ebpf-p4/python/tests/test_replay_profiles.py`.

**Per capture** (manifest columns `execution_id`, `category`, `label`, `anchor_offset_s`):

    sudo python3 live_test/replay_capture.py CAPTURE --out DIR --profile dataset \
        --anchor-offset ANCHOR_OFFSET_S --align-window 4
    python3 live_test/dataset_row.py DIR/windows.csv --execution-id ID --category CAT --label L \
        --skip-windows 4 --out perf/results/committee_replay/replay_rows.csv

(`--align-window` must leave at least 0.5 s before the anchor; 4 windows of 0.5 s is 2 s. Every
`anchor_offset_s` is between -5.1 and 0 s: the anchor lies before the first kept frame.)

**What comes back.** `replay_rows.csv` (110 rows; only its network columns are used), each run's
`summary.json` (alignment error, replay timing error, snapshot intervals, self-check) and `timing.jsonl`, and a
note of any run whose replay or collector failed. Do not rerun a failed capture silently: report it.

## Part 5 (ready, 2026-11-15): the socket tracer's cost on bare metal

*For the committee's socket-level attribution (item 4). In the analysis VM the tracer attributed every flow
correctly (2,841 of 2,841 alone, 8,517 of 8,517 beside three malware samples), but its per-packet cost could
not be resolved: the VM's run-to-run spread (0.3-4.5 us per datagram) was larger than any difference.*

**What it is.** `ebpf_perf/sockowner/`: two `cgroup_skb` programs record the first packet of each 5-tuple on a
socket, two `cgroup/sock_create`/`sock_release` programs record the creating process (README there).
`sockjoin.py` and `hybrid_collector.py --sockowner` join the switch's flows to it; tests
`thesis-hybrid-ebpf-p4/python/tests/test_sockjoin.py`.

**Build** (no root; PC1's own toolchain, as for `hostmon_agg`):

    DEP=/usr CLANG=clang ebpf_perf/sockowner/build.sh

**Measure** (root; loopback only, nothing leaves the host; about 10 minutes):

    sudo ebpf_perf/sockowner/bench/bench_cost.sh perf/results/sockowner_cost 10

Each round sends 200,000 datagrams to a closed port on 127.0.0.1 with one 5-tuple (the steady state: one hash
lookup per packet) and with 50,000 (a FLOW event for each of the first 50,000), first with the tracer off, then
on, attached to the root cgroup as the collector attaches it. `summary.json` gives the added nanoseconds per
datagram for both. Also record the governor (`cpupower frequency-info`) and whether the run was pinned.

**What comes back.** `summary.json`, `bench.jsonl`, `kernel.txt` and the `SOCKOWNER_HEALTH` lines
(drops and errors must be 0).

## Part 6 (ready, 2026-11-15): the dataset's own static benign programs, live

*Why. Live, PC1's own benign programs (Ubuntu 20.04 builds and busybox, parts 2 and 3) are flagged by the host
and stacked detectors in 19 of 47 executions, far more than the dataset's benign rows. Two explanations remain:
the live pipeline differs from the dataset's collector, or PC1's programs differ from the dataset's. The
dataset's static programs carry their own C library, so running them here separates the two: if their live rows
are their dataset rows, the pipeline is faithful and the gap comes from PC1's programs.*

**The programs.** 66 static benign programs of the dataset without a network task (45 amd64, 21 i386; GNU
coreutils, diffutils, gzip, m4, cpio, bzip2, brotli, lz4, ncompress, xxHash, xmlwf, sqlite3), each the exact
binary of its dataset run, with the input files of its task. They come as `static-benign.tar.gz` (107 MB,
SHA-256 `e011e8cabb36d2c8b25d8ad1aee5c704bf7187fc048ad9e07daaeac1756372e9`), not committed (compiled GPL programs): copy it from the lab workstation
(`vbox-runs/hybrid-rf-study-20261010/data/versioned-collector/additional-study-review-20261022/pc1-static-benign/`).

    mkdir -p perf/results/static_benign && cd perf/results/static_benign
    scp WORKSTATION:.../pc1-static-benign/static-benign.tar.gz . && sha256sum static-benign.tar.gz
    tar xzf static-benign.tar.gz && cd ../../..
    (cd perf/results/static_benign/static-benign && python3 -c 'import hashlib,json; m=json.load(open("manifest.json")); bad=[f for f,h in m["files"].items() if hashlib.sha256(open(f,"rb").read()).hexdigest()!=h]; print("bad:", bad or "none")')

The i386 programs need the kernel's 32-bit support (standard in Ubuntu's kernels).

**Run** (from p4_ebpf; about 25 minutes; `--only 2` first as a trial):

    python3 live_test/static_benign/run_static_benign.py --root perf/results/static_benign/static-benign \
        --out perf/results/static_benign/runs --startup-free [--pfexec PATH_OF_PART_3_PFEXEC]

`--startup-free` starts each program as part 3 did: `pfexec` (built from `live_test/prologuefree/pfexec.c`)
moves it into `/sys/fs/cgroup/unified/hazim_prog` at its exec, the launcher's bash stays in `hazim_launch`,
and the runner writes part 3's two-line `hostmon_agg` wrapper itself. Each case is the common collector
command C of section 0 with `--command "pfexec ... -o OUT/ID.stdout PROGRAM ARGS"` (every path absolute), then
`dataset_row.py` with the case's dataset `execution_id`. Without `--startup-free` it runs as part 2 (the
launcher in the cgroup, `bin/outto` for stdout); compare those rows with the published table instead.

**Compare:**

    ../venv/bin/python3 live_test/static_benign/compare_static_benign.py perf/results/static_benign/runs/rows.csv \
        --dataset live_test/prologuefree/features_05s_prologuefree.csv --json perf/results/static_benign/compare.json

Per program: the live and dataset system-call counts, how many of the 90 host columns agree within 1% and 10%,
and the four detectors' scores (host-only, network-only, concatenated, stacked; trained on the 240 start-up-free
rows *without the program's project*) for the live row and for its dataset twin, side by side. The dataset
twins themselves are flagged by host 6, network 0, concatenated 6, stacked 2 of 66 (checked on the workstation:
the script given the dataset's own rows reproduces them exactly, 90 of 90 host columns, identical scores). So a
faithful pipeline gives about those numbers; part 3's 19 of 47 would show as many more live flags here.

**What comes back.** The comparison's printed table and `compare.json`, `runs/rows.csv`, and any case whose
collector failed or whose exit code differs from `cases.tsv` (the runner prints both). Expected differences
worth noting rather than fixing: a few calls from PC1's kernel, and programs whose count depends on timing.

## Part 7 (ready, 2026-11-15): a verdict every window, and a drop rule on the verdict

*For the committee's items 5 (online detection) and 6 (closing the loop: on a malicious verdict, have the switch
drop the host's flows, and measure time-to-containment). Offline (committee-eval-20261113 REPORT.md 2.6), a model
trained on observation prefixes makes about 95% of its detections in the first 0.5-s window, floods 98%.*

**Tool.** `live_test/streaming/stream_verdicts.py COLLECTOR.csv`: the paper's forests trained on every dataset
run at the prefixes 1, 2, 4, 6, 10, 16, 20, 30, 40 windows (`live_test/streaming/dataset_windows.csv.gz`: the
240 runs' 0.5-s window signals, 170 kB; the 40-window summaries reproduce every published row); after each new
window it summarizes the run so far like a dataset row and prints a probability. `--detector network` (default:
a replay has no host side), `--hold-out-group G` trains without the dataset runs of group G (the replayed run's
`cv_group` in the manifest; otherwise the verdict is in-sample), `--skip-windows K` for a replay anchored on
window K, `--follow` to score while the collector writes, `--on-alarm "CMD"` runs CMD once at the first window
over `--threshold` (STREAM_WINDOW and STREAM_PROBABILITY in its environment), `--log` a JSONL record. Checked on
the workstation: syn_fan_40k held out alarms at window 0 (p 0.98), bulk2000 and a coreutils run do not alarm;
in `--follow` mode it scored rows as they were appended and ran the hook once. Training takes ~1 s (network) to
~15 s (stacked).

**Step 1, no switch change: verdicts on the switch's own windows.** After Part 4, for each replay directory:

    ../venv/bin/python3 live_test/streaming/stream_verdicts.py DIR/windows.csv --skip-windows 4 \
        --hold-out-group CV_GROUP --log DIR/stream.jsonl

and note the first alarm window per run (attacks, network-benign and malware separately). The offline value to
compare with comes from the same windows in the dataset.

**Step 2, the drop rule (a switch change for this part only).** Add to `ingress.p4` a table after
`forwarding.apply()`, only for valid IPv4, keyed exactly on `hdr.ipv4.srcAddr`, with the actions `drop` (the
existing one) and `NoAction` (default), size 1,024; the flow registers are updated earlier, so blocked packets are
still counted. A small control-plane script (bfrt, like `program_forwarding.py`) adds and removes an entry and
prints the time the add call returned. Record the compiler's stages and resources, since the table may cost a
stage, and keep the build separate from the measured detector of section 4 / 5.5.

**Step 3, time to containment.** Replay one attack capture at a time (from `cohort-extra`: `udp_sink_60k`,
`syn_sink_40k`, `syn_fan_40k` and a GoldenEye run) through the switch with the collector (`--profile dataset`,
as Part 4) and, beside it,

    ../venv/bin/python3 live_test/streaming/stream_verdicts.py DIR/windows.csv --follow --skip-windows 4 \
        --hold-out-group CV_GROUP --log DIR/stream.jsonl --on-alarm "python3 MITIGATE add 10.0.0.10"

and count, behind port 140 (a capture on PC2, or the port's counters), the replay's packets forwarded before and
after the rule. Per run: first attack packet sent, alarm window and time, rule-install time, last forwarded packet,
and the share of the attack dropped. Then the same with three benign replays (`bulk2000`, `session_1000`,
`dns_10k`): does any get blocked, and when? Remove the entry after every run.

**What comes back.** Step 1's first-alarm windows; for step 3 the per-run times and counts, the `stream.jsonl`
files, the compiler's resource lines for the variant with the table, and any failure.

## Part 8 (proposed, 2026-11-15): several hosts behind the switch

*For the committee's item 9 (several hosts behind the Tofino, with background traffic). Needs a testbed change on
PC1, so run it only if the user agrees.*

**What the collector can do now.** `hybrid_collector.py --scope-ip ADDR` (repeatable) writes, next to the run's
rows, one more CSV per address (`<out-csv stem>.scoped-ADDR.csv`) whose network features count only the flows
with ADDR as source or destination (`sockjoin.ip_scope_windows`: a bucket's flow is the 5-tuple of its latest CPU
report; cleared buckets lose their owner until they report again). Tested: two hosts' flows partition each window
(their packet and byte deltas add up to the whole window's), and the server's address gives back the
window-level join (`test_sockjoin.py`, the collector suite is 152 OK).

**Proposed run.** With only PC1 and PC2 every flow touches both, so the hosts are two client namespaces on PC1
bridged onto `eth1`, with their own addresses (A 10.0.0.11, B 10.0.0.12), talking to `validation/hybrid/servers.py`
on PC2 (10.0.0.2):
1. A alone (`http_poll`), B alone (`http_bulk`), each one collector run with `--scope-ip` its address;
2. A and B at the same time, one collector run with `--scope-ip 10.0.0.11 --scope-ip 10.0.0.12`;
3. step 2 again with background traffic from a third namespace (`bulk2000` replayed from it).
Compare per host, window by window, the scoped rows of steps 2 and 3 with the solo rows of step 1, and with the
window-level rows (every flow); score all three with `validation/hybrid/score.py`'s network detector. Expected:
scoped equals solo up to timing, the window-level rows mix the hosts. The host side stays this machine's monitor
on the monitored host's cgroup (a per-host monitor on each host is the deployment, not tested here).

## Part 9 (ready, 2026-11-17): basic_gtot_ba measured, and a new build that reads its own registers

*Two things. (A) `basic_gtot_ba`, the build of the thesis replay rows (part 4g), has no latency or line-rate
measurement yet. (B) A new build, `perf/variants/sweep`: `basic_gtot_ba` whose registers the data plane reads
itself, one probe packet per bucket, so a window covers every bucket instead of the ~500 the control plane reads in
0.5 s. Offline it matches the published rows as often as the exact build (106 of 110 captures in the 135
non-duration columns, the same 4 floods failing), without the exact build's extra 106 ns. Design and limits:
`perf/variants/sweep/README.md`. Nothing of it has run on a switch yet: report every failure with its message,
and do not rerun a failed step silently.*

**ASROOT** below is the command prefix used for `exact_replay.py` in part 6 (it runs a command as root). It must
pass SIGTERM on to the command (sudo does): `sweep_replay.py` stops tcpdump that way, with `timeout` as a
backstop. `sweep_reader.py` runs on the switch under the SDE environment that `sweep_replay.remote_cmd` sets
(`SDE_INSTALL=/root/bf-sde-9.6.0/install`, `LD_LIBRARY_PATH=/usr/local/lib:$SDE_INSTALL/lib`, python2.7).

**9A. `basic_gtot_ba`: latency and line rate.** The build is on the switch (`/root/hazim_perf/build/basic_gtot_ba`).
- **Latency**, as for `gtot` in part 4d (p4_perf section 4.1's method, `hwl_runs.sh` of
  `perf/results/latency_gtot_20261115/`, 3 runs per program, the baseline and `basic_fix` the same day):

      perf/variants/hwl/make_hwl_sources.sh perf/variants/gtot OUT_DIR
      perf/tools/sw_compile.sh OUT_DIR/basic_hwl basic.p4 BUILD_DIR -DP4_GLOBAL_TOTALS_SPLIT=1

- **Line rate**, p4_perf section 3.2's 27-run matrix as for `gtot` (`perf/results/linerate_gtot_20261115/`) with
  `sw_pktgen_run.py --global-totals`. The tool now finds the split build's registers (`reg_g_pkts_ba`,
  `reg_g_bytes_ba`); `global_delta` then has `pkts_ab`, `pkts_ba`, `bytes_ab`, `bytes_ba` and, as for `gtot`,
  `pkts` and `bytes` (A→B + B→A). The generator's flow goes one way, so pipe 1's `pkts_ab` must grow by the
  generated packets and `pkts_ba` by 0; pipe 0 counts the looped-back copies.
- **Expected:** latency near `gtot`'s 319 ns (the compiler estimates 133 ingress cycles against 135); rates as
  `basic_fix`.

**9B. The sweep build: compile.** Copy `perf/variants/sweep` to the switch as the other variants, then:

      perf/tools/sw_compile.sh SRC/sweep basic.p4 BUILD/basic_sweep
      perf/tools/sw_compile.sh SRC/sweep basic.p4 BUILD/basic_sweep_ctrl -DP4_ENABLE_SWEEP=0 -DP4_FRAME_LEN=0

- The second is `basic_gtot_ba`'s program from these sources: its resources must equal `basic_gtot_ba`'s. It checks
  that the sweep's sources leave the data path alone.
- For both, record ingress/egress stages, SRAM, map RAM, TCAM, stateful ALUs, the critical path and the latency
  cycles, as in p4_perf section 5.6's table. If time allows, also `-DP4_ENABLE_SWEEP=0` alone (what `frame_len`
  costs).
- If the first fails because a register has two index sources (the data path's hash and the probe's MAC), compile
  with `-DSWEEP_SHARED_INDEX=1` and say so. Any other failure: stop and report the message.

**9C. A first replay.** Start the sweep build as `gtot` in part 4d (its switchd in `hz_sw`, then `run_bfrt.sh ...
setup --ports 132,140 --fwd 132:140,140:132 --mirror-sid 1`). From the repo on PC1, with the first cohort capture's
`anchor_us` and `execution_id` from its manifest:

      python3 live_test/sweep_replay.py live_test/captures/cohort/CAPTURE --anchor-us A --execution-id ID \
          --out perf/results/sweep_first --asroot ASROOT

- `sweep_replay.py` copies `sweep_reader.py` to the switch and runs `--setup --reset --frame-min 10.0.0.10/32
  --sweep-ports 132 --export-port 132`.
  - The replay host's port 132 becomes the only probe port, and the exports come back out of it to `eth1`.
  - tcpdump runs there as root and promiscuous, since the exports keep the probe's destination MAC.
  - The replay carries the probes of the 41 window boundaries among the capture's frames.
- `summary.json` lists `checks`:
  - probes sent = the switch's probe count = the model's;
  - exports captured = the switch's export count = the model's;
  - 41 sweeps with consecutive numbers;
  - in every window, the totals equal to the buckets' sum;
  - no tcpdump drop, and no frame refused;
  - the row equal to the model's in the 135 non-duration columns.
- Then the same with `bulk2000` (`cohort-extra/manifest.csv` has its anchor). If a check fails, stop there and
  report it.

**9D. The generator (the deployment path).**

      python3 live_test/sweep_generator_check.py --out perf/results/sweep_generator --asroot ASROOT

- It starts the generator of pipe 1 (local port 68, app 0): 65,536 probes every 0.5 s, 2 µs apart, so a sweep takes
  131 ms. Its port joins `sweep_ports`.
- Midway it sends 200 known flows from `eth1` and checks the sweeps against the program's model (`summary.json`
  `checks`):
  - one record per sweep before the traffic;
  - after it, every used bucket, with the model's registers and totals;
  - probes = buckets × sweeps (the stop can cut the last sweep short; that sweep is then left out);
  - the generator's packet counter = the switch's probe count;
  - exports captured = the switch's export count;
  - the sweeps one period apart on the switch's clock;
  - the packets over all windows = the flows' packets.
- Then, as information only: `--ipg-ns 0` (the generator's own rate: how long a sweep takes, and whether exports are
  lost at port 132 or in tcpdump) and `--ipg-ns 500`.

**9E. The sweep build's latency and line rate.**
- As 9A: `make_hwl_sources.sh perf/variants/sweep OUT_DIR` for the latency, and the line-rate matrix with
  `--global-totals` (the sweep build has the split totals).
- Then two line-rate runs (1518 B and 64 B, paced at 100%) with the sweep's generator running beside the line-rate
  app. Port 69 sends only while 68 is a generator port; here the sweep holds 68.

      sweep_reader.py --setup --sweep-ports 132 --export-port 132
      sweep_reader.py --generator start --pipes 1 --local-port 68 --app 0
      sw_pktgen_run.py OUT_JSON --size 1518 --rate-pct 100 --first-local-port 69 --buffer-offset 4096 --global-totals
      sweep_reader.py --state --pipes 1        # exports and probes so far
      sweep_reader.py --generator stop --pipes 1

- Expected: the same rates and losses as without the sweep. The totals count only the line-rate flow (probes are not
  counted), and the sweep exports 2 records (bucket 0 and the flow's).

**9F. Every capture.**

      python3 live_test/run_sweep_replays.py perf/results/sweep_replays --asroot ASROOT

- 107 captures, about an hour: the 77 cohort captures and 30 of `cohort-extra`. The bulk uploads are left out, as in
  part 4. Calm captures first, then the floods, Chaos last.
- A run with a `summary.json` is not repeated, so the batch can be restarted.
- Expected from the model:
  - the switch's row equal to the model's in all 135 non-duration columns in every run;
  - the row equal to the published row in 103 of the 107. The 4 that differ are Chaos and the three SYN fan-outs,
    whose flows share buckets.
- `rows.csv` is the input of the VM's `score_switch_replay.py`; `runs.csv` has one line per run with its checks.

**What comes back.**
- The compile reports of every build, 9A's and 9E's latency builds included.
- The latency runs (`packet_latencies.csv` and `summary.json` per run, as in parts 4d and 6) and the line-rate JSONs.
- The run directories of 9C and 9D, without `exports.pcap` where it is large.
- 9F's `rows.csv`, `runs.csv` and the runs' `summary.json`.
- A "Results, part 9" section here.
- State after: `basic_fix` running again, checked as in the earlier parts.

## Results, part 4 (PC1, 2026-11-15): 109 of the 110 captures through the Wedge

**What ran.** p4_ebpf `eadb2ca`; release `live-validation` `3e7cb5f` (its `features/` is identical to `main`
`ce7d51c`; `dataset/features.csv` `6d15da30...`). Per capture exactly the two commands above (`--profile dataset
--anchor-offset ANCHOR_OFFSET_S --align-window 4`, then `dataset_row.py --skip-windows 4`, with `--release
~/Desktop/hAZIM/p4-ebpf-malware-detection`: its default is `~/Desktop/p4-ebpf-malware-detection`), driven by
`run_part4.py`. Order: the cohort in manifest order (Chaos last), then the extras, `expect_overload` 0 first and
the 8 with 1 last. Our `basic_fix` switchd (up since 2026-11-08) on the switch, no other user; `enp5s0` up for
the runs and down after; the collector resets the registers at the start of every run.

**PC1's disk.** 146 MB free at the start (771 MB needed for the extras alone). After a cleanup (journal, apt
caches, the old run directories archived to `perf/results/runs_20261029-1108.tar.xz`), 789 MB: still not the
771 MB at once, so each extra was extracted alone (`tar --occurrence=1`), its SHA-256 checked against
`SHA256SUMS` and the manifest, replayed, and deleted (the last 8 from `/dev/shm`). `tx.pcap` is gzipped after
each run.

**What comes back:** `live_test/committee_replay/pc1_20261115.tar.xz` (850 KB): `replay_rows.csv` (109 rows,
sha256 `b4e973c8...`), per run `summary.json`, `timing.jsonl`, `windows.csv` and `collector.log`;
`run_checks.csv`/`.json` (the checks below, per run); `progress.jsonl`, `driver.log`; the scripts
`run_part4.py` and `check_runs.py`; and part 5's files.

### The bulk uploads: bulkup_700 not replayed, bulkup_200 and bulkup_400 incomplete

The three bulk uploads are the only captures with frames over 1,514 B: 4,370 of 14,266 (bulkup_200), 8,824 of
29,078 (bulkup_400) and 15,072 of 49,940 frames (bulkup_700) are guest GSO super-frames of up to **65,226 B**.
eth1 (MTU 1500) refuses them and `replay_absolute.py` counts them as failed (`9896 frames sent, 4370 failed`;
`20254 frames sent, 8824 failed`). **The bulkup_200 and bulkup_400 rows hold only the frames that fit: the
upload's data packets are missing; do not score them as replays.** bulkup_700 was skipped for the same reason.
No Ethernet path carries 65 KB frames (Tofino and mlx5 jumbo frames end at ~9-10 KB): the dataset's extractor
counts each super-frame as one packet where a switch on the wire would see ~44 segments. Resegmenting these
captures (the switch's view, with different counts by design) or leaving the three rows out is the VM side's call.

### Checks (`run_checks.csv`)

- **All 109:** collector exit 0; `40 windows -> 1 row with 90 host and 145 network columns`; alignment error
  median 1.05 ms, max 6.2 ms; snapshot interval 32-35 ms.
- **The 98 runs without an overloaded window:** packets switch = sent in all 98; IPv4 bytes equal in 96:
  bulk1600 and bulk2000 are 320 B short each, part 1's dormant-read race (the first five packets of a reused
  5-tuple between the `reg_pkts` and `reg_bytes` syncs). 3,839 of 3,858 windows inside the self-check bounds
  (session_1000 2, bulk1600 8, bulk2000 9). No overrun.
- **The self-check under `--profile dataset` is off by 14 B per packet:** `replay_capture.py` compares the
  switch's frame bytes (`byte_layer=frame`) with IPv4 bytes, so every window with traffic reads "outside" (first
  run: switch 666 / sent 540 bytes for 9 packets, 126 = 9 x 14). The figures here take 14 B per packet off the switch's
  bytes; the `self_check` in each `summary.json` is the uncorrected one.
- **Overload** (read budget 0.7; switch/sent packets are the 40 windows' sums):

| run | expect_overload | overloaded windows | overrun windows | switch / sent packets |
|---|---|---|---|---|
| Chaos `d538053a` | 1 | 40 | 0 | 28,320 / 221,733 |
| slowloris_500 | **0** | 7 | 0 | 11,087 / 11,087 |
| slowloris_800 | **0** | 8 | 0 | 17,270 / 17,612 |
| syn_fan_40k | 1 | 8 | 4 | 6,263 / 39,847 |
| syn_fan_100k | 1 | 14 | 14 | 16,430 / 99,640 |
| syn_fan_150k | 1 | 21 | 9 | 11,113 / 149,425 |
| syn_sink_40k | 1 | 9 | 1 | 44,200 / 124,666 |
| udp_fan_60k | 1 | 17 | 2 | 7,654 / 59,776 |
| slowloris_1000 | 1 | 8 | 0 | 18,469 / 22,032 |
| goldeneye_p10 | 1 | 6 | 0 | 29,330 / 37,617 |
| goldeneye_r10 | 1 | 7 | 1 | 28,080 / 37,388 |

  Two runs the manifest expects to fit overload the reader at 0.5 s on the hardware (slowloris_500 and _800).
  The overruns (31 windows) are all in the fan-out floods.
- **Replay timing:** the per-run maximum lateness has a median of 2.1 ms. Over 20 ms: **syn_sink_40k (median
  174 ms, max 412 ms: the Python replayer on PC1 does not keep up with its burst, so this run's windows are
  shifted)**, syn_fan_40k (max 242 ms), syn_fan_100k 62, udp_fan_60k 57, udp_sink_250k 32.
- **First look at the rows** (the scoring is `score_switch_replay.py`'s): in the 98 rows without overload a median
  of 137 of the 145 network columns equal the published row (relative 1e-9); the flow durations equal it in one
  row only (the switch's timestamps against the capture's).

### Failures

None of the 109 failed. A trial of the first cohort capture before the loop (`committee_replay/trial1`) is not
in the rows. State after: `enp5s0` down, our switchd untouched, `/dev/shm` clean, `cohort-extra/` holds only
its four metadata files.

## Results, part 5 (PC1, 2026-11-15): the socket tracer's cost

- **Build:** `DEP=/usr CLANG=clang ebpf_perf/sockowner/build.sh` with `BPFTOOL=` a bootstrap bpftool v7.3.0 built
  from `libbpf-bootstrap/bpftool` (PC1 has none installed; the version `hostmon_agg` was built with); clang
  10.0.0-4ubuntu1. `sockowner` sha256 `fbecfc11...`.
- **Run:** `bench_cost.sh` with one change, `bench_cost_pc1.sh` in the tarball: the tracer attaches to
  `/sys/fs/cgroup/unified`, PC1's cgroup-v2 root (hybrid layout; `/sys/fs/cgroup` is the v1 tmpfs there, the
  collector's `--sockowner-attach` would be the same path). 10 rounds, 66 s.
- **Not bare metal:** PC1 is a KVM guest (QEMU vCPU, 2 vCPUs, kernel 5.15.0-139-generic). The guest has no
  cpufreq interface, so no governor; not pinned; VS Code and Firefox were running.

| 200,000 datagrams | off, median (range) | on, median (range) | added per datagram | per round, on - off |
|---|---|---|---|---|
| one 5-tuple | 7,393 ns (7,228-7,812) | 8,014 ns (7,894-8,204) | **+621 ns** | +381 to +935 ns |
| 50,000 new 5-tuples | 7,331 ns (7,230-7,638) | 9,250 ns (8,335-10,207) | **+1,919 ns** | +1,019 to +2,568 ns |

- **Health:** `SOCKOWNER_HEALTH,0,0,0` in all 10 rounds, 0 failed sends; every round's log holds all 50,000 FLOW
  events of the 50,000-tuple run. The two ranges do not overlap for either load, and on is slower in every round.

## Unit tests (PC1, 2026-11-15)

`python3 -m unittest discover -s thesis-hybrid-ebpf-p4/python/tests`: 150 run, 6 skipped (no generated
`bfruntime_pb2`), **1 error**: `test_sockjoin.WindowJoinTests.test_socket_join_recovers_each_program_alone`,
`TypeError: unsupported operand type(s) for |: 'dict' and 'dict'` in the release's `features/switch_model.py`
line 109 (`dict.fromkeys(COUNTERS, 0) | {...}` needs Python 3.9; PC1 has 3.8.10, on `main` too). PC1's runs do
not reach it (`dataset_row.py` reads only `FEATURES`).

## Results, part 4b (PC1, 2026-11-15): two fixes, rechecked and rerun

**1. The self-check counts the sent bytes in the collector's byte layer** (`live_test/replay_capture.py`): under
`--profile dataset` it adds 14 B per sent packet (`self_check_header_bytes`; `self_check` now names its
`byte_layer`). Tests: `test_replay_profiles.SelfCheckByteLayer` (the 14 B equal `PROFILES["dataset"]` and
`ETHERNET_HEADER_BYTES`; a synthetic run whose frame bytes fall inside the bounds only with the fix).
Rechecked offline for all 109 runs (`recheck_selfcheck.py`: windows, timing log and `tx.pcap` of each run; the
original `summary.json` kept, the new one is `summary_fixed.json`): 3,905 of 4,151 windows checked lie inside
the bounds; 108 runs give part 4's corrected counts exactly, slowloris_800 20 instead of 19 (part 4 took 14 B
per switch packet off, the fix adds 14 B per sent packet to the bounds: they differ only where the packet counts
differ, here in an overloaded run).

**2. A torn dormant read no longer loses bytes** (`hybrid_collector.py`, `NetSummarizer.add`): a dormant row with
no new packet in `reg_pkts` keeps the old baseline instead of becoming it, so bytes that `reg_bytes` (synced
~2 ms later) already holds count with their packets in the window whose `reg_pkts` sees them. Test:
`test_dataset_profile.ActiveFilterTests.test_a_torn_dormant_read_keeps_its_bytes_for_the_window_that_counts_its_packets`
(fails on the old code with `0 != 320`). Rerun on the Wedge, 3 times each with the fixed collector:

| run | packets switch / sent | bytes switch / sent (frame) |
|---|---|---|
| bulk1600 x3 | 19,362 / 19,362 each | **2,026,476 / 2,026,476** each (part 4: 320 short) |
| bulk2000 x3 | 24,000 / 24,000 each | **2,520,000 / 2,520,000** each (part 4: 320 short) |

`replay_rows_v2.csv` is `replay_rows.csv` with these two rows from the first rerun (the other 107 rows were
collected with the old collector; none of the calm runs' totals showed a shortfall, the overloaded runs' cannot
show one). The two new rows differ from the old ones in ~90 network columns: another replay, other window cuts,
not only the 320 B. Suite: 153 run, 6 skipped, 1 error (the release's Python 3.9 operator, above).

**Found while checking, not fixed: resumed dormant flows count late.** The rest of the windows outside the bounds
in the bulk runs come in pairs, one short and the next over by the same 25-250 packets (bulk2000 rerun 2,
windows 23/24: 27 under, 27 over). A reused 5-tuple lands in its dormant bucket (occupied, so no CPU report);
the collector sees it only when the round robin re-reads that bucket, and the allowance left after the active
set reads ~220-250 of 700-900 dormant buckets per window (bulk2000: 172 resumed buckets). Totals stay exact;
the per-window distribution shifts, so per-window features (max, std) can differ. The read budget is the limit:
the timing logs give **0.54-0.68 ms per bucket read** (fits over bulk2000, syn_fan_150k, udp_fan_60k), about 500
buckets per 0.5 s window at budget 0.7.

Files: `live_test/committee_replay/pc1_20261115_fix.tar.xz`: `replay_rows_v2.csv`, the six reruns (summary,
timing, windows, collector log) and their rows, every run's `summary_fixed.json`, and the scripts. State after:
`enp5s0` down, our switchd untouched.

## Results, part 4c (PC1, 2026-11-15): dormant buckets probed; the flood read budget kept

**The limitation (part 4b).** A flow that resumes in its dormant bucket (a reused 5-tuple, or a new flow hashed into
an occupied bucket) sends no CPU report. The collector read only ~220-250 of 700-1,700 dormant buckets per window,
round robin, so such packets counted windows late.

**The fix** (`batched_reader.py` `read_window(probe=..., probe_max_full=...)`, `hybrid_collector.py
--dormant-probe`, on in `--profile dataset`; the P4 program is unchanged):
- each window the collector sends the dormant buckets with the packet count it last read; the reader reads only
  `reg_pkts` for them, from the window's snapshot (one register entity per bucket: **0.047 ms per bucket** on the
  Wedge, fitted over bulk2000 and bulk1600, against ~0.55 ms for a full read), and reads in full, in the same
  window, those whose count changed;
- it reads in full at most `probe_max_full` of them (what the allowance leaves after the active reads and the
  probes); the other changed ones are active again and read with the active set from the next window, under its
  budget (`deferred`). The cost model learns the probe cost on its own and keeps 8 full reads in reserve;
- **a second, older bug:** `basic_fix` has no `reg_newconn_dst`, yet every window requested its buckets; the reads
  returned an error and no rows in no time, and each counted 0.15 of a bucket in the cost model, whose per-bucket
  estimate fell from 0.56 to 0.19 ms in windows with destination buckets and few flow buckets. Part 4's
  syn_fan_100k then read 3,933 buckets in one window (2.1 s). Now, after the first "missing" error, no destination
  bucket is requested (nor counted as skipped), and the model learns only from rows read.
- Tests: 12 new (165 run on PC1; the one error is the release's Python 3.9 operator). One replays the round-robin
  case (a resumed flow counted a window late) against the probe (counted in its window); one checks that every
  packet is counted once when changed buckets are deferred.

**Rerun on the Wedge** (`basic_fix`): the 47 captures with resumed dormant buckets in part 4 and Chaos (48; part 4's
run of each against its rerun; `probe_compare.csv`):

| | part 4 | probe |
|---|---|---|
| 37 runs without overload: windows inside the self-check bounds | 1,424 / 1,443 | **1,443 / 1,443** |
| the same: packet and frame-byte totals exact | 35 of 37 | **37 of 37** |
| bulk2000, bulk1600: windows inside the bounds | 29-34 / 40 | **40 / 40** |
| bulk2000: dormant buckets covered per window | ~230 of up to 1,743 | **all** (probed) |
| bulk2000: read time median / max | 335 / 388 ms | **212 / 302 ms** |
| longest read over the 48 runs | 2,120 ms | 524 ms |

**Floods: the read budget is the ceiling.** A first version without `probe_max_full` read every changed dormant bucket
in full: syn_sink_40k then counted 124,666 of 124,666 packets, but reads took up to 4.0 s and 17-34 windows of the
fan-out floods overran. With the cap and the cost-model fix the reads stay within the window (overrun windows
syn_fan_100k 14 -> 7, syn_fan_150k 9 -> 3, syn_fan_40k 4 -> 2) and the floods count fewer packets than in part 4
(syn_fan_100k 16,430 -> 8,079 of 99,640, syn_sink_40k 44,200 -> 34,009 of 124,666, GoldenEye p10 29,330 -> 24,536 of
37,617), because part 4's counts came partly from reads that ran into the next windows. The total read time per
run is the same (11-14 s of 20 s) and full bucket reads within the budget total 13,000-16,000 per run, so no read
schedule counts a 40,000-150,000-packet flood: that is what part 4d's global totals are for. Overloaded windows are
more frequent (GoldenEye p10 6 -> 30) because a changed dormant bucket that does not fit is now an active bucket
left unread, which part 4 did not know about.

**Files:** `live_test/committee_replay/pc1_20261115_probe.tar.xz`: `replay_rows_v3.csv` (`replay_rows_v2.csv` with the
48 reruns' rows, the latest run of each capture), `probe_compare.csv`, and each rerun's `summary.json`,
`timing.jsonl`, `windows.csv` and `collector.log`. The first 45 reruns (`runs_probe`, `runs_probe_trial`) used the
uncapped probe and still the old destination requests; the 14 of `runs_probe2` (Chaos, the 10 overloaded runs,
bulk2000, session_1000, the first cohort capture) the final code; for those 14 captures the rows are
`runs_probe2`'s.

## Results, part 4d (PC1, 2026-11-15): global totals in the data plane, a test build

**Why.** Under a flood the control plane reads ~500 buckets per 0.5 s window (part 4c: 13,000-16,000 full reads per
run) while the flood keeps ~30,000 active, so the window totals, summed over the buckets read, showed 6-35% of the
packets. 19 of the 29 per-window features (95 of the 145 columns: packets, bytes and their A->B / B->A parts, the
three average sizes, packets and bytes per second, the five ratios, SYN, ACK, RST) are sums over all of the window's
packets in `switch_model.py`, so seven whole-switch counters give them exactly.

**The build** (`perf/variants/gtot/`): the sources of the deployed `basic_fix` (hashes as in its `compile_meta.txt`)
plus seven one-entry registers (`reg_g_pkts`, `reg_g_bytes`, `reg_g_pkts_ab`, `reg_g_bytes_ab`, `reg_g_syn`,
`reg_g_ack`, `reg_g_rst`) updated in the same branch as the flow registers with the same values (`pkt_len`,
`dir_ab`, the TCP flags); `-DP4_ENABLE_GLOBAL_TOTALS=0` compiles `basic_fix` itself. bf-p4c 9.6.0 on the switch,
21.9 s (`perf/results/gtot_build_20261115/resources.md`):

| | basic_fix | gtot |
|---|---|---|
| ingress stages | 5 | 6 |
| stateful ALUs | 14 / 48 | 21 / 48 |
| SRAM / map RAM | 20.5% / 34.0% | 22.0% / 36.5% (2 + 2 per one-entry register) |
| ingress MAU latency (compiler estimate) | 131 cycles | 135 cycles |

The compiler moved some flow registers one stage later; what they count is unchanged. **Latency, measured the same
day with p4_perf section 4.1's method (p4_perf section 5.6): median 319 ns against basic_fix's 315 ns and the
baseline's 246 ns, so the totals cost 4 ns. Line rate (p4_perf section 3.2's matrix, 27 runs): the same rates as
basic_fix within 0.01 points, lossless, and the totals exact for all 13.1 billion packets.**

**The software:** `batched_reader.read_window(totals=True)` syncs the seven registers with the flow registers (one
snapshot) and reads them through the client's own parser; `reset_registers.py` clears them at the start of a run
(checked at cell 0); `hybrid_collector.py --global-totals 1` takes the window's packet, byte and flag totals from
their differences (modulo 2^32) and adds `net_gtot_used`, `net_gtot_bucket_pkts_delta`, `net_gtot_bucket_bytes_delta`
to every row; the per-flow features still come from the buckets read; the socket-level join ignores the totals.
Tests: 11 new, 176 run.

**On the switch.** Our `basic_fix` switchd stopped, `gtot` started in `hz_sw`; `run_switchd.sh` did not add the
ports, so `run_bfrt.sh ... setup --ports 132,140 --fwd 132:140,140:132 --mirror-sid 1` did (a first bulk2000 run
before it went out on a link without carrier and is discarded). The 10 overloaded captures, Chaos and three calm ones
with `--global-totals 1` (`runs_gtot/`), against the same captures on `basic_fix` with the same code
(`runs_probe2/`; `gtot_compare.csv`):

| capture | sent | seen, gtot | seen, basic_fix | 95 total columns equal to the published row | median relative error |
|---|---|---|---|---|---|
| Chaos `d538053a` | 221,733 | **99.9%** | 12.6% | 19 / 19 | **0.018** / 0.079 |
| goldeneye_p10 | 37,617 | **100%** | 65.2% | 35 / 0 | **0.001** / 0.355 |
| goldeneye_r10 | 37,388 | **100%** | 73.1% | 35 / 0 | **0.001** / 0.260 |
| slowloris_1000 | 22,032 | **100%** | 93.3% | 44 / 0 | **0.001** / 0.100 |
| slowloris_500 | 11,087 | 100% | 100% | 37 / 17 | 0.000 / 0.006 |
| slowloris_800 | 17,612 | 100% | 100% | 43 / 18 | 0.000 / 0.188 |
| syn_sink_40k | 124,666 | **99.1%** | 27.3% | 20 / 1 | **0.005** / 0.897 |
| syn_fan_40k | 39,847 | **98.0%** | 14.2% | 16 / 4 | **0.408** / 1.000 |
| syn_fan_100k | 99,640 | **98.7%** | 8.1% | 10 / 4 | **0.400** / 1.000 |
| syn_fan_150k | 149,425 | **99.1%** | 6.4% | 10 / 1 | **0.077** / 1.000 |
| udp_fan_60k | 59,776 | **97.6%** | 10.9% | 19 / 49 | 0.333 / 0.000 |
| bulk2000 | 24,000 | 99.8% | 100% | 24 / 41 | 0.000 / 0.000 |
| session_1000 | 12,000 | 99.9% | 100% | 6 / 49 | 0.011 / 0.000 |
| first cohort capture | 9 | 88.9% | 100% | 51 / 95 | 0.000 / 0.000 |

("seen": the 40 dataset windows; gtot / basic_fix in the last two columns.) Overloaded windows, overruns and read
times are about the same in both builds, since they depend on the buckets read, not on the totals (the fan-out
floods: 28-33 overloaded windows and 1-8 overruns in both; the longest read 391-521 ms against 417-524 ms).

- **Every packet is counted.** Over the run's 44 windows the totals equal the packets sent in all 14 runs. The 0.1-2.4%
  missing from the 40 dataset windows are packets of the first milliseconds of dataset window 0 that window 3's
  snapshot already holds: each snapshot starts 1.4-10 ms after its window boundary in the calm runs and 30-36 ms in
  the floods (the collector takes thousands of reports first), and packets in that gap count in the earlier window.
- **Calm runs:** the totals are as good (median errors 0.000-0.011) but equal the published values in fewer columns,
  because the window cuts move: the bucket path counts a new flow's first packets in the window of its CPU report,
  which here puts dataset window 0's first packets where the dataset has them.
- **Floods:** the total-based columns go from median errors of 0.1-1.0 to 0.001-0.02 for Chaos, GoldenEye, slowloris
  and the SYN sink. The SYN and UDP fan-outs stay at 0.08-0.41: their whole flood lasts ~0.7 s, so a cut a few to
  36 ms off the dataset's boundary (plus a replay up to 48 ms late) moves a large part of it between two windows.
- **Not changed:** the 10 per-flow features (flow counts, `dir_valid_count`, flows with A->B / B->A, the length
  statistics, durations) still come from the buckets read and stay sampled under overload.

**Possible next steps (not done):** sync the seven totals first, at the window boundary, before the reports are taken
(the cut would move from up to 36 ms to ~1 ms after the boundary); or use the totals only in overloaded windows; if
the build is adopted, measure its latency and rerun all 109 captures on it.

**State after:** `basic_fix` running again (pid 21258 in `hz_sw`), ports 132/140, forwarding and mirror set by
`run_bfrt.sh setup`, checked with the first cohort capture (9 / 9 packets, 40 of 40 windows inside the bounds);
`enp5s0` down. `live_test/committee_replay/pc1_20261115_gtot.tar.xz`: the runs, `gtot_compare.csv`, the build's
resource report and the setup logs.

## Results, part 4e (PC1, 2026-11-15): all 109 captures on the gtot build

The `gtot` build of part 4d is adopted; all 109 captures were rerun on it with `--global-totals 1`, twice.

**First rerun, with part 4d's code (`runs_gtot_all/`).** Over the run's 44 windows the totals equal the packets and
bytes sent in all 109 runs (1,469,778 packets), and the floods came out as in part 4d. But the calm captures got
**worse** than on `basic_fix`: packets were missing from the 40 dataset windows in 76 of the 96, all of them in the
curl, wget, ftp and telnet captures, and the median number of the 95 total-based columns equal to the published row
fell from 95 to 25.5. The cause: `read_window(totals=True)` appended the seven totals to the batched sync of the flow
registers, and they were synced last. The sync starts a median 1.3 ms after the window boundary in the calm runs
but takes ~33 ms, so the totals were cut ~34 ms after each boundary, and a window's first ~34 ms counted in the window
before. The cohort's first frame comes ~4.7 ms into dataset window 0, so it counted in window 3, which is dropped.
(Part 4d's "1.4-10 ms after the boundary" was the snapshot's start, not the totals' cut.)

**The fix (reader and collector; the P4 build, its latency and its line rate unchanged).**
- `hybrid_collector.py --totals-cut boundary` (the new default): right after each window boundary, before it takes
  the window's CPU reports, the collector sends the reader a request for the totals alone.
- `batched_reader.read_window(totals=True)` reads the seven registers from hardware, without a sync, in one
  ReadRequest of seven entities (2.7 ms median on the Wedge, 5.5 ms p99). The route is checked once against the
  client's parser (parsed, then the parser's values, then parsed again must be in order), else one `entry_get` per
  register. All 109 runs used the one request.
- The read ends a median 4.75 ms after the boundary in the calm runs (3.9-5.9 ms by run), 4.45 ms in the floods.
  18 of the 4,796 windows were cut more than 50 ms late (up to 488 ms), all at the start of a fan-out or sink flood
  (syn_fan_40k/100k/150k, udp_fan_60k, syn_sink_40k), where the collector was still taking the previous window's
  CPU reports (0.4-0.9 s of them) when the boundary passed.
- `--totals-cut read` puts the totals in the window's read, before the flow sync; `--totals-cut snapshot` is part
  4d's behaviour.
- `live_test/replay_capture.py`: for a window with `net_gtot_used` 1 the self-check takes the totals' read as the cut,
  and checks such a window even when it is overloaded (its totals no longer depend on the buckets read).
- Tests: 181 run, with the switch's generated `bfruntime_pb2` on the path (`scripts/patches/NOTES_totals_cut.txt`);
  the only error is the release's Python 3.9 operator (as in part 4).

**Trial of six captures** (`runs_tfirst_trial/` with `read`, `runs_tbound_trial/` with `boundary`; 95 total
columns equal to the published row):

| capture | basic_fix | gtot, part 4d's cut | gtot, `read` | gtot, `boundary` |
|---|---|---|---|---|
| first cohort capture | 95 | 51 | 95 | 95 |
| curl-net-amd64_dynamic | 95 | 5 | 95 | 95 |
| curl-net-amd64_dynamic-2 | 63 | 22 | 63 | 63 |
| bulk2000 | 41 | 23 | 43 | 44 |
| syn_fan_100k | 4 | 10 | 20 | 20 |
| goldeneye_p10 | 0 | 35 | 35 | 46 |

`read` loses in the floods because the window's read starts only after the collector has taken thousands of reports.

**Full rerun with the boundary cut (`runs_gtot_boundary/`, 16:20-17:43).** All 109 done; the totals equal the
packets and bytes sent over the 44 windows in every run, and the self-check passes 44 of 44 windows in every run,
floods included. Against `basic_fix` (the rows of `replay_rows_v3.csv`, found by row equality in `runs_probe2/`,
`runs_probe/`, `runs_probe_trial/` and part 4's `runs/`) and the first rerun (`gtot_all_compare.csv`):

| | basic_fix | gtot, part 4d's cut | gtot, boundary cut |
|---|---|---|---|
| **calm (96 captures, 618,805 packets)** | | | |
| packets in the 40 windows | 618,805 | 612,001 | 618,805 |
| captures with all of them | 96 | 20 | 96 |
| 95 total columns equal: median / mean | 95 / 81.2 | 25.5 / 38.2 | 95 / 81.5 |
| rows with all 95 equal | 61 | 13 | 63 |
| all 145 columns equal: median / mean | 137 / 119.2 | 67 / 76.1 | 137 / 119.4 |
| **overloaded on basic_fix (11 captures, 820,823 packets)** | | | |
| packets in the 40 windows | 192,916 (23.5%) | 814,084 (99.2%) | 820,823 (100%) |
| captures with all of them | 2 | 5 | 11 |
| 95 total columns equal: median / mean | 4 / 10.3 | 20 / 26.2 | 41 / 39.1 |
| their median relative error: median | 0.260 | 0.006 | 0.000 |
| all 145 columns equal: median / mean | 11 / 17.2 | 34 / 33.0 | 49 / 46.1 |
| overloaded / overrun windows | 285 / 17 | 284 / 18 | 279 / 16 |
| **bulkup_200/400 (incomplete replays, 30,150 packets)** | | | |
| 95 total columns equal: mean | 30.5 | 24.0 | 31.5 |

The 50 per-flow columns come from the buckets read in all three and stay where they were (calm mean 38.0 / 37.9 /
37.9; overloaded 6.9 / 6.8 / 7.0). The calm captures: 75 equal to `basic_fix` in the 95 columns, 16 better (slowloris_150
39 -> 69, slowloris_300 39 -> 55, the session, dns and bulk captures +2 to +10, three cohort captures +8 or +9), 5 worse
(the three udp_sink captures 67 -> 37, below; beacon_100 and bulk700 by one column). The overloaded ones:

| capture | sent | in the 40 windows: basic_fix / 4d cut / boundary | 95 columns equal | median relative error |
|---|---|---|---|---|
| Chaos `d538053a` | 221,733 | 27,990 / 221,562 / 221,733 | 19 / 19 / 29 | 0.079 / 0.050 / 0.009 |
| goldeneye_p10 | 37,617 | 24,536 / all / all | 0 / 35 / 45 | 0.355 / 0.001 / 0.000 |
| goldeneye_r10 | 37,388 | 27,340 / all / all | 0 / 35 / 38 | 0.260 / 0.002 / 0.000 |
| slowloris_500 | 11,087 | all / all / all | 17 / 37 / 46 | 0.006 / 0.000 / 0.000 |
| slowloris_800 | 17,612 | all / all / all | 18 / 43 / 56 | 0.188 / 0.000 / 0.000 |
| slowloris_1000 | 22,032 | 20,558 / all / all | 0 / 44 / 57 | 0.100 / 0.000 / 0.000 |
| syn_sink_40k | 124,666 | 34,009 / 123,512 / 124,666 | 1 / 20 / 41 | 0.897 / 0.005 / 0.010 |
| syn_fan_40k | 39,847 | 5,672 / 38,284 / 39,847 | 4 / 16 / 48 | 1.000 / 0.380 / 0.000 |
| syn_fan_100k | 99,640 | 8,079 / 98,327 / 99,640 | 4 / 10 / 16 | 1.000 / 0.400 / 0.200 |
| syn_fan_150k | 149,425 | 9,492 / 148,340 / 149,425 | 1 / 10 / 27 | 1.000 / 0.077 / 0.000 |
| udp_fan_60k | 59,776 | 6,541 / 58,323 / 59,776 | 49 / 19 / 27 | 0.000 / 0.333 / 0.333 |

**What is left (not fixed):**
- **The seven registers are read one after another**, ~0.4 ms apart, in the one request. B->A is the total minus
  A->B, so in a flood the A->B counter, read after the total, holds a few dozen packets more and the difference makes
  B->A packets that were never sent: udp_sink_60k / 150k / 250k get 6 / 10 / 26, udp_fan_60k 17 (and two windows
  with more A->B packets than packets in all), syn_fan_100k / 150k 4 / 8 more than the published 1 / 2. Out of
  60,000-250,000 packets, but in a capture with no B->A traffic it costs the 30 B->A columns (packets, bytes, average
  size, the two B->A ratios and down/up, five aggregates each): the udp_sink captures fall from 67 to 37 columns, and
  udp_fan_60k loses the same 30 (49 -> 27: 34 columns lost, 30 of them B->A, and 12 gained). Only these six captures
  have it; no window of the other 103 runs has more A->B packets than packets in all. A fix needs the P4:
  count B->A in two of the registers in place of the packet and byte totals (total = A->B + B->A; the same seven
  registers and stateful ALUs), so that B->A grows only with B->A packets.
- **Direction comes from the flow's bucket** (`perf/variants/gtot/ingress.p4:331-339`): a packet whose ports match
  neither the bucket's reference nor their reverse (two flows in one bucket) counts as A->B. Chaos has up to ~10,400
  flows in a window over 65,536 buckets: its totals are exact, but 83,244 of its packets count as B->A against the
  published 110,866, so 27,622 (25% of its B->A) counted as A->B, most likely through shared buckets. The same rule
  holds in `basic_fix`'s buckets.
- **The cut is still 4-5 ms after the boundary** (the request's round trip and the read), and later when the
  collector falls behind on the reports (above): the boundary request waits for the loop. The fan-out floods last
  ~0.7 s, so that and a replay up to 48 ms late still move part of them between two windows: syn_fan_100k 16 of 95.
  A timer thread sending the boundary request would not wait for the reports.
- The 50 per-flow columns are still sampled under overload, as before.

**The rows for the thesis:** `replay_rows_gtot.csv` (109 rows from `runs_gtot_boundary/`, in `replay_rows_v3.csv`'s
order) replaces `replay_rows_v3.csv`.

**State after:** `basic_fix` running again (pid 25993 in `hz_sw`), ports 132/140, forwarding and mirror set by
`run_bfrt.sh setup` (`setup_basic_fix_restored_4e/`), checked with the first cohort capture (9 / 9 packets, 40 of 40
windows inside the bounds); `enp5s0` down. `live_test/committee_replay/pc1_20261115_gtot_all.tar.xz`: both reruns and
both trials (rows, `rerun.log`, per run `summary.json`, `timing.jsonl`, `windows.csv`, `collector.log`),
`gtot_all_compare.csv`, `replay_rows_gtot.csv`, the scripts and patches, the setup logs.

## Results, part 4f (PC1, 2026-11-16): B->A counted in the data plane, the six floods rerun

**Why.** Part 4e left one new limitation: the reader reads the seven totals one after another, so in a flood
B->A = total - A->B picked up packets that were never sent (6-26 in six floods), and the captures without B->A
traffic lost all 30 B->A columns.

**The build** (`basic_gtot_ba`): `perf/variants/gtot` compiled with `-DP4_GLOBAL_TOTALS_SPLIT=1`. `reg_g_pkts` and
`reg_g_bytes` become `reg_g_pkts_ba` and `reg_g_bytes_ba`, which count only the packets with `dir_ab` 0 (the
packets the flow registers count as B->A). A B->A register grows only with B->A packets, so the order of the reads
can move a packet into the next window but cannot create one. Without the define the sources compile `gtot` as
before. bf-p4c 9.6.0 on the switch, 21.9 s (`perf/results/gtot_ba_build_20261116/resources.md`): the same 6 ingress
stages, SRAM, map RAM and 21 stateful ALUs as `gtot`. The compiler estimates 133 ingress cycles against `gtot`'s 135,
so the latency should be no higher. **Latency and line rate were not measured** for this build; the user chose to
rerun only the six floods.

**The software.** Both builds' totals are handled by the same code:
- `batched_reader.py` takes whichever full set of seven registers the program has (`GLOBAL_NAMES` or
  `GLOBAL_NAMES_SPLIT`) and reads each direction's packets and bytes one after the other.
- `hybrid_collector.py` (`gtot_keys`) takes B->A as counted and sets the totals to A->B + B->A, each difference
  modulo 2^32. A change of key set between two windows only resets the baseline.
- `reset_registers.py` also clears the two B->A registers.
- `bfrt_mock.py` models both builds.
- Tests: 4 new, 185 run, 1 error (the release's Python 3.9 operator).
- `perf/tools/sw_pktgen_run.py --global-totals` still knows only `gtot`'s names.

**On the switch.** Our `basic_fix` switchd was stopped and `basic_gtot_ba` started in `hz_sw`; `run_bfrt.sh setup`
added the ports, forwarding and mirror (`setup_gtot_ba/`). The reader found the split set. The first cohort capture
was replayed with `--global-totals 1` as a check (`runs_gtot_ba_check/`): 9 / 9 packets, 44 of 44 windows inside the
bounds, 95 of 95 total columns equal to the published row. Then came the six floods (`runs_gtot_ba/`, 04:03-04:07).
In all six, every packet and byte was counted over the 44 windows and 44 of 44 windows were inside the bounds
(`gtot_ba_compare.csv`):

| capture | sent | B->A packets: published / gtot / gtot_ba | windows with A->B above all: gtot / gtot_ba | 30 B->A columns equal: basic_fix / gtot / gtot_ba | 95 total columns equal | all 145 equal |
|---|---|---|---|---|---|---|
| udp_sink_60k | 60,000 | 0 / 6 / **0** | 2 / 0 | 30 / 0 / **30** | 67 / 37 / **75** | 109 / 79 / **117** |
| udp_sink_150k | 150,000 | 0 / 10 / **0** | 2 / 0 | 30 / 0 / **30** | 67 / 37 / **83** | 109 / 79 / **125** |
| udp_sink_250k | 250,000 | 0 / 26 / **0** | 3 / 0 | 30 / 0 / **30** | 67 / 37 / **75** | 109 / 79 / **117** |
| udp_fan_60k | 59,776 | 0 / 17 / **0** | 1 / 0 | 30 / 0 / **30** | 49 / 27 / **75** | 58 / 36 / **84** |
| syn_fan_100k | 99,640 | 1 / 5 / 0 | 1 / 0 | 0 / 0 / 0 | 4 / 16 / **29** | 8 / 20 / **33** |
| syn_fan_150k | 149,425 | 2 / 10 / 0 | 5 / 0 | 0 / 0 / 0 | 1 / 27 / **29** | 5 / 31 / **33** |

The median relative error of the 95 columns is 0.0000 in all six on `gtot_ba` (`gtot`: up to 0.33 for
udp_fan_60k, 0.20 for syn_fan_100k). The udp_sink captures now also beat `basic_fix` (67) by 8-16 columns, the A->B
ratios and average sizes. `basic_fix` reads a bucket's registers at slightly different times too: an A->B ratio
of 1.019 in a window, and an average size of 74.47 B for 74 B frames. On `gtot_ba` the total is A->B + B->A of the
same read, so the ratio is exactly 1 and the size exactly 74 B. The SYN fan-outs' 1 and 2 real B->A packets count as A->B on every build:
with ~100,000 flows over 65,536 buckets their replies land in buckets another flow holds (part 4e's direction
limit). Their B->A columns are therefore 0, against 1 and 2 published.

**The other 103 rows** stay from `runs_gtot_boundary/` (part 4e, `gtot`). `scripts/totals_read_exposure.py` counts,
for each run, the sent packets whose time lies inside a window's totals read, widened by half the shortest round
trip (`totals_read_exposure.tsv`):
- In 67 of the 109 runs no packet was sent during a totals read, so `gtot_ba` would read the same totals there.
- In 36 others besides the six floods, at least one packet was. Most had 1-174 such packets; Chaos had 1,520,
  syn_sink_40k 887 and goldeneye_r10 402.
- There, the old order can move a B->A count between two adjacent windows. It adds B->A that was never sent only
  after a window with more A->B packets than packets in all, and none of the 103 has one (part 4e).
- Rerunning those 36 (~35 min) or all 103 (~80 min) on `gtot_ba` would put every row on one build.

**The rows for the thesis:** `replay_rows_gtot_ba.csv` is `replay_rows_gtot.csv` with these six rows from
`runs_gtot_ba/`:

| | gtot (part 4e) | with the six from gtot_ba |
|---|---|---|
| calm (96): 95 total columns equal, median / mean | 95 / 81.5 | 95 / 82.8 |
| calm: all 145 equal, mean | 119.4 | 120.7 |
| overloaded on basic_fix (11): 95 total columns equal, median / mean | 41 / 39.1 | **45 / 44.8** |
| overloaded: all 145 equal, median / mean | 49 / 46.1 | 52 / 51.8 |

**Still open:** the direction of a packet whose flow shares a bucket (part 4e; Chaos, the SYN fan-outs), the cut
4-5 ms after the boundary and later when the collector falls behind on the reports, and the sampled per-flow
columns under overload.

**State after:** `basic_fix` running again (pid 17781 in `hz_sw`), ports 132/140, forwarding and mirror set by
`run_bfrt.sh setup` (`setup_basic_fix_restored_4f/`), checked with the first cohort capture (9 / 9 packets, 40 of 40
windows inside the bounds); `enp5s0` down. The build stays on the switch in `/root/hazim_perf/build/basic_gtot_ba`.
`live_test/committee_replay/pc1_20261116_gtot_ba.tar.xz`: the runs, the check, `gtot_ba_compare.csv`,
`replay_rows_gtot_ba.csv`, `totals_read_exposure.tsv`, the scripts, the build's resource report and the setup logs.

## Results, part 4g (PC1, 2026-11-16): all 109 captures on basic_gtot_ba

**Space first.** PC1 had 295 MB free. Freed:
- the superseded run directories `runs_gtot/` (part 4d), `runs_gtot_all/` (part 4e's first rerun) and the two trials
  of part 4e, 76 MB. Each is complete in a committed archive (rows, `rerun.log`, per run `summary.json`,
  `timing.jsonl`, `windows.csv`, `collector.log`); only their `tx.pcap.gz` files are gone.
- Firefox's cache (58 MB; Firefox was not running) and apt's package cache (`apt-get clean`, 362 MB).

790 MB free afterwards. Not touched: VS Code's folders (2.8 GB), the journal (324 MB), and a 368 MB file VS Code
deleted but still holds open (`/tmp/DxX4kjv0`); reloading VS Code frees that one.

**The rerun.** `basic_gtot_ba` started again in `hz_sw` (`setup_gtot_ba_rest/`). The other 103 captures were replayed
with `--global-totals 1` into `runs_gtot_ba/`, next to part 4f's six, 04:16-05:17 (PC1's clock).
- All 109 done, and in every run the totals equal the packets and bytes sent over the 44 windows.
- The self-check passes 4,796 of 4,796 windows.
- No window has more A->B packets than packets in all.
- The totals' read ends a median 4.72 ms after the boundary (longest median 7.43 ms).

Against `basic_fix` (`replay_rows_v3.csv`) and `gtot` with the boundary cut (part 4e; `gtot_ba_all_compare.csv`):

| | basic_fix | gtot | gtot_ba |
|---|---|---|---|
| **calm (96 captures, 618,805 packets)** | | | |
| B->A packets in the 40 windows (published 78,400) | 78,417 | 78,442 | **78,400** |
| 30 B->A columns: rows with all equal | 67 | 64 | 67 |
| 95 total columns equal: median / mean | 95 / 81.2 | 95 / 81.5 | 95 / **82.7** |
| rows with all 95 equal | 61 | 63 | 63 |
| all 145 equal: mean | 119.2 | 119.4 | **120.6** |
| **overloaded on basic_fix (11 captures, 820,823 packets)** | | | |
| packets in the 40 windows | 192,916 | 820,823 | 820,823 |
| 30 B->A columns equal: mean | 3.4 | 7.5 | **10.0** |
| 95 total columns equal: median / mean | 4 / 10.3 | 41 / 39.1 | **42 / 43.1** |
| all 145 equal: median / mean | 11 / 17.2 | 49 / 46.1 | 47 / **50.1** |
| overloaded / overrun windows | 285 / 17 | 279 / 16 | 283 / 17 |
| **all 109** | | | |
| captures with all their packets in the 40 windows | 100 | 109 | 109 |
| 95 total columns equal: mean | 73.1 | 76.3 | **77.8** |
| all 145 equal: mean | 107.6 | 110.7 | **112.2** |

(bulkup_200/400 are the same on `gtot` and `gtot_ba`: 31.5 of 95 columns, incomplete replays as before.)

**What changed against gtot:**
- **The six floods of part 4f** gain 185 columns between them.
- **91 of the other 103 match the same number of the 95 columns.** 4 match more (bulkdl +3; bulk700, syn_sink_40k,
  goldeneye_r10 +1 each) and 8 fewer (goldeneye_p10 -11, syn_fan_40k -5, dns_10k and slowloris_1000 -4,
  beacon_100 -2; slowloris_800, bulk400, bulk1000 -1), net -23. Their B->A sums are the same on both builds; the
  columns they lose are mostly window maxima and sums. These differences come from the replays, not the build:
  - **goldeneye_p10's replay ran late this time** (95th percentile of the timing error 90 ms, against 1.3 ms on
    `gtot`), which accounts for 11 of the 23 (9 window maxima, a standard deviation, the active windows).
  - **The replay's alignment to the window grid** has a median error of 1.05 ms on both builds, and 15-17 of the
    109 runs land within 0.5 ms. Which captures get such a run differs from run to run, and a millisecond moves
    a few packets across a window boundary.
  - **Late replays:** 10 runs had a 95th percentile above 10 ms on `gtot_ba`, against 6 on `gtot`. All but
    goldeneye_p10 are floods that PC1's Python replayer is known to fall behind on (part 4).
- **Net over all 109: +162 columns** (mean 76.3 -> 77.8 of 95).

**The rows for the thesis:** `replay_rows_gtot_ba.csv` now holds all 109 rows from `runs_gtot_ba/`, one build. It
replaces part 4f's file of the same name (six rows from `gtot_ba`, 103 from `gtot`), which stays in
`pc1_20261116_gtot_ba.tar.xz`.

**Still open:**
- The direction of a packet whose flow shares a bucket: Chaos counts 83,244 B->A packets against the published
  110,866, and the SYN fan-outs' 1-2 replies count as A->B.
- The totals' cut 4-5 ms after the boundary, and later when the collector falls behind on the reports.
- Late replays of the floods (PC1's Python replayer).
- The per-flow columns are still sampled under overload.
- `basic_gtot_ba`'s latency and line rate have not been measured (compiler: the same stages, 133 against 135
  cycles).

**State after:** `basic_fix` running again (pid 31911 in `hz_sw`), ports 132/140, forwarding and mirror set by
`run_bfrt.sh setup` (`setup_basic_fix_restored_4g/`), checked with the first cohort capture (9 / 9 packets, 40 of 40
windows inside the bounds); `enp5s0` down. `live_test/committee_replay/pc1_20261116_gtot_ba_all.tar.xz`: the 103
runs (part 4f's six are in `pc1_20261116_gtot_ba.tar.xz`), `rows.csv` and `rerun.log` of all 109,
`gtot_ba_all_compare.csv`, `replay_rows_gtot_ba.csv`, the scripts, the setup logs.

## Results, part 6 (PC1, 2026-11-16): the exact build, every window feature in the data plane

The user asked for P4 code with no leak and no drop. p4_perf.md section 5.7 has the program, its compile, latency,
line rate and the window clock from the packet generator; this part has the analysis behind it and the replays.

**Where the rows of part 4g still differed from the published ones** (offline, `perf/results/exact_gap_analysis/`):
- A Python 3.8 copy of `features/switch_model.py` on the 110 captures reproduces all 110 published rows.
- **`basic_fix`'s design with ideal reads and ideal cuts** would match all 135 non-duration columns in 89 of the
  110. Two things cost the rest:
  - **Shared buckets** in 4 floods (syn_fan_40k/100k/150k, Chaos).
  - **Ethernet padding** in 21 captures. The dataset counts frames as the guest's capture saw them: 27,813
    received frames padded to 60 B, all toward 10.0.0.10; 40,395 sent 54 B frames unpadded. IPv4 totalLen + 14
    misses the padding, and the wire length would add it to the sent frames too.
- **The parser:** no VLAN tag, IPv4 option or fragment occurs in the dataset, so its differences from the model
  cost nothing here.
- **On the switch, three more causes add to these:**
  - each window's cut lands a few ms after its boundary, later when the collector falls behind;
  - the replay runs late in floods;
  - the reads cover only part of the active buckets under overload.

**The fix: `perf/variants/exact/`.**
- **Windows** are switched by an in-band marker into one of two banks, so every window is cut at one point for
  all registers.
- **Flows** are tracked exactly: 4 ways × 16,384 slots with a 32-bit signature, keyed on the ordered endpoints, and
  direction comes from the first packet's (address, port).
- **All 29 features** are computed per window in the data plane, so a flood can no longer force sampling.
- **`frame_len`** counts the frame minimum toward the guest.
- **The parser** matches the model's.

New code:
- `window_reader.py` reads one window in 51 cells, and `window_features.py` rebuilds the features from them.
- `exact_model.py` is a software model of the program.
- `replay_absolute.py --markers` puts a marker at each of the 41 window boundaries, in order with the frames.
- `live_test/exact_replay.py` drives one run, and `perf/results/exact_replay/scripts/run_exact.py` drives all of
  them.

`tests/test_exact_windows.py` checks the model and `window_features.py` against `switch_model.py` window by window
on random traffic: both directions, padded frames, flows returning after the TTL, swapped port pairings, equal
ports, a flow to itself, and a full table.

**The replays.**
- **Switch:** `basic_fix` stopped, `basic_exact` started in `hz_sw`; ports and forwarding from `run_bfrt.sh setup`
  (`setup_exact/`).
- **Runs:** all 109 captures (`bulkup_700` skipped as in part 4), 07:38–08:27 on PC1's clock, 25 s each, into
  `perf/results/exact_replay/runs/`.
- **Each run:**
  1. reset all registers over gRPC (0.12 s);
  2. install the `frame_len` entry for 10.0.0.10;
  3. follow the window clock on the switch;
  4. replay the capture at its recorded times with the markers, epochs 1–41;
  5. rebuild windows 1–40 and summarize them as the release does.

| | basic_fix | gtot_ba | exact |
|---|---|---|---|
| **calm (96)**: all 135 non-duration columns equal to the published row | 61 | 63 | **96** |
| calm: 95 total-based columns equal (mean) | 81.2 | 82.7 | **95.0** |
| **overloaded on basic_fix (11)**: all 135 equal | 0 | 0 | **6** |
| overloaded: 135 columns equal (mean) | 16.6 | 49.5 | **115.5** |
| bulkup_200/400 (frames over the MTU): 135 columns equal (mean) | 46.5 | 45.5 | 71.0 |
| **all 109**: all 135 equal | 61 | 63 | **102** |
| all 109: 95 total-based columns equal (mean) | 73.1 | 77.8 | **92.8** |

- **No leak:**
  - No window was read after its bank was reused.
  - No packet fell outside the markers: window 0 held none.
  - A window's read took at most 56 ms, of a 500 ms deadline.
- **What is left:**
  - **Five floods with more distinct flows than the 65,536 slots.** Their totals are exact, and their packets
    without a slot are counted and reported per window (net_untracked_pkts):

    | Capture | Packets without a slot | 135 columns equal |
    |---|---|---|
    | Chaos (d538053a) | 1,930 | 71 |
    | syn_fan_40k | 363 | 120 |
    | udp_fan_60k | 98 | 123 |
    | syn_fan_100k | 35,194 | 70 |
    | syn_fan_150k | 83,936 | 77 |

    In Chaos and the 100k/150k fans, the B→A packets of those flows count as A→B. 2^15 slots per way did not
    compile (bf-p4c internal error), and the 100k/150k fans have more distinct flows (99,639, 149,423) than any
    single-stage register on Tofino 1 holds per flow.
  - **bulkup_200/400:** their GSO frames over 1514 B cannot be sent, the replay's limit as in part 4.
  - **Durations** come from the switch's clock: median relative error 4.5·10⁻⁵, at most 17% on short flows.
    The release's notes already treat the switch's durations as information only.
- **The marker method:** the switch is told the capture's window boundaries in band, so these rows test what the
  program computes, independent of the replay's timing.
  - In deployment the packet generator's timer switches the windows; p4_perf 5.7 shows it at 500 ms, 40 ticks in
    20 s.
  - The rows for the thesis could be `perf/results/exact_replay/replay_rows_exact.csv` (the method stated), or
    part 4g's `replay_rows_gtot_ba.csv` (timer-like windows from the replay's timing). The user decides.
- **Not supported by this build:** the socket-level join of the live end-to-end test needs the per-flow counters
  of `basic_fix`, which this build drops. `basic_fix` stays the build for that test.

**Latency, line rate, timer** (p4_perf 5.7):
- **Latency:** median 421 ns against 315 ns for `basic_fix` (+106 ns, 11 ingress stages against 5).
- **Line rate:** the same as `basic_fix` and lossless. The window totals counted all 13.1 billion generated
  packets exactly.
- **Timer:** works (build `basic_exact_timer`).

**Incident:** the first latency attempt found switchd failing to start for every build, `basic_fix` too: "Error
Getting the Board info from BMC". The BMC's REST service (port 8080 over `usb0`) refused connections for about 3
minutes, then came back by itself. The rerun worked (`console_bmc_down.txt`). A second attempt measured nothing
because I passed the root wrapper as a relative path (`failed_relative_asroot/`).

**Disk:** apt's cache had grown back to 362 MB (automatic updates), so `apt-get clean` again: 744 MB free.

**State after:**
- **Switch:** `basic_fix` running again (pid 22204 in `hz_sw`), ports 132/140, forwarding and mirror set by
  `hwl_runs.sh`'s restore (`latency_exact_20261116/setup_basic_fix_restored/`); `enp5s0` down.
- **Check:** the first cohort capture, 9 / 9 packets, 40 of 40 windows inside the bounds
  (`committee_replay/restored_check_exact/`).
- **Archive:** `live_test/committee_replay/pc1_20261116_exact.tar.xz` holds the runs (reads, windows, rows,
  summaries, logs), `exact_compare.csv`, `replay_rows_exact.csv`, the offline analysis, the build records, the
  latency, line rate and timer results, and the scripts.

## Results, part 6b (PC1, 2026-11-16): the exact build hardened, and hybrid_collector.py on it

The user asked for the fixes of the review and for `hybrid_collector.py` to match the P4 code.

**The program** (`perf/variants/exact/`, build `basic_exact_v3`; README.md there):
- **Markers only from configured ports.**
  - The parser takes a window marker only from the ports in the value set `marker_ports`, which the reader
    fills: the CPU port 192 when the collector's reader sends the markers, the replay host's port 132 for an
    in-band replay, none with the timer.
  - A marker from any other port is dropped and counted (`rejected_markers`).
  - **Test:** with `marker_ports` = {192}, five forged markers sent from PC1 through port 132 left the clock
    at 0 and counted 5. A marker from the CPU port showed on the clock 1.6 ms after it was sent.
- **Timer per pipe.**
  - A deployment build (`-DTIMER_LOCAL_PORT=68`) ticks each pipe's clock from that pipe's own generator.
    `basic_exact_v3_timer`: 40 ticks in 20 s, 0.5000 s apart as polled (0.4978-0.5024), no tick counted.
  - The default build has no timer port, so the line-rate generator's ports stay traffic ports.
  - Local port 71, tried first, never ticked: the generator showed no sign of sending from it.
- **Per-pipe clocks in the reader.**
  - A window combines only the pipes whose clock has passed it.
  - The packets of a pipe whose clock lags are reported (`net_unclocked_pkts`), not mixed in.
  - A window whose set of clocked pipes changed is marked lost.
- **The reader race:** a clear of the extremes that ends after the bank's next window started marks that window
  lost.
- **Not changed:** the flow table keeps every flow of a run. Aging in the data plane would let a live flow in a
  later way claim a second slot after an earlier way's slot is freed, so it would need recirculation. The
  README and p4_perf.md section 9 say so.
- **Resources:** same 11 ingress stages, 23 stateful ALUs and 260 cycles; 122 SRAM blocks (+2, the counter).
  Line rate: the same as before and lossless, with the window totals exact for 13.1 billion packets
  (`linerate_exact_v3_20261116/`).

**hybrid_collector.py `--switch-program exact`:**
- `window_reader.py --serve` runs on the switch. It sets the program up (reset, `frame_len`, marker ports) and
  sends or follows the markers.
- `collect_windows_exact()` takes each window's 29 features from `window_features.py`, the code of
  `exact_replay.py`. It adds `net_untracked_pkts`, `net_window_lost`, `net_unclocked_pkts` and
  `net_rejected_markers`.
- There is no CPU report, bucket or read budget in this mode.
- `--sockowner` and `--global-totals` are refused: they need the bucket program.
- **`--window-markers cpu` (live):** the reader sends the markers from the switch's CPU port at the collector's
  window boundaries.
  - **Test:** a plain replay of bulk2000 in 1 s windows. All 24,008 packets counted; 26 of 26 checkable windows
    within the bounds of the packets sent between their markers (on this host's clock, via the reader's
    timestamps). A marker showed on the clock a median 2.8 ms after the reader sent it (max 3.3 ms). No lost
    window, no rejected marker.
- **`--window-markers inband` (replays):** `replay_capture.py --exact` makes `replay_absolute.py` send a marker
  at each collector window boundary, in order with the frames. The reader follows the switch's clock itself and
  reads each window as soon as it ends.
  - **Self-check:** every window must equal the frames the replayer sent between its markers, taken from the
    replayer's own schedule: the capture, less frames over the MTU. tcpdump's send capture is kept as a
    secondary figure, because it dropped 14-26 frames in goldeneye_p10's bursts.

**Two faults found by the collector runs, both fixed:**
- **Lost windows in two floods.** The first run of all 109 (`exact_collector/runs/`) lost 5 windows each in Chaos
  and udp_sink_250k, which cost 2-3 windows' extremes.
  - Cause: the replayer takes up to 1.9 s to load a big capture. It counted itself late only against the first
    frame, so the markers of the 4 empty alignment windows, due earlier, went out in one burst.
  - The reads of those empty windows then cleared a bank's extremes after the dataset's first window had
    started in it. The reader's new check flagged exactly that.
  - Fix: `replay_absolute.py` now measures lateness from the first marker and shifts the whole schedule, so
    there is no burst. The windows are the markers', so the shift changes nothing the switch counts.
- **PC1 lag.** The reader now follows the clock on the switch ("follow") instead of waiting for PC1's
  requests.

**All 109 captures on the final code** (`exact_collector/runs_follow/`; `compare_collector.py`):

| | calm (96) | overloaded on basic_fix (11) | bulkup_200/400 | all 109 |
|---|---|---|---|---|
| windows equal to the frames sent between their markers | 4,224 / 4,224 | 484 / 484 | 88 / 88 | 4,796 / 4,796 |
| packets counted / sent | 618,805 / 618,805 | 820,823 / 820,823 | 30,150 / 30,150 | 1,469,778 / 1,469,778 |
| windows lost | 0 | 0 | 0 | 0 |
| rows equal to part 6's driver row (135 non-duration columns) | 96 | 11 | 2 | **109** |
| rows equal to the published row (135 columns) | 96 | 6 | 0 | **102** |

- **The collector gives the same rows as the standalone driver.** All 109 rows equal part 6's in every
  non-duration column, so the collector matches the P4 code.
- The 7 rows not equal to the published ones are part 6's: the bulk uploads (frames over the MTU) and the
  five floods with more distinct flows than slots (121,521 packets without a slot, counted and reported).
- The thesis rows from this path: `perf/results/exact_collector/replay_rows_exact_collector.csv`.
- **Timing:** 12 of the floods were run first, with both fixes in. The replayer started 0.18-1.9 s late in each
  (loading) and shifted its schedule. The other 97 followed, 11:43-12:47 on PC1's clock, about 36 s each.
- **Before the fixes:** the first run (`exact_collector/runs/`) had 101 rows equal to the published ones, 107
  equal to the driver's, and 16 lost windows.

**Latency** of `basic_hwl_exact_v3`: median 421 ns (420-426 ns, p99 424-425 ns), as part 6's build: 1010 of 1010 reports in each of 3 runs (`perf/results/latency_exact_v3_20261116/`).

**State after:** `basic_fix` running again (pid 16998 in `hz_sw`), restored by `hwl_runs.sh`, checked with the first cohort capture
(9 / 9 packets, 40 of 40 windows inside the bounds; `committee_replay/restored_check_exact_v3/`); `enp5s0` down.
`live_test/committee_replay/pc1_20261116_exact_v3.tar.xz`: the collector runs (final and first; without the send
captures `tx.pcap.gz`, which stay in `perf/results/exact_collector/`), the live test, the build records, line rate,
latency, timer results, the scripts.

## Results, part 6c (PC1, 2026-11-16): a live hybrid run on the exact build

The user asked for the live hybrid test after part 6b. Set-up as section 2b:
- **Switch:** `basic_exact_v3`, forwarding 132 <-> 140.
- **Servers:** `servers.py` on PC2 (192.168.0.2, behind port 140).
- **Programs:** the release's seven network workloads on PC1, each 20 s in the collector's cgroup.
- **Host side:** the real eBPF host monitor (`hostmon_agg`).
- **Collector:** `hybrid_collector.py --profile dataset --switch-program exact --window-markers cpu --frame-min
  192.168.0.1/32`. The reader sends the window markers from the switch's CPU port at the collector's boundaries,
  and `frame_len` counts frames toward PC1 at the frame minimum.
- **Driver:** `perf/results/exact_live/scripts/run_live.sh`, with eth1 captured in both directions;
  `check_live.py` compares.

**Every run:**
- `HOSTMON_HEALTH` all zeros.
- 40 rows, host and network windows aligned.
- No window lost, no untracked or unclocked packet, no rejected marker.
- The programs ran to the 20 s stop or finished early, as in section 2b.
- A marker showed on the switch's clock a median 2.5-2.6 ms after the reader sent it.

**Against the wire:**
- **Small-packet programs** (http_poll, tcp_beacon, interactive): every checkable window, 39 of 39 each, holds
  between the packets and bytes surely and possibly sent between its markers.
- **Bulk programs** (fanout, http_bulk, threaded, mixed): PC1's capture holds TSO/GRO super-frames, up to
  31,124 B of IPv4, where the wire and the switch carry 1,500 B segments, so the capture cannot be the reference.
  Rerun with the offloads off on eth1 (`ethtool -K eth1 tso off gso off gro off`, back on afterwards):
  - 40 of 40 windows within the bounds;
  - packets and bytes over the 40 windows equal to the wire exactly (fanout 190 / 65,700 B, http_bulk 700 /
    662,712 B, threaded 449 / 106,258 B, mixed 452 / 338,340 B).
  - Without receive offload PC1 acknowledges every segment, so these counts are larger than with offloads on.
    The rows below use the runs with offloads on, as on 2026-11-08 (`exact_live/offload_on/`).

**Scored** by the published detectors (the dataset construction's `.venv`, `score.py`;
`exact_live/score_exact_live.txt`):

```
execution          category         host  network  hybrid  in range    (section 2b, basic_fix:  host network hybrid in range)
fanout_exact       benign           0.98     0.11    0.62   80/235                              0.98    0.11   0.62   80
http_poll_exact    network_benign   0.82     0.56    0.69  113/235                              0.82    0.55   0.69  111
http_bulk_exact    network_benign   0.90     0.09    0.46  177/235                              0.91    0.09   0.46  179
tcp_beacon_exact   network_benign   0.90     0.70    0.80  155/235                              0.90    0.70   0.80  155
interactive_exact  network_benign   0.71     0.77    0.77  166/235                              0.71    0.79   0.77  164
threaded_exact     network_benign   0.89     0.12    0.50  182/235                              0.90    0.13   0.51  180
mixed_exact        benign           0.92     0.22    0.54   74/235                              0.92    0.21   0.54   74
```

- Every probability is within 0.02 of section 2b's `basic_fix` rows, and every in-range count within 2.
- These light programs never overloaded `basic_fix`, so both builds give the same rows.
- The features furthest outside the dataset's ranges are those of section 2b: PC1's process start-up, and the
  benign downloads' B->A bytes. The exact build changes nothing on the host side.

**Also fixed:**
- `--frame-min` now replaces the dataset profile's default (10.0.0.10, the dataset's guest) instead of adding to
  it, and the reader replaces the `frame_len` entries on setup instead of keeping old ones.
- The collector's timing log now records the first window's marker too.

**State after:**
- **PC2:** left as found (server stopped; `/tmp/servers.py`, `/tmp/www`, `/tmp/servers.log` removed).
- **Switch:** `basic_fix` running again (pid 20586), ports and forwarding from `setup_basic_fix_restored_6c/`.
- **Check:** the first cohort capture (9 / 9 packets, 40 of 40 windows inside the bounds;
  `committee_replay/restored_check_6c/`); `enp5s0` down.
- **Archive:** `live_test/committee_replay/pc1_20261116_exact_live.tar.xz` holds the runs (CSV, timing,
  collector and host-monitor logs, without the eth1 captures), the rows, the scores and the scripts.

## Results, part 6d (PC1, 2026-11-16): the timer with traffic, and a second pipe

The two paths of the exact build that had not run on the switch: windows from the generator's timer with traffic,
and traffic in a second pipe. Results in `perf/results/exact_timer_traffic_20261116/` (scripts there).

**How the tests run.**
- **One gRPC client per program.** Only one client may bind the program, and an unbound client must name it in
  every request. While `window_reader.py --follow` holds the binding, `sw_window_timer.py` and `sw_pktgen_run.py`
  now work unbound. They have no other changes in behaviour.
- **`sw_window_timer.py --pipes 0,1`** enables the timer app of each pipe's generator, one after the other,
  0.7-1.0 ms apart.
- **`replay_absolute.py --send-log`** writes this host's time just after each frame was sent.
- **Generator traffic in pipe 0:** `sw_pktgen_run.py --pipe 0`, one UDP flow at 0.01% of line rate (14.9 kpps)
  for 9.1 s. The sink port loops each frame back into pipe 0, so pipe 0 counts every packet twice. The count
  to check against is the generator's own figure for the run (`window_delta`).

**1. Timer windows with traffic** (`basic_exact_v3_timer`; timers on both pipes; captures replayed into port
132, pipe 1, with no markers; `run_timer.py`, `analyse.py`):
- **The reader as it was found a fault.**
  - The two pipes' ticks are about 1 ms apart, and the reader read each window as soon as the first pipe had
    ticked. In 15 of 47 windows of slowloris_500 only pipe 0 had ticked, so these windows were marked lost
    (`t1a_before/`).
  - Window 15 was not marked, yet it held 8,589,930,205 packets. A window is the difference of two reads of
    its bank, and that bank had last been read with the other set of pipes.
  - The flow features rebuilt from these windows were wrong too.
- **Fixed in `window_reader.py` and `window_features.py`:**
  - Once the clock has passed window e, the reader waits up to 50 ms (`--pipe-grace-ms`) for every pipe that
    has reached e to pass it. A pipe further behind is not waited for.
  - A window whose bank was last read with another set of pipes is marked lost. After a change of the set,
    that is the next window of each bank.
  - A pipe's unclocked count restarts when it lags again.
  - `net_window_lost` also marks the 3 windows after a lost one, whose flow features are rebuilt from it.
  - 5 new unit tests.
- **With the fix:**

  | Run | Windows | Lost | Pipes combined | Packets switch / sent | Exact windows (27 non-duration features) |
  |---|---|---|---|---|---|
  | slowloris_500 (`t1a/`) | 47 | 0 | both, every window | 11,087 / 11,087 | 47 of 47 (17 with flows) |
  | session_1000 (`t1a_session1000/`) | 35 | 0 | both, every window | 12,000 / 12,000 | 35 of 35 (26 with flows) |

  - **Where the windows cut the stream.** Each window boundary falls between two sent frames: the switch's
    cumulative window counts say which frames, and the send log says when they were sent. One tick every
    0.5000168 s fits all 35 cut points of slowloris_500, with a 77 µs margin, the tightest gap. Every tick is
    where a periodic timer puts it. The fitted period is 15-34 ppm off 0.5 s, the rate difference between
    PC1's clock and the switch's.
  - **Features:** the frames so cut, through the dataset's model (the unit tests' `reference_windows`), give
    the switch's windows exactly. That includes the flows' ageing over the 3-window TTL, as 517 flows fall to
    0 after the first burst.
  - **The ticks themselves:** none counted as traffic; ticks 0.5000 s apart (0.4970-0.5032 as polled); pipe 1's
    ticks as polled at most 3.4 ms after pipe 0's.
- **Traffic in both pipes** (`t1b/`; session_1000 plus the generator in pipe 0):
  - 55 windows, none lost, both pipes combined in every window, no unclocked packet.
  - The windows hold 282,124 packets: the replay's 12,000 plus the 270,124 pipe 0 counted (135,062 generated,
    each counted twice).

**2. A second pipe with markers** (`basic_exact_v3`, slowloris_500 through `exact_replay.py`, markers from port
132; `run_pipe0.py`):
- Pipe 0 had no marker port, so its clock stayed at 0 and only pipe 1 was combined in all 41 reads.
- The generator in pipe 0 sent 135,044 packets, which pipe 0 counted twice: 270,088. The reader reported
  exactly 270,088 as unclocked, in windows 4-22 while the generator ran. None was counted in a window.
- No window lost, no untracked packet. The row equals the published one in all 135 non-duration columns, as in
  part 6.

**The generator in pipe 0.** The first two attempts sent next to nothing (`t2_port69_nosend/`,
`t2_port68_after_stall/`):
- Port 69, enabled while port 68 of that pipe was not a generator port, sent 4 packets.
- After that, pipe 0's generator sent nothing from any port or app: 1 packet, then none, in later tries.
- A switchd restart cleared it.
- The timer runs used port 69 while the timer held port 68, and that works. This is probably also why port 71
  never ticked in part 6b.
- `sw_pktgen_run.py`'s help now says so.

**Not changed:** the P4 code (one comment), the builds, the collector. The collector had no timer mode yet;
part 6e adds it.

**Unit tests:** 206 run, the same single known error (`test_sockjoin`: the release's Python 3.9 dict syntax on
PC1's 3.8); `test_exact_windows.py` has 21 tests (16 before).

**State after:**
- **Switch:** `basic_fix` running again (pid 768), ports and forwarding from `setup_basic_fix_restored/`.
- **Check:** the first cohort capture gave 9 of 9 packets and 40 of 40 windows inside the bounds
  (`exact_timer_traffic_20261116/restored_check/`).
  - The first try counted 0: `basic_fix` reports through the CPU port, and `enp5s0` comes back down after a
    restart.
  - It was brought up for the check and set down again afterwards.
- **Archive:** `live_test/committee_replay/pc1_20261116_exact_timer.tar.xz` holds the runs (reads, send logs,
  timer and generator reports, analyses) and the scripts.

## Results, part 6e (PC1, 2026-11-16): the collector's timer mode

The user asked for the open item of part 6d: `hybrid_collector.py` had no timer mode. Results in
`perf/results/exact_timer_collector_20261116/` (scripts there).

**What was added.**
- **`window_reader.py` starts the timer itself.** The reader owns the program's gRPC binding, so it drives the
  generators itself (`WindowTimer`): timer app 0 of every pipe on local port 68, one pipe after the other.
  - `--serve` command `{"cmd": "timer", ...}`: `prepare` configures the apps (about 20 ms), `enable` starts them
    (about 1 ms per pipe), `stop` stops them. Quit, end of input, SIGTERM and errors stop them too.
  - A setup with reset first stops any timer left running, so no stale tick moves the clock.
  - `--follow --timer-ns NS` does the same without the collector.
- **`hybrid_collector.py --window-markers timer`:**
  - No marker port counts.
  - `start_window_timer()` prepares the timer, then enables it one window before the collector's window 0. The
    first tick (epoch 1) then starts window 0, as the first CPU marker does, and window w is epoch w + 1.
  - The window origin is put far enough ahead for that, in both start paths (the eBPF monitor's cgroup start
    and the plain one).
  - Then the collector reads as with in-band markers: the reader follows the clock.
  - If window 0 never ends, the error asks whether the build has the timer port.
- **Unit test:** the collector loop on the program's model with the timer's ticks gives the model's windows
  (22 tests in `test_exact_windows.py`).

**On the switch** (`basic_exact_v3_timer`; `run_timer_collector.sh`, `check_timer_collector.py`; each replay
with `--send-log`):

| Run | Windows | Lost | Pipes combined | Packets switch / sent | Ticks after the collector's boundaries |
|---|---|---|---|---|---|
| A: bulk2000, `--profile switch`, 1 s, stub host monitor | 27 | 0 | both, every window | 24,008 / 24,008 | 3.1-3.8 ms |
| B: session_1000, `--profile dataset`, 0.5 s, eBPF monitor in its cgroup | 40 | 0 | both, every window | 12,000 / 12,000 | 2.4-3.2 ms |

- **Where the ticks fall:** taken from where the windows cut the sent stream, as in part 6d. One lag and one
  rate fit every cut point. The rates that fit are under 40 ppm, under 1 ms over a run, and a constant lag fits
  too.
- **B, the host side:** `HOSTMON_HEALTH` all zeros, with 41 host windows to 40 network windows as in part 6c's
  runs. No unclocked or untracked packet and no rejected marker in either run.
- **The first version** configured and enabled the generators in one command, and the ticks came 19.1-20.0 ms
  after the boundaries (`A_bulk2000_onestep/`, otherwise the same). The reader spent 17.7 ms configuring them
  before the first enable. Hence the prepare / enable split.
- **The timer stops:** after the collector's run the clock stood still (epoch 41, unchanged 1.5 s later).
  `window_reader.py --follow --timer-ns 500000000 --until-epoch 6` read 6 windows over both pipes, stopped the
  timer, and the clock stood still at 6.

**Limits:**
- The timer runs free on the switch's clock, so the windows drift from the host's by the two clocks' rate
  difference: under 40 ppm here, which would reach about 140 ms in an hour.
- The live hybrid runs keep CPU-port markers, which put every window on the collector's boundary.
- The timer suits a switch with no collector clock, or traffic in pipes the CPU port's markers cannot reach.

**Unit tests:** 207 run, the same single known error (`test_sockjoin`).

**State after:**
- **Switch:** `basic_fix` running again (pid 3158), ports and forwarding from `setup_basic_fix_restored/`.
- **Check:** the first cohort capture gave 9 of 9 packets and 40 of 40 windows inside the bounds
  (`exact_timer_collector_20261116/restored_check/`, with `enp5s0` up for it); `enp5s0` down.
- **Archive:** `live_test/committee_replay/pc1_20261116_exact_timer_collector.tar.xz` (runs, checks, scripts).

## Results, part 9 (PC1, 2026-11-17): basic_gtot_ba measured; the sweep build does not compile

The user pulled `0476a0a` and asked to run part 9. Results in `perf/results/part9_20261117/` (git-ignored); archive
`live_test/committee_replay/pc1_20261117_part9.tar.xz` (compile reports, latency runs, line-rate JSONs, scripts).
- **Done:** 9A (latency and line rate of `basic_gtot_ba`) and 9B's control builds.
- **Stopped at 9B:** the sweep build fails table placement, with and without `-DSWEEP_SHARED_INDEX=1`. 9C-9F need
  that build, so they did not run. Nothing was rerun silently: every compile is listed below.

**9A, latency** (part 4d's `hwl_runs.sh` with `basic_hwl_gtot_ba` in place of `basic_hwl_gtot`: hairpin, 1010 probes,
10 warm-up probes excluded, 3 runs per program, all on the same day; every run 1010 of 1010 reports, none missing or
malformed; `latency/`):

| Program | min | median | mean | p99 | max (ns) |
|---|---|---|---|---|---|
| Baseline | 244 | 246 | 245.62–245.64 | 247 | 247–248 |
| basic_fix | 314 | 315 | 315.36–315.41 | 318–319 | 319–320 |
| basic_gtot_ba | 316 | 317 | 317.02–317.06 | 320–321 | 322 |

- **As expected:** 2 ns over `basic_fix` and 2 ns under `gtot`'s 319 ns (part 4d), the compiler's 133 against 135
  ingress cycles.
- **Same-day controls:** the baseline and `basic_fix` give part 4d's values to the nanosecond.
- **The latency build** (`make_hwl_sources.sh perf/variants/gtot`, compiled with `-DP4_GLOBAL_TOTALS_SPLIT=1`) has
  6/2 stages and 133/172 cycles. The current `perf/variants/gtot` sources are byte for byte those of the switch's
  `basic_gtot_ba` build.

**9A, line rate** (part 4d's 27-run matrix, 10 s each, `--flow-index 44993 --global-totals`; `linerate_gtot_ba/`,
`summarize.py` with one check added: B→A stays 0):

| Frame (B) | Paced, basic_gtot_ba (3 runs) | Paced, basic_fix (31 Oct) | Saturating: offered / sent |
|---|---|---|---|
| 64 | 91.09% / 91.09% / 91.09% (generator maximum) | 91.09% | – |
| 128 | 99.88% / 99.88% / 99.88% | 99.88% | 111% / 100.00% |
| 256 | 99.89% / 99.89% / 99.89% | 99.89% | 128% / 100.00% |
| 512 | 99.87% / 99.87% / 99.87% | 99.87% | 140% / 100.00% |
| 1024 | 99.90% / 99.89% / 99.89% | 99.90% / 99.90% / 99.89% | 148% / 100.00% |
| 1280 | 99.88% / 99.88% / 99.88% | 99.88% / 99.88% / 99.89% | 149% / 100.00% |
| 1518 | 99.88% / 99.89% / 99.88% | 99.88% | 150% / 100.00% |

- **Rates:** the same as `basic_fix` within 0.01 points. Lossless when paced and at 64 B. When saturating, the TM
  dropped exactly the excess.
- **Totals, 0 checks failed in 27 runs (13.1 billion packets):** pipe 1's `pkts_ab` = generated, pipe 0's = looped
  back, `pkts_ba` = `bytes_ba` = 0, the byte totals as the flow's `reg_bytes` (mod 2³²), no TCP flags.
- **The switch's tool:** `sw_pktgen_run.py` there was replaced by `0476a0a`'s, which finds the split registers.
  The old copy is kept as `sw_pktgen_run.py.8ed5ffa`.

**9B, compile** (bf-p4c 9.6.0 on the switch, `sw_compile.sh`; `builds/`, table `builds/resources.md`):

| Build | Flags | Result | Stages ig/eg | SRAM | TCAM | Stateful ALUs | Latency ig/eg (cycles) |
|---|---|---|---|---|---|---|---|
| basic_gtot_ba (16 Nov, reference) | `-DP4_GLOBAL_TOTALS_SPLIT=1` (gtot) | ok | 6/1 | 211 | 3 | 21 | 133/170 |
| basic_sweep_ctrl | `-DP4_ENABLE_SWEEP=0 -DP4_FRAME_LEN=0` | ok | 6/1 | 211 | 3 | 21 | 133/170 |
| basic_sweep_noprobe | `-DP4_ENABLE_SWEEP=0` (`frame_len` only) | ok | 6/1 | 212 | 5 | 21 | 133/170 |
| basic_sweep | – | **failed** (exit 3, 71 s) | | | | | |
| basic_sweep_si | `-DSWEEP_SHARED_INDEX=1` | **failed** (exit 3, 71 s) | | | | | |
| basic_hwl_sweep, basic_hwl_sweep_si | latency builds (9E), with and without the flag | **failed** (exit 3) | | | | | |

- **The control check passes:** `basic_sweep_ctrl` equals `basic_gtot_ba` in every resource of the table, PHV
  included. So the sweep's sources leave the data path alone.
- **`frame_len`** costs 1 SRAM, 2 TCAM and 1 logical table, and no cycles.
- **The error**, the same in all four failed builds:

      error: Table placement cannot make any more progress.  Though some tables have not yet been placed,
      dependency analysis has found that no more tables are placeable.  This may be due to shared attachments on
      partly placed tables; may be able to avoid the problem with @stage on those tables

- **Why** (from `pipe/logs/table_placement_7.log`): 46 tables stay unplaced, the same 46 with and without
  `-DSWEEP_SHARED_INDEX=1`. So the two index sources were not the cause.
  - A register sits in one stage, with every table that uses it. In the probe branch every register gets a second
    table.
  - The partly placed tables are the probe's reads of `reg_g_pkts_ab`, `reg_g_bytes_ab`, `reg_g_pkts_ba`,
    `reg_g_bytes_ba`, `reg_g_syn` and `reg_g_rst`, plus the data path's `reg_pkts` and `reg_ack`.
  - The probe's reads of the totals depend on nothing, so they were placed in stages 2-3. The data path updates
    the packet and byte totals after its direction logic: stage 4 in `basic_gtot_ba`, where those four registers
    take all four stateful ALUs.
  - Placement then cannot go on.
- **Possible fixes (not tried, a P4 change):**
  - Pin each probe read to its register's data-path stage with `@stage`. `basic_gtot_ba`'s placement is in
    `builds/resources.md`.
  - Or give each register one RegisterAction for both paths (update, or read on a probe) on a shared index, so
    no register has a second table.

**Also run:**
- **Unit tests** (`python3 -m unittest discover -s tests`, Python 3.8.10): 238 run, 8 skipped, the one known
  error (`test_sockjoin`: the release's `dict | dict` needs Python 3.9). The new `test_sweep.py` (24) and
  `test_window_timer.py` pass.
- **A slip of mine, no effect on the results:** the first compile batch gave `sw_compile.sh` relative paths, and
  nothing was built. Its empty output directories were removed, and the batch was rerun with absolute paths.

**State after:**
- **Switch:** `basic_fix` running again (pid 9715), ports and forwarding from `setup_basic_fix_restored/`.
- **Check:** the first cohort capture gave 9 of 9 packets (666 of 666 bytes) and 40 of 40 windows inside the
  bounds (`restored_check/`, with `enp5s0` up for it); `enp5s0` down.
- **On the switch:** sources in `/root/hazim_perf/src/{basic_sweep,basic_hwl_gtot_ba,basic_hwl_sweep}`, builds in
  `/root/hazim_perf/build/`, failed ones included.

## Results, part 9b (PC1, 2026-11-17): two fixes for the sweep build; the merged layout compiles and works

The user asked to try both fixes proposed in part 9 and to say which is better. Sources of both in
`perf/results/part9_20261117/fixes/{pinned,merged}/`. Results there (`builds/`, `latency_fixB/`, `linerate_sweepB/`,
`sweep_first_fixB/`, `sweep_generator_fixB/`) and in the archive `live_test/committee_replay/pc1_20261117_part9.tar.xz`
(the `exports.pcap` of Chaos and `syn_fan_40k`, 17 MB, only in `perf/results`). Fix B is now `perf/variants/sweep`.

**Fix A: the probe's reads pinned to the data path's stages (`@stage`). It does not compile.**
- **What changed:** each probe read is its own keyless table, pinned to the stage where `basic_gtot_ba` keeps
  the register (the same with `frame_len`). The data path is untouched.
- **Result:** "Table placement cannot make any more progress", both by default and with `-DSWEEP_SHARED_INDEX=1`.
- **The pins hold:** the totals' reads went to stages 4 and 1.
- **Hash and MAC indexes (default):** the probe's `reg_dir_valid` read is tried in stage 0 and never fits there,
  beside the data path's table for the same register. The data path addresses that stateful ALU by the hash, the
  probe by its MAC.
- **Shared index:** the probe's own write of `meta.ridx` (stage 0) keeps its stage-0 reads (`dir_valid`,
  `first_ts`, `last_ts`) out of stage 0, against their pins.
- **The data path's stages with `meta.ridx`** (`basic_sweep_noprobe_si`) are unchanged: the compiler uses the
  hash for it.

**Fix B: one table per register for both paths ("merged"). It compiles after three corrections.**
- **The layout:** each register has one table, applied once on the path both kinds of packet take. Its key
  (`is_probe`, plus `dir_old`, the TCP flags or the bucket where the data path had conditions) picks the data
  path's RegisterAction, unchanged, or the probe's read.
- **With the sweep off, unchanged:** `-DP4_ENABLE_SWEEP=0` keeps `basic_gtot_ba`'s code word for word, and the
  control build has exactly its resources.
- **The three corrections:**
  1. **Shared index:** with hash and MAC indexes, "Incompatible attached indexing between actions in table
     t_dir_valid_0". A table's actions must index a register the same way, so both use `meta.ridx`.
  2. **One metadata field per value:** the assembler failed with "action bus slice (0..31) can't fit in a single
     slot for 16 bit access". The probe's read of a register the data path also reads (`dir_valid`, the reference
     ports) went to `hdr.sweep`, a 32-bit container, and the data path's to a 16-bit metadata field. Both now land
     in the same metadata field; the probe copies them into its record at the end.
  3. **One if/else:** the two writes of `meta.ridx` sat in two `if`s, which bf-p4c orders and which cost a stage
     (8 stages, 185 cycles). In one if/else: 7 stages, 166 cycles.
- **Stage pins** on the merged tables (safe here: each register has one table) pack them into 6 stages: 158
  cycles.

| Build | Stages ig/eg | Critical path | SRAM | TCAM | Stateful ALUs | Ingress cycles | Median latency |
|---|---|---|---|---|---|---|---|
| basic_gtot_ba | 6/1 | 4 | 211 | 3 | 21 | 133 | 317 ns |
| fix B, pinned (`perf/variants/sweep`) | 6/1 | 5 | 239 | 20 | 22 | 158 | 337 ns |
| fix B, `-DSWEEP_PIN_STAGES=0` | 7/1 | 5 | 239 | 20 | 22 | 166 | 344 ns |

- **Latency:** hairpin, 3 runs per program, every run 1010 of 1010 reports; baseline 246 ns and `basic_gtot_ba`
  317 ns in the same session (`latency_fixB/`).
- **The cost of the shared index:** the data path reaches its first register one stage later (stage 1): +25
  cycles, +20 ns. The exact build costs 421 ns.
- **The final sources:** `perf/variants/sweep` compiled with no flags gives the assembly of the measured pinned
  build, apart from the compiler's generated names.

**Fix B on the switch** (pinned build):
- **Line rate** (the 27-run matrix of part 9A, `linerate_sweepB/`): the same rates as `basic_fix` within 0.01
  points, lossless, 0 checks failed. The totals and the flow's registers are exact for 13.1 billion packets.
- **In-band replays (9C)** (`sweep_replay.py`, `sweep_first_fixB/`): every check passes and the switch's row
  equals the model's in all 135 non-duration columns.

  | Capture | Packets | Probes = exports (switch = model) | Sweeps | Published row (model's prediction) |
  |---|---|---|---|---|
  | first cohort capture | 9 | 50 | 41 | 135 (135) |
  | bulk2000 | 24,000 | 2,078 | 41 | 135 (135) |
  | slowloris_500 | 11,087 | 1,919 | 41 | 135 (135) |
  | syn_fan_40k | 39,847 | 33,662 | 41 | 120 (120) |
  | Chaos | 221,733 | 106,363 | 41 | 67 (67) |

  `slowloris_500` overloads `basic_fix`'s control-plane reader at 0.5 s; here it equals the published row. tcpdump
  dropped nothing (106,363 exports for Chaos).
- **Generator (9D)** (`sweep_generator_check.py`, `sweep_generator_fixB/`): after the stop fix below, 5 runs in a
  row pass every check.
  - **The runs:** 15 whole sweeps each, the generator's counter = the switch's probes = 983,040, the sweeps
    500,000,001 to 500,000,004 ns apart. After the traffic every sweep's 201 records equal the model's.
  - **Speed:** a sweep takes 130.9 ms at 2 µs, 32.8 ms at 0.5 µs, and 0.64 ms at the generator's full rate
    (`--ipg-ns 0`); no export lost at any of them.

**Three tool bugs found and fixed on the way** (pulled code, written without a switch):
- **`sweep_replay.pipe_value`:** the Wedge returns the one-cell counters `sweep_probes` and `sweep_exported` as a
  single value, `[50]`, not per pipe. The probe and export checks then failed (`None`) although the switch's
  counts were right. A single value is now taken as is.
- **`sweep_replay.Capture.stop`:**
  - **The problem:** our ASROOT (`committee_replay/scripts/asroot.sh`) pipes the password into sudo, so a SIGTERM
    reaches only the wrapper, and an exec'd sudo runs as root and may not be signalled. tcpdump kept running (it
    was killed by PID after the first replay) and printed no statistics.
  - **The fix:** `stop()` now sends SIGINT through ASROOT with `pkill -f '^tcpdump .* -w FILE'`.
  - **The first replay:** its capture was complete; it is kept as `sweep_first_fixB/cohort1_before_tool_fix/`
    and was rerun.
- **`sweep_reader.py --generator stop`:**
  - **The problem:** disabling the app in the middle of a 65,536-probe batch lost 3 probes (the generator counted
    976,621, the switch 976,618), and the next start sent nothing (trigger counter 0) until switchd was restarted.
    It happened both times a stop fell in a batch: the 3 runs after the first such stop and the run after the second
    were silent. After a stop between batches the next run was normal.
  - **The fix:** `stop()` waits until the app's packet counter stands still (8-30 ms), then disables it, and
    reports a stop the timer overtook (`idle.moved_after_idle`).
- **Tests:** `tests/test_sweep.py` +3 (27); whole suite 241 run, 8 skipped, the known `test_sockjoin` error.

**Which is better: B.**
- **A does not compile** with bf-p4c 9.6.0, whatever the index. Making it place would mean pinning the data
  path's tables too, which needs B's restructuring plus hard-coded stages for both paths.
- **B compiles without pins**, at 7 stages and 344 ns. The pins only buy back a stage (337 ns), and a wrong pin
  fails at compile time.
- **B ties each probe read to its register by construction,** so a later change to the data path cannot separate
  them again.
- **B's cost** is the shared index: +20 ns over `basic_gtot_ba`, still 84 ns under the exact build.

**Not run yet:** 9E's two line-rate runs with the sweep's generator beside the line-rate app, and 9F (all 107
captures, about an hour).

**State after:** the switch runs `basic_fix` again (pid 19629). The first cohort capture gave 9 of 9 packets and 40
of 40 windows inside the bounds (`restored_check_2/`, with `enp5s0` up for it); `enp5s0` down. Builds on the switch:
`basic_sweep_final`, `basic_hwl_sweep_final`, `basic_sweep_merged_pin` (measured), the failed fix A builds.

## Results, part 9c (PC1, 2026-11-17): the sweep build on the exact build's 109 captures (9F)

The user asked to run the sweep build (`perf/variants/sweep`, the merged layout of part 9b, `basic_sweep_final`)
against the 109 captures of the exact build's part 6, that is all 110 but `bulkup_700`.
- **How:** `live_test/run_sweep_replays.py --include-oversize --only <the 109 ids>`, 53.5 minutes, in-band probes
  ("changed").
- **Results:** `perf/results/part9_20261117/sweep_replays/`: `rows.csv` (the rows, input of `score_switch_replay.py`),
  `runs.csv`, `compare_exact.csv` and `.json` from `compare_sweep_exact.py`. In the archive without the runs'
  `exports.pcap` (55 MB).

**The switch against its model (the program's software model on the same frames and probes):**
- **All 109 runs:** probes sent = the switch's count = the model's, and every export was captured: 475,080 of
  each, tcpdump dropping none. Each run had 41 consecutive sweeps, and in every window the totals equal the
  buckets' sum.
- **107 of 109 runs pass every check, with the row equal to the model's in all 135 non-duration columns.**
- **The other 2 are `bulkup_200` and `bulkup_400`:** eth1 (MTU 1500) refused their GSO super-frames (4,370 of
  14,266 and 8,824 of 29,078), as in part 4. The switch counted exactly the frames sent; the model counts all of
  them.
- **The offline prediction held:** the switch's row equals the row `sweep_offline_check.py` predicted in all 107
  replayable captures.

**Against the published rows, the same 109 captures for every build** (columns equal, of the 135 non-duration
columns; the others from `perf/results/exact_replay/exact_compare.csv`):

| Build | Rows equal in all 135 | Mean of 135 |
|---|---|---|
| sweep (`perf/variants/sweep`, part 9b) | 103 | 131.8 |
| exact (part 6) | 102 | 131.9 |
| basic_gtot_ba (part 4g) | 63 | 110.4 |
| basic_fix | 61 | 105.8 |

The captures below 135 on the sweep or the exact build:

| Capture | sweep | exact | basic_gtot_ba | basic_fix | Exact build's untracked packets |
|---|---|---|---|---|---|
| bulkup_200 | 71 | 71 | 47 | 47 | 0 |
| bulkup_400 | 71 | 71 | 44 | 46 | 0 |
| syn_fan_40k | 120 | 120 | 47 | 8 | 363 |
| syn_fan_100k | 70 | 70 | 33 | 8 | 35,194 |
| syn_fan_150k | 67 | 77 | 33 | 5 | 83,936 |
| udp_fan_60k | 135 | 123 | 84 | 58 | 98 |
| Chaos (d538053) | 67 | 71 | 42 | 32 | 1,930 |

- **Equal everywhere else:** all 102 other captures, every calm one among them, equal the published row in all
  135 columns on both builds.
- **The sweep build is better on `udp_fan_60k`:** 135 against 123. That flood exceeds the exact build's flow
  table (98 untracked packets), while its flows land in separate buckets of the bucket table.
- **The exact build is better on Chaos and `syn_fan_150k`:** 71 against 67 and 77 against 67, where many flows
  share a bucket. The exact build keeps up to 65,536 flows apart and counts the rest as untracked; the bucket table
  merges flows that collide, without saying so.
- **The bulk uploads** are limited by the replay, not the program.
- **Overall a tie:** 103 against 102 rows, 131.8 against 131.9 columns on average. The sweep build takes 6
  ingress stages against 11 and 337 against 421 ns.

**Not run yet:** 9E's two line-rate runs with the sweep's generator beside the line-rate app (run in part 9f).

**State after:** the switch runs `basic_fix` again (pid 29739). The first cohort capture gave 9 of 9 packets and 40
of 40 windows inside the bounds (`restored_check_3/`, with `enp5s0` up for it); `enp5s0` down.

## Results, part 9d (PC1, 2026-11-17): a collision counter in the sweep build

Part 9c showed that the bucket table merges colliding flows without saying so. The build now counts them.
- **The counter:** `reg_coll`, one byte per bucket, saturating at 255.
  - A data packet adds 1 when it matches neither direction of its bucket's reference ports (the direction logic's
    fallback branch), which makes it a second flow in the bucket.
  - A probe reads the count into `sweep_t.coll`, the record's former reserved byte. The probe takes the same fallback
    branch, so the table has one application for both kinds of packet.
  - The table is pinned to stage 3, the first stage with the reference ports in the PHV and a free stateful ALU.
  - Two flows with the same ports and different addresses are not seen, because the bucket keeps no addresses.
- **On the host:** `sweep_features.SweepWindows` adds 4 columns per window:
  - `net_sweep_coll_pkts`: the counts' rise in the window;
  - `net_sweep_coll_saturated`: the buckets at 255;
  - `net_sweep_merged_active`: the active buckets with a count;
  - `net_sweep_merged_buckets`: all buckets with a count so far.

  The software model counts the same, and `sweep_reader.py` clears `reg_coll` with the other registers.
- **Build** (`basic_sweep_coll`; `perf/results/part9_20261117/builds_coll/resources_coll.md`):

| Build | Stages ig/eg | Critical path | SRAM | TCAM | Stateful ALUs | Ingress cycles | Median latency |
|---|---|---|---|---|---|---|---|
| basic_sweep_final (part 9b, no counter) | 6/1 | 5 | 239 | 20 | 22 | 158 | 337 ns |
| basic_sweep_coll | 7/1 | 5 | 245 | 20 | 23 | 164 | 342 ns |
| basic_sweep_coll_ctrl (`-DP4_ENABLE_SWEEP=0 -DP4_FRAME_LEN=0`) | 6/1 | 4 | 211 | 3 | 21 | 133 | (basic_gtot_ba) |

- The control build has exactly `basic_gtot_ba`'s resources, as before.
- **Latency** (`latency_coll/`, hairpin as in part 9, 3 runs per build, 1,010 reports per run, none missing): baseline
  246 ns, `basic_sweep_final` 337 ns, `basic_sweep_coll` 342 ns (p99 346 ns). The counter costs a seventh ingress
  stage, 6 cycles and 5 ns.
- **In-band replays** (`sweep_coll/`): 4 captures, every check of part 9 passing. The collision counts equal the
  model's in every window.

| Capture | Colliding packets | Merged buckets | Windows with merged active buckets | Row vs published (of 135) |
|---|---|---|---|---|
| cohort 0004b57f | 0 | 0 | 0 | 135 |
| bulk2000 | 0 | 0 | 0 | 135 |
| syn_fan_40k | 10,050 | 8,185 | 5 | 120 |
| Chaos (d538053) | 55,245 | 14,899 | 40 | 67 |

- **Generator check** (`sweep_generator_coll/`, `sweep_generator_check.py`, 2 µs): 15 whole sweeps, every record after
  the traffic equal to the model's, all checks passing.
- **Unit test:** `test_collisions_are_counted_and_saturate` (`tests/test_sweep.py`).
- **Line rate** (`linerate_coll/`, the 27-run matrix of p4_perf 3.2 with `--global-totals`, the same script as part
  9b's, `summary.md` from `linerate_coll/summarize.py`): every rate equals the build without the counter to within 0.01
  points (91.09% at 64 B; 99.87-99.89% paced and 100.00% saturating from 128 to 1518 B). There is no loss beyond the
  saturating runs' excess, and all checks pass: the flow's registers and the split totals are exact for 13.1 billion
  packets in both pipes.
- **The 109 captures** (`sweep_replays_coll/`, `run_sweep_replays.py --include-oversize` with part 9c's list, in-band
  probes, 52.9 minutes; `runs.csv` now has the collision columns):
  - **The same as without the counter:** 103 of 109 rows equal to the published row in all 135 non-duration columns,
    mean 131.8. Every one of the 109 captures has the same score as on `basic_sweep_final` (part 9c).
  - **Against the model:** 107 of 109 equal in all 135 columns, the collision counts included. The other 2 are again
    `bulkup_200` and `bulkup_400`, whose GSO super-frames eth1's MTU refuses. Probes = exports = 475,080, none lost.
  - **The counter flags exactly the floods that are not exact.** 4 captures have collisions, and they are the 4 whose
    rows the bucket table cannot make equal to the published row:

| Capture | Colliding packets | Merged buckets | Windows with merged active buckets (of 40) | Row vs published (of 135) |
|---|---|---|---|---|
| syn_fan_150k | 90,599 | 43,388 | 16 | 67 |
| Chaos (d538053) | 55,245 | 14,899 | 40 | 67 |
| syn_fan_100k | 48,461 | 29,463 | 8 | 70 |
| syn_fan_40k | 10,050 | 8,185 | 5 | 120 |

  - The other 105 captures have no collision. All of them equal the published row except the 2 bulk uploads, which
    the replay limits. `udp_fan_60k`'s flows land in separate buckets, so its row is exact and the counter shows 0.

## Results, part 9e (PC1, 2026-11-17): how fast PC1 takes the exports

The generator sweeps all 65,536 buckets each window, and every used bucket comes back as a 104-byte record. These
runs measure how fast PC1's eth1 takes them.
- **How:** `live_test/sweep_generator_check.py --flows N --ipg-ns GAP` on `basic_sweep_coll` (part 9d), with the
  exports written to `/dev/shm` (the disk was full). Lost = exports the switch counted minus records captured. The NIC's
  `rx_out_of_buffer` and `rx_discards_phy` were read before and after each run (`nic_counters.txt`).
- **Results:** `perf/results/part9_20261117/sweep_export_rate/`; the 10 runs' `exports.pcap` are in
  `exports_pcaps.tar.xz` there (14 MB).

| Flows (used buckets) | Gap (a sweep) | eth1 ring 1,024 (default): lost / exported | ring 8,192: lost / exported |
|---|---|---|---|
| 30,000 (17,788) | 2 µs (131 ms) | 251 / 193,009 | 0 / 190,706 |
| 30,000 (17,788) | 1 µs (66 ms) | 3,015 / 191,901 | 0 / 175,497 |
| 30,000 (17,788) | 0.5 µs (33 ms) | 3,406 / 174,251 | 0 / 173,857 |
| 30,000 (17,788) | 0, the generator's rate (0.64 ms) | 155,224 / 173,406 | 81,942 / 175,218 |
| 60,000 (19,720) | 2 µs (131 ms) | 320 / 275,738 | 0 / 275,666 |

- **The losses are PC1's NIC, not the switch or tcpdump.** tcpdump dropped none in any run. Where the counters were
  read, the loss equals the rise of `rx_out_of_buffer`: 3,406 at 0.5 µs, 320 at 60,000 flows. At the generator's full
  rate `rx_discards_phy` rose too (23,677 and 31,671).
- **With 8,192 receive descriptors** (`ethtool -G eth1 rx 8192`, the NIC's maximum) **no export was lost down to a
  0.5 µs gap.** At the generator's full rate about half is lost either way.
- The ring was set back to 1,024 after the runs.

## Results, part 9f (PC1, 2026-11-17): line rate beside the sweep's generator (9E)

**First attempt (`linerate_9e_wedged_port69_alone/`):** the line-rate app ran alone on local port 69, before the sweep
held port 68. The generator sent 2 packets, and pipe 1's generator then sent nothing from any port, the sweep's
included, until switchd was restarted. This is part 6d's rule: a port other than 68 sends only while 68 of the same
pipe is a generator port. The runs below put the line-rate app alone on port 68.

**Form 1: both apps on pipe 1's generator (`linerate_9e/`).** The sweep runs on local port 68 (65,536 probes, 2 µs apart,
every 0.5 s) and the line-rate app on port 69 (`--first-local-port 69 --buffer-offset 4096`), 10 s per run.

| Frame | Alone (port 68) | Beside the sweep (port 69) | 1 − 131 ms / 500 ms of the alone rate |
|---|---|---|---|
| 1518 B, paced at 100% | 99.99% | 73.88% | 73.78% |
| 64 B, the generator's maximum | 91.09% | 67.26% | 67.21% |

- **The generator serves one app at a time.** While the sweep's batch runs (131 ms of every 500 ms), the line-rate app
  sends nothing. This is the generator's limit, not a data-plane cost.
- Every generated packet was counted (the flow's `reg_pkts` and the totals equal the generated packets in both pipes),
  with no drop at the traffic manager.
- 54 sweeps, 108 exports (bucket 0 and the flow's bucket), all 108 captured on PC1.

**Form 2: line rate from pipe 0 into the swept pipe (`linerate_9e2/`).** Pipe 0's generator sends the line-rate flow
(`--pipe 0`) to the sink dev_port 148 (port 3/0, pipe 1, MAC near loopback), so the traffic enters pipe 1, where pipe 1's
generator sweeps the same registers.

| Frame | Alone | With the sweep in pipe 1 |
|---|---|---|
| 1518 B, paced at 100% | 99.99% (89,985,885 packets) | 99.99% (89,894,607) |
| 64 B, the generator's maximum | 91.09% (1,500,971,008) | 91.09% (1,499,725,824) |

- **The sweep costs the line rate nothing.** No drop at the traffic manager. The flow's `reg_pkts` and the totals grew by
  exactly the generated packets in both pipes.
- 55 sweeps, 110 exports, all 110 captured on PC1, tcpdump dropping none.
- The generator stopped between two sweeps (its counter 3,604,480 = 55 × 65,536). Cleanup removed the sink port and
  the forwarding entries.

## Results, part 9g (PC1, 2026-11-17): hybrid_collector.py --switch-program sweep

The user asked for `hybrid_collector.py` to fit the sweep build.

**The collector** (`hybrid_collector.py`):
- **The reader:** `sweep_reader.py --serve` runs on the switch. It sets the program up (reset, `frame_len`, probe
  and export ports) and drives the generator: prepare, enable, and a stop between two sweeps.
- **`--sweep-probes generator`** (the deployment): the generator is enabled one period before the collector's window 0,
  so its first sweep falls on window 0's start. Measured: the sweeps arrived 1.1–2.6 ms after the collector's
  boundaries over the 46 windows of a run.
- **`--sweep-probes inband`** (replays): the scenario sends the probes with its frames.
- **The windows:** `collect_windows_sweep()` turns each pair of consecutive sweeps into a window with
  `sweep_features.SweepWindows`, the code of `sweep_replay.py`. Each window adds `net_sweep_totals_mismatch`,
  `net_sweep_coll_pkts`, `net_sweep_coll_saturated`, `net_sweep_merged_active`, `net_sweep_merged_buckets`,
  `net_sweep_buckets` and `net_sweep_span_us`.
- There is no CPU report and no register read in this mode. `--sockowner`, `--global-totals` and `--scope-ip` are
  refused.

**The replay driver:** `live_test/replay_capture.py --sweep inband|generator` sends one capture through the collector.
It compares every window with the program's software model on the same frames, with in-band probes and perfect cuts,
and compares the dataset row with the model's and the published one. `live_test/run_sweep_collector.py` runs a list
of captures through it. The dataset's window 0 is the collector's window 6, so that the replayer has loaded a flood
before its first frame is due.

**In-band probes** (`sweep_collector_inband/`, the 4 captures of part 9d):

| Capture | Windows equal to the model (27 non-duration features) | Packets, collector / model | Colliding packets, collector / model | Row vs published (of 135) |
|---|---|---|---|---|
| cohort 0004b57f | 46 / 46 | 9 / 9 | 0 / 0 | 135 |
| bulk2000 | 46 / 46 | 24,000 / 24,000 | 0 / 0 | 135 |
| syn_fan_40k | 46 / 46 | 39,847 / 39,847 | 10,050 / 10,050 | 120 |
| Chaos (d538053) | 46 / 46 | 221,733 / 221,733 | 55,245 / 55,245 | 67 |

- **Every window equals the model's**, and the rows equal those of `sweep_replay.py` (part 9c): through the collector,
  in-band, the sweep build gives the same rows.
- **Fix 1: a late in-band start.** Chaos first failed: "sweep 1: no export within 5.0 s". The replayer plans Chaos's
  106,363 probes before it starts, so it began 5.95 s late and shifted its whole schedule. The collector now waits up
  to 120 s for the first in-band sweep, then awaits each later one from its boundary plus that shift
  (`inband_shift_s` in the timing file).

**Generator probes** (0.5 µs gap, eth1's ring at 8,192, set back to 1,024 after):
- **Fix 2: the capture.** With an AF_PACKET socket read by a Python thread (`sweep_collector_gen500_socket/`), the two
  floods failed. In `syn_fan_40k` the records came in later each window from window 12 on (0.16 s, then up to 4.9 s
  late). From window 17 the socket dropped them (129,000 by window 21), until a whole sweep was missing. PC1 has 2
  cores and was replaying the flood at the same time. The collector now has tcpdump write the records into a file in
  `/dev/shm` and parses it behind (`--sweep-capture tcpdump`, the default). With it (`sweep_collector_gen500_tcpdump_v1/`)
  both floods completed: Chaos gave 46 windows from 1,636,958 records, tcpdump dropping none, and `syn_fan_40k` counted
  all 39,847 packets, its collisions equal to the model's.
- **Fix 3: when a sweep is complete.** In that run `bulk2000` counted 23,388 of 24,000 packets. tcpdump handed the
  records over in blocks up to 1 s late, and the collector judged a sweep complete by the records' own arrival
  timestamps, so it closed sweeps that tcpdump still held part of. Now tcpdump runs with `--immediate-mode`. A sweep is
  complete once a later one has begun, or once the file is read to its end and no record of the sweep has come in for
  0.25 s of this host's time.
- **After the fixes** (`sweep_collector_gen500/`):

| Capture | Windows equal to the model | Packets, collector / model | Row vs published (the model's in-band row: 135) |
|---|---|---|---|
| cohort 0004b57f | 44 / 46 | 9 / 9 | 91 |
| bulk2000 | 6 / 46 | 24,000 / 24,000 | 44 |

- **PC1 hung during `syn_fan_40k`.** The last kernel message, at 13:05:41, is the export capture starting. The journal
  then stalls, with entries written up to a minute late, and ends at 13:09:32 without a shutdown. PC1 came back at
  13:10:30 after a reset. Nothing logged an out-of-memory kill or a panic. PC1 has 2 cores, 3.9 GB and no swap, and was
  replaying the flood while taking the exports' bursts. The floods were not run again in this mode.
- **PC1's NIC drops exports under a flood** even with 8,192 descriptors: 80,443 during `syn_fan_40k` and 27,812 during
  Chaos (`tcpdump_v1`). A lost record leaves its bucket's last one in place, so that bucket's packets count in a later
  window and no packet is lost over the run.
- **Why generator mode loses parity: the cut.** Bucket *i* is read at its boundary + 1.1–2.6 ms + *i* × 0.5 µs, over
  33 ms. A packet in that time counts in the window before for every bucket probed after it. The dataset's captures
  begin a few ms after their anchor, so their first packets are exactly such packets. In `bulk2000`'s continuous
  traffic, the cut of almost every window differs from the perfect cut, while every packet is still counted.
- **So the 103 of 109 (part 9c) holds with in-band probes, not with the generator.** The exact build's timer mode
  (part 6e) cuts in one instant, 2.4–3.8 ms after the collector's boundaries, but its rows have not been scored on the
  109 captures either.

**Tests:** `thesis-hybrid-ebpf-p4/python/tests/test_sweep.py`, 36 tests, all pass. They cover the collector's
generator and in-band windows against the sweeps', a late in-band start, tcpdump's file read as it grows with a record
split across two writes, a missing sweep, the summary columns, and the options refused. In the full suite (248 tests)
one test fails as before: `test_sockjoin` runs the release's `switch_model.py`, which needs Python 3.9 (PC1 has 3.8).

**Results of parts 9d-9g** are in `perf/results/part9_20261117/` and, without the captures' pcaps, in the archive
`live_test/committee_replay/pc1_20261117_part9d.tar.xz`.

**State after:** the switch runs `basic_sweep_coll` with the generator stopped; eth1's ring is at 1,024.

## Part 10 (proposed, 2026-11-17): the socket join on the sweep build, live

*Why. The sweep build exports its buckets without addresses, and its collector takes no CPU report, so part 9g
refused `--sockowner` with `--switch-program sweep`. The collector now names a bucket's flow from this host's own
sockets: the local 5-tuple that the switch hashes to the bucket (`flow_index.py`) and that has the bucket's
reference ports. A 5-tuple with other ports in the same bucket is a second flow merged into it (the collision
counter counts its packets), so the bucket stays with its first flow; a loopback 5-tuple that happens to hash onto
a used bucket almost never has its ports, so it owns nothing. The owner is taken at the bucket's own cut (the
record's switch time after the sweep's first record), which matters only when a 5-tuple is reused by another
socket. Code: `hybrid_collector.sweep_socket_join`, `sockjoin.BucketOwners`; `SweepWindows.add(select=...)`
computes the features of the owned buckets from the records the collector keeps (only those that changed). Tests
on the program's model (`tests/test_sweep_sockjoin.py`, 11): two programs through one switch each get exactly the
windows of their own traffic; a selector that owns everything gives the window rows; a merged flow, a loopback
5-tuple on a used bucket, a reused 5-tuple and the generator's per-bucket cut. Not yet run on the switch.*

**New:** `--socket-join-also CGROUP_DIR` (repeatable) writes the socket join of another existing cgroup from the same
windows (network columns only) to `OUT.socket.NAME.csv`; `live_test/check_sweep_sockjoin.py` checks, per window,
that the joins add up to the window rows (packets, bytes, flags, flow counts), and with no `--also` that the socket
rows equal the window rows in all 29 features.

**Set-up:** the switch on `basic_sweep_coll` (state after 9g), `servers.py` on PC2 as in section 2b, `sockowner`
built as in part 5, eth1's receive ring raised for the exports and the 0.5 µs gap of 9g's collector runs (part 9e):

```sh
REL=$(realpath ../p4-ebpf-malware-detection); OUT=perf/results/sweep_sockjoin; mkdir -p $OUT
sudo ethtool -G eth1 rx 8192                       # back to 1024 at the end
S="$C --switch-program sweep --sweep-probes generator --sweep-ipg-ns 500 \
    --sweep-export-port 132 --sweep-export-iface eth1 --frame-min 192.168.0.1/32 \
    --hostmon ebpf_perf/build/hostmon_agg --hostmon-cgroup /sys/fs/cgroup/unified/hazim_collect \
    --sockowner ebpf_perf/sockowner/build/sockowner --sockowner-attach /sys/fs/cgroup/unified"
```

**10A, the program alone** (expected: the socket rows equal the window rows in all 40 windows, the owned buckets are
the program's connections, no shared bucket and no hidden flow):

```sh
$S --scenario-name sj_alone --label benign --sockowner-log $OUT/alone.sockowner.log \
   --command "python3 $REL/validation/hybrid/workloads.py http_poll --server 192.168.0.2" \
   --out-csv $OUT/alone.csv --reader-timing-file $OUT/alone.timing.jsonl
python3 live_test/check_sweep_sockjoin.py --window $OUT/alone.csv --socket $OUT/alone.socket.csv \
   --json $OUT/alone.check.json
```

A remainder here is TCP or UDP of another process on eth1 during the run: its 5-tuples are the `FLOW` lines of
`alone.sockowner.log` whose cgroup id is not the collector's.

**10B, beside a background program in its own cgroup** (expected: in every window the two joins add up to the
window rows, remainder 0):

```sh
sudo mkdir -p /sys/fs/cgroup/unified/hazim_bg
sudo sh -c "echo \$\$ > /sys/fs/cgroup/unified/hazim_bg/cgroup.procs; exec runuser -u $USER -- sh -c \
  'while true; do python3 $REL/validation/hybrid/workloads.py tcp_beacon --server 192.168.0.2; done'" &
sleep 3
$S --scenario-name sj_beside --label benign --sockowner-log $OUT/beside.sockowner.log \
   --command "python3 $REL/validation/hybrid/workloads.py http_bulk --server 192.168.0.2" \
   --socket-join-also /sys/fs/cgroup/unified/hazim_bg \
   --out-csv $OUT/beside.csv --reader-timing-file $OUT/beside.timing.jsonl
sudo sh -c 'echo 1 > /sys/fs/cgroup/unified/hazim_bg/cgroup.kill'; sleep 1; sudo rmdir /sys/fs/cgroup/unified/hazim_bg
python3 live_test/check_sweep_sockjoin.py --window $OUT/beside.csv --socket $OUT/beside.socket.csv \
   --also $OUT/beside.socket.hazim_bg.csv --json $OUT/beside.check.json
sudo ethtool -G eth1 rx 1024
```

**What comes back:** the CSVs, the two `*.check.json`, both `*.sockowner.log` (with their `SOCKOWNER_HEALTH` line,
which must be `0,0,0`), the timing logs and the collector's console, including its line `socket-level join (sweep
build): cgroup ..., N owned buckets, ...`. Also note the generator's sweep timing (`lag_s` in the timing log). The
join attributes a name lookup sent through the host's local resolver to the resolver, as before; `workloads.py`
connects to the server's address directly.

## Part 11 (proposed, 2026-11-19): the exact build with a block rule, `perf/variants/exact_block`

*Why. The user chose the exact build for the architecture and asked for a rule that, when a program is flagged
malicious, the switch stops forwarding its flows. `perf/variants/exact_block` is the exact build plus one ternary
table, `block_rules` (ingress port and 5-tuple), looked up for every IPv4 packet after `forwarding.apply()`; a match
is dropped at the end of ingress, after the window registers have counted it (`README.md` there). 7 of the 8 files
are the exact build's, and `ingress.p4` only has lines inserted. The control plane: `window_reader.py` gains a
`block` command (add, del, clear, list) and `--block-add/--block-del/--block-clear/--block-list`; a reset also clears
the table. The loop: `hybrid_collector.py --block-on-alarm` scores the run after every window with
`live_test/streaming/stream_verdicts.py`'s detectors and, at the first window over `--block-threshold`, blocks the
flagged program's flows (both directions, named by `--sockowner`, and the flows it opens later) and, when a window
has more than 500 active flows, its host (`block_policy.py`). Tests without a switch (`tests/test_exact_block.py`,
25): the program's sources, the reader's command on a fake BF Runtime client, the policy, and the whole loop on
`exact_model.py` (after the alarm the program's packets are dropped and still counted; another program's flow
passes). Not compiled yet. Part 7's drop rule (for `basic_fix`) is replaced by this part.*

**11A. Compile.** Copy `perf/variants/exact_block` to the switch as the other variants, then:

      perf/tools/sw_compile.sh SRC/exact_block basic.p4 BUILD/basic_exact_block
      perf/tools/sw_compile.sh SRC/exact_block basic.p4 BUILD/basic_exact_block_timer -DTIMER_LOCAL_PORT=68
      perf/variants/hwl/make_hwl_exact.sh SRC/exact_block OUT_DIR
      perf/tools/sw_compile.sh OUT_DIR/basic_hwl_exact basic.p4 BUILD/basic_hwl_exact_block

- Record, as in p4_perf section 5.7's table, ingress/egress stages, SRAM, map RAM, TCAM, stateful ALUs, the critical
  path and the latency cycles, next to `basic_exact_v3` (11/1 stages, SRAM 122 = 12.7%, map RAM 119 = 20.7%, TCAM 7
  = 2.4%, 23 ALUs, 260 cycles).
- **Expected:** TCAM +6 blocks (a 113-bit key is 3 blocks wide, 1,024 entries 2 deep), no new ALU, the same stages if
  bf-p4c places the table in an early stage (it depends only on the headers and on the forwarding table).
- If it does not fit in 12 ingress stages or bf-p4c refuses the direct counter: `-DBLOCK_DIRECT_COUNTER=0`, then
  `-DBLOCK_ENTRIES=512` (then give the collector `--block-entries 512`), and say which. Any other failure: stop and
  report the message.

**11B. The windows are unchanged.** With no entry the program computes exactly the exact build's windows. Replay
the 5 captures of part 9C through `basic_exact_block` as in part 6b (`exact_replay.py`) and compare the rows with
`basic_exact_v3`'s rows of the same captures (part 6b's `perf/results/exact_replay/`): expected identical in all 145
columns. If time allows, all 109 (`run_exact.py`).

**11C. Latency and line rate.** `basic_hwl_exact_block` as `basic_hwl_exact_v3` in part 6b (3 x 1010 hairpin
probes, the baseline the same day): expected near 421 ns if the stage count is unchanged. Line rate: p4_perf section
3.2's 27-run matrix with the table empty, then the 1518 B and 64 B paced runs again with 1,024 entries installed that
match nothing (a lookup that misses must cost nothing extra), e.g.:

      for i in $(seq 0 1023); do echo "--block-add src=203.0.$((i/256)).$((i%256)),dport=9"; done | \
          xargs python2.7 window_reader.py      # on the switch, under the SDE environment
      python2.7 window_reader.py --block-list | python3 -c 'import json,sys; print(len(json.load(sys.stdin)["entries"]))'

  and `--block-clear` afterwards.

**11D. The block function, by hand, on a replay.** One cohort capture with the replayed host's packets in both
directions (the first of part 9C), replayed into port 132 with in-band markers, a capture on PC2 behind port 140:

      python3 live_test/replay_capture.py CAPTURE --exact --profile dataset --out perf/results/exact_block/11d \
          -- --block-on-alarm --block-detector network --block-host 10.0.0.10 --block-force-alarm-window 10

- The alarm is forced at window 10, and there is no `--sockowner` in a replay, so the reader blocks the host:
  `src=10.0.0.10`.
- **Expected:**
  - PC2 receives every frame of the capture sent before the block was written (`t_reply` of the `block` record in
    `OUT.block.jsonl`), and after it none from 10.0.0.10, while the frames toward 10.0.0.10 keep arriving.
  - The summary's `blocked_pkts` equals the frames from 10.0.0.10 that the replayer sent after that time
    (`replay_absolute.py`'s send log).
  - The 40 rows are equal to 11B's rows of the same capture: the blocked packets are still counted.
- Then the same with `--block-host-port 132` added: after the block, nothing from port 132 reaches PC2.
- Note the reader's write time (`write_ms`) and the time from the alarm's row to `t_reply`.
- One check by hand, while a replay runs: `window_reader.py --block-add src=10.0.0.10` from a second shell. The
  collector's reader owns the program, so this client runs unbound; record whether BF Runtime accepts the write.

**11E. Time to containment, real verdicts on replays** (Part 7 step 3, now on the exact build). Each capture with its
own group held out (`cv_group` in `live_test/captures/cohort/manifest.csv` or the cohort-extra manifest):

      python3 live_test/replay_capture.py CAPTURE --exact --profile dataset --out perf/results/exact_block/11e/NAME \
          -- --block-on-alarm --block-detector network --block-host 10.0.0.10 --block-hold-out-group CV_GROUP

- **Attacks:** `udp_sink_60k`, `syn_sink_40k`, `syn_fan_40k` and a GoldenEye run.
- **Benign:** `bulk2000`, `session_1000`, `dns_10k`: is any blocked, and when?
- **Per run:**
  - the first attack packet sent;
  - the alarm's window and time;
  - `t_request` and `t_reply` of each block;
  - the last frame from 10.0.0.10 that reached PC2;
  - the share of the run's frames from 10.0.0.10 that the switch dropped (`blocked_pkts` against the send log).

**11F. Live, with the host monitor and the socket tracer** (part 10's set-up on `basic_exact_block`, `servers.py` on
PC2). Rebuild the monitor first (`ebpf_perf/build.sh`): since 2026-11-19 `hostmon_agg` ends each window with
`HOSTMON_WINDOW_DONE,<window>` (the kernel program is unchanged), and the collector then writes a row, and scores it,
about 50 ms after its window ends instead of about 1 s later; check that the monitor's log has those lines. Only
benign programs run on PC1, so the alarm is forced. The collector runs under the interpreter that has NumPy and
scikit-learn (the dataset repository's `.venv`, as for part 2's scoring: PC1 has no room for its own venv); its own
modules need only the standard library. That venv has scikit-learn 1.9.1, so the stacked detector's inner folds, and
its probabilities, differ a little from the published ones (they need older than 1.8); the forced alarm does not
depend on them.

      PY=../p4_ebpf-dataset-construction/.venv/bin/python3   # NumPy and scikit-learn for the detectors (part 2's score.py)
      E="sudo $PY hybrid_collector.py --profile exact --mode command --switch-ssh root@172.168.1.2 \
          --forward-int-port 132 --forward-ext-port 140 --cpu-iface enp5s0 --frame-min 192.168.0.1/32 \
          --p4-forwarder thesis-hybrid-ebpf-p4/python/program_forwarding.py --windows 40 \
          --hostmon ebpf_perf/build/hostmon_agg --hostmon-cgroup /sys/fs/cgroup/unified/hazim_collect \
          --sockowner ebpf_perf/sockowner/build/sockowner --sockowner-attach /sys/fs/cgroup/unified \
          --block-on-alarm --block-force-alarm-window 8"
      $E --scenario-name blk_poll --label benign --sockowner-log $OUT/poll.sockowner.log \
         --command "python3 $REL/validation/hybrid/workloads.py http_poll --server 192.168.0.2" --out-csv $OUT/poll.csv

- Run it beside part 10B's background `tcp_beacon` in `hazim_bg`.
- **Expected:**
  - The block log has `flows` at the alarm and `new_flows` in later windows: `http_poll` opens a new connection
    every poll.
  - PC2's capture has the program's connections up to the window after each one starts, and none of them later.
    The background program's connections keep arriving throughout.
  - `HOSTMON_HEALTH` all zeros, 40 rows.
  - Each `score` record of the block log is written within about 0.1 s after its window ends (its `time` against
    the run's start plus (window + 1) x 0.5 s).
- Then the same without `--block-force-alarm-window`, with each of the seven workloads of section 2b. The detectors
  were trained on the dataset's rows, and part 2-3's live benign rows scored high, so record each false alarm and
  block. That is the false-alarm cost of the rule as it stands.

**What comes back.**
- 11A's resource table.
- 11B's comparison.
- 11C's latencies and rates.
- For 11D-11F, per run: `OUT.block.jsonl`, the rows, PC2's capture counts and the summary.

## Results, part 11 (PC1, 2026-11-19): the exact build with a block rule

The user asked to run part 11 (28fde45), and during the run pulled 50ef77e (host rows as soon as the monitor prints
a window; 11F's updated steps), which is included below. The switch ran `basic_exact_block` from 11A on. Files:
`perf/results/part11_20261119/` (git-ignored) and the archive `live_test/committee_replay/pc1_20261119_part11.tar.xz`
(everything but the captures and send logs; the scripts in `src/`).

**Set-up:**
- **Disk:** PC1 had 37 MB free at the start. Part 9's captures were compressed with xz in place (310 to 122 MB),
  and this run's captures after each step.
- **Detectors:** the collector ran under the dataset construction's `.venv` (Python 3.11, NumPy 2.4.6, scikit-learn
  1.9.1), as 50ef77e's 11F now says; `/usr/bin/python3` has no scikit-learn. The workloads still ran on
  `/usr/bin/python3`. scikit-learn 1.9.1 shuffles `StratifiedGroupKFold` differently (part 3), so the stacked
  detector of 11F is a little different from the published one; the network detector (11D, 11E) has no inner folds.
- **Unit tests:** under the `.venv` 297 OK, 8 skipped (296 of 50ef77e and one added here). Under `/usr/bin/python3`
  the one known error of part 4 (the release's `switch_model.py` needs Python 3.9).
- **PC2 cannot capture:** its `dumpcap` is `root:wireshark` 0754 and sudo asks for a password, so there is no
  capture on PC2.
  - **Replays (11D, 11E):** the switch forwarded 132 -> 132, and `tcpdump -Q in` on eth1 recorded what the switch
    let through. The block acts at ingress, so the egress port does not change what it drops.
  - **Live (11F):** a copy of `servers.py` on PC2 that logs every accepted connection, HTTP request and echo
    session with PC2's clock (`src/servers_log.py`; same files, ports and replies). Measured through it, PC2's clock
    was 10.0 ms ahead of PC1's before the runs and 12.2 ms after.

**11A. Compile.**
- **The direct counter is refused.** The build as written fails, as do the timer and latency builds:
  `table Ingress.block_rules: There are issues with the following indirect externs: The action block_drop uses Counter
  Ingress.blocked_pkts but does not use DirectCounter Ingress.block_hits. The Tofino architecture requires all
  indirect externs to be addressed with the same expression across all actions they are used in.`
- **The plan's fallback `-DBLOCK_DIRECT_COUNTER=0` compiles** (`basic_exact_block`, `_timer`, `basic_hwl_exact_block`),
  so `--block-list` gives no per-entry drops, and `blocked_pkts` still counts them all.
- **It takes all 12 ingress stages, not 11.** `forwarding` and `block_drop` both write `drop_ctl` (an output
  dependency), so `block_rules` goes to stage 1. The `is_flow` gateway that follows it in control order
  (`ANTI_NEXT_TABLE_DATA`) then moves `prep`, `set_sig`, `frame_len` and the whole flow-table chain down one stage.
- **Two placements as a side check** (compiled only, not run on traffic; sources in `src/alt/`):
  - **alt1:** `blocked_pkts` counted on `block_rules.apply().hit` outside the action. bf-p4c accepts the direct
    counter.
  - **alt2:** alt1, with the lookup also moved to the end of the data path. It gives the exact build's 11 stages and
    260 cycles back.

| Build | Stages ig/eg | Critical path | SRAM | Map RAM | TCAM | Stateful ALUs | Ingress cycles | Power ig (bf-p4c) |
|---|---|---|---|---|---|---|---|---|
| basic_exact_v3 | 11/1 | 9 | 122 (12.7%) | 119 (20.7%) | 7 (2.4%) | 23 | 260 | 0.56 W |
| basic_exact_block (`-DBLOCK_DIRECT_COUNTER=0`) | 12/1 | 10 | 125 (13.0%) | 121 (21.0%) | 13 (4.5%) | 23 | 279 | 0.52 W |
| basic_exact_block_timer (`-DTIMER_LOCAL_PORT=68`) | 12/1 | 10 | 125 | 121 | 13 | 23 | 279 | 0.52 W |
| alt1 (direct counter kept) | 12/1 | 10 | 127 (13.2%) | 123 (21.4%) | 13 | 23 | 279 | 0.52 W |
| alt2 (alt1, lookup last) | 11/1 | 9 | 127 | 123 | 13 | 23 | 260 | 2.11 W |

- **As expected:** +6 TCAM blocks, no new stateful ALU.
- **Not as expected:** the extra stage. 12 is the most Tofino 1 has, so this build has no room left.

**11B. The windows are unchanged** (`exact_replays_5/`, `exact_replay.py` through `run_exact.py`, the 5 captures of
part 9C, `compare_11b.py`):
- **Rows:** all 5 equal to `basic_exact_v3`'s (part 6b's collector rows) and to part 6's in all 135 non-duration
  columns.
- **Windows:** every window equal to part 6's in all non-duration features (40 of 40 each).
- **Durations:** 137-145 of the 145 columns are equal. The durations are the switch clock's and follow the replay's
  timing (`syn_fan_40k` equal in all 145).
- **Against the published rows:** 135 (cohort), 71 (Chaos, 1,930 untracked packets), 135 (`slowloris_500`), 135
  (`bulk2000`), 120 (`syn_fan_40k`, 363 untracked), as in part 6.
- **Reset:** the reader's reset also cleared the block table each time (`block_cleared`).
- **All 109:** not run.

**11C. Latency and line rate** (`latency/`, `linerate/`):
- **Latency:** hairpin, 3 runs of 1,010 probes per build, none missing. Baseline 246 ns, `basic_hwl_exact_v3` 421
  ns, `basic_hwl_exact_block` **437 ns** (p99 439-440), alt2's latency build 421 ns. The 12th stage costs 19 cycles
  and 16 ns.
- **Line rate, table empty:** the 27-run matrix gives the same rates as `basic_exact_v3` at every size (64 B 91.09%,
  paced 99.87-99.89%, maximum 100.00%), lossless, the window totals exact.
- **Line rate, 1,024 entries that match nothing** (`src=203.0.0.0-203.0.3.255, dport=9`, written in one request in
  174 ms):
  - 1518 B paced 99.88 / 99.88 / 99.89% and maximum 100.00%, 64 B 91.09% x 3;
  - `blocked_pkts` 0 before and after; the entries were cleared afterwards.
  - 34 runs, 18.0 billion packets, 0 checks failed.

**11D. The block by hand, on replays** (`11d/`, `src/run_block_replay.sh`, `src/block_check.py`):
- **The command:** `replay_capture.py --exact --profile dataset --align-window 4 --send-log`, the collector with
  `--skip-p4-forwarding --block-on-alarm --block-detector network --block-host 10.0.0.10 --block-skip-windows 4` and
  the alarm forced at window 10 (dataset window 6).
- **The first cohort capture has frames in one direction only:** nine SYN retries from 10.0.0.10. So `bulk2000`
  (12,000 frames each way) was run as well.

| Run | Entries | Alarm | Alarm to reply | From 10.0.0.10: sent before the request / during the write / after the reply | Through | `blocked_pkts` | Toward 10.0.0.10 through | Windows = 11B |
|---|---|---|---|---|---|---|---|---|
| cohort, the plan's command | src | window 4, real (in-sample p 1.000) | 4.3 ms | 1 / 0 / 8 | 1 | 8 | - | 40/40 |
| cohort, `--block-threshold 2` | src | window 10, forced | 3.6 ms | 4 / 0 / 5 | 4 | 5 | - | 40/40 |
| bulk2000 | src | window 10, forced | 3.1 ms | 2,133 / 2 / 9,865 | 2,134 | 9,866 | 12,000 of 12,000 | 40/40 |
| bulk2000 `--block-host-port 132` | src, port 132 | window 10, forced | 5.1 ms | 2,129 / 4 / 9,867 | 2,129 | 19,743 | 2,128 of 12,000 | 40/40 |

- **Every expected value holds.** No frame sent after the reply passes, and the frames toward the host keep arriving
  (until the port entry). `blocked_pkts` equals exactly the frames that did not come back. In `bulk2000` that is
  9,866 = 9,865 + 1 of the 2 frames sent during the write; with the port entry, 19,743 = 19,735 + all 8 sent during
  the write.
- **The blocked packets are still counted:** every window equals 11B's, and `replay_capture.py`'s exact self-check
  is 44 of 44 in every run.
- **The plan's command alarmed at once.** Without a held-out group the cohort run is in the detector's own training
  data, so it raised a real alarm at the first scored window. `--block-threshold 2` isolates the forced alarm.
- **Timing:** the switch writes an entry in 1.5-2.4 ms (`write_ms`), 3-5 ms from the collector's request to its
  reply.
- **By hand, while a replay ran** (`src/run_11d_manual.sh`):
  - `window_reader.py --block-add src=10.0.0.10` failed with `Failed to subscribe to server`. The collector's reader
    already uses the default client id 9.
  - With `--client-id 10` it ran unbound ("another client is bound to basic: continuing unbound"), and BF Runtime
    accepted the write (1.2 ms).
  - The first frame was dropped 0.53 s into the 0.56 s call (Python start-up, connect, write). The 9,003 frames sent
    after the call returned were all dropped, and `blocked_pkts` 9,021 = the frames that did not come back.
  - The collector's own block at window 30 found the entry already there ("0 added, 1 there").

**11E. Time to containment, real verdicts on replays** (`11e/`, `src/run_11e.sh`, `src/summarize_11e.py`):
- **The detector:** each capture's group held out, the network detector, a host block on 10.0.0.10, no port block.
- **Times:** seconds from the run's anchor, taken from the window markers in `tx.pcap`. The replayer starts 0.2-1.0
  s late while it loads a capture and shifts its whole schedule, markers included.

| Capture | First frame from 10.0.0.10 | Alarm (dataset window, p) | Alarm after that window's end | Block request / reply | Last frame from 10.0.0.10 through | From 10.0.0.10: sent / through / dropped | Dropped |
|---|---|---|---|---|---|---|---|
| udp_sink_60k | 0.003 s | 0, 0.982 | 282 ms | 0.782 / 0.786 s | 0.784 s | 60,000 / 36,657 / 23,343 | 38.9% |
| syn_sink_40k | 0.004 s | 0, 0.871 | 299 ms | 0.839 / 0.842 s (flood) | 0.841 s | 82,332 / 37,153 / 45,179 | 54.9% |
| syn_fan_40k | 0.004 s | 0, 0.983 | 261 ms | 0.761 / 0.764 s (flood) | 0.727 s | 39,846 / 39,846 / 0 | 0% |
| goldeneye_p10 | 0.184 s | 0, 0.911 | 212 ms | 0.712 / 0.718 s (flood) | 0.711 s | 19,674 / 12,615 / 7,059 | 35.9% |
| bulk2000 (benign) | 0.004 s | no alarm (max p 0.132) | | | | 12,000 / 12,000 / 0 | 0% |
| session_1000 (benign) | 0.004 s | no alarm (max p 0.044) | | | | 6,000 / 6,000 / 0 | 0% |
| dns_10k (benign) | 0.003 s | 0, 0.700 | 305 ms | 0.805 / 0.809 s | 0.807 s | 10,000 / 6,354 / 3,646 | 36.5% |

- **Every attack alarms on its first 0.5-s window.** Its host is blocked 0.71-0.84 s into the run.
- **Where the 212-305 ms after the window's end go:** the reader reads the window (40-46 ms, plus a 4 ms clear), then
  ssh, then the forest's 80-145 ms of scoring on PC1, then the write (3-5 ms).
- **`syn_fan_40k`'s flood had ended at 0.727 s**, before the block, so nothing was dropped.
- **The frames toward 10.0.0.10 all passed** (a host block is by source).
- **One false alarm:** `dns_10k`, benign, alarms on window 0, so the block drops 36.5% of its frames.
- **The windows:** every run's windows equal part 6's replays of the same captures (40 of 40), and the self-checks
  are 44 of 44: the dropped packets are counted.
- **`--block-skip-windows 4` (added here, below)** makes the detector score the dataset's windows and not the replay's
  4 windows before the anchor.
  - Offline, `stream_verdicts.py` on the same CSVs (`11e/offline_skip/`) reproduces the collector's probabilities
    exactly with the skip.
  - Without it the alarms fall in the same windows with lower probabilities (e.g. 0.899 instead of 0.982), so these
    7 decisions do not depend on it.

**11F. Live, with the host monitor and the socket tracer** (`11f/`, `src/run_11f*.sh`, `src/check_11f.py`):
- **The monitor was rebuilt first** (50ef77e):
  - The build: `DEP=/usr CLANG=/usr/bin/clang BPFTOOL=... ebpf_perf/build.sh`, with bpftool v7.3.0 built from
    `libbpf-bootstrap/bpftool` in `/dev/shm` (PC1 has none).
  - `hostmon_agg.bpf.o` is byte-identical (f0944e7a...); only `hostmon_agg.c` and the binary changed.
  - `test_agg_equiv` passes: 3,006 scenarios, 37,445 rows identical.
  - Every run's log has 41 `HOSTMON_WINDOW_DONE` lines.
- **The forced run:** `http_poll`, alarm forced at window 8 with `--block-threshold 2`. The stacked verdict was
  already at or above 0.5 from window 1, so without the higher threshold it would have alarmed there. It ran beside
  `tcp_beacon` looping in `hazim_bg`.
  - **Health:** 40 rows, `HOSTMON_HEALTH` and `SOCKOWNER_HEALTH` all zeros.
  - **Blocks:** at the alarm the 10 flows seen so far (20 entries, 16.9 ms); then each window's new flow (30 times,
    2 entries, 2.6-3.9 ms). 80 entries in all.
  - **Nothing was dropped:** `blocked_pkts` 0. All 40 of the program's connections reached PC2 and were served, 30
    of them after the alarm. Each of its connections lasts a few ms, so its entry came 0.13-0.46 s after its last
    packet: no connection had a packet after its entry.
  - **The background program:** its 21 echo connections reached PC2, 15 after the alarm.
- **The seven workloads of section 2b, no forced alarm** (no background program, the conditions of section 2b and
  part 6c):

| Workload | Alarm (window, p) | Flows blocked (entries) | Connections on PC2 / after the alarm | Packets dropped |
|---|---|---|---|---|
| fanout | 0, 0.523 | 12 (24) | 12 / 11 | 0 |
| http_poll | 1, 0.727 | 36 (72) | 36 / 33 | 2 (the end of one connection) |
| http_bulk | 5, 0.540 | 6 (12) | 6 / 4 | 0 |
| tcp_beacon | 2, 0.809 | 20 (40) | 20 / 18 | 0 |
| interactive | 1, 0.603 | 1 (2) | 1 / 0 | 9 |
| threaded | 7, 0.625 | 32 (64) | 32 / 15 | 0 |
| mixed | 1, 0.609 | 12 (24) | 12 / 8 | 0 |

- **Every run is clean:** 40 rows, `HOSTMON_HEALTH` and `SOCKOWNER_HEALTH` all zeros.
- **All seven benign programs are flagged**, at windows 0-7, as part 6c's high scores suggested (`http_bulk`'s
  40-window row was 0.46, but its prefix of 6 windows crossed 0.5). That is the false-alarm cost of the rule with the
  dataset's detectors: every live program here would be blocked.
- **The flow block stopped nothing it was meant to.** Six of the seven open short connections, so each one ended
  before its entry was written, the next window. `interactive` keeps one echo session open, so its entry cut it:
  PC2 echoed 7 of its 90 commands, and the program ended with code 1.
- **Verdict timing** (50ef77e's check, "within about 0.1 s"): each `score` record came a median 268-275 ms after its
  window ended (maximum 284-309 ms), not 0.1 s.
  - The row was complete about 114 ms after the window's end. The switch's window is back at the collector after
    107 ms; the monitor's window is already there by then.
  - The stacked detector's scoring takes 158-162 ms per window on PC1.
  - With the old monitor the row would wait for the next window, a further 0.5 s.

**Changed here:**
- `hybrid_collector.py --block-skip-windows K` (`block_policy.Blocker(skip_windows=K)`): a replay's collector
  windows before the run's first (`replay_capture.py --align-window K`) are neither scored nor checked for a flood.
  The detectors were trained on prefixes from the run's first window. Default 0, so a live run is unchanged. Test
  `test_the_windows_before_the_run_are_not_scored`.
- `replay_capture.py --send-log`: `replay_absolute.py`'s send log (this host's clock after each frame) in
  `DIR/send_log.txt`.
- `perf/variants/exact_block/README.md` (status and the compile result) and `p4_perf.md` section 5.9.

**Open points:**
- **The direct counter and the 12th stage:** alt2 keeps per-entry drops at the exact build's stages and latency. It
  needs 11B-11D again before adoption, and bf-p4c's power estimate for it is 2.11 W. (Done: "Results, part 11b".)
- **Short connections pass a flow block:** blocking at the alarm by host or by the program's local ports, or at the
  socket on the host, would stop new connections.
- **Live false alarms:** 7 of 7 live benign programs were flagged. The detectors need rows collected the way the
  live rows are.
- **Verdict latency on PC1** is about 0.27 s:
  - the forest's scoring is about 160 ms, which more jobs, fewer trees or a compiled forest would cut;
  - the switch's window reaches the collector about 107 ms after its end. Reading and clearing it take about 45 ms;
    the reply leaves the reader about 50 ms after that, which the timing log does not break down.
- **11B's optional step:** all 109 captures were not run (about an hour).

**State after:**
- **Switch:** `basic_exact_block` (pid 26079, our `hz_sw`), forwarding 132 <-> 140, the block table empty, `enp5s0`
  down.
- **PC1:** eth1 back to 1,024 receive descriptors, offloads untouched, the test cgroups removed. `ebpf_perf/build/`
  holds the rebuilt monitors (git-ignored).
- **PC2:** as found; the logging server was stopped and its files removed.

## Results, part 11b (PC1, 2026-11-19): the block table in the exact build's 11 stages

The user asked whether `block_drop` could be worked around so that the build fits. It can: part 11's alt2 is now
`perf/variants/exact_block` itself (`basic_exact_block_v2` on the switch), and 11B-11F were run again on it. Files:
`*_v2` directories in `perf/results/part11_20261119/`, the archive `live_test/committee_replay/pc1_20261119_part11b.tar.xz`.

**The change** (`ingress.p4`, still only inserted lines against `perf/variants/exact`):
- `block_drop` only drops and counts the entry's direct counter `block_hits`.
- `blocked_pkts` is counted on `block_rules.apply().hit`, outside the action. bf-p4c refused the action with both
  counters.
- The lookup is the data path's last step, after the flow table. Right after `forwarding.apply()` it needed a 12th
  stage: both tables write `drop_ctl`, and the flow-table chain that follows it in control order started a stage later.
- The semantics are unchanged: every IPv4 packet of the data path is looked up (markers and timer packets never), and
  the drop takes effect at the end of ingress, after the window registers have counted the packet.

**Compile:** `basic_exact_block_v2`, `_v2_timer` and `basic_hwl_exact_block_v2` compile with the defaults (direct
counter on).

| Build | Stages ig/eg | Critical path | SRAM | Map RAM | TCAM | Stateful ALUs | Ingress cycles | Latency (median) |
|---|---|---|---|---|---|---|---|---|
| basic_exact_v3 | 11/1 | 9 | 122 | 119 | 7 | 23 | 260 | 421 ns |
| basic_exact_block_v2 | 11/1 | 9 | 127 | 123 | 13 | 23 | 260 | 421 ns |
| basic_exact_block (part 11, `-DBLOCK_DIRECT_COUNTER=0`) | 12/1 | 10 | 125 | 121 | 13 | 23 | 279 | 437 ns |

- **Latency:** 3 runs of 1,010 probes per build, none missing; baseline 246 ns and v3 421 ns the same hour.
- **bf-p4c's power estimate** is 2.11 W (ingress), against v3's 0.56 W. It counts the table's 6 TCAM blocks, searched
  for every IPv4 packet, which part 11's build searched too: its 0.52 W left the table off the estimate's worst-case
  path (`always_runs` false there, true here).

**Found on the switch, fixed:**
- **Capacity:** with the direct counter the table takes 1,023 entries. The 1,024th add fails with `RESOURCE_EXHAUSTED,
  'Table Add failed table:pipe.Ingress.block_rules Not enough space'`, and BF Runtime keeps the batch's earlier entries.
  - `window_reader.py block_add` now reports a full table (`table_full`, an `error`, the entries added) instead of
    raising.
  - `block_policy.BLOCK_ENTRIES` and `--block-entries` default to 1,023.
  - The flow entries leave room for the host's entries, so a `table_full` host block always fits.
- **Listing:** with the counter attached, reading every entry from the hardware costs 51 ms per entry (5.1 s for 100).
  At the end of the forced live run, listing 80 entries held the run 4.1 s.
  - `block_list` now syncs the table's counters once (the `SyncCounters` operation of BF Runtime) and reads the entries
    from software: 1,023 entries in 0.61-0.68 s.
  - Checked with pings: an ICMP entry showed 5 and then 8 dropped, the counts sent.
- **Tests:** 3 new and the placement test rewritten (300 run, 8 skipped, under the `.venv`).

**The checks again** (the same commands as part 11):
- **11B** (`exact_replays_5_v2/`): the 5 rows equal v3's in 135 of 135 non-duration columns, every window equal, the
  reset clearing the table.
- **11C** (`linerate_v2/`): the 27-run matrix gives the same rates as v3 at every size, lossless, totals exact
  (18.0 billion packets). With the table full (1,023 entries that match nothing) the 1518 B paced and maximum runs and
  the 64 B runs give the same rates again, and nothing is blocked.
- **11D** (`11d_v2/`, hairpin):

| Run | Entries | Alarm to reply | From 10.0.0.10: before / during / after the write | Through | Dropped per entry | `blocked_pkts` | Windows |
|---|---|---|---|---|---|---|---|
| cohort, forced at 10 (threshold 2) | src | 3.3 ms | 4 / 0 / 5 | 4 | 10.0.0.10: 5 | 5 | 40/40 |
| bulk2000, forced at 10 | src | 4.1 ms | 2,151 / 0 / 9,849 | 2,151 | 10.0.0.10: 9,849 | 9,849 | 40/40 |
| bulk2000 + `--block-host-port 132` | src, port 132 | 5.0 ms | 2,127 / 2 / 9,871 | 2,127 | 10.0.0.10: 9,873; port 132: 9,874 | 19,747 | 40/40 |

  - **The per-entry counts add up to `blocked_pkts`.** A frame that matches both entries counts on one: the host's
    frames on the host entry, and the replies toward it, which match only the port entry, on the port entry.
  - The exact self-checks are 44 of 44.
- **11E** (`11e_v2/`): the same decisions as part 11.

| Capture | Alarm (dataset window, p) | After that window's end | Dropped (of the frames from 10.0.0.10) |
|---|---|---|---|
| udp_sink_60k | 0, 0.982 | 255 ms | 41.2% |
| syn_sink_40k | 0, 0.871 | 316 ms | 58.3% |
| syn_fan_40k | 0, 0.983 | 260 ms | 0% (the flood is over at 0.742 s, the block in at 0.764 s) |
| goldeneye_p10 | 0, 0.911 | 201 ms | 35.9% |
| bulk2000 / session_1000 (benign) | no alarm (max p 0.132 / 0.044) | | 0% |
| dns_10k (benign) | 0, 0.700 | 367 ms | 31.7% |

  - Every run's windows equal part 6's (40 of 40), the self-checks are 44 of 44, and the per-entry counts equal
    `blocked_pkts`.
- **11F** (`11f_v2/`, with the PC2 logging server):
  - **Forced `http_poll` beside `tcp_beacon` in `hazim_bg`:** 40 rows, health zeros. 31 requests wrote 80 entries;
    `blocked_pkts` 0. All 40 of the program's connections reached PC2, 30 after the alarm, none with a packet after its
    entry. The background program's 26 connections all reached PC2, 20 after the alarm.
  - **`interactive`:** alarm at window 1 (p 0.604). Its echo session's entry toward PC2 dropped 9 packets (the client's
    retransmissions), the reply direction's entry 0.
  - **Verdict timing:** a median 270-273 ms after the window's end, as in part 11.

**State after:**
- **Switch:** `basic_exact_block_v2` (pid 31757), forwarding 132 <-> 140, the block table empty and `blocked_pkts`
  reset, `enp5s0` down. Part 11's builds stay in `/root/hazim_perf/build/` as the record.
- **PC1:** eth1 at 1,024 receive descriptors.
- **PC2:** as found.

## Results, part 11c (PC1, 2026-11-19): an alarm stops all forwarding from the flagged host

The user's requirement: once the control plane classifies something as malicious, the switch forwards nothing more
from it. Part 11's live policy blocked only the flagged program's 5-tuples, each new one from the next window on, so
every new short connection got through (11F).

**The change** (control plane only; the P4 program of part 11b is unchanged):
- `hybrid_collector.py --block-scope host|flows`, default `host`, through `block_policy.Blocker(scope=...)`.
- **`host`:** at the alarm the collector has the switch drop everything the flagged host sends: one entry
  `src=ADDRESS` for each source address of the monitored program (sockowner's `FLOW` lines) and each `--block-host`,
  and with `--block-host-port` one entry for everything entering that switch port.
  - Every later window adds an address the program has used since, and retries a write that failed.
  - If the program has sent nothing yet at the alarm, its address is blocked as soon as sockowner shows one.
- **`flows`:** part 11's policy, unchanged.
- **Tests:** 304 run, 8 skipped. The loop test runs the same traffic under both scopes. Under `host`, nothing from the
  host passes after the alarm, including a flow it opens later and another program's flow from the same host. The
  replies toward it pass, and every packet is still counted.

**Live, on `basic_exact_block_v2`** (`11f_host/`; the 11F set-up, `servers_log.py` on PC2, clock offset measured
with its accepts the same minutes, -1.7 ms):

| Run | Alarm | Entry, alarm to reply | PC2 accepts from PC1 before / after the block | PC1's SYNs after the block | Packets from PC2 after it | `blocked_pkts` |
|---|---|---|---|---|---|---|
| `http_poll`, forced at window 8 (threshold 2), beside `tcp_beacon` in `hazim_bg` | window 8 | `src=192.168.0.1`, 3.3 ms | 15 (10 of the program, 5 of the background) / **0** | 11 | 0 | 11 |
| `tcp_beacon`, real verdict | window 2, p 0.758 | `src=192.168.0.1`, 3.0 ms | 2 / **0** | 4 | 0 | 4 |

- **Nothing more from the host reached PC2 after the block**, new connections included. Every later connection
  attempt (its SYN and the retransmissions) was dropped, and the counts equal `blocked_pkts` and the entry's own
  counter.
- **The background program in another cgroup was blocked too.** The switch sees addresses, not programs: that is the
  price of blocking at the switch by host.
- The verdict timing is that of 11F (about 0.27 s after the window).
- Both runs: 40 rows, `HOSTMON_HEALTH` zeros.

**State after:** switch on `basic_exact_block_v2`, block table empty and `blocked_pkts` reset, `enp5s0` down; PC2 as
found.

## Results, part 12 (PC1, 2026-11-19): every capture on the final build, shorter windows, recalibrated detectors, live attacks

The user asked for the four next steps of the evaluation:
1. recalibrate the detectors with live benign runs and measure live false alarms on a larger set;
2. shorter windows;
3. all 109 captures on the final build;
4. a live attack through the whole loop.

Switch: `basic_exact_block_v2` throughout. Files: `perf/results/part12_20261119/` (git-ignored; scripts in `src/`) and
the archive `live_test/committee_replay/pc1_20261119_part12.tar.xz` (everything but the captures).

**12A. The 109 captures on the final build** (`replays_109/`, `src/run_replays_109.py`):
- **How:** part 6b's collector path, plus a streaming verdict per capture. The network detector was trained without
  the capture's own group, and the alarm blocked the host, 10.0.0.10.
- **Measurement:** every replay is exact (44 of 44 windows, every packet counted).
- **Rows:** 102 of 109 equal the published rows in all 135 non-duration columns (mean 131.86), and all 109 equal
  `basic_exact_v3`'s (part 6b). The 7 others are part 6b's: Chaos 71, `bulkup_200`/`400` 71 (the MTU), `syn_fan_40k`
  120, `syn_fan_100k` 70, `syn_fan_150k` 77, `udp_fan_60k` 123.
- **Detection:** all 67 attacks alarmed (52 malware, 15 floods), 53 of them at the first window. The other 14 are
  malware that starts slowly (windows 1-10).
- **False alarms:** 11 of 42 benign runs: ftp x4, telnet x4, `dns_2k`/`5k`/`10k`.
- **Timing:** the alarm came a median 213 ms after its window ended (p90 252, max 378 ms).
- **Containment:** the share of the host's frames sent after the block, on the capture's own timeline. Malware mean
  82%; floods mean 48%, from 2% (`syn_fan_40k`) to 87% (`syn_fan_150k`).
- **The false alarms' cost:** the ftp and telnet runs had sent everything before their block; `dns_10k` lost 42% of
  its traffic.
- **One replay was spoiled by my own ssh to PC2 during it** (366 packets counted against 15) and was rerun exact. Any
  traffic from PC1 through port 132 during a replay counts in its windows.

**12B. Shorter windows.**
- **Offline** (`windows/`, `src/compute_windows.py`, `study_windows.py`):
  - The 29 network features of the 110 captures at 0.1, 0.25 and 0.5 s, from the release's switch model. At 0.5 s
    they equal the detectors' training table in every window of all 110 runs.
  - The network detector was retrained at each length, leaving one group out (42 groups), with the block assumed
    50 ms after the alarm (a decent control-plane host).

| Window | Run-level balanced accuracy (AUC) | Attacks alarmed | Benign alarmed | First alarm (median) | Floods: packets blocked (mean) | Malware: host frames blocked (mean) |
|---|---|---|---|---|---|---|
| 0.5 s | 0.837 (0.973) | 67/67 | 14/43 | 0.50 s | 55% | 89% |
| 0.25 s | 0.830 (0.967) | 67/67 | 14/43 | 0.25 s | 71% | 89% |
| 0.1 s | 0.837 (0.969) | 67/67 | 14/43 | 0.10 s | 83% | 89% |

  - **Per flood, at 0.5 / 0.25 / 0.1 s:** `syn_fan_40k` 24 / 58 / 79%, `goldeneye_p10` 36 / 79 / 100%, `udp_sink_60k`
    58 / 78 / 90%, `syn_sink_40k` 72 / 91 / 95%.
  - **Accuracy does not change with the window.** The same 14 benign runs alarm at every length: the bulk uploads,
    the DNS runs, and ftp/telnet, which look like attacks to a network-only detector.
- **On the switch** (`short_windows/`, `exact_replay.py --window-us`):
  - **0.25 s works:** `bulk2000` gives 80 of 80 windows equal to the model's, none lost.
  - **0.1 s does not keep up:** `udp_sink_60k` gives 200 of 200, but `bulk2000` only 47 of 200 (199 marked lost),
    the cohort capture 192 of 200 (155 lost), and `syn_fan_40k` 192 of 200 (137 lost, plus its 363 untracked
    packets).
  - **The cause is the reader on the switch.** Its read of a window takes 37-40 ms and the clear 4 ms, but its whole
    cycle is about 100 ms. At 0.1 s it falls a window behind, and its clear of the extremes lands after the bank's
    next window has started.
  - **To run 0.1 s:** a faster reader (batched reads, or C++), or more banks (four would give three windows of
    slack).

**12C. Live benign runs and recalibration.**
- **74 live benign executions through the pipeline** (`live_benign/`):
  - part 2's 47 programs of the dataset's kind: null x2, 30 GNU tools at three sizes, 7 network clients against
    `servers_log.py`, `banners.py` and `openssl s_server` on PC2, and 8 busybox;
  - the release's 9 workloads x3.
  - All have 40 rows and `HOSTMON_HEALTH` zeros. `git-heavy` failed early (its repository fixture is missing) and is
    kept as a benign run; `telnet` ended with 1, as in part 2.
  - They are converted to the training table's format in `live_test/streaming/live_benign_windows.csv.gz`.
- **The study** (`recalibration/`, `src/recalibrate.py`):
  - 5 group folds over the 240 dataset runs and the 74 live runs.
  - Model A is trained on the dataset runs of the training folds; model B on those plus the live benign runs of the
    training folds.
  - Every run is scored after each of its windows. "stream" means an alarm in any window, as the block rule acts.

| Detector | Training | Live benign alarmed (stream) | Dataset TPR (stream) | Dataset FPR (stream) | Dataset balanced accuracy (run level) | Live attacks alarmed |
|---|---|---|---|---|---|---|
| network | A, dataset only | 9.5% | 0.588 | 0.111 | 0.738 | 3/3 |
| network | B, + live benign | 5.4% | 0.588 | 0.048 | 0.774 | 3/3 |
| host | A | 83.8% | 0.816 | 0.230 | 0.813 | 3/3 |
| host | B | 6.8% | 0.798 | 0.191 | 0.831 | 2/3 |
| stacked | A | 56.8% | 0.798 | 0.175 | 0.807 | 3/3 |
| stacked | B | **2.7%** | 0.816 | 0.206 | 0.833 | 3/3 |

- **As deployed** (trained on all 240 runs, no fold), the share of the 74 live benign runs alarmed: stacked 70.3%,
  host 85.1%, network 8.1%.
- **The live false alarms come from the host side**, from PC1's environment. Stacked B leaves only `rsync` (its 2
  runs).
- **Recalibrating the host side alone has a cost:** host B finds the SYN flood only at window 3 and misses the port
  scan (max p 0.482). The stacked detector covers it through the network side.
- **Caveat:** every live training row is benign. The live attacks were never trained on and are still flagged, but
  they are network floods; live malware with mostly host-side behaviour is untested (no malware on PC1).

**12D. Live attacks, the original detector** (`live_attack/`):
- `hping3` from PC1 in the monitored cgroup to PC2.
- The stacked detector trained on the dataset only, and a host block on 192.168.0.1.
- PC2's eth1 receive counter read around each run.

| Attack | Alarm | After the window's end | Block written | Sent | Dropped by the switch | Reached PC2 |
|---|---|---|---|---|---|---|
| SYN flood, 20 kpps, 60,000 | window 0, p 0.795 | 356 ms | 3.4 ms | 60,000 | 49,755 (82.9%) | 10,245 |
| UDP flood, about 40 kpps, 60,000 | window 0, p 0.896 | 328 ms | 3.1 ms | 60,000 | 42,571 (71.0%) | 17,429 |
| port scan, 10 kpps, 30,000 | window 0, p 0.740 | 381 ms | 3.7 ms | 30,000 | 24,365 (81.2%) | 5,635 |

- `hping3`'s replies (10,245 and 5,635) equal the packets that got through, and PC2's counter agrees (plus 2-3 other
  frames).

**12E. The recalibrated detector, live** (`live_recal/`):
- **How:** `--block-train-extra live_test/streaming/live_benign_windows.csv.gz`, each benign workload with its own
  live group held out.
- **The 7 workloads of 11F: no alarm in any of them.** In 11F the original detector alarmed on all 7.
- **The 3 attacks** were alarmed at window 0 (p 0.862, 0.914, 0.786), 274-343 ms after the window ended. The blocks
  took 2.9-3.2 ms and dropped 50,757 (84.6%), 42,723 (71.2%) and 24,844 (82.8%) packets.

**Changed here:**
- **`live_test/streaming/stream_verdicts.py`:**
  - `train(..., extra_paths)` and `--train-extra`: further window tables trained on, with the hold-out applying to
    them;
  - `train_arrays()`, training on arrays;
  - `score.batch`, many prefixes in one call.
- **`block_policy.load_scorer(extra_windows=...)` and `hybrid_collector.py --block-train-extra`** (repeatable). The
  default stays the dataset only.
- **`live_test/streaming/live_benign_windows.csv.gz`:** the 74 live benign runs.
- **Tests:** `test_stream_extra.py` (3; they need scikit-learn); the suite under the `.venv` is 307 OK, 8 skipped.

**Notes for later runs:**
- The dataset launcher runs programs from `tempfile.mkdtemp()`; on PC1 set `TMPDIR` to `/dev/shm` when they write
  big outputs.
- Loops that read a case list must keep `ssh` and the collector off their standard input (`ssh -n`, `< /dev/null`).

**State after:** switch on `basic_exact_block_v2` (pid 31757), the block table empty and reset, `enp5s0` down; PC2 as
found (its services stopped and files removed); `/dev/shm` cleaned.
