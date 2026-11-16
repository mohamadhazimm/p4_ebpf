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

**Captures.** 110 in all, both sets sanitized (headers only, payload bytes zeroed):
- the 77 cohort captures in `live_test/captures/cohort/` (rows 0-203 with traffic; Chaos `d538053a...` last:
  it overloads the reader in every window);
- 33 new ones for the network attacks and network-benign rows (rows 204-239; the 3 null runs have no
  traffic): `live_test/captures/cohort-extra.tar.gz` (26 MB; 771 MB unpacked, git-ignored). Unpack first:

      tar xzf live_test/captures/cohort-extra.tar.gz -C live_test/captures
      (cd live_test/captures/cohort-extra && sha256sum -c SHA256SUMS)

  Its `manifest.csv` has the cohort's columns plus `attack_type`. Replay the 8 runs with `expect_overload` 1
  last (the fan-out floods, `slowloris_1000`, the two GoldenEye runs).

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
