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
