# RUNBOOK: register readout of the flow collector on the Wedge100BF-32X

Commands to validate and measure the batched register reader (`--reader batched`)
against the legacy one (`--reader legacy`) on the hardware switch. Everything here
is control plane only; the P4 program, the report format, the window length, the
feature definitions and the CSV layout are unchanged.

## 0. What the two readers do per window

| | legacy (`read_registers_with_index.py`) | batched (`batched_reader.py`) |
|---|---|---|
| session | a new bfshell/bfrt_python session per window (1.4-1.5 s before any read; over SSH two ssh connections more) | one gRPC client for the whole run, in a `--serve` process (local or on the switch over one SSH session) |
| snapshot | 14 (15 with `reg_newconn_dst`) `operation_register_sync`, each awaited | 14 (15) `Sync` table operations, one Write RPC each, answered when the DMA is done (`--sync-batched`: all in one Write RPC) |
| reads | `reg.get(REGISTER_INDEX=i)` once per register per bucket: 14 calls per bucket, ~80 us each from the shadow copy | one Read RPC per register table with all active indexes (chunked at 4,096 keys), `from_hw=False` |
| clears | `reg.mod(...)` once per register per idle bucket, then `complete_operations()` | one Write RPC with all `register x bucket` zero updates |
| rows | `combine()` over the pipes, derived `pkts_ba`/`bytes_ba`/`duration_ns` | the same functions (copies checked identical by `tests/test_batched_reader.py`) |

The collector consumes the same payload from both; only the number of RPCs changes.

## 1. Prerequisites

- `bf_switchd` with the `basic` program is running on the switch (SDE 9.6.0 in
  `/root/bf-sde-9.6.0/install`); its BF Runtime gRPC server listens on
  `127.0.0.1:50052` on the switch (default), its CLI on 9999.
- Passwordless SSH from the control host (PC1) to `root@172.168.1.2`.
- `enp5s0` up on the switch (CPU reports), ports 1/0 and 2/0 (dev ports 132 and 140)
  forwarding, mirror to 192: `python3 thesis-hybrid-ebpf-p4/python/program_forwarding.py
  --ssh root@172.168.1.2 --int-port 132 --ext-port 140 --report-port 192 --mirror-sid 1`.
- This repository on the control host, with the Python unit tests passing:

```sh
cd thesis-hybrid-ebpf-p4/python && python3 -m unittest discover -s tests && cd ../..
```

Two ways to run the batched reader; step 2 tells which ones work:

- **on the switch** (`--switch-ssh root@172.168.1.2`, default placement): the collector
  copies `batched_reader.py` to the switch and runs it there with the SDE's own
  Python client (`/root/bf-sde-9.6.0/install/lib/python2.7/site-packages/tofino/bfrt_grpc`,
  interpreter `python2.7`), against the switch-local gRPC server. Same client/server
  versions, so this is the reference placement; the switch CPU does the response parsing.
- **on the control host** (`--reader-local --grpc-addr HOST:50052`): the reader runs
  here with open-p4studio's client (`/home/ubuntu/open-p4studio/install`, Python 3.10,
  protobuf 4.23 with the fast `upb` implementation) against the switch's gRPC server over
  the management network, or through an SSH tunnel when 50052 is not reachable:

  ```sh
  ssh -N -L 50052:127.0.0.1:50052 root@172.168.1.2 &     # then --grpc-addr 127.0.0.1:50052
  ```

  The client (9.13.4) is newer than the server (9.6.0). bfruntime.proto grew by
  addition, so the messages used here (Read with keys and `table_flags.from_hw`, Write
  with `table_operation` and MODIFY updates, Get/SetForwardingPipelineConfig,
  Subscribe) should be understood, but it is not guaranteed: the probe below decides.

## 2. Compatibility probe (2 minutes)

On the switch:

```sh
scp thesis-hybrid-ebpf-p4/python/batched_reader.py root@172.168.1.2:/root/hazim_perf/tools/
ssh root@172.168.1.2 'python2.7 /root/hazim_perf/tools/batched_reader.py --probe \
    --sde-install /root/bf-sde-9.6.0/install'
```

From the control host (optional, enables `--reader-local`):

```sh
python3 thesis-hybrid-ebpf-p4/python/batched_reader.py --probe --grpc-addr 172.168.1.2:50052
```

Expected: one JSON line with `"tables"` listing the 14 registers, `"missing": []`,
`"dst_table": true`, `"sync_ops"` all `"Sync"` (the bf-rt.json of the program lists
`Sync` as the register operation; the server also accepts `SyncRegisters`),
`"fast_equals_safe": true` (the fast response parser agrees with the client's
`to_dict()`), `"pipes"` = number of pipes in the program's scope, and
`"sync_reg_dir_valid_ms"` of a few ms. A host-side probe that fails (RPC error, missing
field, `fast_equals_safe: false`) means: use the on-switch placement only.

`"protobuf"` names the client's protobuf package and implementation, e.g.
`3.6.1/python`: `python` means no C implementation, where the generic protobuf classes
cost 40-120 us per register entry (Section 10) and the wire-format route is the one to
use. Probe it with `--raw-wire` as well: expected `"parser": "raw"` and
`"raw_equals_safe": true` (the module's wire-format parser agrees with the client's).

## 3. Known answer and idle clearing (bucket 6886)

The 100-packet test connection of `perf/tools/make_test_pcaps.py sanity` lands in bucket
6886 (both directions). Replay it from PC1 through port 1/0 as in p4_perf.md Section
5.1, then:

```sh
# values after the connection (expected: pkts 100, bytes 32440, pkts_ab 51, bytes_ab 24068,
# pkts_ba 49, bytes_ba 8372, min_len 40, max_len 1500, syn 2, ack 98, rst 2,
# ref ports 40001 -> 5001, dir_valid 1, duration_ns 990000000 +- replay jitter)
ssh root@172.168.1.2 'python2.7 /root/hazim_perf/tools/batched_reader.py --indexes 6886 --format json'

# idle clearing: clear only if the count is still 100, then the bucket reads zero
ssh root@172.168.1.2 'python2.7 /root/hazim_perf/tools/batched_reader.py --indexes 6886 --clear-if-unchanged 6886:100 --format json'
ssh root@172.168.1.2 'python2.7 /root/hazim_perf/tools/batched_reader.py --indexes 6886 --format json'
# one more packet of the connection: a new CPU report with flow_index 6886 on enp5s0, pkts 1
ssh root@172.168.1.2 'timeout 10 tcpdump -i enp5s0 -c 1 -nn "ether[0:2] = 0xbef1"' &
# ... send one packet of 10.99.0.1:40001 -> 10.99.0.2:5001 from PC1 ...
ssh root@172.168.1.2 'python2.7 /root/hazim_perf/tools/batched_reader.py --indexes 6886 --format json'
```

The legacy reader gives the same rows: replace the command by
`python3 thesis-hybrid-ebpf-p4/python/read_registers_with_index.py --ssh root@172.168.1.2 --indexes 6886 --format json`.
On the Tofino model the whole sequence is `live_test/p4_known_answer.py --reader batched`
(crafted flows, see Section 7).

## 4. Timing table

On the switch (reference placement), 5 windows per size, each window = one Sync of the
14 registers + 14 batched Reads + one clear of all sampled buckets:

```sh
ssh root@172.168.1.2 'python2.7 /root/hazim_perf/tools/batched_reader.py \
    --bench 100,500,1000,2000,5000,10000,20000 --bench-windows 5 \
    --out /root/hazim_perf/bench_switch_py27.json'
scp root@172.168.1.2:/root/hazim_perf/bench_switch_py27.json perf/results/
```

From the control host, if the probe passed:

```sh
python3 thesis-hybrid-ebpf-p4/python/batched_reader.py --grpc-addr 172.168.1.2:50052 \
    --bench 100,500,1000,2000,5000,10000,20000 --bench-windows 5 --out perf/results/bench_switch_host.json
```

The same table with the wire-format route and the Syncs in one RPC (Section 10):

```sh
ssh root@172.168.1.2 'python2.7 /root/hazim_perf/tools/batched_reader.py \
    --bench 100,500,1000,2000,5000,10000,20000 --bench-windows 5 --raw-wire --sync-batched \
    --out /root/hazim_perf/bench_switch_py27_raw.json'
```

Each prints the table of the report (`sync ms | read ms | clear ms | total ms |
us/bucket | fits 0.5 s?`, with the error count of a size whose reads or clears failed);
`--bench-budget` changes the window length, `--safe-parse` times the client's own parser
instead of the fast one, `--raw-wire` the wire-format route, `--chunk N` the keys per
Read, `--sync-batched` the 14 Syncs in one Write RPC instead of 14 (exact on the switch,
Section 9; see Section 8 for why it is not the default).
The sampled buckets are random and are zeroed by the clear: run it on an idle switch
(the collector resets all registers at the start of a run anyway).

The legacy numbers for the same table come from the collector's instrumentation
(Section 6, `--reader legacy --reader-timing`) or from p4_perf.md Section 6.2
(1.14 ms per bucket from the shadow copy, 1.4 s per session).

## 5. Live A/B, 20 windows

Both readers on the same traffic, same active set, read one after the other at every
window end (idle clearing off for both, so one reader's clear cannot change what the
other reads):

```sh
python3 live_test/reader_ab.py --switch-ssh root@172.168.1.2 --cpu-iface enp5s0 \
    --windows 20 --window-sec 10 --out perf/results/reader_ab_switch.json
# add --reader-local --grpc-addr 172.168.1.2:50052 to run the batched reader on this host
```

with traffic through the switch meanwhile (e.g. `tcpreplay` of a capture from PC1, or
the `testers/` through 1/0 -> 2/0). Each window prints `identical`, `traffic between`,
`MISMATCH` and `only in one` counts for the flow rows and for the `reg_newconn_dst`
rows, and the wall time of both reads. Expected: `MISMATCH 0` and `only in one 0` for
both kinds in every window, verdict `PASS`. `traffic between` rows are buckets whose
packet counter (connection counter for dst rows) differs between the two snapshots
(they are taken ~1.5 s apart because the legacy read opens a bfshell session; the later
snapshot has the larger counters, which the script checks): they are the documented case
"rows identical except where the two snapshots fall on different sides of a packet
arrival". The JSON keeps the per-row differences. `--raw-wire` and `--sync-batched`
pass through to the batched reader.

The CSV-level variant: two collector runs of the same replayed capture, one with
`--reader legacy`, one with `--reader batched`; the `net_*` columns of the two CSVs
equal, except where the window boundaries fell on different sides of a packet.

## 6. The collector with the batched reader

```sh
sudo python3 hybrid_collector.py --mode command --scenario-name ab_batched --label benign \
    --command "..." --window-sec 0.5 --out-csv hybrid_windows.csv \
    --switch-ssh root@172.168.1.2 --forward-int-port 132 --forward-ext-port 140 \
    --forward-report-port 192 --cpu-iface enp5s0 \
    --reader batched --reader-timing --reader-timing-file timing_batched.jsonl
```

`--reader-timing` (or `P4_READER_TIMING=1`) prints one line per window for either reader:

```
[TIMING] window 12: reader=batched/fast active=2143 dst=37 sync=41.2 ms read=118.7 ms clear=3.1 ms wall=171.0 ms overhead=8.0 ms cleared=5 rpcs={'sync_rpcs': 1, 'read_rpcs': 15, 'read_entities': 30039, 'clear_rpcs': 1}
```

`overhead` is wall time minus sync, read and clear: the bfshell session and SSH for the
legacy reader, the request/answer pipe for the batched one; `/fast`, `/raw` or `/safe` is
the batched reader's route. `--reader-timing-file` keeps the same values as JSON lines;
`--reader legacy --reader-timing` gives the "before" column. `--reader-local --grpc-addr
...` places the batched reader on this host; `--reader-chunk`, `--reader-safe-parse`,
`--reader-raw-wire`, `--reader-sync-batched`, `--grpc-client-id` and `--p4-name` pass
through. For the switch, Section 10 recommends `--reader-raw-wire --reader-sync-batched`.

The default is still `--reader legacy`; switch the default once Sections 3 to 5 have
passed on the switch.

## 7. The same checks on the Tofino model of this VM

The model is ~200x slower than the switch (a register sync 15-45 s, a per-cell hardware
read 0.27 s), so only semantics are checked here, not times. The commands used:

```sh
sudo live_test/testbed.sh up                                    # model + bf_switchd + ports 0-2
python3 thesis-hybrid-ebpf-p4/python/batched_reader.py --probe   # gRPC against the model's bf_switchd
sudo python3 live_test/p4_known_answer.py --int-iface veth0 --ext-iface veth2 \
    --reader batched --out live_test/results/ka_batched.json    # 19 checks incl. clear and re-report
python3 thesis-hybrid-ebpf-p4/python/batched_reader.py --bench 100,500,1000,2000,5000,10000,20000 \
    --bench-windows 3 --bench-nosync --out live_test/results/bench_model.json   # Read/clear path only
sudo env WIN=60 INTERVAL=0.1 EXTRA="--reader batched --reader-timing --clear-idle-windows 0" \
    live_test/run_pcap_test.sh                                   # the collector end to end, 84 flows exact
sudo live_test/testbed.sh down
```

Results on this VM (2026-11-05, open-p4studio 9.13.4, model + bf_switchd, Python 3.10 client):

| check | result |
|---|---|
| probe | 14 tables, `Sync`, 4 pipes, fast parser = client parser |
| `p4_known_answer.py --reader batched` | 19/19: all 14 registers and `reg_newconn_dst` exact for 10 crafted flows, clear, zero read-back, re-report counting from 1 |
| `run_pcap_test.sh` with `--reader batched` | 1,023/1,023 packets, 84/84 flows exact, CSV equals the per-bucket read model in all 7 windows (as the legacy run of 2026-11-03) |
| unit tests (`tests/test_batched_reader.py`) | legacy and batched windows and CSV rows identical over 120 windows; 21 tests |
| model times (not the ASIC) | one register `Sync` 0.35-4 s, 15 registers 57-74 s per window; one shadow entry read 2-6 ms on the model's bf_switchd (the ASIC: < 80 us); IPC overhead per window 3-8 ms |
| client-side cost, this host | 3 us to build a key, 5-6 us to decode one entity of 4 pipes (protobuf 4.23 upb): 2,000 buckets x 14 registers = 28,000 entities in about 0.25 s |

## 8. Troubleshooting

- `BF_RT_INFO not received`: wrong `--p4-name` (the program is `basic`).
- Subscribe or bind fails: another client uses the same id; pass `--grpc-client-id`
  (collector) / `--client-id` (reader). bfshell sessions (program_forwarding.py,
  reset_registers.py) are unaffected by a bound gRPC client.
- `Timed out waiting for completion of operation` in `bf_drivers.log`: a register sync
  took longer than the 5 s the server waits before answering anyway (seen on the model
  with `--sync-batched`, where the 14 syncs of one Write run one after the other at
  ~2.5 s each; on the switch a sync takes 2-3 ms). Do not use `--sync-batched` then.
  The request metadata `deadline_sec` that would extend the wait is rejected by the
  9.13 server (`DEADLINE_EXCEEDED, Write RPC request timed out`), so it is not used.
- A read hangs: the collector kills the reader process after `--p4-read-timeout`
  seconds, starts a new one and retries `--p4-read-retries` times, like the legacy path.
- "Only one Python shell instance allowed" never applies to the batched reader.
- Host-side placement errors (`AttributeError` in `bfrt_grpc`, protobuf decode errors):
  client/server version mismatch, use the on-switch placement.
- `ALREADY_EXISTS ... already owns this P4`: only one gRPC client can be bound to the
  program. The reader then continues as an independent client that names the program
  in every request (logged); nothing to do. Stop a leftover reader (`--serve` process)
  if two are not intended.
- The probe or bench against the Tofino model is slow (seconds per read): the model's
  bf_switchd serves one register entry in milliseconds and a register sync in seconds;
  only the ASIC's numbers count.
- `"parser": "fast"` or `"safe"` in the ready line although `--raw-wire` was given: the
  route disagreed with the client's parser on the first read (logged as
  `[batched] the raw route disagrees with the client's parser ...`) or the client has no
  `channel`/field ids. The values are still right, only slower; send the log line.

## 9. Results on the switch (2026-11-05)

Sections 1 to 6 on the Wedge100BF-32X, run from the control host (PC1), with the batched
reader in the reference placement (on the switch: SDE 9.6 client, Python 2.7.13). The raw
logs, JSON and CSVs stay on PC1 in `perf/results/batched_reader_20261105_182414/`
(git-ignored; its README lists the files).

Setup and deviations from Sections 1 to 6:

- Program `basic_newconn_head`, compiled from this repository's P4 sources (identical to
  HEAD): 15 registers with `reg_newconn_dst`. The switch ran `basic_fix` (no
  `reg_newconn_dst`) before the run and was restored to it afterwards.
- Not run: the host placement (host probe, host bench, `--reader-local`), because PC1 has
  no Python 3 `bfrt_grpc` client; Section 7, because PC1 has no Tofino model.
- `--p4-reader`, `--p4-forwarder` and `--hostmon` were passed explicitly: the defaults of
  `hybrid_collector.py` (and so of `reader_ab.py`) point to `/home/ubuntu/Desktop/p4_ebpf/...`.
  HostMon is not built on PC1. `--hostmon` named a stand-in that prints no host windows, so
  the collector CSVs have the P4 columns only.
- Traffic for Sections 5 and 6: `live_test/make_benign_pcap.py --sessions 2000` (seed 7),
  35,388 packets, 2,768 flows, 2,100 new connections in 12 `reg_newconn_dst` buckets.
  Replayed from PC1 with `tcpreplay -i eth1 --multiplier=6.5` (181.5 s, 0 failed packets).

```sh
# switch: the program with reg_newconn_dst, then ports, forwarding, mirror, CPU netdev
ssh root@172.168.1.2 'bash /root/hazim_perf/tools/sw_switchd.sh stop && bash /root/hazim_perf/tools/sw_switchd.sh start /root/hazim_perf/build/basic_newconn_head/basic.conf LOG_DIR'
perf/tools/run_bfrt.sh RUN_DIR setup setup --prog basic --ports 132,140 --fwd 132:140,140:132 --mirror-sid 1
python3 thesis-hybrid-ebpf-p4/python/program_forwarding.py --ssh root@172.168.1.2 --int-port 132 --ext-port 140 --report-port 192 --mirror-sid 1
ssh root@172.168.1.2 'ip link set enp5s0 up'
# Section 5, twice: default order, then --order alternate after reset_registers.py --ssh root@172.168.1.2
python3 live_test/reader_ab.py --switch-ssh root@172.168.1.2 --cpu-iface enp5s0 --windows 20 --window-sec 10 \
    --p4-reader thesis-hybrid-ebpf-p4/python/read_registers_with_index.py --out reader_ab_switch.json
# Section 6, three runs: batched with 0.5 s windows, legacy with 10 s, batched with 10 s
sudo python3 hybrid_collector.py --mode command --scenario-name NAME --label benign \
    --command "tcpreplay -i eth1 --multiplier=6.5 ab_mix.pcap" --window-sec 10 --out-csv hybrid_windows.csv \
    --switch-ssh root@172.168.1.2 --forward-int-port 132 --forward-ext-port 140 --forward-report-port 192 \
    --cpu-iface enp5s0 --reader batched --reader-timing --reader-timing-file timing_batched.jsonl \
    --hostmon HOSTMON_STAND_IN --p4-reader thesis-hybrid-ebpf-p4/python/read_registers_with_index.py \
    --p4-forwarder thesis-hybrid-ebpf-p4/python/program_forwarding.py
```

| check | result |
|---|---|
| unit tests | 65/69 on PC1 as checked out: the 4 tests that need the fast parser fail because no generated `bfruntime_pb2` is importable there. 69/69 with the switch's `tofino/bfrt_grpc/bfruntime_pb2.py` and `tofino/google/rpc/status_pb2.py` copied under `DIR/lib/python3.8/site-packages/tofino/` and `SDE_INSTALL=DIR` |
| probe (switch) | as expected: 14 tables, `missing: []`, `dst_table: true`, all `Sync`, `fast_equals_safe: true`, `pipes: 2`, bound; one Sync 2.2 ms; connect 0.26 s |
| known answer (bucket 6886) | one CPU report with `flow_index` 6886; batched = legacy = the values of Section 3, `duration_ns` 989,951,385; `reg_newconn_dst` bucket 55719: 1 |
| idle clearing | `6886:99`: nothing cleared; `6886:100`: cleared in 1 Write RPC (1.6 ms), all 14 registers 0, bucket 55719 kept; one more packet: a new report, `pkts` 1 in both readers; a clear by the legacy reader reads 0 with the batched reader |
| `--sync-batched` | known answer exact, with the 15 Syncs in one RPC (26 ms) |
| live A/B (Section 5), 2 x 20 windows | 30,862 rows identical, `MISMATCH` 0, `only in one` 0; `reader_ab.py` prints FAIL for the dst rows (below) |
| collector (Section 6), 3 runs | each: 2,768 reports, 0 index mismatches, 0 overruns, retries or errors; the CSV sums of pkts, bytes, pkts_ab, bytes_ab, SYN, ACK, RST equal the capture (35,388; 19,689,510; 17,711; 1,415,529; 4,100; 31,952; 100) |

Timing table (Section 4): medians of 5 windows, each with 14 Syncs, the batched Reads and
one Write clearing every sampled bucket. The whole table took 11 min 42 s.

| active buckets | sync ms | read ms | clear ms | total ms | us/bucket | fits 0.5 s? |
|---|---|---|---|---|---|---|
| 100 | 60.1 | 128.2 | 55.7 | 244.0 | 2439.9 | yes |
| 500 | 62.2 | 601.2 | 276.8 | 940.3 | 1880.6 | no |
| 1000 | 58.9 | 1136.6 | 577.9 | 1773.4 | 1773.4 | no |
| 2000 | 61.8 | 2203.5 | 1349.9 | 3615.3 | 1807.6 | no |
| 5000 | 58.4 | 5876.0 | 3535.4 | 9469.8 | 1894.0 | no |
| 10000 | 61.7 | 13388.8 | 7335.7 | 20786.2 | 2078.6 | no |
| 20000 | 59.0 | 30940.7 | 14991.0 | 45990.7 | 2299.5 | no |

- **Per-bucket cost.** Reads take 1.1-1.55 ms per bucket (80-110 us per register entry),
  clears 0.55-0.75 ms per bucket, and the 14 Syncs 58-62 ms. Read RPCs are as designed
  (14 up to 4,096 buckets, 70 at 20,000), and one Write with 280,000 updates succeeded.
- **`--sync-batched`** (100, 1,000, 2,000 buckets): Syncs 24.8-31.0 ms; reads and clears
  unchanged.
- **`--safe-parse`** (100, 1,000 buckets): reads 524.6 and 4,767.1 ms, clears 242.5 and
  2,541.5 ms. The fast parser is 4.1-4.4x faster.
- **Bottleneck.** At 2,000 buckets the reader process uses 90% of one core and
  `bf_switchd` 26% (19-29 us per entry), so the switch's Python 2.7 client limits the
  reader. Section 7's client cost (5-6 us per entry, Python 3.10 with upb) does not apply
  to this placement: the 28,000 entries of 2,000 buckets take 2.2 s here, not 0.25 s.

Live A/B (Section 5), 106-938 active buckets per window:

- **Run 1** (`batched-first`): 15,428 rows identical. `dst equal` False in windows 0-17,
  True in 18 and 19, which came after the replay.
- **Run 2** (`--order alternate`): before it, `reset_registers.py` cleared the 15 registers
  in 0.1 s, and a wrapper around `reader_ab.py` logged each read's `dst_rows`.
  - 15,434 rows identical.
  - Of 227 dst comparisons, 44 were equal and 183 larger in the later read; none was
    smaller.
  - In both readers the last reads of all 12 dst buckets equal the capture's counts, as
    did an idle read after run 1.
- **dst rows.** The readers agree on `reg_newconn_dst`. Its buckets count the connections
  of a whole destination and grow between the two reads. Section 5's "`dst equal True` in
  every window" therefore holds only if no connection arrives between the reads.
- **`traffic between` stayed 0.** No flow row changed between the two reads: the replayed
  flows last under 0.1 s, and a report from the last ~100 ms of a window is taken in the
  next window. The dst buckets covered the later-is-larger case.
- **Wall time per window** at ~915 active buckets: batched 1.21 s (Syncs 70 ms, reads
  1.10 s). Legacy 4.7-5.2 s, of which its own sync and reads take 1.03 s.

Collector (Section 6), same replay; the collector resets the registers at the start:

| run | windows | active buckets, median | wall per window, median (p95) | sync / read / clear / overhead, median ms |
|---|---|---|---|---|
| legacy, 10 s | 19 | 608 | 4,643 ms (4,894) | 49.7 / 656.2 / 148.3 / 3,781.6 |
| batched, 10 s | 20 | 607 | 917 ms (949) | 71.0 / 721.3 / 81.1 / 37.3 |
| batched, 0.5 s | 363 | 31 | 138 ms (151) | 69.9 / 59.2 / 0.0 / 3.7 |

- **Per-bucket cost.** Reads 1.08 ms (legacy) and 1.21 ms (batched) per active bucket;
  clears 1.00 ms (legacy) and 0.57 ms (batched) per cleared bucket.
- **Legacy overhead.** The bfshell session, SSH and the payload printed through the CLI
  cost 3.8 s at ~600 buckets. That is more than the 1.4-1.5 s session alone and grows with
  the payload.
- **CSV-level variant** (the two 10 s runs). Windows 0 and 1 and the totals are equal. The
  other windows differ by a few flows that fell on different sides of a window boundary in
  the two replays (cumulative offset -81 to +106 of 35,388 packets).

What this means:

- **Data.** On the switch the batched reader returns the same data as the legacy reader,
  and the collector's counts with it are exact.
- **Speed per window.** At 600-900 active buckets it is 4-5x faster (0.9-1.2 s instead of
  4.6-5.2 s), because it opens no bfshell session.
- **Speed per bucket.** It is not faster: its reads cost about as much as the legacy
  reader's (1.1-1.55 ms vs 1.07-1.14 ms), and its clears about half as much.
- **Capacity.** 0.5 s windows work up to about 350 active buckets with few clears (60 ms of
  Syncs plus ~1.2 ms per bucket). A 10 s window holds about 5,000 active buckets even if
  every bucket is cleared.

Open items:

1. The collector default is still `--reader legacy`. Sections 3 to 5 have passed (with the
   dst point above), which is Section 6's condition for switching; the user decides.
2. `--sync-batched` is exact on the switch and halves the snapshot. Section 8's reason
   against it, the server's 5 s wait, applies to the model. It is a candidate default for
   the switch.
3. `live_test/reader_ab.py`: classify dst rows like flow rows (the later read >= the
   earlier one) and keep them in the JSON. *Done 2026-11-05 (Section 10).*
4. `tests/test_batched_reader.py`: four tests assume the fast parser and fail where
   `bfruntime_pb2` cannot be imported; skip them there. They are
   `test_rpc_counts_per_window`, `test_safe_parse_and_chunking_give_the_same_windows`,
   `test_reads_come_from_the_synced_snapshot` and `test_one_shot_probe_and_bench_modes`.
   *Done 2026-11-05: the expectations follow the route in use, so they pass there too.*
5. `batched_reader.py --bench` does not report a window's `errors`, so a failed clear would
   show as `clear 0.0 ms`. *Done 2026-11-05: errors and cleared counts per size, in the
   table and the JSON.*
6. `ReportCollector` with `ssh_host`: `stop()` ends the local ssh only; the tcpdump on the
   switch keeps running until it captures the next frame. *Done 2026-11-05: the remote
   shell reports its PID and `stop()` kills it over ssh.*
7. The host placement is not measured. From the CPU split, a host client that parses at
   Section 7's rate could cut the per-bucket cost about 3-4x (an estimate). *Section 10
   measures where the client's time goes and adds a route that does not need the host.*

## 10. Follow-up on this VM (2026-11-05): where the client's time goes, and `--raw-wire`

What Section 9 established: the batched reader returns the legacy reader's data on the
switch and the collector's counts with it are exact; per window it is 4-5x faster because
it opens no bfshell session; per bucket it is not faster (1.1-1.55 ms vs 1.14 ms), so a
0.5 s window holds about 350 active buckets, not the 2,000 of the target. The reader
process at 90% of a core against bf_switchd at 26% says the time is in the client.

The client-side cost of one register table read and of the clear, measured here on the
same code paths with 2,000 keys and 2 pipes (`protobuf 4.23.4`, Python 3.10, i7-13620H;
best of 5):

| step | protobuf with its C implementation (`upb`) | protobuf without it (`python`) | wire format (`--raw-wire`) |
|---|---|---|---|
| decode the ReadResponse (per entity) | 2.9 us | 44.2 us | 4.3-4.6 us |
| build the ReadRequest (per key) | 1.7 us | 41.6 us | 0.1 us |
| build the clear WriteRequest (per update) | 2.2 us | 120.5 us | 0.1 us |

The `python` column is the client the switch runs (the SDE's Python 2.7 protobuf has no
C extension unless the probe's `"protobuf"` field says `cpp`): request building and
response decoding through the generic protobuf classes are what the reader process does
at 90% of a core. The wire-format route costs the same few microseconds whatever the
protobuf implementation, with identical output (`tests/test_batched_reader.py`,
`RawWireTests`: same 120 windows and CSV as the fast route, the request bytes equal the
protobuf-built requests, the parser decodes server-style responses, and the route falls
back to the fast one when its self-check fails). Against the real BF Runtime server of
this VM's model (open-p4studio 9.13.4) the probe reports `raw_equals_safe: true` and
`p4_known_answer.py --reader batched --raw-wire` passes 19/19, including the clear through
a raw Write, the zero read-back and the re-report (`live_test/results/ka_batched_raw.json`).

Expected on the switch, to be measured (the switch CPU is about 3x slower than this one
and bf_switchd's own ~20 us per entry stays): reads about 0.3-0.4 ms per bucket instead
of 1.1-1.55, clears about 0.3 ms per bucket instead of 0.55-0.75, so a 0.5 s window with
`--sync-batched` (30 ms) holds about 1,000-1,300 active buckets. 2,000 per 0.5 s stays
out of reach of a gRPC client because of the server's cost per entry; that is Phase 2's
case (a C++ bf_rt client in process reads the shadow without gRPC or protobuf).

Commands for the next switch session, after `scp` of the current `batched_reader.py`
(Section 2):

```sh
# 1. the client's protobuf implementation and the wire-format self-check (2 lines of JSON)
ssh root@172.168.1.2 'python2.7 /root/hazim_perf/tools/batched_reader.py --probe --sde-install /root/bf-sde-9.6.0/install'
ssh root@172.168.1.2 'python2.7 /root/hazim_perf/tools/batched_reader.py --probe --raw-wire --sde-install /root/bf-sde-9.6.0/install'
# 2. the timing table of Section 4 with the new route (compare with Section 9's)
ssh root@172.168.1.2 'python2.7 /root/hazim_perf/tools/batched_reader.py --bench 100,500,1000,2000,5000,10000,20000 \
    --bench-windows 5 --raw-wire --sync-batched --out /root/hazim_perf/bench_switch_py27_raw.json'
# 3. known answer and idle clearing (Section 3) with --raw-wire added to each command
# 4. the A/B of Section 5 and the collector of Section 6 with the new route
python3 live_test/reader_ab.py --switch-ssh root@172.168.1.2 --cpu-iface enp5s0 --windows 20 --window-sec 10 \
    --raw-wire --sync-batched --out perf/results/reader_ab_switch_raw.json
sudo python3 hybrid_collector.py ... --reader batched --reader-raw-wire --reader-sync-batched \
    --reader-timing --reader-timing-file timing_batched_raw.jsonl
```

If 1 shows `raw_equals_safe: true` and 2-4 pass, the collector's switch defaults become
`--reader batched --reader-raw-wire --reader-sync-batched`.

Also done on this VM: `live_test/reader_ab.py` classifies the `reg_newconn_dst` rows like
the flow rows (`dst_counts`, `dst_diffs`, verdict without the "dst equal" condition);
`batched_reader.py --bench` reports errors and cleared counts; the four tests pass without
`bfruntime_pb2`; `ReportCollector.stop()` ends the tcpdump on the switch; the probe and the
ready line report `protobuf` and `parser`; `--reader-timing` prints the route
(`reader=batched/raw`).

## 11. Read cadence: profiles, read budget, report-only aggregates (2026-11-07)

Why: the window length and the per-flow read cost pull against each other. On the switch a
register read costs 1.1-1.55 ms per bucket plus 58-70 ms of syncs (Section 9), so a 0.5 s
window holds ~350 active buckets and a 1 s window ~600 (about 2,000 with `--reader-raw-wire`
once Section 10's expectation is confirmed). The dataset's own runs (lab analysis
`deployment-design-20261107/flow_dynamics.json`) show what a monitored host produces: ordinary
programs have at most 2 active flows; benign bulk transfers and request loops up to 380 active
flows (10 ms lifetimes, 16-83 new flows/s); a scanner 27,306 active flows (1,934 new/s); SYN
fan-out floods 111,760 active (3,000-6,300 new/s). Nothing per-flow can follow a flood, and a
fixed per-flow watch of 20 s costs 5-10x a TTL-based read for the same information because the
flows live milliseconds. Detection accuracy is flat from 0.5 to 10 s windows (lab window-length
test, 2026-11-06). Hence the design below; `hybrid_collector.py` implements it without changing
any default (no `--profile` = the old behaviour).

What changed in `hybrid_collector.py`:

- `--profile switch`: 1 s windows, `--active-ttl-windows 3` (the dataset model's TTL),
  `--clear-idle-windows 3`, `--reader batched --reader-raw-wire --reader-sync-batched`,
  `--p4-snapshot sync`, `--read-budget-frac 0.7` (0.8 until Section 14), `--max-dst-reads 256`, `--clear-expired 1`,
  `--clear-budget-frac 0.5` (Section 11.4),
  `--forward-report-port 192`. `--profile model`: 60 s windows, batched reader,
  `--p4-snapshot sync`, `--p4-read-timeout 600`, `--clear-idle-windows 0`, no budget (the
  model's syncs alone take 45-140 s), report port 2. (Until 2026-11-07 it had
  `--p4-snapshot hw` and the default 120 s timeout: the batched reader's hardware reads cost
  ~0.47 s per register entry on the model, so 18 buckets took 118 s and larger active sets timed
  out; see `live_test/RESULTS.md`.) Explicit options override the profile.
- `--read-budget-frac F`: a read may take F of the window, and never more than the time left
  until the next window boundary minus the collector's measured post-read work (the deadline
  rule, Section 11.4: a read that is decided late shrinks instead of pushing every later
  window). A running cost model (`ReadCostModel`: fixed ms per window for the syncs and the RPC
  overhead, ms per flow bucket read, ms per `reg_newconn_dst` bucket read, ms per bucket
  cleared; initial values for the reader route in use from Sections 9, 10 and 12.1 and from the
  model's runs, `ROUTE_COSTS`; updated from every window's measured timing) says how many
  buckets fit next to that window's clears and destination reads. When the active set is
  larger, the most recently reported or changed buckets are read and the rest skipped; the
  window carries `net_overload`, `net_buckets_active`, `net_buckets_read`,
  `net_buckets_skipped`, `net_read_budget_ms`, `net_read_allow_ms`, `net_read_late_ms`,
  `net_read_overrun`. `--max-read-buckets N` is a hard cap; `--max-dst-reads N` caps the
  `reg_newconn_dst` buckets read (the most reported destinations first).
- `--clear-expired 1` (on in `--profile switch`): a bucket that leaves the active set without
  having been cleared is cleared unconditionally in a later read, oldest first, within
  `--clear-budget-frac` of the window's allowance (Section 11.4); the window carries
  `net_buckets_cleared` and `net_clear_backlog`.
- Report-only columns `rep_*` in every row, from the CPU reports alone (no register read):
  `rep_new_flows`, `rep_new_flows_per_sec`, `rep_distinct_src_ips`, `rep_distinct_dst_ips`,
  `rep_distinct_dst_ports`, `rep_tcp_share`, `rep_max_flows_to_one_dst`,
  `rep_max_flows_to_one_dst_port`. These are the flood/scan signal and stay available when the
  active set cannot be read. Because the CSV gains columns, appending to an older
  `hybrid_windows.csv` is refused; use a new `--out-csv`.
- `--hostmon-cgroup DIR` with `--hostmon ebpf_perf/build/hostmon_agg`: the in-kernel monitor.
  The collector starts it on the cgroup (created if missing), waits for `HOSTMON_READY`, sends a
  shared monotonic start time one second ahead, starts the scenario inside the cgroup at that
  instant, and anchors the network windows there too; `HOSTMON_HEALTH` is printed at the end.
  Without the option `--hostmon` is the streaming monitor, started as before.
- Tests: `thesis-hybrid-ebpf-p4/python/tests/test_collector_cadence.py` (budget, caps,
  aggregates, profiles, CSV guard, monitor protocol with a stand-in monitor, cgroup wrapper);
  run with `python3 -m unittest tests.test_collector_cadence` from
  `thesis-hybrid-ebpf-p4/python`.

Cadence to use: one window Δ for both sensors, 1 s on the switch (2 s if the monitored hosts
keep more than ~600 flows active, or until `--reader-raw-wire` is confirmed), both under the
4.295 s timestamp wrap; read every active bucket every window, no fixed per-flow watch; the
host monitor's windows at the same Δ (its map may be read later without loss, up to 65,536
live entries). Under a flood the budget keeps the reader inside the window and the `rep_*`
columns carry the signal.

### 11.1 On the Tofino model (logic only; the model's timings say nothing about the switch)

From the repository root (`testbed.sh up` leaves the testbed in replay mode, which the known
answer injects on; the command run needs live mode, the PCAP run replay mode):

```sh
sudo live_test/testbed.sh up
sudo python3 live_test/p4_known_answer.py --reader batched --raw-wire       # unchanged, 19/19 (~12 min)
sudo live_test/testbed.sh mode live
sudo python3 hybrid_collector.py --profile model --mode command --scenario-name model_cadence \
    --label benign --command "ip netns exec p4int setpriv --reuid=$USER --regid=$USER --init-groups \
    bash live_test/benign_workload.sh mixed" \
    --out-csv cadence_model.csv --reader-timing --reader-timing-file timing_model.jsonl
# the overload path on the model: a budget the model cannot meet (its syncs alone take 45-140 s)
[ -f live_test/data/benign_mix.pcap ] || python3 live_test/make_benign_pcap.py \
    --out live_test/data/benign_mix.pcap --truth live_test/data/benign_mix_truth.json
sudo live_test/testbed.sh mode replay
sudo python3 hybrid_collector.py --profile model --read-budget-frac 0.5 --mode pcap \
    --scenario-name model_overload --label benign --pcap live_test/data/benign_mix.pcap \
    --int-iface veth0 --ext-iface veth2 --interval 0.1 --out-csv cadence_model.csv --reader-timing
```

Expect (measured on 2026-11-07, `live_test/RESULTS.md`): the first run reads every active
bucket (`net_overload` 0 in every row) and its `rep_new_flows` sum to the collector's CPU report
count (70). The second read all of window 0 when the cost model started from the switch's
numbers, then learned the model's cost (~99 s fixed for the syncs, ~2.1 s per bucket) and read
no flow bucket in the later windows (`net_buckets_skipped` > 0, `net_overload` 1; the syncs and
the `reg_newconn_dst` reads still run), while `rep_new_flows` sum to the report count (84, the
capture's flows). `net_read_overrun` is 1 in every row of both runs: the model's reads
(52-232 s per window) end after the next 60 s boundary. Since Section 11.4 the cost model
starts from the model's own costs (`ROUTE_COSTS["model"]`), so window 0 is skipped as well;
nothing else changes for `--profile model` (no budget, no `--clear-expired`), except that a
window with nothing to read is no longer synced and that the CSV has four more columns (use a
new `--out-csv`). This run need not be repeated for 11.4.

### 11.2 On the Wedge100BF-32X (the cadence measurement)

Prerequisites: Sections 1-2, 9 (program, ports, forwarding, mirror, `enp5s0` up), and the
current `batched_reader.py` copied to the switch (Section 2). Three replays from PC1 at 1 s
windows, each with `--reader-timing-file`; the dataset captures are on the lab workstation under
`vbox-runs/hybrid-rf-study-20261010/data/versioned-collector/additional-study-review-20261022/`
(`flood21-collect/20261026T151240756153Z/runs/bulk2000.zip/output/run_*/packet_capture.pcap`,
`flood21-collect/20261026T154421063760Z/runs/syn_fan_40k.zip/output/run_*/packet_capture.pcap`).

```sh
C="sudo python3 hybrid_collector.py --profile switch --mode command --label benign \
    --switch-ssh root@172.168.1.2 --forward-int-port 132 --forward-ext-port 140 --cpu-iface enp5s0 \
    --hostmon HOSTMON_STAND_IN --p4-reader thesis-hybrid-ebpf-p4/python/read_registers_with_index.py \
    --p4-forwarder thesis-hybrid-ebpf-p4/python/program_forwarding.py --out-csv cadence_switch.csv \
    --reader-timing"
# (a) ordinary benign traffic: Section 9's mix, ~100 active buckets per 1 s window
$C --scenario-name cad_mix --command "tcpreplay -i eth1 --multiplier=6.5 ab_mix.pcap" \
    --reader-timing-file timing_cad_mix.jsonl
# (b) heavy benign: a dataset download loop, 230 active flows per window, 24k packets in 20 s
$C --scenario-name cad_bulk --command "tcpreplay -i eth1 bulk2000.pcap" \
    --reader-timing-file timing_cad_bulk.jsonl
# (c) a SYN fan-out flood: 40k single-packet flows in 20 s (2,000 new flows/s, 30k+ active)
$C --scenario-name cad_flood --label attack --command "tcpreplay -i eth1 syn_fan_40k.pcap" \
    --reader-timing-file timing_cad_flood.jsonl
```

Pass criteria: (a) and (b) have `net_overload` 0 and `net_read_overrun` 0 in every window, and
`wall_ms` in the timing file stays under 800 ms (the budget); (b) reads ~230 buckets per window
in about 70 + 230 x 1.2 ms = 350 ms (about 150 ms with `--reader-raw-wire` confirmed); (c)
shows `net_overload` 1 from the first busy window with `net_buckets_read` near the budget's
fit (~600 at 1.2 ms per bucket), `wall_ms` still under 800 ms, no overrun, and
`rep_new_flows_per_sec` about 2,000 with `rep_distinct_dst_ips` in the thousands. The CSV sums
of (a) and (b) must still equal the capture (Section 9's check); for (c) only the read buckets
are summed, so compare `rep_new_flows` with the report count instead.

### 11.3 The host side (any Linux host with root, the monitor built in `ebpf_perf/build`)

Build the monitor with `./ebpf_perf/build.sh`; on a machine without the lab's dependency
bundle, `DEP=/usr ./ebpf_perf/build.sh` uses the system's clang-14 and libelf, and
`CLANG=clang-10` (for example) another clang for the BPF objects (`-fno-common` is set for
clang 10, as PC1 needed). Until 2026-11-07 the last step, `test_agg_equiv`, did not compile from
this repository: the reference monitor it is checked against (the cgroup-scoped streaming
`hostmon.c` measured in `ebpf_perf/COMPARISON.md`) had never been committed. It is now
`ebpf_perf/hostmon_ref/`, the build uses it, and `./ebpf_perf/build/test_agg_equiv` passes
(3,006 scenarios, 37,445 rows identical); on the lab workstation the build reproduces the
2026-10-27 binaries byte for byte (`build/sha256.txt`).

```sh
sudo python3 hybrid_collector.py --profile switch --mode command --scenario-name host_agg \
    --label benign --command "bash live_test/benign_workload.sh files" --hostmon ebpf_perf/build/hostmon_agg \
    --hostmon-cgroup /sys/fs/cgroup/hazim_collect --skip-p4-forwarding --no-register-reset ...
# on the Tofino model of this VM, with the network side as well (testbed in live mode);
# 120 s windows so that the model's reads end inside the window
sudo python3 hybrid_collector.py --profile model --window-sec 120 --mode command --scenario-name host_agg \
    --label benign --command "ip netns exec p4int setpriv --reuid=$USER --regid=$USER --init-groups \
    bash live_test/benign_workload.sh mixed" --hostmon ebpf_perf/build/hostmon_agg \
    --hostmon-cgroup /sys/fs/cgroup/hazim_collect --out-csv cadence_host_agg.csv --reader-timing
```

Expect `HOSTMON_READY`, then `HOSTMON_HEALTH {'lost': 0, 'capacity_errors': 0, ...}` at the end,
and host rows whose `host_window_start_sec` equals the network windows' (the shared origin).
On the model (2026-11-07): health all 0, equal starts in both rows, the cgroup removed afterwards.

### 11.4 Changes after the 2026-11-07 runs (Section 12.2), and what to rerun

Section 12.2 (c) found two design problems in the budget as first committed; both are fixed in
`hybrid_collector.py`, `batched_reader.py` and `read_registers_with_index.py` (tests in
`test_collector_cadence.py` and `test_batched_reader.py`), with no change to any default except
the two new keys of `--profile switch`.

1. **The budget did not keep the window on time.** The allowance was a fixed fraction of the
   window counted from the read's start, the collector's own work per window (taking ~1,500
   reports, two CRCs per report, ~1,150 rows) was not counted, and the cost model started from
   the protobuf route's values. Now:
   - the allowance of a window is `min(F x window, time left until the next window boundary -
     measured post-read work - 5 ms)`, measured when the read is decided, so a read that starts
     late (`net_read_late_ms` > 0) shrinks and the schedule recovers in the next window instead
     of lagging by 250-300 ms per window;
   - the clears and the `reg_newconn_dst` reads are counted in the cost (`ReadCostModel`:
     a destination read costs 0.15 of a flow bucket read, one register entity instead of
     fourteen; the estimate is fitted per unit);
   - the model starts from the route in use (`ROUTE_COSTS`: raw 65 ms fixed, 0.62 ms per
     bucket read, 0.09 ms per bucket cleared; fast 70 / 1.3 / 0.7; legacy 1.5 s / 3.6 / 1.5;
     model 99 s / 2.1 s / 3 s) and the printed cost estimate names it.
2. **Under overload no bucket was ever cleared.** A bucket is read once, in its report window,
   newer buckets outrank it afterwards, so it never reached three idle reads and left the
   active set at its TTL still occupied on the switch (46% of the table after (c); the next
   capture lost 54% of its flows). Now, with `--clear-expired 1`, a bucket that leaves the
   active set without a clear goes into a queue and is cleared unconditionally in a later read
   (`clear_indexes` in the reader request: one Write RPC together with the idle clears, no read
   of the bucket, 0.09 ms per bucket on the raw route), oldest first, at most
   `--clear-budget-frac` (0.5) of the allowance left after the fixed cost per window; the rest
   waits (`net_clear_backlog`). A bucket that reports again meanwhile is live and leaves the
   queue; one whose clear fails three times is given up (counted at the end of the run). What
   this costs: a live flow the budget never read is split in two when its bucket is cleared,
   not lost. Without `--clear-expired` the behaviour is as before, and the end-of-run summary
   says how many buckets stayed occupied.
3. A window with nothing to read (no active flow bucket and no destination bucket) is no longer
   synced by the batched reader (a clear needs no snapshot): the 15 syncs the model's overloaded
   windows still ran (RESULTS.md 2026-11-07, problem 4), 30 ms on the switch.

What to rerun on the switch (PC1, `--profile switch`, the Section 12.2 stand-ins are fine):

- (c) the SYN fan-out again, with `--reader-timing-file`. Expect `net_read_late_ms` to stay
  small (median well under 100 ms, no growth over the run), `wall_ms` at or under
  `net_read_allow_ms` in nearly every window, `net_buckets_cleared` > 0 from the first windows
  after the buckets' TTL (window 4-5 on) with `net_clear_backlog` bounded, and the printed
  cost estimate starting at the raw route's values. After the run the occupancy check
  (`024_occupancy_after_flood`) should show the flood buckets cleared, not 46% of the table.
- (d) the benign capture right after (c) with `--no-register-reset`: the CPU reports should be
  close to the capture's 2,768 flows and the CSV sums equal the truth (not 54%).
- (a)/(b) once more as a regression (same criteria as 11.2; `net_buckets_cleared` now also
  counts their idle clears).

## 12. Results on the switch (2026-11-07): Sections 10 and 11.2-11.3

Run from PC1 with HEAD's P4 (`basic_newconn_head`) and HEAD's `batched_reader.py` on the
switch. The raw data is in the git-ignored run dir `perf/results/cadence_raw_20261107_102808/`
(README with every number, logs `NNN_*.txt`, the scripts used in `scripts/`).

Deviations:

- 11.2 (b) and (c): the dataset captures are not on PC1. (b) is Section 9's `ab_mix.pcap`
  (2,768 flows, exact truth) at x59: 20 s, ~140 new flows/s, ~558 active buckets.
- (c) is a stand-in: 40,000 single-packet SYN flows to 5,000 addresses and ports 1-1024 in
  20 s, which touch 29,902 distinct buckets.
- 11.3 ran on PC1 with `hostmon_agg` built there (clang 10 needs `-fno-common`) on
  `/sys/fs/cgroup/unified/hazim_collect` (PC1 has the hybrid cgroup layout).
- 11.1 was not run: no model on PC1.

### 12.1 Section 10: the wire-format route on the switch

- The probe reports `protobuf 3.6.1/cpp`: the switch's client does have the C implementation,
  so Section 10's `python` column is not the switch.
- `--raw-wire`: `raw_equals_safe: true`.
- Timing table, `--raw-wire --sync-batched`, every bucket cleared each window:

  | active | sync ms | read ms | clear ms | total ms | us/bucket |
  |---|---|---|---|---|---|
  | 100 | 30.5 | 77.3 | 15.0 | 122.9 | 1229 |
  | 500 | 30.5 | 311.1 | 44.2 | 385.8 | 772 |
  | 1,000 | 30.8 | 557.6 | 89.1 | 677.5 | 678 |
  | 2,000 | 31.7 | 1,076.5 | 177.6 | 1,285.8 | 643 |
  | 5,000 | 31.2 | 2,638.9 | 418.8 | 3,088.9 | 618 |
  | 10,000 | 30.4 | 5,032.6 | 836.6 | 5,899.6 | 590 |
  | 20,000 | 31.1 | 10,655.8 | 1,674.8 | 12,361.7 | 618 |

  - Reads 0.50-0.56 ms per bucket and clears 0.084-0.089 ms. The fast route in the same session
    gives 1.12-1.19 and 0.58-0.72 ms.
  - So the raw route is 2.1x cheaper for reads, 6.5-8.6x for clears, 2.6-3.1x in total.
    Section 10 expected 0.3-0.4 ms reads and 0.3 ms clears.
  - CPU at 2,000 buckets: client 71% of a core, bf_switchd 44% (fast route: 90% / 26%).
  - What is left per bucket is about 0.24 ms of client decoding (17 us per entity, measured
    without a server) and about 0.28 ms of server work.
  - Capacity: a 0.5 s window holds about 750-880 active buckets, an 800 ms budget about
    1,240-1,450. Section 10 expected 1,000-1,300 per 0.5 s.
- Known answer (Section 3) with `--raw-wire`: every field equals the expected value and the
  legacy reader. Clear with a stale count: nothing. With the right count: cleared in 1 RPC,
  all zero, dst kept. Re-report: pkts 1, dst 2.
- Live A/B with `--raw-wire --sync-batched`: **PASS**.
  - Flow rows: 15,443 identical, 0 mismatches.
  - dst rows: 54 identical and 173 "later larger", 0 mismatches (the new classification
    works on hardware).
  - Wall time at ~915 active: batched 0.60-0.67 s (fast route 1.21 s), legacy 4.5-5.1 s.
- Collector, 10 s windows, raw route: CSV sums equal the truth. Wall per window: median
  474 ms (fast route 917).
- No tcpdump and no `/tmp/batched_reader_*.py` were left on the switch after nine runs
  (open item 6 holds).

Section 10's condition holds: 1 shows `raw_equals_safe: true` and 2-4 pass, so
`--reader batched --reader-raw-wire --reader-sync-batched` can be the switch default (as
`--profile switch` already sets).

### 12.2 Section 11.2: `--profile switch`

| run | windows | active median / max | overload rows | overrun rows | wall median / max | CSV sums |
|---|---|---|---|---|---|---|
| (a) ab_mix x6.5 | 182 | 62 / 70 | 0 | 0 | 101 / 135 ms | = truth |
| (b) ab_mix x59 | 21 | 558 / 569 | 0 | 0 | 445 / 498 ms | = truth |
| (c) SYN fan-out stand-in | 25 | 5,019 / 6,624 | 24 | **19** | 783 / **953** ms | read buckets only |
| (d) ab_mix x59 right after (c), `--no-register-reset` | 22 | 296 / 318 | 0 | 0 | 266 / 341 ms | **19,023 of 35,388 packets** |

**(a) and (b)** pass every criterion. `rep_new_flows` equals the report count in every run.

**(c)** shows the overload mode working:

- `net_overload` 1 from the first busy window; ~1,180 buckets read per window once the cost
  model has converged.
- `rep_new_flows` 29,902, equal to the capture's distinct buckets.
- `rep_new_flows_per_sec` up to 1,697 (the replay ran at ~1,730 packets/s).
- `rep_distinct_dst_ips` up to 1,433 per window.

(c) fails two criteria and shows two design problems:

1. **The budget does not keep the window on time.**
   - From window 6 on, the reads take 690-870 ms and still end after the next window boundary,
     so each read starts 250-300 ms late. `wall_ms` > 800 in 9 windows; the lag reaches 1.1 s
     by window 21.
   - The late start comes from the collector's own work per window on PC1, which the budget
     does not count: ~1,500 reports per window (`take()`, two Python CRCs per report for the
     dst index) and ~1,150 rows to process.
   - The cost model starts from the fast route's values (70 ms + 1.3 ms per bucket, EMA 0.3), so
     window 1 read 615 of 1,775 buckets. Windows only reached ~1,180 buckets from window 11.
   - The per-bucket cost the collector learns, 0.62-0.70 ms, is above the bench's 0.53.
   - Suggestions:
     - compute the allowance from the time left until the next boundary, minus the measured
       per-window processing, instead of a fixed fraction from the read's start;
     - count the clears and the dst reads in the cost;
     - start the cost model from the route in use (raw: ~65 ms fixed, 0.62 ms per bucket read,
       0.09 ms per bucket cleared).
2. **Under overload no bucket is ever cleared.**
   - (c) cleared 0 buckets. A bucket is read once, in its report window. After that, newer
     buckets outrank it, so it never reaches 3 idle reads, and it leaves the active set at its
     TTL without a clear.
   - After (c), all 29,902 flood buckets were still occupied (`024_occupancy_after_flood`: 46%
     of 65,536).
   - (d) measures the effect. The same benign capture, replayed right after the flood without
     the register reset, gave 1,493 CPU reports for 2,768 flows (54%; the occupancy predicts
     1,505), and the CSV holds 54% of its packets.
   - So until the next register reset the collector misses about half of all new flows: a
     flood blinds the monitor to the traffic that follows it.
   - A fix has to clear the buckets that leave the active set unread, for example:
     - a blind clear on expiry (raw clears cost 0.09 ms per bucket, counted in the budget);
     - or, under overload, reading and clearing the oldest buckets as well as the newest.

### 12.3 Section 11.3: `hostmon_agg` on PC1 with the switch

Command: `--profile switch --hostmon hostmon_agg --hostmon-cgroup
/sys/fs/cgroup/unified/hazim_collect`, scenario `benign_workload.sh fanout; tcpreplay ...
ab_mix.pcap x59`.

- `HOSTMON_READY`, then `HOSTMON_HEALTH {'lost': 0, 'capacity_errors': 0, 'late_events': 0,
  'failed': 0}`.
- Host and network window start and end are equal in all 26 rows (the shared origin).
- The host rows show the fan-out (14-21 processes), then tcpreplay.
- The network CSV sums equal the truth.
- The cgroup was created and removed.

Notes:

- On a host with the hybrid cgroup layout the cgroup must be under `/sys/fs/cgroup/unified/`,
  not the RUNBOOK's `/sys/fs/cgroup/hazim_collect`.
- `ebpf_perf/build.sh` assumes the workstation's clang 14 and bpftool.
- `test_agg_equiv` does not build from this repo: it includes
  `libbpf-bootstrap/examples/c/hostmon.c`, and the committed copy is older than the one the
  test was written against (no `monotonic_ns`, `capacity_errors`, ...).

## 13. Results on the switch (2026-11-07, second session): the Section 11.4 reruns

Run from PC1 with ad2ee2e (`hybrid_collector.py`, `batched_reader.py`,
`read_registers_with_index.py`). The P4 is unchanged (`basic_newconn_head`), and the stand-in
captures are the ones from Section 12. The raw data is in the git-ignored run dir
`perf/results/cadence_fix_20261107_080818/` (README with every number, logs `NNN_*.txt`, the
scripts in `scripts/`).

### 13.1 Unit tests and the `clear_indexes` known answer

- `test_collector_cadence` + `test_batched_reader`: 55 OK (5 skipped).
- The full suite (104 tests) has one error that comes and goes (2 of 4 runs), in a file
  ad2ee2e does not touch:
  - `test_collector_robustness.HostmonStopTests.test_a_hostmon_that_ignores_signals_is_killed_with_its_group`;
  - its `alive()` helper opens `/proc/<pid>/stat` after the child has been reaped and raises
    `FileNotFoundError`, which should count as "not alive".
- Known answer, bucket 6886, raw route:
  - `--clear-indexes 6886` alone, with the bucket not read: cleared in 0 syncs, 0 read RPCs
    and 1 clear RPC (`cleared_unconditional` 1).
  - All 14 registers are 0 afterwards; dst stays 1.
  - The next packet sends a CPU report for 6886 and reads pkts 1, dst 2.
  - The legacy reader's `--indexes 6886 --clear-indexes 6886` clears it as well.

### 13.2 The reruns (`--profile switch`)

| run | windows | active median / max | read median | overrun rows | late_ms median / max | wall median / max | cleared | CSV sums |
|---|---|---|---|---|---|---|---|---|
| (c) SYN stand-in | 24 | 5,988 / 6,816 | 708 | 6 (Section 12: 19) | 273 / 452 | 656 / 836 (953) | 29,547 | read buckets only |
| (d) after (c), `--no-register-reset` | 21 | 507 / 536 | all | 0 | 16 / 33 | 410 / 505 | 2,171 | **91.2% of packets** (Section 12: 54%) |
| (c') (c) + `; sleep 6` | 31 | 5,924 / 6,607 | 794 | 5 | 231 / 476 | 654 / 797 | 35,062 | read buckets only |
| (d') after (c'), `--no-register-reset` | 21 | 559 / 575 | all | 0 | 19 / 32 | 442 / 493 | 2,376 | = truth |
| (b) ab_mix x59 | 21 | 555 / 575 | all | 0 | 17 / 43 | 439 / 469 | 2,362 | = truth |
| (a) ab_mix x6.5 | 183 | 62 / 71 | all | 0 | 3 / 7 | 97 / 128 | 2,739 | = truth |

**`--clear-expired` works.**

- In (c), 29,547 expired buckets were cleared unconditionally, from window 4 on (TTL 3).
  `net_clear_backlog` was 0 in every window; 0 clears were given up.
- After (c), 5,429 of 65,536 buckets were still occupied (8.3%; Section 12: 46%).
  - That is exactly the last window's active set: buckets still inside their TTL when
    tcpreplay ended. `--mode command` stops with the command (`drain_seconds` 0).
- (d) therefore reported 2,530 of 2,768 flows (91.4%; the occupancy predicts 2,539).
- With 6 more windows after the flood, (c'):
  - every reported bucket was cleared (35,062);
  - the table was empty afterwards (0 occupied);
  - (d') reported 2,768 of 2,768 with every CSV sum equal to the truth.
- So a collector that keeps running loses no flows after a flood. Only the end of a run leaves
  buckets occupied, which matters for a following `--no-register-reset` run.
- (c) has 34,976 reports against 29,902 distinct buckets: cleared buckets report again when a
  later flow lands in them.

**The deadline rule stops the lag but does not meet both 11.4 timing criteria.**

- What holds:
  - the cost estimate starts at the raw route's values;
  - the lateness does not grow (late_ms median 268 ms in the first half, 285 ms in the second);
  - there is no "overran by" warning;
  - overruns are 6 of 24 (19 of 25 before), and wall max is 836 ms.
- Criterion 1: `net_read_late_ms` "well under 100 ms" fails, with a **median of 273 ms**.
  - This is the collector's work between the boundary and the decision (`prep_ms` 193 ms).
  - `compute_newconn_dst_index` runs twice per report in the main loop (lines 1205 and 1234). It
    is a bitwise CRC-16, 44.5 us per call on PC1, which comes to 130-260 ms at 1,500-2,950
    reports per window.
  - The report thread computes `compute_flow_index` (49 us) for every arriving report and
    competes for the GIL.
  - When the reports stop ((c') window 24 on) late_ms is 12-28 ms. In (a), (b) and (d) it is
    3-19 ms.
  - The rule shrinks the allowance correctly (median 687 ms), so the price is fewer buckets read
    (median 708 vs ~1,180 in Section 12), not lag.
- Criterion 2: `wall_ms` ≤ `net_read_allow_ms` "in nearly every window" fails: 10 of 24 exceed
  it (nine by 0-41 ms, one by 105 ms).
  - The allowance is fixed at the decision. The selection after it is not counted: the dst
    ranking, the clear list, `select_within_budget` and the clear candidates. Offline at 6,000
    active and 6,000 dst buckets it takes 26 ms; it takes more under the report thread.
  - In 5 of the 6 overruns, late_ms + wall_ms is under 1,000 ms: those reads ended after the
    boundary only because of 11-58 ms of work between the decision and the read. Only one (w17)
    is an estimation miss.

**Fix 3 holds.** A window with nothing to read takes 2 ms ((c') w30), against 46-47 ms for one
that still reads dst buckets.

**(a) and (b)** pass every 11.2 criterion as before, and their wall times are unchanged.

### 13.3 Suggestions

1. Compute the dst index once per report, in the report thread when the report arrives (as
   `compute_flow_index` is), and use a table-driven CRC-16. That takes ~200 ms per window off
   the boundary at flood rates.
2. Take the decision time after the selection, or subtract its measured time from the
   allowance.
3. At the end of a run, clear the active set and the backlog (~0.5 s for 5,429 buckets on the
   raw route), or allow `--drain-seconds` in `--mode command`.
4. Make the `alive()` helper in `test_collector_robustness.py` treat a missing `/proc/<pid>/stat`
   as not alive.

### 13.4 What changed after 13.3, and what to rerun

All four suggestions are in `hybrid_collector.py`, `listen_cpu_reports.py`, `flow_index.py` and
the tests; no option or default changed.

1. **The dst index is computed in the capture thread, with a table-driven CRC.**
   `listen_cpu_reports.parse_cpu_report()` adds `dst_idx` to every TCP report as it arrives (`None`
   for other protocols), from the report's raw address integers. The window loop uses it and
   computes the index itself only for a report without it. `flow_index.crc16_arc()` does one table
   lookup per byte; `crc16_arc_bitwise()` is the old loop, kept as the reference, and the two agree
   on 4,000+ random keys (`test_flow_index`). On the lab workstation the bitwise CRC takes 5.1 us
   per 13-byte key and the table 0.93 us, and `parse_cpu_report()` with both indexes 3.6 us per
   report; PC1 measured 44.5 us for the bitwise `compute_newconn_dst_index`. The window loop no
   longer computes any CRC for a captured report.
2. **The work between the decision and the read is taken off the allowance, and so are the
   reads' prediction errors.** The cost model measures the selection (decision to read start,
   `select_ms`) and subtracts it, with `post_ms`, from the time left until the next boundary.
   It also keeps `margin_ms`, an average of how much the reads took longer than predicted (only
   overshoots count, so it decays to 0 while the predictions hold), and plans the read with that
   much time free. Both are in the printed cost estimate.
3. **With `--clear-expired`, the end of a run clears what is still occupied.** After the last
   window one more request clears the last windows' active set and the clear backlog
   unconditionally (nothing is read, and the batched reader does not sync), printed as
   `end of run: cleared N of the M buckets still occupied`. A failure there only prints a
   warning. `--drain-seconds` in `--mode command` is unchanged.
4. **`alive()`** in `test_collector_robustness.py` counts a process reaped between its two checks as
   not alive: `FileNotFoundError` before the open of `/proc/<pid>/stat`, and `ProcessLookupError`
   between the open and the read (the form seen on the lab workstation). The full suite, 111
   tests, passed 4 of 4 runs.

Not changed: `on_window()` re-reads the whole monitor log every window to write the ready host
rows. That is negligible for these runs, but it grows with the run's length, so an hours-long
run needs an incremental reader there.

Rerun on PC1 (pull first; `--profile switch`, the stand-in captures):

- (c), then (d) right after it with `--no-register-reset`, without the `; sleep 6` of (c').
  Expect `net_read_late_ms` with a median well under 100 ms, `wall_ms` at or under
  `net_read_allow_ms` in nearly every window, 0-1 overruns, and the end-of-run line clearing about
  5,400 buckets. After (c) the occupancy check should find 0 occupied, and (d) should report
  2,768 of 2,768 flows with the CSV sums equal to the truth.
- (a) and (b) as a regression (Section 11.2's criteria).

The dataset's own captures are now in the repository: `live_test/captures/bulk2000.pcap`
(heavy benign, for (b)) and `live_test/captures/syn_fan_40k.pcap` (the SYN fan-out, for (c)),
each with its truth and the replay commands in `live_test/captures/README.md`. Note that the
dataset's SYN flood is a 0.70 s burst at 57,000 SYNs/s: replay it with `--pps 2000` to compare
with the stand-in, and at its original timing for the burst.

## 14. Results on the switch (2026-11-07, third session): the Section 13.4 reruns

Run from PC1 with e8a3d2d and 45129e0. P4, captures and setup are as in Sections 12 and 13.
The raw data is in the git-ignored run dir `perf/results/switch_v3_20261107_091147/` (README
with every number, `cad_flood/cost_replay.txt`, the scripts in `scripts/`).

### 14.1 PC1 without the switch

- Full unit-test suite: 111 OK (5 skipped) in 4 of 4 runs. The `alive()` race is fixed.
- `DEP=/usr CLANG=clang-10 BPFTOOL=<bpftool v7.3.0> ./ebpf_perf/build.sh` builds every binary
  and `sha256.txt`, then **exits 141**.
  - The cause is `"$BPFTOOL" --version | head -1` under `set -o pipefail`: this bpftool prints
    3 lines, and `head` closes the pipe after the first.
  - It happened in both builds. `clang-version.txt` and the `built:` line are missing.
  - `sed -n 1p` instead of `head -1` (for both version lines) fixes it.
  - The warnings about `struct bpf_link_info` / `enum bpf_link_type` come from PC1's older
    system UAPI headers and are harmless (`-I$BOOT/libbpf/include/uapi` silences them).
- `test_agg_equiv` now builds from the repository and **passes on PC1**: 3,006 scenarios,
  37,445 rows identical.

### 14.2 The reruns (`--profile switch`)

| run | windows | active median / max | read median | overrun rows | late_ms median / max | wall > allow | wall median / max | end-of-run clear | CSV sums |
|---|---|---|---|---|---|---|---|---|---|
| (c) SYN stand-in | 22 | 6,517 / 7,803 | 919 (Section 13: 708) | 2 (6) | 71 / 307 (273 / 452) | 5 (10) | 770 / 894 | 6,619 of 6,619 in 594 ms | read buckets only |
| (d) after (c), `--no-register-reset` | 21 | 559 / 572 | all | 0 | 3 / 5 | 0 | 426 / 466 | 391 | **= truth** (Section 13: 91%) |
| (b) ab_mix x59 | 21 | 561 / 576 | all | 0 | 3 / 12 | 0 | 422 / 453 | 384 | = truth |
| (a) ab_mix x6.5 | 183 | 62 / 71 | all | 0 | 2 / 5 | 0 | 97 / 117 | 30 | = truth |

What meets the 13.4 expectations:

- **The end-of-run line:** `cleared 6619 of the 6619 buckets still occupied`, in 594 ms.
  - Every bucket reported in (c) was cleared: 28,208 on expiry plus 6,619 at the end, which is
    the report count of 34,827.
- **Occupancy after (c):** 0 of 65,536.
- **(d):** 2,768 of 2,768 flows, and every CSV sum equals the truth.
- **(a) and (b):** pass Section 11.2's criteria. Their late_ms fell from 3-17 ms to 2-3 ms.

What falls slightly short:

- **`net_read_late_ms` "well under 100 ms":** median 71 ms, steady at 67 / 73 in the two halves.
  - The cost model ends at `prep_ms` 59, `select_ms` 54 and `post_ms` 50 ms (~1,600 reports and
    ~6,500 active buckets per window).
  - The max, 307 ms in w14, follows w13's overrun. The deadline rule cut w14's allowance to
    509 ms, and w15 was back at 41 ms.
- **`wall_ms` ≤ `net_read_allow_ms` "in nearly every window":** 16 of 21; 5 exceed it by
  12-106 ms.
- **"0-1 overruns":** 2 (w10 and w13).

Why (`cost_replay.txt`, the cost model replayed over the run's timing records):

- Clears (0.085-0.092 ms per bucket), syncs (30-35 ms) and the overhead are predicted well.
- The read cost on the switch varies from 0.52 to 0.75 ms per unit. w10 and w13 ran at 0.69 and
  0.75 ms against the model's ~0.60, which is 111 and 131 ms over the prediction.
- The margin before them was 16 and 25 ms. It is an EMA (alpha 0.3) of the overshoots, which
  occur in 7 of 21 windows, so it decays in between.
- In flood windows, late + select + post + 5 ms leaves ~820 ms before the boundary, so the
  800 ms budget is nearly the deadline. Every read is planned for 800 ms, and a read that is
  15-25% slow crosses the boundary.

### 14.3 Suggestions

1. Size the margin from a high percentile of the recent overshoots (for example the p90 of the
   last 10 windows, or the max with a slow decay) instead of the EMA. Or keep a relative headroom
   of ~15% of the predicted read time. Or lower `--read-budget-frac` to 0.7 in `--profile switch`.
   Each costs about 100-150 buckets per flood window, and should bring the overruns to 0-1.
2. `ebpf_perf/build.sh`: replace `| head -1` with `| sed -n 1p` on the two version lines.
3. `test_batched_reader.EquivalenceTests.test_rpc_counts_per_window` fails wherever the SDE's
   `bfruntime_pb2` is importable (checked on PC1 with the switch's SDE 9.6 modules): `197 != 203`.
   - Line 477 expects one sync Write per window with `--sync-batched` (`len(win_s) +
     windows_with_clears`). Since Section 11.4, a window with nothing to read is not synced.
   - In the scenario, 114 of 120 windows sync and 83 clear: 114 + 83 = 197 is right, and the
     expected value should be `windows_with_sync + windows_with_clears`.
   - Without `bfruntime_pb2` the line takes its `else` branch, so the suite passes on PC1 and
     the lab workstation as they are.
4. `test_batched_reader.RawWireTests.test_wire_parser_decodes_a_server_style_response` still
   errors with the SDE 9.6 modules: it sets `ReadResponse.status`, a field SDE 9.6 does not have
   (open since Section 10). It should skip when the field is absent.

## 15. The 14.3 fixes, and the 0.7 budget on the switch (2026-11-07, fourth session)

Changes, made on PC1 on top of 45129e0 (with this section, uncommitted when written):

- `ebpf_perf/build.sh`: `sed -n 1p` instead of `head -1` on the two version lines (14.1).
- `test_batched_reader.py`:
  - `test_rpc_counts_per_window` expects one sync Write per synced window (14.3 item 3);
  - `test_wire_parser_decodes_a_server_style_response` adds `ReadResponse.status` only where
    the field exists (item 4).
- `hybrid_collector.py`: `--profile switch` sets `--read-budget-frac 0.7` instead of 0.8
  (item 1, the simplest of its three options), with the comment and the `--profile` help
  updated. The file keeps its CRLF line endings.
- `test_collector_cadence.py`: the profile test expects 0.7.

Results (raw data in the git-ignored `perf/results/switch_v4_20261107_094158/`, README with
every number):

- Unit tests: 111 OK both without the SDE protobufs and with the switch's SDE 9.6
  `bfruntime_pb2` (2 of 2 runs each). `build.sh` exits 0 on PC1; `test_agg_equiv` passes.
- On the switch, `--profile switch` (budget 700 ms), stand-in captures:

  | run | read median | overrun rows | late_ms median / max | wall max | CSV sums |
  |---|---|---|---|---|---|
  | (c) SYN stand-in | 764 (0.8: 919) | **0** (0.8: 2) | 58 / 122 | 837 | read buckets only |
  | (d) after (c), no reset | all | 0 | 3 / 5 | 556 | = truth |
  | (c2) SYN stand-in again | 711 | **0** | 57 / 85 | 717 | read buckets only |
  | (b) ab_mix x59 | all | 0 | 3 / 7 | 507 | = truth |
  | (a) ab_mix x6.5 | all | 0 | 2 / 4 | 122 | = truth |
  | (e) ab_mix x6.5 for 20 s, then the SYN stand-in | 65 benign; 506-892 flood | **0** | 20 / 95 | 714 | - |

  - All flood buckets are cleared, the last ones by the end-of-run clear (5,829-6,728 buckets
    in 0.5-0.6 s). The occupancy after (c) is 0.
  - In a flood window the allowance now leaves ~120 ms before the boundary, so a read up to
    ~120 ms slower than planned still ends in time. Two reads in (c) were 60 and 137 ms slower
    than their allowance; neither overran.
  - The cost is ~150-200 fewer buckets read per flood window. For benign traffic the budget
    does not bind: (b)'s largest read takes 507 ms.
  - late_ms levels off with the active set (41-85 ms in windows 11-21 at ~6,500 active
    buckets); it does not grow with time.
  - The clear backlog was nonzero once: up to 1,116 buckets in (c2) windows 5-7, when window
    1's ~3,000 buckets expired together. It was empty from window 8 on.

One smaller finding (not changed): the cost model's cold start.

- The per-bucket read and clear costs are fitted without a per-request part, so small reads
  overstate them.
  - In (c2), window 0 read 11 buckets in 31 ms, ~24 ms of it the 15 read requests, so the
    model learned 2.46 ms per unit.
  - Window 1 then read 509 buckets instead of ~1,000; the model recovered by window 4.
- In (e), the realistic case, the benign windows (~65 reads, ~16 clears) taught the model
  0.75-0.9 ms per read and 0.13-0.21 ms per clear. At flood sizes these are ~0.58 and 0.09.
  - So the first six flood windows read 506-892 buckets, each ending 65-125 ms inside its
    allowance (10-30% under what fits), until ~w29.
- The error is on the safe side.
- Fix, if wanted: fit read time = a + b x units and clear time = c + d x buckets (or fold the
  per-request part into `fixed_ms`), or update the per-bucket estimates only from windows with
  at least ~200 units.

Not yet run: the real dataset captures (`bulk2000`, `syn_fan_40k`, on the lab workstation,
not on PC1), and runs longer than ~3 minutes (`on_window()` re-reads the whole monitor log,
Section 13.4).

## 16. The dataset's own captures on the switch (2026-11-07, fifth session)

These are the replays of `live_test/captures/` (51cc9d7) with the Section 15 working tree
(budget 0.7), as its README describes. The raw data is in the git-ignored
`perf/results/switch_v5_20261107_104051/` (README with every number, the scripts in
`scripts/`).

| run | overload rows | overrun rows | late_ms median / max | CPU reports | after the run |
|---|---|---|---|---|---|
| (b) `bulk2000`, original timing | **5** | 0 | 2 / 4 | 2,002 (1,830-2,002 expected) | CSV sums **= truth** in all seven columns |
| (c1) `syn_fan_40k --pps 2000` | 20 | 0 | 64 / 102 | 33,509 (≥ 29,843) | **176 buckets occupied**; (d) then 2,762 of 2,768 flows |
| (c2) `syn_fan_40k`, original timing (57,000 SYNs/s) | 11 | 2 (the burst windows) | 17 / 652 | **29,844 = 29,843 buckets + 1 probe** | 0 occupied; (d) 2,768 of 2,768, = truth |

What holds:

- (b) is exact and on time.
- The CPU-report path loses nothing at the dataset's 57,000 SYNs/s: every distinct bucket
  reported, all delivered within ~2 windows.
- The clear backlog after the burst (peak 22,164 expired buckets) drains at ~3,500-3,850 per
  window and is empty by window 12, as `live_test/captures/README.md` expects.

Three findings:

1. **The cost model's cold start gives a false overload in benign traffic** (Section 15's
   finding, now harmful).
   - In (b), window 1 read one bucket (the collector's connection probe) in 21 ms of
     per-request overhead, and the model learned 18.6 ms per bucket.
   - Windows 3-7 of benign traffic then skipped 359 bucket reads and carry `net_overload` 1,
     with reads of only 142-308 ms in a 700 ms allowance. The model recovered by window 8.
   - The totals stay exact (the skipped buckets' packets show up in later reads), but those
     windows' register features are low and wrongly flagged. Any run that starts with a single
     connection gets this.
   - Fix: fit read time = a + b x units and clear time = c + d x buckets (or move the
     per-request part into `fixed_ms`), or learn the per-bucket costs only from windows with
     at least ~100-200 units.
2. **Reports that arrive after the last window are never cleared.**
   - After (c1), 176 buckets stayed occupied. Matched to the capture by bucket index and source
     port, all 176 are single SYNs sent in the last 0.1 s of the replay (19.89-19.99 s). None
     is from earlier, so no report was lost mid-run.
   - Their reports reached the collector after its last window took its reports. The end-of-run
     clear covers only tracked buckets, so it skipped them, and the next capture without a reset
     lost 6 of 2,768 flows.
   - Fix: before the end-of-run clear, wait briefly (~0.5-1 s, or until no report for ~0.3 s),
     take the late reports, and clear their buckets as well. Or run one more full window after
     the command ends (`--drain-seconds` in `--mode command`).
   - Likely factor (not measured): tcpreplay's pacing on PC1. A 0.5 ms gap plus ~80 us of timer
     overshoot gives 1,724 packets/s, the rate the stand-in replays actually ran at and the
     `rep_new_flows` of several (c1) windows. At `--pps 2000`, tcpreplay catches up in bursts.
3. **A 57,000/s burst decides two reads late.**
   - Processing 17,859 and 11,450 reports in a window (~36 us each on PC1) puts w1 651 ms and w2
     309 ms behind. The deadline rule shrinks both allowances, but both end slightly after the
     boundary; w3 is on time.
   - Acceptable as is. The burst window reads 438 of 17,859 active buckets (its `rep_*`
     features are complete).

## 17. The fixes for 16's findings 1 and 2, on the switch (2026-11-07, sixth session)

Changes (on PC1, with Sections 14-16 in the same commit):

1. **`ReadCostModel` per-request parts.**
   - `ROUTE_COSTS["raw"]` now holds `read_fixed_ms` 23 (the Read RPCs), `read_ms_per_bucket`
     0.56, `clear_fixed_ms` 3 (the Write), `clear_ms_per_bucket` 0.088 and `min_rate_units` 20.
     They are fitted to Section 16's reads: 1 bucket 21 ms, 101 buckets 74 ms, 1,054 units
     612 ms.
   - `predict_ms` and `buckets_within` add the per-request parts.
   - `update` takes them off before learning the per-bucket costs, and learns nothing per bucket
     from reads or clears smaller than `min_rate_units`.
   - `"fast"` gets `min_rate_units` 20 only; `"legacy"`, `"model"` and directly built models are
     unchanged.
2. **Late reports at the end of a run.**
   - `ReportCollector.take_after(t)`.
   - With `--clear-expired`, `wait_for_late_reports()` waits until no report has come for
     0.3 s (at most 1 s). The buckets of the reports received after the last window are then
     added to the end-of-run clear (named in its line, `windows[-1]["late_report_indexes"]`).
3. Five tests. The two collector tests fail against the previous code, with exactly Section
   16's symptoms. Suite: 116 OK, with and without SDE 9.6's `bfruntime_pb2`.

Results (git-ignored `perf/results/switch_v6_20261107_113553/`, README with every number):

- **bulk2000 (b):** 0 overloaded windows (Section 16: 5) and 0 skipped bucket reads (359). After
  the one-bucket first window, every active bucket was read. All seven CSV sums equal the
  truth.
- **`syn_fan_40k --pps 2000` (c1), twice:** 0 overruns, occupancy 0 afterwards, and (d) after the
  first gives 2,768 of 2,768 flows with every sum equal to the truth.
  - Neither run had a late report; Section 16's had 176, as tcpreplay's timing varies.
  - So a third run adds 300 SYNs at 200/s from 0.2 s after tcpreplay exits. The end-of-run clear
    took 184 buckets from 184 late reports.
  - 33 buckets stayed occupied: the trickle's last packets (264-299), sent after the
    collector's 1 s wait had ended, which no run can see.
- **The burst (c2):** as in Section 16. No report lost, 2 overruns in the burst windows,
  occupancy 0.
- **ab_mix x6.5 (a):** exact, 0 overload.

One new, rare finding: **a clear can race a packet and leave a torn bucket.**

- After the trickle run, bucket 20531 held pkts 1 and bytes 60, with dir_valid, ports, lengths,
  timestamps and flags 0. Its only packets are flood packets #10514 and #21201 (~5.3 s and
  ~10.6 s).
- The likely cause is the clear's order. `batched_reader._clear` sends one Write ordered by
  register (every bucket's `reg_pkts`, then every bucket's `reg_bytes`, ..., `reg_rst`), so a
  bucket's first and last registers are zeroed up to the Write's duration apart: ~150 ms for a
  flood window's clears.
- A packet in that gap:
  - is counted in the registers that are already zero;
  - sees the old `dir_valid` 1, so it sends no CPU report, and its flow is lost;
  - leaves the bucket with dir_valid 0 and stale counts once the clear finishes.
- Seen once in three flood runs (~30,000 clears each). It predates these fixes.
- Possible fix: order the clear's updates bucket by bucket, so each bucket's 14 registers are
  zeroed in 14 consecutive updates; then re-measure the clear cost.

## 18. The torn-bucket fix, and two report-capture fixes (2026-11-07, seventh session)

Raw data in the git-ignored `perf/results/switch_v7_20261107_120526/` (README with every number,
the scripts in `scripts/`). Unit tests: 118 OK, with and without SDE 9.6's `bfruntime_pb2`.

### 18.1 The clear writes bucket by bucket

- **The change** (`batched_reader.py`): the raw and fast routes write their one clear Write
  bucket by bucket (all 14 registers of a bucket, then the next) instead of register by
  register.
- **The order within a bucket** (`CLEAR_FIRST`): the two reference ports, `reg_dir_valid`, then
  the counters. A packet that lands mid-clear then either:
  - still sees the old `reg_dir_valid` and is wiped with the rest (the bucket ends empty and the
    flow reports at its next packet);
  - or sees it 0 and reports as a new flow with its own reference ports, losing only its own
    counts.
- **Unchanged:** the safe route (`entry_mod`, one Write per table) stays register-ordered; the
  legacy reader already clears bucket by bucket.
- **Race test:** 16,000 buckets cleared in one Write while the same 16,000 SYNs are replayed at
  2,500/s (~3,400 land mid-clear).
  - Old order: **10 and 10 torn**, 5 of each without a CPU report.
  - New order: **0 and 0**; every bucket filled after its clear is consistent and has exactly one
    report.
- **Cost:** +22-29% clear time (1,000 buckets 95 → 116 ms, 5,000 423 → 532 ms, 16,000 1,320 →
  1,708 ms). `ROUTE_COSTS["raw"]["clear_ms_per_bucket"]` is 0.105 now. That is ~35 ms (~60 bucket
  reads) per flood window and ~2.5 ms per benign window.

### 18.2 The workload starts once the capture listens

- **The problem:** a flood run left 33 consistent buckets occupied, from the first 0.02 s of the
  replay. Their reports were sent before the remote tcpdump listened.
- **The change:**
  - `ReportCollector.wait_ready()` waits for tcpdump's `listening on` line (its stderr is kept in
    `capture_messages`);
  - the collector waits for it, at most 10 s (`REPORT_CAPTURE_READY_S`), before starting the
    workload; so does `reader_ab.py`.
- **On the switch:** listening after 0.3 s; occupancy after four flood runs: 0.

### 18.3 `tcpdump --immediate-mode`: the reports came in one burst per ~1 s

- **The symptom:** with 18.2, all 7 ab_mix x59 runs had one window with 0 reports and 0 packets
  (w8-w10), and 13-21 reports arrived after the last window.
- **Ruled out:** a gap in the capture, a wall-clock step (sampled), PC1's sending (eth1 counter
  and capture continuous), the switch (a second tcpdump on `enp5s0` saw all reports
  continuously), and the start time.
- **What a trace showed:**
  - `traced_collector.py` wraps `_add`, `take` and the batched read: the reports reached the
    collector **in one burst per 1.016-1.017 s**;
  - the bursts drift ~16 ms per second, and when one crosses a window boundary that window gets
    none and every later window the previous window's.
- **The cause:** the remote `tcpdump -U -w -` ran without immediate mode. libpcap hands captured
  packets over in blocks, at the latest when its 1 s timeout expires; `-U` flushes only what
  tcpdump already has.
- **The fix:** `tcpdump --immediate-mode -U ...` (tcpdump 4.9.3 on the switch).
- **With it:**
  - reports arrive continuously (largest gap 34 ms), w0 holds the whole first second, and the
    per-window counts follow PC1's sending second by second;
  - ab_mix x59 and bulk2000: no empty window, 0 late reports, CSV sums = truth;
  - flood at 2,000/s: 0 overruns, occupancy 0;
  - the 57,000 SYNs/s burst: 29,844 reports, every bucket.
- **Consequence for Sections 9-17:**
  - every switch collector run received its reports up to ~1 s late, in bursts. Totals are
    unaffected, but `rep_*` features and a new flow's first read could fall one window late, and
    w0 often had no reports;
  - Section 16's late reports at the end of a run and the 1,724-per-window plateaus come from
    this batching, not from tcpreplay's pacing as guessed there;
  - per-window results from those runs should not be used as window-exact.
- **Note:** with immediate mode a burst window's `cpu_indexes` CSV field reaches ~150 KB, so
  readers using Python's `csv` module need `csv.field_size_limit()` raised.

## 19. For the VM side: how to run the end-to-end evaluation (decision needed, 2026-11-07)

Written on PC1 after Section 18 for the agent and the user on the VM, where `hybrid_collector.py`
runs with HostMon (eBPF) and the Tofino model (`--profile model`). Nothing is decided yet; the
answers to 19.3 decide it. Paths in `dataset-construction/` are in the dataset repository.

### 19.1 What limits the choice

- **The model only manages 60 s windows** (`--profile model`; its 15 syncs take 45-140 s, sync
  plus read 52-232 s per window). The hardware switch reads exactly every 1 s (Sections 15-18).
- **The trained detection model uses 0.5 s windows and ~20 s samples:**
  - `dataset-construction/scripts/vbox_malware_batch.sh:64` `WINDOW_SEC="0.5"`, the default,
    to be confirmed from the cohort's run metadata;
  - `:63` `TIMEOUT="20"`, the per-sample runner timeout;
  - the two cohort captures in `live_test/captures/` last 22.2 s and 23.3 s.
- **The inference statistics** are mean, max, sum, std and active_windows over a sample's
  windows (`dataset-construction/src/live_arm_inference.py:12`). 7 of the 9 network metrics are
  per-window totals; only `net_bytes_per_second` and `net_packets_per_second` are rates
  (`thesis-hybrid-ebpf-p4/python/live_feature_export.py:64-74`).
- **So at 60 s windows a 20 s sample is one partial window:** mean = max = sum, std = 0,
  active_windows = 1. That input is outside what the model was trained on, whatever the
  values. Retraining at 60 s cannot fix it, because a sample is shorter than one window.
- **Host metrics:**
  - the counts (`host_exec_total`, `host_connect_total`, `host_file_events_total`) can be
    summed from 0.5 s windows into longer ones;
  - `host_active_processes`, `host_entropy_mean/max`, `host_avg_run_length_mean/max` and
    `host_cpu_percent` cannot.
- **The live network values also differ from the training ones**, at any window length.
  Training measured in the guest (`dataset-construction/src/malware_runner.py`):
  - two unidirectional flows per connection, against one symmetric bucket on the switch;
  - whole frames, against the IPv4 length;
  - all frames, against IPv4 TCP/UDP only;
  - the guest's send and receive, against the direction of the bucket's first packet.

### 19.2 Options

| | how | gives | costs |
|---|---|---|---|
| **A** (recommended from PC1) | Compute the 9 network metrics of every cohort sample from its packet capture with the switch's rules at 0.5 s windows and retrain. Check the extractor by replaying cohort captures through the Wedge100BF at `--window-sec 0.5`, window by window. For detection, run inference on the switch's windows plus the same sample's recorded eBPF windows. Run the VM + model once live as a demonstration. | Detection results from the real P4 program on hardware, comparable to training; no malware on NETLAB (only packets are replayed) | the extractor and a retrain; a 0.5 s capacity run on the switch; the host side comes from recordings |
| **B** | Live on the VM + model at 60 s | The whole pipeline running with live malware | No comparable detection numbers (19.1) |
| **C** | Retrain at 1 s, the switch's measured cadence | The hardware at its proven cadence | Exact host features at 1 s only if each sample's raw eBPF events were kept (19.1) |
| **D** | On the VM, compute the 9 network metrics in software from the live packets with the switch's rules, at 0.5 s; the model cannot keep up, so it stays out of the feature path | Live malware runs with features comparable to training | The P4 program is not in the loop for the numbers; the software rules need A's hardware check |

### 19.3 Questions for the VM side

1. Which window length and sample length did the trained model use? A cohort run's
   `window_seconds` and observation length would tell.
2. Are each sample's raw eBPF events kept, or only its 0.5 s windows? This decides C.
3. Does `analyze_p4_pcap_ablation.py` (after 0b64bef) already follow the switch's rules? Those
   are: IPv4 length, one symmetric bucket per CRC16 index with collisions merged, IPv4 TCP/UDP
   only, direction from the bucket's first packet. If it does, A's extractor is mostly done.
4. What must the thesis show:
   - that the pipeline runs live (B or D);
   - that live detection matches offline detection (A);
   - or both (A + B)?

### 19.4 What PC1 can do once decided

- **The 0.5 s capacity run on the switch:** bulk2000 and the flood at `--window-sec 0.5`. It is
  not measured yet; the estimate:
  - the allowance would be 0.7 x 500 = 350 ms;
  - at 65 + 23 ms per read and 0.56 ms per bucket, that holds roughly 430 buckets next to ~60
    clears;
  - bulk2000 had at most 456 active buckets at 1 s windows (3 s TTL), so about 250-300 are
    expected at 0.5 s (1.5 s TTL).
- **Replays through the switch** of any cohort capture added to the repository, compared window
  by window with an offline extractor.

## 19.5 Answers from the VM side (2026-11-07)

Written on the lab workstation from the collections' own metadata, the release repository
(`p4-ebpf-malware-detection`), and the offline tests of 2026-11-04 to 2026-11-07. The decisions
below were taken by the author.

### 19.5.1 Which trained model counts

- The model 19.1 describes (`dataset-construction/src/live_arm_inference.py`,
  `train_shared_arm_classifier.py`, the 2026-10-15 run under
  `data/malware/revision4/family-heldout-balanced-224-v1-20261014/models/`) is the shared-arm
  classifier: 9 runtime network counters and 9 host counters, 5 statistics each, plus 2
  availability flags, trained on the 224-malware / 138-benign cohort (362 executions, 57 groups)
  whose benign controls are shell scripts. The thesis lists it as future work only and never
  reports it as a result. Do not evaluate against it.
- The thesis and paper detectors use 29 P4 window features x 5 = 145 network columns and 18 ADFA
  host features x 5 = 90 host columns, from the same 0.5 s windows. Definitions: release
  `features/switch_model.py` and `features/host_model.py`; data: `dataset/features.csv`
  (240 rows); `evaluation/heldout.py` and `evaluation/combined.py` reproduce Tables IV and V.
- Against that contract, 19.1's "training differs from live" list reads:

  | 19.1 says training measured | thesis contract |
  |---|---|
  | two unidirectional flows per connection | no: one bidirectional flow per (protocol, sorted endpoints), direction from its first packet, as on the switch |
  | all frames | no: IPv4 TCP/UDP first fragments only, as on the switch |
  | direction from the guest's send/receive | no: first packet |
  | whole frames instead of the IPv4 length | yes: the dataset counts Ethernet frame bytes; the switch counts IPv4 `totalLen` (14 B per packet less, and no padding under 60 B) |

  Two differences 19.1 does not list, both measured in release `validation/RESULTS.md` (13 of 13
  count features equal on 8 captures): the switch merges flows that collide in a CRC-16 bucket
  (the extractor keeps an exact table), and the switch's 32-bit ns clock wraps at 4.295 s
  (durations alias).
- The host metrics listed as "cannot be summed into longer windows" are the shared-arm model's.
  The thesis host features are recomputed from archived raw events at any window length (19.5.3).

### 19.5.2 Q1: window and sample length

From every cohort run's `run.json` (checked on all 240 dataset rows): `window_seconds` 0.5,
`windows` 40, `timeout_seconds` 20.0, `observation_mode` "fixed", observation end minus sample
start = 20.000 s, `p4_network_active_ttl_windows` 3, `telemetry_schema_version` 2026-10-24.21.
The grid is anchored at `sample_started_wall_us` (whole microseconds): window k covers
[anchor + 0.5k s, anchor + 0.5(k+1) s). The two captures in `live_test/captures/` last 22-23 s
because they include the pre- and post-window capture probes and the 1 s drain.

### 19.5.3 Q2: raw eBPF events

Kept. Each run archives `syscall_events.csv` (`timestamp_ns, window_id, pid, tid, comm, event,
detail=id=N`), `ebpf_events.csv` (named events) and `exec_events.csv` (exec successes and
returns). On 2026-11-06 all 240 runs were re-binned at 1, 2, 5 and 10 s with the release
`host_model.py`, and the network side recomputed from the captures (TTL 3 windows at every
length). At 0.5 s the rebuild equals the stored telemetry in every window of every run (0 cells
off). Grouped CV, 10 fold assignments (seeds 42 and 0-8), balanced accuracy:

| window | host | network | hybrid |
|---|---|---|---|
| 0.5 s | .784 | .756 | .823 |
| 1 s | .782 | .753 | .815 |
| 2 s | .780 | .756 | .816 |
| 5 s | .795 | .763 | .826 |
| 10 s | .789 | .772 | .836 |

Option C's cost is already paid: 1 s windows change nothing, host or network.

### 19.5.4 Q3: does the offline extractor follow the switch's rules

| switch rule | release `switch_model.py` | to make it switch-exact |
|---|---|---|
| IPv4 TCP/UDP only | same | - |
| one bucket per connection, direction from the first packet | same | - |
| rates over the nominal window | same | - |
| IPv4 total length | Ethernet frame (`len(frame)`), padding included | count the IPv4 total length; the study extractor `analyze_p4_pcap_ablation.py` already has `byte_layer="ipv4"` |
| CRC-16 bucket, collisions merged | exact 5-tuple table | key by `crc16_arc` from release `p4/control_plane/flow_index.py` (equal to the compiled hash bit for bit); only the 15 DoS runs and one scanner collide (cohort p99: 9 active flows per 0.5 s window) |
| 32-bit ns timestamps | unbounded | mask first and last timestamps to 32 bits |

A's extractor is therefore three small changes, then a recompute of the 240 rows and a retrain.

### 19.5.5 Q4 and the decision

- What the thesis claims today: the sensors are validated live (release `validation/`,
  2026-11-04); the detection numbers are offline; no live detection number is claimed; the
  three-arm pipeline is future work. A live detection result is an addition, not a repair.
- **Decision: option A at 1 s windows** (A and C together), **B once as a demonstration without
  numbers**, D not needed (its software rules are the extractor that A validates on hardware).
  Reasons: 1 s is the cadence Sections 15-18 proved (exact benign sums, 0 overruns at budget 0.7,
  overload mode for floods, empty table afterwards); 0.5 s is unmeasured and tight (19.4: about
  430 buckets against bulk2000's 250-300); retraining at 1 s costs nothing (19.5.3); host
  features at 1 s are exact rebins. If 0.5 s is insisted on later, run 19.4's capacity test first.

### 19.5.6 The launch prologue: excluded on both sides

- Every dataset row's host features include the collector's launch wrapper,
  `/bin/bash -c 'exec "$@"' sample-launch <program> <args>` (stdin `/dev/null`, new session,
  cwd = a private workspace). Bash's startup before it execs the target is exactly 178 system
  calls, with one run of 54 identical calls, all in window 0: host total = the program's own calls
  + 178 (null rows 196 = 18 + 178). It is class-independent. The 2026-11-04 ablation removed it
  (root pid, timestamp before the second root exec success in `exec_events.csv`) and recomputed
  the 90 host columns: held-out host BA 0.929 -> 0.929 (same confusion matrix), grouped CV host
  0.632 -> 0.748 and hybrid 0.718 -> 0.807, combined host 0.784 -> 0.832 and hybrid
  0.823 -> 0.866. The scripts and the 240-row `features_launcherfree.csv` are on the lab
  workstation (`additional-study-review-20261022/launcher-ablation/`), not in a repository yet.
- **Decision:** for A's comparison and for any live run, host features start at the target's own
  exec, on both sides. Recorded rows: drop the root's calls before its exec success (the window
  grid stays anchored at launch). Live rows: the monitored process joins the cgroup immediately
  before it execs the target, and nothing else runs in the cgroup first. Train the models used
  for A on the prologue-free rows. The published tables stay as collected; the thesis reports the
  ablation.
- Consequence for `hybrid_collector.py --hostmon-cgroup`: `cgroup_wrapped_command` runs
  `bash -c 'echo $$ > cgroup.procs && exec "$1" -c "$2"'`, so the monitored lineage starts with
  the cgroup write and a second bash parsing a command string: a prologue that matches neither the
  dataset's 178 calls nor the validation's `collect.py`. Change it to join the cgroup and then
  `exec "$@"` with the program and its arguments as argv (or cut at the exec boundary in
  post-processing), before any A or B run.

### 19.5.7 Plan

1. VM side: the switch-exact extractor (19.5.4); recompute the 240 network rows at 1 s (20
   windows, TTL 3 windows) and the prologue-free host rows at 1 s; retrain; report grouped CV
   mean and sd over the 10 fold assignments as the offline reference.
2. PC1: replay the cohort captures through the Wedge at `--window-sec 1`, TTL 3,
   `--clear-expired`, immediate-mode report capture, with the window grid anchored at each run's
   `sample_started_wall_us` (the first frame is the pre-window probe about 1 s before the anchor;
   offset the collector's window 0 accordingly). Compare the 29 features window by window with the
   switch-exact extractor: counts, bytes, durations and collisions should now all be exact.
3. Score the switch windows together with the same run's prologue-free eBPF windows using the
   retrained models, and compare the decisions with the offline rows.
4. VM: one live run with the Tofino model (`--profile model`) as the demonstration; no numbers.

Data: the 204 CLI-benign and malware captures total 25 MB (largest 24 MB); the flood21
collection's 41 captures total 923 MB (largest 372 MB, `bulkup_700`), 36 of them in the pool.
Replays carry packets only; destinations are 10.0.0.x and the floods' random scan targets.

## 19.6 PC1's notes on the plan, and the replay driver (2026-11-08)

Written on PC1 for the VM side after 19.5. PC1 agrees with 19.5.5: option A at 1 s, B once as a
demonstration. The user decided that the floods are not replayed on hardware, so the 36 flood21
runs stay offline only (PC1's disk could not hold them anyway: 328 MB free). Raw data is in the
git-ignored `perf/results/replay_v1_20261108_061848/` (README with every number).

### 19.6.1 What step 2 (19.5.7) can expect, window by window

1. **The registers are cut after the window ends.**
   - A window's register values are taken in the snapshot that follows its end. On bulk2000 it
     starts 5-7 ms after the boundary and lasts ~35 ms (max 37.6). Packets sent in that interval
     count in the window that just ended.
   - CPU reports are cut by their arrival on PC1, a few ms after the packet with
     `--immediate-mode`.
   - Measured with the replay on the grid (19.6.3): the switch's per-window packet counts equal a
     nominal-boundary count in 13 of 21 busy windows and differ by 3-7 packets (at most 0.6%) in
     the others. Totals are exact.
   - So expect small but non-zero per-window differences in counts and in features built from
     them. The extractor can reproduce them exactly by cutting at the logged snapshot times
     (19.6.2).
2. **The replay must keep the capture's timing.**
   - tcpreplay times each frame relative to the previous one. On PC1 it was 254 ms late after
     bulk2000's 22 s (156 ms with `-K`; 2.7-2.9 s with `--timer=nano` or `select`). That would put
     the network windows out of step with the run's recorded eBPF windows.
   - The driver replays with `live_test/replay_absolute.py` instead: frame i goes out at
     start + (t_i - t_0). Timing error median 0.09 ms, max 8.4 ms; anchor alignment error
     0.02 ms.
   - Compare against what PC1 actually sent: the driver records it as `tx.pcap`.
3. **The collector's rules, not only the switch's.** The extractor must also reproduce:
   - the active set: a bucket counts from the window of its CPU report or of a change in its
     packet count, for 3 windows;
   - the idle clear after 3 unchanged reads, after which the bucket's next packet starts a new
     flow (new first timestamp, new report);
   - the unconditional clear of expired buckets.

   Durations are the modular difference of the 32-bit timestamps
   (`hybrid_collector.py:1650-1652`). The 32-bit masking in 19.5.4 matches if the extractor also
   subtracts modulo 2^32.
4. **Overload:** at 1 s windows, above roughly 1,000 active buckets the read is budgeted, and a
   window with `net_overload` 1 can match only on the report-based features and the totals. Only
   floods get there, and they are not replayed.
5. **The feature mapping:** the collector's CSV has 30 feature-like `net_*` columns
   (`net_flow_count_seen` ... `net_dir_valid_count`). Mapping them to the 29 thesis features
   (release `features/switch_model.py`) needs those definitions, which are not on PC1.

### 19.6.2 New: cut times in the timing log

- **On the switch's clock:** the batched reader reports when a request arrived, when its
  register snapshot began and ended, and when the reply left (`reader_t_recv`,
  `reader_t_sync_start`, `reader_t_sync_end`, `reader_t_send`).
- **On the collector's clock:** `BatchedReaderProcess` adds when the request was sent and the
  reply received (`collector_t_sent`, `collector_t_reply`).
- **In the log:** the timing log keeps all six per window under `clock`, with `t_window_end`,
  `t_read_start` and `t_read_end`.
- **The clock offset** follows from each read (NTP's formula). From the reads with the shortest
  round trip (0.9-1.2 ms on PC1) it is known to about ±0.6 ms.
- **The window origin:** the collector exports it to the scenario as `HYBRID_T0`.

### 19.6.3 New: the replay driver

`sudo python3 live_test/replay_capture.py CAPTURE --out DIR --anchor-offset A [--align-window K]`:
- **Setup:** it records what PC1 sends, runs the collector with `--profile switch`, and replays
  with `replay_absolute.py`, so that the run's anchor (A = `sample_started_wall_us` minus the
  first frame's time) falls on the start of collector window K (default 2). Collector window
  K + j is then dataset window j.
- **Outputs:** `windows.csv`, `timing.jsonl`, `collector.log`, `tx.pcap` and `summary.json`.
  The summary holds the sha256, t0, the alignment error, the replay timing error and the clock
  offset, and per window its start, its snapshot interval on PC1's clock and the self-check.
- **The self-check** compares each window's switch packet and byte counts with the packets sent
  that are certainly or possibly in it (the bounds are in the script's docstring).
- **On bulk2000** (anchor offset assumed 1.0 s, since its `run.json` is not on PC1): 23 of 23
  windows inside the bounds; packets 24,008 and bytes 2,184,448, both equal to what was sent.

### 19.6.4 What PC1 needs for step 2

- **The captures:** the 204 non-flood captures (25 MB) in the repository, like
  `live_test/captures/`, each with:
  - its run id, to pair it with the eBPF windows;
  - `sample_started_wall_us` and the capture's first frame time, or their difference.
- **The mapping** of the 29 features to the collector's columns (19.6.1, item 5), or the release's
  `features/switch_model.py`.
- **The comparison:** either the switch-exact extractor on PC1, or the VM side runs it on the
  driver's outputs (per capture: `windows.csv`, `timing.jsonl`, `tx.pcap`, `summary.json`).
- **Not done on PC1:** the cgroup prologue change of 19.5.6, which concerns live runs, not
  replays.

## 19.7 The VM side's decisions on 19.6 (2026-11-08)

Written on the VM for PC1 and for whoever runs step 1 where the collections are (the lab
workstation). Sources: `hybrid_collector.py`, `batched_reader.py`, and the release repository
(`p4/ingress*.p4`, `features/switch_model.py`, `validation/features_from_registers.py`,
`dataset/features.csv`). The cohort's raw runs are not on the VM, so the per-run figures below
come from `dataset/features.csv` (0.5 s windows, the published extractor).

### 19.7.1 The feature mapping (19.6.1 item 5)

- **Names:** the 29 thesis features are 29 of the collector's 30 `net_*` columns, with the same
  names in the same order (`NET_ZERO`, `hybrid_collector.py:116-163`, against `FEATURES` in
  `features/switch_model.py`). Drop `net_new_conn_dst_max`.
- **One unit differs:** `net_flow_duration_mean` and `net_flow_duration_max` are nanoseconds in
  the collector's CSV (`hybrid_collector.py:1667-1669`) and seconds in the thesis. Divide them by
  1e9, as `validation/features_from_registers.py:53-57` does. The collector keeps writing ns,
  since its tests and PC1's earlier runs use them.
- **Everything else matches by definition:**
  - rates use the nominal window;
  - a ratio with a zero denominator is 0;
  - `net_dir_valid_count` is the number of occupied buckets read, and every occupied bucket has
    `dir_valid` 1;
  - `net_flows_with_ab` and `net_flows_with_ba` come from the cumulative registers.
- **The statistics per sample** (mean, max, sum, population std, active_windows) are taken over
  dataset windows j = 0..19, which are collector windows K..K+19. The VM side computes them in
  step 3.

### 19.7.2 The switch-exact extractor: six rules, not three

19.5.4 listed three changes. Reading the parser, the ingress program and `collect_windows_live`
adds three more.

| | the switch and the collector | `features/switch_model.py` |
|---|---|---|
| 1. lengths | IPv4 `totalLen` for bytes, min_len and max_len (`ingress_parser.p4:61`) | `len(frame)` |
| 2. parsing | EtherType at byte 12 (no VLAN); the IPv4 header read as 20 bytes whatever its IHL; TCP or UDP at byte 34; no fragment check, so non-first fragments count, with "ports" taken from their payload (`ingress_parser.p4:51-80`) | VLAN tags skipped, IHL honoured, non-first fragments dropped |
| 3. flow key | CRC-16 bucket (`flow_index.py`); colliding flows merge | exact 5-tuple |
| 4. direction | each bucket keeps its first packet's (sport, dport). A packet is A->B if its ports equal those, B->A if they are swapped, and A->B otherwise (`ingress.p4:244-281`). Addresses are not compared, so a flow with sport == dport (53<->53, 123<->123) counts entirely as A->B | first endpoint (address, port) |
| 5. time | low 32 bits of the switch's ns arrival clock; durations are (last - first) mod 2^32 | seconds, unbounded |
| 6. idle clear | a bucket with no packet in windows s+1..s+3 is cleared after the read of window s+3 (`clear_idle_windows` 3, `hybrid_collector.py:1380-1385`). Its next packet starts a new flow, with new reference ports, first_ts, min/max and CPU report | a flow never ends: a C2 connection that is idle for 3 s keeps its first timestamp and its direction |

Notes on the table:
- **Correction to 19.5.1:** its "first fragments only, as on the switch" is wrong for the switch
  (rule 2).
- **Unchanged:** a bucket is active in windows s..s+3 after a packet in window s, which is 4
  windows. Both sides test `w - last_seen <= 3` (`hybrid_collector.py:1306-1313`).
- **Not modelled: the unconditional clear of expired buckets.** It runs only in two cases: when
  a compare-and-clear loses a race with a packet inside the snapshot interval, or when a bucket
  was skipped under overload. Windows where that can happen count as ambiguous (19.7.4).
- **Step 1 trains on all six rules**, so the retrained models see what the switch delivers,
  including durations that alias at 4.295 s.
- **Where it goes:** a `--switch-exact` mode of `features/switch_model.py`, standard library
  only. The default stays off, so the paper's tables still reproduce as published. The VM side
  writes it next.

### 19.7.3 The replay set and the captures (19.6.4)

- **Replay 77 of the 204 runs:** the 52 malware and 25 benign runs that have any IPv4 TCP/UDP
  packet in their observation.
  - The other 127 have none (`net_pkts_total_delta__sum` is 0). Their switch windows are zero by
    construction, so step 3 uses zero network windows for them.
  - The packager checks each of them with the switch-exact extractor. Any run that does not come
    out all zero joins the replay set.
- **One of the 77 overloads at 1 s: Chaos `d538053ada48405e` (train split).**
  - Per 0.5 s window it has 9,587 active flows on average (max 10,423); in 20 s it sends
    221,733 packets, 27,716 of them SYNs. It is the "one scanner" of 19.5.4, and probably the
    24 MB capture.
  - So 19.6.1 item 4 ("only floods get there") does not hold for this run.
  - Replay it last and expect `net_overload` 1 in most windows. Leave it out of the exactness
    check and report it on its own: its live decision under overload is a result in itself.
  - The next largest runs are Mirai `0714651541a17ca4` (max 77 flows per 0.5 s window) and Chaos
    `2d8b09556b0e45a6` (max 11).
- **Trim each capture to its observation**, [anchor, anchor + 20 s).
  - Why: the pre-window probe would land in collector window K-1. Through the TTL it would stay
    active into dataset windows 0-2 and add a flow to the count, length, duration and
    `net_flows_with_*` features there, which the offline rows never count. The post-window probe
    is dropped too.
  - Effect on the driver: `--anchor-offset` becomes the anchor minus the first kept frame, which
    is <= 0. `replay_absolute.py` (start = HYBRID_T0 + K x window - A) and `analyse` both accept
    a negative value.
- **Sanitize each capture:**
  - keep IPv4 frames only, since nothing else touches the registers;
  - in each frame, keep the Ethernet header, the IPv4 header with its options, the TCP header
    (to its data offset) or the UDP header, and at least the 20 or 8 bytes the parser reads at
    byte 34 (for non-first fragments);
  - zero every byte after that, keep every length, and recompute the TCP/UDP checksum.

  Why: the switch reads nothing past those bytes, so the counts do not change. And the
  repository then carries no malware payload: the dataset does not distribute the binaries, and
  a dropper's or a worm's traffic can carry them. The packager checks that the original and the
  sanitized capture give the same switch-exact features in every window.
- **The manifest**, `live_test/captures/cohort/manifest.csv`, has these columns:
  - `execution_id`: the key in `dataset/features.csv`;
  - `run_id`: the collection run, to pair the capture with its eBPF windows;
  - `category`, `label`, `cv_group`;
  - `capture`, `sha256_original`, `sha256`;
  - `anchor_us`: `sample_started_wall_us`;
  - `first_frame_us`: the first frame of the original capture;
  - `anchor_offset_s`, `ipv4_packets`, `expect_overload`.
- **Who:** the VM side writes the packager, and it runs where the collections are. The user
  decides whether the sanitized captures (about 25 MB) go into this public repository or reach
  PC1 by scp.

### 19.7.4 The comparison (19.6.1 items 1-3, 19.6.4)

- **No cut time is exact.** The reader sends one `Sync` per register table (`batched_reader.py:11`).
  The tables are synced one after another inside [`reader_t_sync_start`, `reader_t_sync_end`],
  so the registers of one bucket are not all cut at the same instant. Rather than cutting the
  extractor at a logged time, each window is classified as clean or ambiguous.
- **Three comparisons per run:**

  | | what is compared | grid | who |
  |---|---|---|---|
  | (i) switch | collector window k against the extractor run on `tx.pcap` | collector windows | PC1, right after each replay |
  | (ii) replay | the extractor on `tx.pcap` against the extractor on the capture | dataset windows | PC1 |
  | (iii) end to end | collector window K+j against window j of the switch-exact offline row | dataset windows | VM side, with step 3 |

- **(i) Clean windows:** window k is clean if two conditions hold:
  - no sent IPv4 frame lies in either snapshot interval that bounds it, [s_(k-1)_lo, s_(k-1)_hi]
    or [s_k_lo, s_k_hi], each widened by the clock-offset uncertainty;
  - no bucket's first packet lies within L (`--report-latency`) before b_k or before b_(k+1).
- **(i) Pass criteria:**
  - clean windows: the 27 features other than the durations are exactly equal, and the 2
    durations agree within 1 ms (the switch's MAC stamps against PC1's send stamps; report the
    distribution);
  - other windows: the 9 count deltas lie within the self-check's bounds, and the rest is only
    reported;
  - per run: the 9 count totals are equal;
  - overload windows are reported, not judged.
- **Expect almost every window to be clean.** Apart from the Chaos run, the 77 runs have at most
  77 active flows per 0.5 s window, against roughly 40 ms of uncertainty at each boundary.
- **Tooling:** `live_test/compare_replay.py RUN_DIR --capture C --release DIR` does (i) and (ii)
  and writes `compare.json`. The VM side writes it along with the extractor. PC1 gets the
  release repository with
  `git clone -b live-validation https://github.com/mohamadhazimm/p4-ebpf-malware-detection`
  (about 2 MB).
- **What comes back from PC1:**
  - per run, `windows.csv`, `summary.json` and `compare.json`, committed under
    `perf/replay_cohort/<execution_id>/` (not git-ignored);
  - `timing.jsonl`, `collector.log` and `tx.pcap` stay in the git-ignored results folder unless
    the run fails (i) or (ii).

### 19.7.5 Order

1. VM side: the `--switch-exact` mode, `compare_replay.py` and the packager. PC1 can try
   `compare_replay.py` on `replay_v1_20261108_061848` (bulk2000) straight away.
2. The user, where the collections are: run the packager and deliver the 77 captures and the
   manifest.
3. PC1: step 2 on the 77 runs, with the Chaos run last.
4. Where the collections are: step 1 at 1 s with `--switch-exact` and prologue-free host rows,
   then the retrain; then step 3 with PC1's windows.
5. VM, before step 4 (the live demonstration): the cgroup change of 19.5.6. The monitored
   process joins the cgroup and then runs `exec "$@"`; post-processing cuts at the target's exec
   success, as for the recorded rows.
