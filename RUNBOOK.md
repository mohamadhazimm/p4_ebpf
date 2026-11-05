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
