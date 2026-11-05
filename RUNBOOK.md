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

Each prints the table of the report (`sync ms | read ms | clear ms | total ms |
us/bucket | fits 0.5 s?`); `--bench-budget` changes the window length, `--safe-parse`
times the client's own parser instead of the fast one, `--chunk N` the keys per Read,
`--sync-batched` the 14 Syncs in one Write RPC instead of 14 (worth measuring on the
switch; see Section 8 for why it is not the default).
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
`MISMATCH` and `only in one` counts and the wall time of both reads. Expected:
`MISMATCH 0`, `only in one 0`, `dst equal True` in every window. `traffic between`
rows are buckets whose packet counter differs between the two snapshots (they are
taken ~1.5 s apart because the legacy read opens a bfshell session; the later snapshot
has the larger counters, which the script checks): they are the documented case
"rows identical except where the two snapshots fall on different sides of a packet
arrival". The JSON keeps the per-row differences.

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
[TIMING] window 12: reader=batched active=2143 dst=37 sync=41.2 ms read=118.7 ms clear=3.1 ms wall=171.0 ms overhead=8.0 ms cleared=5 rpcs={'sync_rpcs': 1, 'read_rpcs': 15, 'read_entities': 30039, 'clear_rpcs': 1}
```

`overhead` is wall time minus sync, read and clear: the bfshell session and SSH for the
legacy reader, the request/answer pipe for the batched one. `--reader-timing-file` keeps
the same values as JSON lines; `--reader legacy --reader-timing` gives the "before"
column. `--reader-local --grpc-addr ...` places the batched reader on this host;
`--reader-chunk`, `--reader-safe-parse`, `--reader-sync-batched`, `--grpc-client-id` and
`--p4-name` pass through.

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
