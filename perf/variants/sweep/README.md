# perf/variants/sweep: the bucket table read by the data plane

A Tofino 1 program: the deployed bucket table with seven one-entry totals (`basic_gtot_ba`, i.e. `perf/variants/gtot`
with `-DP4_GLOBAL_TOTALS_SPLIT=1`), whose registers the data plane reads itself. A probe packet names one bucket,
picks up its 14 registers and leaves the switch as an export record. A sweep of probes at each window boundary gives
the state of every bucket at that boundary, so no window depends on how many buckets the control plane can read.

**Status (2026-11-17): compiled and tested on the Wedge** (`PC1.md` "Results, part 9" and "part 9b"; `p4_perf.md`
5.8). The first version (a probe branch of its own) did not compile with bf-p4c 9.6.0; this one gives every register
one table for both kinds of packet (the "merged" layout, `ingress.p4`'s header comment).
- **Cost:** 6 ingress stages like `basic_gtot_ba`, 158 against 133 ingress cycles, a median latency of 337 against
  317 ns (the exact build: 421 ns). The line rate is `basic_fix`'s, lossless, the totals exact.
- **With the collision counter** (`reg_coll`, added after part 9c; `PC1.md` "Results, part 9d"): 7 ingress stages, 164
  cycles, 342 ns, 23 stateful ALUs. These sources include it; the 6-stage figures above are the build without it
  (`basic_sweep_final`, the 109 captures of part 9c). With the counter the line-rate matrix and the 109 captures give
  the same results: 103 rows equal to the published one, every capture with the same score. Collisions show in exactly
  the 4 floods whose rows are not exact.
- **On the switch:** in-band replays equal to the program's model in all 135 non-duration columns (5 captures,
  Chaos included). The generator path: whole sweeps every 0.5 s, every record equal to the model's, at 2 µs, 0.5 µs
  and the generator's full rate (a sweep in 0.64 ms).
- **The exact build's 109 captures** (`PC1.md` "Results, part 9c"): 103 rows equal to the published row in the 135
  non-duration columns (exact build 102), 107 equal to the model (the other 2: bulk uploads over the replay's MTU).
- **Line rate beside the sweep** (`PC1.md` 9E, "Results, part 9f"): with the generator sweeping pipe 1 every 0.5 s,
  line-rate traffic looped into that pipe ran at 99.99% (1518 B) and 91.09% (64 B, the generator's maximum), as
  without it, with no drop. A line-rate app on the same pipe's generator as the sweep loses the sweep's share of the
  time instead (26% at 2 µs): the generator runs one app at a time.
- **`hybrid_collector.py --switch-program sweep`** (`PC1.md` "Results, part 9g"): with in-band probes, every window of
  4 replayed captures (Chaos included) equal to the model's. With the generator, see the limits below.
- The control build (`-DP4_ENABLE_SWEEP=0 -DP4_FRAME_LEN=0`) has exactly `basic_gtot_ba`'s resources.

## Why this design

- **Control-plane reads are the limit.** The control plane reads a bucket in ~0.55 ms (14 registers through BF Runtime,
  the raw-wire reader), so a 0.5 s window covers ~500 buckets. A flood keeps ~30,000 buckets active, and its per-flow
  features become a sample (`p4_perf.md` 5.6; PC1.md part 4c). `gtot`/`basic_gtot_ba` fixed the totals (95 of the 145
  columns), not the 10 per-flow features.
- **The exact build's parity comes from its reads, not its table.** `perf/variants/exact` computes every window
  feature in the data plane and costs 106 ns more latency than `basic_fix` (421 against 315 ns, 11 ingress stages).
  PC1's gap analysis (`perf/results/exact_gap_analysis`, offline, perfect reads and cuts) gives the bucket table,
  read in full at each boundary and with the frame minimum counted, the same parity as the exact build's 4-way flow
  table: 106 of the 110 captures equal to the published row in the 135 non-duration columns, with the same 4 floods
  failing (Chaos and the three SYN fan-outs, where flows share buckets).
- **So this build keeps the bucket table and reads all of it in the data plane.** The data path is
  `basic_gtot_ba`'s, plus the `frame_len` table of the exact build (the 60-byte frame minimum toward the dataset's
  guest, 10.0.0.10). The probe path only reads registers.

## The probe and the export

| | |
|---|---|
| Probe | EtherType `0x88B6`, from a port in the parser's value set `sweep_ports`. The bucket is the low 16 bits of the destination MAC, where the packet generator writes its packet id; an in-band probe puts it there itself. After Ethernet: a `sweep_t` (90 bytes, magic `0x5357`). From any other port a `0x88B6` frame is an ordinary frame (forwarded, not counted), so a monitored host cannot read the registers. |
| What a probe reads | The bucket's 14 registers and its collision count (`reg_coll`) into `sweep_t`. A probe of bucket 0 also reads the seven totals and increments `reg_sweep_seq`; every probe carries the sweep number. Every probe is counted in `sweep_probes`. |
| Export | `sweep_export`, a keyless table: its default action `export_to(port)` sends the probe, filled in, to the export port; until the control plane sets it, `export_drop()`. A probe of a bucket that was never used since the reset (`dir_valid` 0) is dropped, except bucket 0's, so every sweep exports at least one record. Exports are counted in `sweep_exported`. |
| Record | 104-byte frame: the probe's Ethernet header (its destination MAC unchanged, so capture in promiscuous mode), `sweep_t` with the registers as they were when the probe passed, the bucket, the generator's header fields, the probe's `ingress_mac_tstamp[31:0]`. Layout: `headers.p4`; parser: `sweep_features.parse_export`. |

## Build

```sh
perf/tools/sw_compile.sh perf/variants/sweep basic.p4 OUT_DIR [-D...]
```

| Option | Default | Meaning |
|---|---|---|
| `P4_ENABLE_SWEEP` | 1 | 0 leaves out the probe path (parser states, value set, the merged register tables): `basic_gtot_ba`'s data path, word for word. |
| `P4_FRAME_LEN` | 1 | 0 leaves out `frame_len`. `-DP4_ENABLE_SWEEP=0 -DP4_FRAME_LEN=0` compiles `basic_gtot_ba`'s program (apart from the unused `sweep_t` declarations): a control for the resources (equal, checked 17 November). |
| `SWEEP_SHARED_INDEX` | `P4_ENABLE_SWEEP` | Both paths index the registers with `meta.ridx` (the flow hash for a data packet, the destination MAC for a probe). The merged layout needs it: a table's actions must index a register the same way, so 0 with the sweep is a compile error. Without the sweep, 0: `basic_gtot_ba`'s addressing straight from the hash unit. |
| `SWEEP_PIN_STAGES` | 1 | `@stage` pins on the register tables: 6 ingress stages, 158 cycles. 0 leaves the placement to bf-p4c: 7 stages, 166 cycles. Each register has one table, so a pin moves the data path's access and the probe's read together; a change to the data path may need new pins (or 0). |
| `P4_ENABLE_GLOBAL_TOTALS`, `P4_GLOBAL_TOTALS_SPLIT` | 1, 1 | As in `gtot`. The probes read the split totals, so the sweep requires `P4_GLOBAL_TOTALS_SPLIT=1`. |

Latency builds: `perf/variants/hwl/make_hwl_sources.sh perf/variants/sweep OUT_DIR` (the patch applies to these
sources as to `gtot`'s).

## Two ways to send the probes

| | Generator (deployment) | In-band (dataset replay) |
|---|---|---|
| Who sends | The packet generator of each pipe, timer app: one batch of 65,536 probes (packet ids 0..65535) every window. `sweep_reader.py --generator start --period-ns 500000000 --ipg-ns 2000`. | The replay host, at each window boundary, in order with the capture's frames, as the exact build's window markers. `replay_absolute.py --probes changed`. |
| Where the window is cut | When each bucket's probe passes: bucket i at the boundary + about i × ipg (131 ms for a full sweep at 2 µs). A packet that arrives during a sweep counts in one window for the buckets probed after it and in the next for those probed before, so during traffic the totals (read at the sweep's start) can disagree with the buckets' sum. The window features follow each bucket's own cut. | Where the probes sit in the packet sequence: exact, whatever the replay's timing. |
| Which buckets | All 65,536; the switch exports the used ones and bucket 0. | "changed": the buckets of the frames since the previous boundary, bucket 0 first. A bucket left out had no packet, so its record is its last one. "all": every bucket used so far (same rows offline). |
| Export rate | At most 1/ipg (500 kpps at 2 µs) during a sweep, used buckets only. | The replay host's probe rate. |

## Host side

| File | Runs on | Does |
|---|---|---|
| `thesis-hybrid-ebpf-p4/python/sweep_reader.py` | the switch (Python 2.7 or 3) | `--setup [--reset] [--frame-min] [--sweep-ports] [--export-port]`, `--generator start/stop`, `--state` (sweep number and counters per pipe, export action, ports, `frame_len`, totals, generator counters). One JSON line per command. |
| `thesis-hybrid-ebpf-p4/python/sweep_features.py` | the host (Python 3) | Record format, `group_sweeps` (exports to sweeps), `SweepWindows` (sweeps to the 29 window features, with a totals check per window), `summarize` (the release's 145 columns), `SweepModel` (the program's registers in software), `probe_plan`, `simulate_inband`. |
| `live_test/replay_absolute.py --probes` | PC1, as root | The capture with the probes among its frames. |
| `live_test/sweep_replay.py` | PC1 | One capture through the switch: setup, tcpdump of the exports, replay, state, row; compared with the published row and with the model's. |
| `live_test/run_sweep_replays.py` | PC1 | All captures with traffic; `rows.csv` is the input of the committee's `score_switch_replay.py`. |
| `live_test/sweep_generator_check.py` | PC1 | The generator path with known traffic: whole sweeps, records equal to the model, counters, sweep period. |
| `live_test/sweep_offline_check.py` | anywhere | The captures through `SweepModel` with in-band probes, against the published rows. |
| `hybrid_collector.py --switch-program sweep` | PC1, as root | The live collector on this build: `sweep_reader.py --serve` on the switch (setup, the generator's prepare, enable and stop), the exports taken by tcpdump into `/dev/shm` (`--sweep-capture tcpdump`, the default) and turned into windows by `SweepWindows`. `--sweep-probes generator` (the deployment: the generator's first sweep falls on the collector's window 0) or `inband` (the scenario sends them). Each window adds `net_sweep_totals_mismatch`, `net_sweep_coll_pkts`, `net_sweep_coll_saturated`, `net_sweep_merged_active`, `net_sweep_merged_buckets`, `net_sweep_buckets`, `net_sweep_span_us`. |
| `live_test/replay_capture.py --sweep inband\|generator` | PC1, as root | One capture through the collector on this build, every window compared with `SweepModel` on the same frames (in-band probes, perfect cuts), and the dataset row with the model's and the published one. |
| `live_test/run_sweep_collector.py` | PC1 | Captures of `run_sweep_replays.py` through `replay_capture.py --sweep`; `runs.csv`. |

Tests: `thesis-hybrid-ebpf-p4/python/tests/test_sweep.py` (the model against an independent bucket table on random
traffic with collisions, both directions and short frames; record and probe formats; the reader against a fake
BF Runtime client under SDE 9.6 and 9.13 names; probe placement against the markers; cohort captures against the
published rows).

## Offline result (the software model, not the switch)

`live_test/sweep_offline_check.py OUT --extras` (all 110 captures with traffic, in-band probes, perfect cuts):

- **106 of 110 rows equal to the published row in the 135 non-duration columns**, including every calm capture
  (101 of 101). The 4 that differ are Chaos (67 of 135), `syn_fan_40k` (120), `syn_fan_100k` (70) and
  `syn_fan_150k` (67): flows that share a bucket, as the gap analysis predicted.
- In every window of every capture the totals equal the buckets' sum (0 mismatches).
- 475,839 probes in all ("changed"); "all" gives the same rows on the six captures tried (2.7 million probes).
- Durations are not compared: the switch times packets when they arrive, not at their capture times.

## Limits

- **The shared index costs one dependency stage.** The data path reaches its first register in stage 1, not
  stage 0: +25 cycles, +20 ns against `basic_gtot_ba`. A table's actions must index a register the same way, and a
  probe's index (its MAC) and a data packet's (the flow hash) can only meet in a PHV field.
- **The stage pins follow the data path.** Without them (`-DSWEEP_PIN_STAGES=0`) bf-p4c places the tables in 7
  stages (166 cycles, 344 ns). A change to the data path may need new pins.
- **Stop the generator between sweeps.** On the Wedge, disabling the app in the middle of a batch lost probes and
  left that pipe's timer dead until switchd was restarted. `sweep_reader.py --generator stop` waits for the gap
  (the app's packet counter standing still) and reports a stop the timer overtook (`idle.moved_after_idle`).
- Flows that share a bucket stay merged (the 4 captures above), as on every bucket-table build. `reg_coll` counts
  the packets that match neither direction of a bucket's reference ports (saturating at 255), so the host sees which
  windows merge flows (`net_sweep_coll_pkts`, `net_sweep_merged_active`). Two flows with the same ports and other
  addresses are not seen: the bucket keeps no addresses.
- Generator mode: a sweep takes buckets × ipg, so the cut is not one instant (above). With 65,536 used buckets a
  sweep exports 65,536 records (6.8 MB): the export port and the receiver must take them at the probe rate.
  - **The receiver** (`PC1.md` "Results, part 9e"): PC1's NIC with its default 1,024-entry receive ring lost
    exports at every gap tried (251 of 193,009 at 2 µs, 30,000 flows); with 8,192 entries none at 2 µs, 1 µs and
    0.5 µs. At the generator's full rate (0.64 ms a sweep) it lost about half either way.
  - **The cut against a replay's windows** (part 9g): a packet up to buckets × ipg after a boundary counts in the
    window before for buckets probed after it. The dataset's captures start a few ms after their anchor, so their
    first packets are exactly such packets.
- Every pipe has its own registers: a pipe's probes read only that pipe's buckets (the testbed's ports 132, 140 and
  192 are all in pipe 1).
- `first_ts`/`last_ts` are the switch's 32-bit nanosecond clock (wraps every 4.295 s); durations are unwrapped with
  the window count (`SweepWindows.duration_s`).
