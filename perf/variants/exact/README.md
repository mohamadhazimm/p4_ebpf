# perf/variants/exact: the window features in the data plane

A Tofino 1 program that computes the 29 network window features of the dataset's model
(`features/switch_model.py` of the release) in the data plane. The control plane reads 51 register
cells per window, so a window never depends on when, or how much, the control plane reads.
The design is in the header comment of `ingress.p4`. The measurements are in `p4_perf.md`,
section 5.7, and `PC1.md`, part 6.

## Build

```sh
perf/tools/sw_compile.sh SRC_DIR basic.p4 OUT_DIR [-DWAY_BITS=14] [-DTIMER_LOCAL_PORT=68]
```

| Option | Default | Meaning |
|---|---|---|
| `WAY_BITS` | 14 | The flow table has 4 ways of 2^WAY_BITS slots (65,536 in all). 15 crashed bf-p4c 9.6.0 with an internal error. |
| `TIMER_LOCAL_PORT` | 127 (no port) | The generator's local port whose timer packets advance the window clock, on any pipe. A deployment build sets 68. The default keeps ports 68-70 free for the line-rate tests. |

The result uses 11 ingress stages, 23 of 48 stateful ALUs and 120 of 960 SRAM blocks. Its latency is 421 ns,
against 315 ns for `basic_fix`.

## Control plane

`thesis-hybrid-ebpf-p4/python/window_reader.py` runs on the switch. It sets the program up:
- **reset:** clears every register (`--reset`);
- **frame minimum:** fills the `frame_len` table (`--frame-min DST/PREFIX`);
- **marker ports:** sets the ports whose window markers count (`--marker-ports`).

Then it reads one window at a time, either following the clock (`--follow`) or on the collector's request
(`--serve`). `window_features.py` turns the reads into the features.

| Use | Window clock | Marker ports |
|---|---|---|
| Live collection: `hybrid_collector.py --switch-program exact --window-markers cpu` | The reader sends a marker from the CPU port at each of the collector's window boundaries, about 3 ms to take effect. | the CPU port, 192 |
| Dataset replay: `replay_capture.py --exact`, or `live_test/exact_replay.py` | The replayer sends the markers in order with the capture's frames. | the replay host's port, 132 |
| Deployment without a collector clock | Build with `-DTIMER_LOCAL_PORT=68` and start a timer app on the generator (`perf/tools/sw_window_timer.py`). | none |

A marker frame from any other port is dropped and counted (`rejected_markers`), so a monitored host
cannot move the window clock.

## Limits

- **The flow table holds every flow of a run.**
  - The dataset's model forgets no flow, so slots are never reused; the registers are reset at the start of
    each run.
  - A flow that finds no slot is still counted in the totals, as A→B. Its packets are reported per window
    (`net_untracked_pkts`), and that window's flow features are then not exact.
  - Aging is not done in the data plane: with sequential way probes, freeing a slot in an earlier way would let
    a live flow from a later way claim a second slot. A long-running deployment would need recirculation for
    claims, or periodic resets.
- **Every pipe has its own clock.**
  - A marker or a tick moves only the clock of the pipe it enters; the testbed's ports 132, 140 and 192 are all
    in pipe 1.
  - The reader combines only the pipes whose clock has passed the window. It reports the packets of a lagging
    pipe as `net_unclocked_pkts`, and marks a window lost if the set of clocked pipes changes.
  - Traffic on two pipes needs a timer on each pipe, and their phases are not aligned.
- **A window's read must finish before the window after the next one starts** (1 window of slack). A late
  read, or a late clear of the extremes, marks the window lost (`net_window_lost`).
- **Number ranges:**
  - Window numbers are kept per flow in 16 bits (9 h of 0.5 s windows).
  - Times are 32-bit at 65.536 µs (78 h).
  - A window's sum of flow durations must stay below 2^32 units (281,475 s).
  - Bytes per window per pipe must stay below 2^32.
- **Durations come from the switch's clock**, in 65.536 µs units.
- **No per-flow counters:** the socket-level join of the live test needs `basic_fix`.
