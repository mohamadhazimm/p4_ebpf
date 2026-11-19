# perf/variants/exact_block: the exact build with a block table

`perf/variants/exact` (the 29 window features in the data plane, `README.md` there) plus one ternary table,
`block_rules`: once the detectors flag a host, the switch forwards nothing more from it. Everything else is the exact build's, line
for line: 7 of the 8 files are identical to `perf/variants/exact`, and `ingress.p4` only has lines inserted (a header
comment, the table, and its lookup as the data path's last step), checked by `tests/test_exact_block.py`.

**Status (2026-11-19, `PC1.md` "Results, part 11" and "part 11b"): compiled and tested on the Wedge.** The exact
build's 11 ingress stages, 260 cycles and 421 ns, with the per-entry counter.
- **The placement.** The table is looked up after the flow table, and `blocked_pkts` is counted on
  `block_rules.apply().hit`, outside the action.
- **The first version** (part 11) looked the table up right after `forwarding.apply()` and counted both counters in
  `block_drop`. bf-p4c refused the action ("all indirect externs to be addressed with the same expression across
  all actions"). With `-DBLOCK_DIRECT_COUNTER=0` it took 12 stages, 279 cycles and 437 ns: `forwarding` and
  `block_drop` both write `drop_ctl`, so the table could not share stage 0 and the flow-table chain behind it
  moved down one stage.
- **Power:** bf-p4c's estimate is 2.11 W (ingress) against the exact build's 0.56 W, for the 6 TCAM blocks searched
  per packet. The first version's 0.52 W left the table off its worst-case path; it searched the same blocks.
- Resources, line rate, unchanged windows and the block function: `p4_perf.md` 5.9.

## The table

| | |
|---|---|
| Key | `ig_intr_md.ingress_port`, `hdr.ipv4.srcAddr`, `hdr.ipv4.dstAddr`, `hdr.ipv4.protocol`, `meta.l4_sport`, `meta.l4_dport`, all ternary (113 bits: 3 TCAM blocks wide); a field set to mask 0 matches anything |
| Actions | `block_drop` (drop, count in the entry's direct counter `block_hits`; `blocked_pkts` is counted on the hit); default `NoAction` |
| Size | 1,024 entries (`-DBLOCK_ENTRIES=N`); 1,024 entries are 2 TCAM blocks deep, 6 blocks in all. With the direct counter the Wedge takes 1,023 (the 1,024th add fails with `RESOURCE_EXHAUSTED`), so `--block-entries` defaults to 1,023 |
| Lookup | every IPv4 packet of the data path, as its last step (after the flow table, stage 10 of 11); window markers and timer packets never |
| Counting | a dropped packet is still counted by the window registers (the drop takes effect at the end of ingress), so the windows, and the verdicts after the block, go on seeing the attack |

What an alarm blocks (`block_policy.py`, `hybrid_collector.py --block-scope`):

| Scope | Entries | From when |
|---|---|---|
| `host` (the default) | everything the flagged host sends: `src=ADDRESS` for each source address of the monitored program (from `--sockowner`) and each `--block-host`, and with `--block-host-port` everything entering that switch port (spoofed sources). Each later window adds an address the program has used since, and retries a write that failed | the alarm: entries written 3-5 ms after it, new connections dropped from their first packet (`PC1.md` part 11c) |
| `flows` | each 5-tuple the program's sockets carried, one exact entry per direction, and every new 5-tuple of its cgroup once per window; its host on a flood (more than 500 active flows in a 0.5-s window, about twice the busiest benign window of the dataset), when no flow is named (a replay without `--sockowner`), or when the flow entries would not fit (`--block-entries`, 1,023) | a new connection only from the next window: one that ends sooner is never stopped (`PC1.md` 11F) |

## Build

```sh
perf/tools/sw_compile.sh perf/variants/exact_block basic.p4 OUT_DIR [-DTIMER_LOCAL_PORT=68] [-DBLOCK_ENTRIES=1024] [-DBLOCK_DIRECT_COUNTER=1]
```

| Option | Default | Meaning |
|---|---|---|
| `BLOCK_ENTRIES` | 1024 | the table's size |
| `BLOCK_DIRECT_COUNTER` | 1 | 0 leaves out the per-entry counter `block_hits` (then `--block-list` gives no per-entry drops; `blocked_pkts` still counts them all); the default compiles with bf-p4c 9.6.0 |
| `WAY_BITS`, `TIMER_LOCAL_PORT` | as in `exact` | |

Latency build: `perf/variants/hwl/make_hwl_exact.sh perf/variants/exact_block OUT_DIR` (the exact build's patch applies
unchanged).

## Control plane

`thesis-hybrid-ebpf-p4/python/window_reader.py` (runs on the switch, owns the program):

| | |
|---|---|
| `--block-add SPEC` / `--block-del SPEC` / `--block-clear` / `--block-list` | by hand; SPEC is `port=,src=,dst=,proto=,sport=,dport=` (an address may be `ADDR/PREFIX`; a field left out matches anything) |
| `--serve`: `{"cmd": "block", "op": "add"/"del"/"clear"/"list", "entries": [...]}` | the collector's requests; one write for a list of entries |
| `"setup"` with `"reset"` | also deletes every block entry and zeroes `blocked_pkts` (the exact build, without the table, is unaffected) |
| A second client | while the collector's reader owns the program, another `window_reader.py` needs its own `--client-id` (with the default 9 it cannot subscribe); it then works unbound |

A full table is reported, not raised: the add returns `table_full` and the entries that went in (BF Runtime keeps those
of a batch before the first that did not fit). The list syncs the table's counters once (`SyncCounters`) and reads the
entries from software: 1,023 entries in 0.6 s, where reading each from the hardware took 51 ms per entry.

`hybrid_collector.py --switch-program exact --block-on-alarm` (or `--profile exact --block-on-alarm`): the detector of
`live_test/streaming/stream_verdicts.py` (`--block-detector`, default stacked with the host monitor, network without),
trained before the run, scores the run after every window; at the first window with a probability of at least
`--block-threshold` (0.5) the collector asks the reader for the entries above. `--block-force-alarm-window W` raises the
alarm at window W, to test the blocking with benign programs. The scores, the alarm and every request go to
`--block-log` (JSONL); at the end the entries are listed with their drops and deleted (`--block-keep` leaves them).
Needs NumPy and scikit-learn older than 1.8. `--block-train-extra live_test/streaming/live_benign_windows.csv.gz` also
trains the detector on 74 live benign runs collected through this pipeline: live false alarms then fall from 56.8% to
2.7% (stacked, cross-validated), with the dataset's detection unchanged (`PC1.md` part 12C).

## Limits

- **The first packets pass.** With the host monitor, after each switch window the collector waits (at most 0.25 s)
  for the monitor's window, which `hostmon_agg` prints about 50 ms after the window ends and closes with a
  `HOSTMON_WINDOW_DONE` line, so the verdict on window w comes about 50-60 ms after it ends, plus the write of the
  entries. (With a monitor build before 2026-11-19, which has no such line, the row waits for the next window's
  header: about 1 to 1.5 s.) Without the host monitor (a replay, the network detector) each window is scored as soon
  as the switch's window is read. With `--block-scope flows` a new flow of a flagged program passes until the end of
  the window it starts in.
- **The host block is by address or port, not by program.** The switch sees addresses and ports, so a host block
  also drops the host's other programs (`PC1.md` part 11c: the background program's connections stopped too).
  Without `--block-host-port`, a program that spoofs its source addresses is not stopped by it. Traffic toward the
  host still passes (the block is on what it sends).
- **Window length.** The data plane takes any length (the markers or the timer set it), but the reader on the switch
  needs about 100 ms per window: 0.25-s windows are exact, 0.1-s windows fall behind with two banks (`PC1.md` 12B).
- **The live detectors are the dataset's.** They were trained on the dataset's rows, with its launcher and its C
  library; live benign programs started differently score higher (`PC1.md` parts 2-3), so live false blocks are
  likely until the detectors are trained on rows collected the same way.
- **One switch-wide flood measure.** `net_flow_count_seen` counts every flow through the switch, so other hosts'
  traffic adds to it.
- **Entries are never aged.** They stay until the run ends (or the next reset). A host block takes one or two
  entries; with `--block-scope flows` the 1,023 entries hold 511 flows in both directions.
