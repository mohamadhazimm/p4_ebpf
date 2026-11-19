# perf/variants/exact_block: the exact build with a block table

`perf/variants/exact` (the 29 window features in the data plane, `README.md` there) plus one ternary table,
`block_rules`, that drops the packets of a program the detectors flagged. Everything else is the exact build's, line
for line: 7 of the 8 files are identical to `perf/variants/exact`, and `ingress.p4` only has lines inserted (a header
comment, the table, and its lookup after `forwarding.apply()`), checked by `tests/test_exact_block.py`.

**Status (2026-11-19): not compiled yet.** The design, the control plane and the loop are tested offline (the
program's software model `exact_model.py`, a fake BF Runtime client). Compile, resources, latency, line rate and the
block function on the Wedge: `PC1.md` part 11.

## The table

| | |
|---|---|
| Key | `ig_intr_md.ingress_port`, `hdr.ipv4.srcAddr`, `hdr.ipv4.dstAddr`, `hdr.ipv4.protocol`, `meta.l4_sport`, `meta.l4_dport`, all ternary (113 bits: 3 TCAM blocks wide); a field set to mask 0 matches anything |
| Actions | `block_drop` (drop, count in `blocked_pkts` and the entry's direct counter `block_hits`); default `NoAction` |
| Size | 1,024 entries (`-DBLOCK_ENTRIES=N`); 1,024 entries are 2 TCAM blocks deep, 6 blocks in all |
| Lookup | every IPv4 packet of the data path, after `forwarding.apply()`; window markers and timer packets never |
| Counting | a dropped packet is still counted by the window registers (the drop takes effect at the end of ingress), so the windows, and the verdicts after the block, go on seeing the attack |

Entries the control plane installs (`block_policy.py`):

| Verdict | Entries |
|---|---|
| A flagged program, with `--sockowner` | each 5-tuple its sockets carried, one exact entry per direction; after the alarm, every new 5-tuple of its cgroup, once per window |
| A flood or a scan (more than 500 active flows in a 0.5-s window, about twice the busiest benign window of the dataset) | its host: `src=ADDRESS` for each local address of its flows and each `--block-host`, and with `--block-host-port` everything entering that port (spoofed sources) |
| No flow identities (a replay, no `--sockowner`) | the host, as above |
| More flow entries than the table holds (`--block-entries`, 1,024) | the host, as above |

## Build

```sh
perf/tools/sw_compile.sh perf/variants/exact_block basic.p4 OUT_DIR [-DTIMER_LOCAL_PORT=68] [-DBLOCK_ENTRIES=1024] [-DBLOCK_DIRECT_COUNTER=1]
```

| Option | Default | Meaning |
|---|---|---|
| `BLOCK_ENTRIES` | 1024 | the table's size |
| `BLOCK_DIRECT_COUNTER` | 1 | 0 leaves out the per-entry counter `block_hits` (then `--block-list` gives no per-entry drops; `blocked_pkts` still counts them all): a fallback if bf-p4c refuses the direct counter |
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

`hybrid_collector.py --switch-program exact --block-on-alarm` (or `--profile exact --block-on-alarm`): the detector of
`live_test/streaming/stream_verdicts.py` (`--block-detector`, default stacked with the host monitor, network without),
trained before the run, scores the run after every window; at the first window with a probability of at least
`--block-threshold` (0.5) the collector asks the reader for the entries above. `--block-force-alarm-window W` raises the
alarm at window W, to test the blocking with benign programs. The scores, the alarm and every request go to
`--block-log` (JSONL); at the end the entries are listed with their drops and deleted (`--block-keep` leaves them).
Needs NumPy and scikit-learn older than 1.8.

## Limits

- **The first packets pass.** With the host monitor, the row of window w is written once the monitor's window w + 1
  has appeared (a window's block is complete only when the next begins), so the verdict on window w comes when window
  w + 2 has been read: about 1 to 1.5 s after window w ends at 0.5-s windows, plus the write of the entries. Without
  the host monitor (a replay, the network detector) each window is scored as soon as the switch's window is read. A new
  flow of a flagged program passes until the end of the window it starts in.
- **The host block is by address or port, not by program.** It also drops the host's benign traffic. Without
  `--block-host-port`, a program that spoofs its source addresses is not stopped by it.
- **The live detectors are the dataset's.** They were trained on the dataset's rows, with its launcher and its C
  library; live benign programs started differently score higher (`PC1.md` parts 2-3), so live false blocks are
  likely until the detectors are trained on rows collected the same way.
- **One switch-wide flood measure.** `net_flow_count_seen` counts every flow through the switch, so other hosts'
  traffic adds to it.
- **Entries are never aged.** They stay until the run ends (or the next reset); 1,024 entries hold 512 flows in both
  directions.
