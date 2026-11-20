# Switch: the P4 programs and their control plane

The switch side runs on an Intel Tofino 1. It was tested on the Tofino model (open-p4studio) and on a Wedge
100BF-32X (SDE 9.6.0). It keeps per-flow state for the monitored host's traffic and gives the collector the 29
network window features of the dataset's model (`features/switch_model.py` of the release repository).

| Path | What |
|---|---|
| `p4/` | The first version: a table of 65,536 flow buckets whose registers the control plane reads at each window's end, plus a per-destination new-connection counter (`reg_newconn_dst`). It mirrors each new flow's first packet to the CPU as a report. `ports.json` and `commands.txt` set it up on the Tofino model; `P4_new_conn_rate_feature.md` is the counter's design. |
| `variants/` | The later builds (below). Each folder's `README.md` gives its design, build options and measurements. |
| `control/` | The control plane, in Python: the forwarding and mirror setup, the register readers (`read_registers_with_index.py` through bfshell, `batched_reader.py` over BF Runtime gRPC), the CPU-report listener, the flow index (`flow_index.py`, the switch's hash), and the readers and software models of the later builds. |
| `tools/` | Scripts to compile, load and benchmark a build on the Wedge from PC1, the host attached to it: `sw_compile.sh`, `sw_switchd.sh`, `sw_pktgen_run.py` (line rate with the switch's packet generator), `run_lat.py` and the hash and readout checks. |
| `results/` | The per-probe latencies of the hairpin runs that `../docs/p4_perf.md` sections 4.1 and 5.5 cite. Other benchmark outputs stay on PC1 (git-ignored here). |

## The builds in `variants/`

| Build | What it adds | Status |
|---|---|---|
| `gtot/` | Seven one-entry global totals on the bucket table. `-DP4_ENABLE_GLOBAL_TOTALS=0` compiles `basic_fix`, the fixed build of `p4_perf.md` 5.5. | measured (`p4_perf.md` 5.6) |
| `sweep/` | Probes from the switch's packet generator that read every bucket at each window boundary in the data plane (with `gtot`'s split totals), and a collision counter. | measured (`PC1.md` part 9) |
| `exact/` | All 29 window features computed in the data plane (a 4-way flow table, two banks of window registers); the control plane reads 51 register cells per window. | measured (`PC1.md` part 6) |
| `exact_block/` | `exact` plus a block table that drops a flagged host's traffic. **The final build:** 11 ingress stages, 421 ns. | measured (`PC1.md` parts 11-13) |
| `hwl/`, `lat/` | Patch scripts that add the latency instrumentation to a build. | used for the latency tables |
| `fingerprint/` | A 16-bit flow fingerprint per bucket that detects and reports two flows sharing a bucket (patch). | tested on the switch, not deployed (`p4_perf.md` 5.3) |
| `baseline.p4`, `make_bucket_variant.sh` | Forwarding only (the baseline of every cost), and a copy of a build with a wider flow index. | |

The P4 sources stay as they were compiled and measured, including the comments that cite the paths of the earlier
layout (`../docs/LAYOUT.md`).

## Build

`switch/tools/sw_compile.sh` runs bf-p4c on the switch into a folder of its own and records the sources' hashes in `compile_meta.txt`:

```sh
switch/tools/sw_compile.sh switch/variants/exact_block basic.p4 OUT_DIR -DTIMER_LOCAL_PORT=68
```

The control-plane readers that run on the switch (`window_reader.py`, `sweep_reader.py`, `batched_reader.py`) run
under its Python (2.7 or 3). The collector copies them there itself. The unit tests in `../tests/` check them
against mocks and software models, without a switch.
