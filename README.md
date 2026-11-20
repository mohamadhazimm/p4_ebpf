# P4 + eBPF hybrid malware monitor

A malware monitor that watches a Linux host from two sides. A P4 program on a Tofino switch keeps per-flow
state of the host's traffic, and an eBPF program in the host's kernel keeps statistics of each process's system
calls. A collector cuts both views into the same windows, joins them, scores every window with random forests
trained on a dataset of 240 program executions, and can tell the switch to stop forwarding a flagged host's
traffic.

This repository holds the system's code and the record of how it was built and measured. It has the switch
programs and their control plane, the eBPF monitors, the collector and its detectors, and the experiments on the
Tofino model and on a Wedge 100BF-32X (Tofino 1), with their logs and benchmarks. The dataset and the paper's
evaluation are in the release repository ([below](#related-repositories)).

## The system as measured

The last version tested on the Wedge is tagged `final-2026-11-20` (in the file layout of before that day; see
[docs/LAYOUT.md](docs/LAYOUT.md)). Its parts, in the current layout:

| Part | Where | What it does |
|---|---|---|
| Switch | [`switch/variants/exact_block/`](switch/variants/exact_block/) | Computes the 29 network window features of the dataset's model in the data plane, and drops the traffic of a host the collector blocks. 11 ingress stages, 421 ns latency, line rate. |
| Host | [`host/hostmon_agg/`](host/hostmon_agg/) | Aggregates each process's system calls per window in the kernel. User space reads each window once and prints ten statistics per process, from which the collector builds the 18 host window features. |
| Collector | [`collector/hybrid_collector.py`](collector/) | Reads both sides at every window boundary (`switch/control/window_reader.py` on the switch), writes one row per window and scores it. |
| Detectors | [`collector/detector/`](collector/detector/), [`collector/block_policy.py`](collector/block_policy.py) | The paper's random forests, trained at several observation prefixes so that every window gets a verdict. At the first alarm the switch blocks the host. |
| Windows | 0.25 s | The dataset's runs are 40 windows of 0.5 s; the detectors were retrained on the same runs in windows of 0.25 s (`collector/detector/dataset_windows_0.25s.csv.gz`). |

The measurements: [docs/PC1.md](docs/PC1.md) parts 11-13 (the final system live on the Wedge, from PC1, the host
attached to it), [docs/p4_perf.md](docs/p4_perf.md) (the switch programs' resources, latency and line rate) and
[host/COMPARISON.md](host/COMPARISON.md) (the eBPF monitor's overhead against published monitors).

## Layout

| Folder | What |
|---|---|
| [`switch/`](switch/) | The P4 programs: the first version (`p4/`, a flow table read by the control plane) and the later builds (`variants/`, `exact_block` is the final one). Also the control plane (`control/`), the tools to compile, load and benchmark on the Wedge (`tools/`) and the hairpin latency records (`results/`). |
| [`host/`](host/) | The eBPF monitors: `hostmon_agg/` (the one used), `sockowner/` (which process owns each flow), and the earlier streaming monitors (`hostmon_ref/`, `streaming/`), with their overhead benchmarks. |
| [`collector/`](collector/) | The collector, the block policy, the socket-level join and the detectors with their training tables. |
| [`experiments/`](experiments/) | Live tests on the Tofino model, replays of the dataset's captures through the Wedge, the captures themselves, the result archives of the runs on PC1, and the benign workloads. |
| [`analysis/`](analysis/) | The offline studies of October 2026, which rebuilt the switch's features from packet captures. |
| [`tests/`](tests/) | Unit tests of the control plane, the collector and the experiment scripts. They need no switch and no root. |
| [`docs/`](docs/) | [`PC1.md`](docs/PC1.md) (the log of the hardware runs), [`p4_perf.md`](docs/p4_perf.md) (the switch's performance), [`RUNBOOK.md`](docs/RUNBOOK.md) (the register readout on the Wedge), [`USAGE.md`](docs/USAGE.md) (running the first version) and [`LAYOUT.md`](docs/LAYOUT.md). |
| [`third_party/`](third_party/) | libbpf-bootstrap (libbpf, bpftool, `vmlinux.h`) and the reference detector of the latency method. |
| [`archive/`](archive/) | Superseded code kept for the record. |

## Quick start

```sh
python3 -m unittest discover -s tests       # 325 tests, a minute; 8 skip without the SDE's generated bfruntime_pb2
make -C host/streaming hostmon               # the streaming monitor (clang >= 11, libelf-dev, zlib1g-dev)
DEP=/usr host/build.sh                       # hostmon_agg and the benchmark binaries into host/build/ (clang-14)
python3 collector/hybrid_collector.py --help
```

Some tests and the detectors read the release repository. Clone it next to this one
(`../p4-ebpf-malware-detection`). The detectors need NumPy and scikit-learn; a scikit-learn older than 1.8
reproduces the paper's fold assignments. Running the monitors needs root and a kernel with BTF. Running the switch
side needs Intel's P4 Studio SDE: 9.6.0 on the Wedge, or open-p4studio for the Tofino model
([experiments/README.md](experiments/README.md)).

## Related repositories

- [p4-ebpf-malware-detection](https://github.com/mohamadhazimm/p4-ebpf-malware-detection): the public release of
  the paper. It holds the P4 program, the in-kernel monitor, the feature code, the 240-execution dataset and the
  evaluation scripts.
- [p4_ebpf-dataset-construction](https://github.com/mohamadhazimm/p4_ebpf-dataset-construction): the malware
  acquisition, the isolated VirtualBox laboratory, the benign workloads, the dataset collections and the model
  evaluations.
- The thesis and the paper's LaTeX sources are in private repositories.

## License

GPL-2.0 ([LICENSE](LICENSE)). The code in [`third_party/`](third_party/) keeps its own licenses, and files with
their own SPDX header keep theirs.
