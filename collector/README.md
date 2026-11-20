# Collector: the join of the two views, the detectors and the block rule

| Path | What |
|---|---|
| `hybrid_collector.py` | The collector. It starts the host monitor and the switch's reader for the program the switch runs (`--switch-program buckets`, `sweep` or `exact`), cuts both views into the same windows, and writes one CSV row per window with the host and network columns. Option bundles: `--profile dataset`, `exact`, `switch` and `model`. |
| `block_policy.py` | `--block-on-alarm`: scores the run after every window. At the first alarm it installs block rules on the switch (`switch/variants/exact_block`), for the whole host (the default) or only the flagged program's flows. The detector runs in a process of its own. |
| `sockjoin.py` | The socket-level join (`--sockowner`): with `host/sockowner`'s record of which process and cgroup own each flow, it gives each monitored program the network columns of its own flows instead of the whole window's. |
| `detector/stream_verdicts.py` | The detectors: the paper's random forests (`--detector network`, `host`, `concat` or `stacked`), trained on the dataset runs at nine observation prefixes from 0.5 to 20 s, so that a run gets a verdict after every window. It also runs alone on a collector CSV (`--follow`). |
| `detector/dataset_windows.csv.gz` | The training table: the 240 dataset runs, 40 windows of 0.5 s each, the 18 host and 29 network signals of every window. |
| `detector/dataset_windows_0.25s.csv.gz` | The same runs in 80 windows of 0.25 s, the window of the final system. `net_windows.py` and `host_windows.py` rebuilt it from the runs' captures and system calls; their JSON reports record how. |
| `detector/live_benign_windows*.csv.gz` | Benign runs collected live on PC1 (`../docs/PC1.md` part 12), optional extra training rows (`--block-train-extra`). |

The detectors use the release repository's `evaluation/` code for their forests. Clone it next to this one
(`../p4-ebpf-malware-detection`) or give `--block-release`. They need NumPy and scikit-learn. A version older than
1.8 reproduces the paper's fold assignments.

```sh
python3 collector/hybrid_collector.py --help
python3 collector/detector/stream_verdicts.py --help
```

The commands of the runs on the Wedge, with every option, are in `../docs/PC1.md` (parts 11-13 for the final system).
