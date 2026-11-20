# Analysis: the offline studies of October 2026

These scripts came before the switch computed the network features itself. They rebuild the switch's flow
features from the packet captures of the dataset runs, and they compare network, host and combined models on them.
The paper's evaluation is in the release repository (`p4-ebpf-malware-detection`), not here.

| Script | What |
|---|---|
| `analyze_p4_pcap_ablation.py` | Rebuilds the P4-shaped features of each run from its capture (`derive_p4_features`, `recover_frame_windows`), and compares them with the eBPF features in a family-balanced ablation. |
| `reconstruct_ambiguous_p4.py` | Averages the P4 features over every window assignment that the capture's packet counters allow. |
| `evaluate_family_stratified_50_50.py`, `evaluate_unknown_50_50.py`, `score_balanced_in_sample.py` | The models on a half-per-family hold-out, on unknown cohorts (with benign-only novelty detection), and in sample. |
| `benchmark_pcap_extraction.py` | The time to decode a capture and rebuild its features offline (not a switch measurement). |
| `analyse_hostmon.py`, `view_csv.py` | A summary of a host monitor's CSV, and a CSV printed one field per line. |

`analyze_p4_pcap_ablation.py` is byte for byte the file the dataset repository's scripts import, and some of them
record its hash, so it is left unchanged. Its `main()` still sets `--study-dir` to `../vbox-runs/hybrid-rf-study-20261010`
next to the folder it is in, which was the repository root when it was written. Give `--study-dir` explicitly.

```sh
cd analysis && python3 -m unittest discover -s tests
```

`tests/test_pcap_window_alignment.py` marks one test as an expected failure: it was written for a window rule that
this version of the extractor does not have (the comment above the test explains).
