# The 240 dataset rows without the launcher's startup (training rows for the live rerun)

`features_05s_prologuefree.csv` (SHA-256 `0ba3e62df86ba2b43d69f4f04d66ea880c982071a72921fa1ef91722d8d2ca7b`)
has the layout of the release's `dataset/features.csv`. Metadata and the 145 network columns are
unchanged. The 90 host columns are recomputed from each run's raw `syscall_events.csv` with the release's
`features/host_model.py`, at 0.5 s x 40 windows, without the root process's calls before its second exec
success: the launcher `/bin/bash -c 'exec "$@"' sample-launch` up to the exec of the program, 178 calls in
all 240 runs (RUNBOOK 19.5.6). With every call kept, the same code reproduces the published host columns
of all 240 rows (relative 1.8e-15).

Built on the workstation by `vbox-runs/.../additional-study-review-20261022/launcher-ablation-05s/build_05s.py`
(2026-11-11). Scored with the release's evaluation code, unchanged:

| BA | host | network | hybrid |
|---|---|---|---|
| Table IV (held-out), published -> startup-free | 0.929 -> 0.929 | 0.750 -> 0.750 | 0.926 -> 0.946 |
| Table V (10 fold assignments), published -> startup-free | 0.784 -> 0.832 | 0.756 -> 0.756 | 0.823 -> 0.866 |

Purpose: train the detectors that score live rows collected without the launcher's startup (PC1's
launcher makes 134 calls, the dataset's 178; PC1.md part 2).
