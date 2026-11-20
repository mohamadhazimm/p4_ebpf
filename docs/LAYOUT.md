# The repository's layout before and after 2026-11-20

On 2026-11-20 the files moved into one folder per component. The moves changed no compiled or measured file: the P4
sources and patches, the eBPF C sources, the captures and the training tables are byte for byte the same. Scripts
and documents got their paths updated. The tag `final-2026-11-20` is the last commit in the old layout, the one
measured on PC1 (the host attached to the Wedge 100BF-32X). The run logs (`PC1.md`, `RUNBOOK.md`, `p4_perf.md`,
`experiments/RESULTS.md`, `host/COMPARISON.md`) keep that layout's paths, because they record commands as they were
run.

| Before | Now |
|---|---|
| `hybrid_collector.py`, `block_policy.py`, `sockjoin.py` | `collector/` |
| `live_test/streaming/` | `collector/detector/` |
| `live_test/` | `experiments/` |
| `testers/` | `experiments/workloads/` |
| `hybrid_data_generator.py` | `experiments/` |
| `tests/validation/known_answer.c` | `experiments/known_answer.c` |
| `thesis-hybrid-ebpf-p4/*.p4`, `ports.json`, `commands.txt`, `P4_new_conn_rate_feature.md` | `switch/p4/` |
| `thesis-hybrid-ebpf-p4/python/` | `switch/control/` |
| `thesis-hybrid-ebpf-p4/python/tests/` | `tests/` |
| `perf/variants/` | `switch/variants/` |
| `perf/tools/` | `switch/tools/` |
| `perf/results/` | `switch/results/` |
| `ebpf_perf/` | `host/` |
| `libbpf-bootstrap/examples/c/{hostmon,execmon,modelmon,filemon}.{c,bpf.c,h}` | `host/streaming/`, with its own `Makefile` |
| `libbpf-bootstrap/` | `third_party/libbpf-bootstrap/` |
| `reference_evaluation/P4_Code/` | `third_party/dns-water-torture-detector/` |
| `reference_evaluation/P4_Code (1).zip` | removed: the same 17 files as the folder |
| `analyze_p4_pcap_ablation.py`, `benchmark_pcap_extraction.py`, `reconstruct_ambiguous_p4.py`, `evaluate_family_stratified_50_50.py`, `evaluate_unknown_50_50.py`, `score_balanced_in_sample.py`, `analyse_hostmon.py`, `view_csv.py` | `analysis/` |
| `tests/test_pcap_window_alignment.py` | `analysis/tests/` |
| `tests/validation/` | `archive/validation-2026-10/` |
| `thesis_hostmon/` | `archive/thesis_hostmon/` |
| `RUNBOOK.md`, `PC1.md`, `p4_perf.md` | `docs/` |
| `.env` | removed from the repository and from its history |

## What else changed

- `collector/hybrid_collector.py`: the default paths of the readers, the forwarding script and the streaming monitor
  are now relative to the checkout. They were absolute paths of the machine with the Tofino model
  (`/home/ubuntu/Desktop/p4_ebpf/...`), and `switch/control/read_registers_with_index.py` likewise finds
  `indexes_unique.txt` next to itself.
- `host/streaming/Makefile` builds the four streaming monitors. It is libbpf-bootstrap's example Makefile with the
  paths of `third_party/`; it also builds `filemon`, which the old one did not. The programs it builds equal those
  built in the old place: the BPF objects differ only in the source path that BTF records.
- `host/build.sh` and `host/sockowner/build.sh` build from `host/`. The code and data sections of the BPF objects
  are identical to those of the recorded builds (`host/build/sha256.txt`, built in `ebpf_perf/`), and only the
  recorded paths differ. `test_agg_equiv` still passes.
- The unit tests run from the repository root with `python3 -m unittest discover -s tests` (325 tests, 8 skipped
  without the SDE's generated `bfruntime_pb2`). Each test file sets its own `sys.path` and also runs alone.
- `analysis/tests/test_pcap_window_alignment.py` marks its one test that has failed since it was written as an
  expected failure, and says why.

## A clone from before 2026-11-20

The history was rewritten on 2026-11-20: every commit has a new hash, and the tag `final-2026-11-20` points to the
new one of its commit. Reset such a clone instead of pulling into it. If the machine uses the file `.env`, copy it
first: the reset deletes the old tracked copy, and `.gitignore` now keeps a new one out of the repository.

```sh
cp .env ../p4_ebpf.env.bak 2>/dev/null
git fetch origin --prune --force --tags
git checkout main && git reset --hard origin/main
cp ../p4_ebpf.env.bak .env 2>/dev/null
```

Git does not move untracked files, so local outputs stay at the old paths. To move them (needs `rsync`):

```sh
move() { [ -d "$1" ] || return 0; mkdir -p "$2"; rsync -a --remove-source-files "$1"/ "$2"/ && find "$1" -depth -type d -empty -delete; }
move perf/results switch/results
move perf/plots switch/plots
for d in run results data www; do move live_test/$d experiments/$d; done
move live_test/captures/cohort-extra experiments/captures/cohort-extra
for d in build results tools sockowner/build; do move ebpf_perf/$d host/$d; done
move thesis-hybrid-ebpf-p4/basic.tofino switch/p4/basic.tofino
move thesis-hybrid-ebpf-p4/pcaps switch/p4/pcaps
make -C host/streaming hostmon modelmon      # the streaming monitors were built in libbpf-bootstrap/examples/c
git status --short --ignored | grep -v '^!! .*__pycache__' | head
```

Whatever `git status` still lists under the old folder names is local and can be moved or deleted.

Scripts outside this repository that use its old paths, for example those of the dataset repository, need this
repository at the tag: `git checkout final-2026-11-20`.
