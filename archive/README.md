# Archive

Superseded code, kept for the record. Nothing here is used by the rest of the repository, and nothing here is
expected to run in this layout.

| Path | What |
|---|---|
| `validation-2026-10/` | The pytest suite of the collector audit of October 2026, with its reports (`REPORT.md`, `REPAIRS.md`, `SUMMARY.md`) and JUnit results. It tests the collector of that time, and its paths are those of the layout before 2026-11-20 (`../docs/LAYOUT.md`). Its fixture `known_answer.c` moved to `experiments/`, where `ebpf_known_answer.py` still uses it. |
| `thesis_hostmon/` | An intermediate copy of the streaming host monitor (2026-10-27). Its `Makefile` expects the folder inside libbpf-bootstrap's `examples/`. |
