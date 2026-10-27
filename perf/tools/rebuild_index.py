#!/usr/bin/env python3
"""Rebuild RUN_DIR/INDEX.tsv from the headers of the NNN_label.txt logs.

The per-command log files written by logrun.sh/swrun.sh are the authoritative
record; INDEX.tsv is only a convenience view, one line per command, with
newlines and tabs in the command escaped.

    python3 perf/tools/rebuild_index.py RUN_DIR
"""
import re
import sys
from pathlib import Path

LOG_NAME = re.compile(r"^(\d{3})_.+\.txt$")


def parse_log(path):
    host = start = cmd = None
    cmd_lines = []
    in_cmd = False
    rc = wall = ""
    for line in path.read_text(errors="replace").splitlines():
        if line.startswith("# host: "):
            host = "switch" if "(switch" in line else "PC1"
        elif line.startswith("# start_utc"):
            start = line.split(": ", 1)[1].strip()
        elif line.startswith("# cmd: "):
            in_cmd = True
            cmd_lines = [line[len("# cmd: "):]]
        elif line.startswith("# ---- output"):
            in_cmd = False
            cmd = "\n".join(cmd_lines)
        elif in_cmd:
            cmd_lines.append(line)
        m = re.match(r"^# ---- exit_code: (\S+)\s+wall_s: (\S+)", line)
        if m:
            rc, wall = m.group(1), m.group(2)
    cmd = (cmd or "").replace("\t", "\\t").replace("\n", "\\n")
    return host, start, rc, wall, cmd


def main():
    run_dir = Path(sys.argv[1])
    rows = []
    for path in sorted(run_dir.iterdir()):
        m = LOG_NAME.match(path.name)
        if m:
            rows.append((m.group(1),) + parse_log(path))
    with open(run_dir / "INDEX.tsv", "w") as out:
        for row in rows:
            out.write("\t".join(x or "" for x in row) + "\n")
    print(f"{len(rows)} entries written to {run_dir / 'INDEX.tsv'}")


if __name__ == "__main__":
    main()
