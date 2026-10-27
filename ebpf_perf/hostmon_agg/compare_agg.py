#!/usr/bin/env python3
"""Compare hostmon and hostmon_agg outputs recorded side by side (check_agg.sh).

Usage: compare_agg.py HOSTMON_OUT HOSTMON_AGG_OUT [--threaded-pids FILE] [--json OUT] | --self-test

Both collectors watched the same cgroup with the same start time and window, so
every (window, PID) row should be identical. Two differences are expected and
allowed:
  * boundary shifts: the collectors timestamp an event at slightly different
    points (hostmon when its ring-buffer record is submitted, hostmon_agg when the
    syscall enters the kernel), so an event within a few hundred ns of a window
    boundary can fall on either side. Such a shift moves counts between adjacent
    windows of one PID; the PID's totals over all windows still agree.
  * multi-threaded processes (PIDs listed in --threaded-pids): the two collectors
    order concurrent threads' syscalls independently (ring-buffer order versus a
    per-process lock), so only order-independent columns must match there.
Anything else is a mismatch.
"""
import csv
import json
import re
import sys
import tempfile
from pathlib import Path

COUNT_COLS = ["EXEC", "OPEN", "REN", "DEL", "CONN", "TOTAL_SYSCALLS"]
ORDER_FREE = COUNT_COLS + ["UNIQIP", "UNIQPRT", "UNIQUE_SYSCALLS", "ENTROPY", "TOP_SYSCALL_FREQ", "RARE_SYSCALL_RATIO"]
WINDOW_RE = re.compile(r"^==== HOST WINDOW (\d+) START=(\S+) END=(\S+) DUR=\S+ ====$")


def parse(path):
    windows, health, header, current = {}, None, None, None
    for line in Path(path).read_text(errors="replace").splitlines():
        m = WINDOW_RE.match(line)
        if m:
            current = int(m.group(1))
            windows[current] = {"start": m.group(2), "end": m.group(3), "rows": {}}
        elif line.startswith("COMM,PID"):
            header = line.split(",")
        elif line.startswith("HOSTMON_HEALTH,"):
            lost, capacity, late, failed = (int(x) for x in line.split(",")[1:5])
            health = {"lost": lost, "capacity_errors": capacity, "late_events": late, "failed": failed}
        elif header and current is not None and line and not line.startswith("HOSTMON_"):
            values = next(csv.reader([line]))
            if len(values) == len(header):
                row = dict(zip(header, values))
                windows[current]["rows"][row["PID"]] = row
    return windows, health


def compare(orig_path, agg_path, threaded=()):
    orig, orig_health = parse(orig_path)
    agg, agg_health = parse(agg_path)
    threaded = set(threaded)
    problems, notes = [], []
    if orig_health is None or agg_health is None:
        problems.append("missing HOSTMON_HEALTH line")
    elif orig_health["lost"] or orig_health["late_events"]:
        problems.append(f"hostmon itself dropped events, comparison invalid: {orig_health}")
    if orig_health and agg_health:
        for key in ("capacity_errors", "late_events"):
            if orig_health[key] != agg_health[key]:
                problems.append(f"health {key}: hostmon {orig_health[key]} vs hostmon_agg {agg_health[key]}")
    if sorted(orig) != sorted(agg):
        problems.append(f"window ids differ: {sorted(set(orig) ^ set(agg))}")
    ids = sorted(set(orig) & set(agg))
    for w in ids:
        if orig[w]["start"] != agg[w]["start"] or (w != ids[-1] and orig[w]["end"] != agg[w]["end"]):
            problems.append(f"window {w} bounds differ")

    pids = sorted({p for w in ids for p in orig[w]["rows"]} | {p for w in ids for p in agg[w]["rows"]}, key=int)
    rows_identical = rows_total = 0
    shifted = set()
    for pid in pids:
        # Count differences per window; a boundary shift moves counts to an adjacent window.
        for col in COUNT_COLS:
            diffs = [int(orig[w]["rows"].get(pid, {}).get(col, 0)) - int(agg[w]["rows"].get(pid, {}).get(col, 0)) for w in ids]
            if sum(diffs):
                problems.append(f"PID {pid} {col}: totals over all windows differ by {sum(diffs)}")
                continue
            running = 0
            for i, d in enumerate(diffs):
                running += d
                if d:
                    shifted.add((ids[i], pid))
                if abs(running) > 3:
                    problems.append(f"PID {pid} {col}: {abs(running)} events moved across the end of window {ids[i]}")
                    break
        for w in ids:
            a, b = orig[w]["rows"].get(pid), agg[w]["rows"].get(pid)
            if a is None and b is None:
                continue
            rows_total += 1
            if a == b:
                rows_identical += 1
                continue
            if (w, pid) in shifted:
                notes.append(f"window {w} PID {pid}: boundary shift")
                continue
            if a is None or b is None:
                problems.append(f"window {w} PID {pid}: row only in {'hostmon_agg' if a is None else 'hostmon'}")
                continue
            cols = [c for c in a if a[c] != b[c]]
            if pid in threaded and not set(cols) & set(ORDER_FREE):
                notes.append(f"window {w} PID {pid} (multi-threaded): order-dependent columns differ: {cols}")
            else:
                problems.append(f"window {w} PID {pid}: {', '.join(f'{c} {a[c]} vs {b[c]}' for c in cols)}")
    return {"verdict": "PASS" if not problems else "FAIL", "windows": len(ids), "pids": len(pids),
            "rows": rows_total, "rows_identical": rows_identical, "boundary_shift_rows": len(shifted),
            "health": {"hostmon": orig_health, "hostmon_agg": agg_health},
            "problems": problems, "notes": notes}


def self_test():
    header = "COMM,PID,EXEC,OPEN,REN,DEL,CONN,UNIQIP,UNIQPRT,TOTAL_SYSCALLS,UNIQUE_SYSCALLS,ENTROPY,TOP_SYSCALL_FREQ,AVG_RUN_LENGTH,MAX_RUN_LENGTH,TRANSITION_COUNT,RARE_SYSCALL_RATIO,FIRST50_UNIQUE,FIRST100_UNIQUE"

    def out(windows, health="0,0,0,0"):
        text = "HOSTMON_READY,1\n"
        for w, rows in enumerate(windows):
            text += f"\n==== HOST WINDOW {w} START={w}.000000 END={w + 1}.000000 DUR=1.000000 ====\n{header}\n"
            text += "".join(f'"p",{pid},0,{op},0,0,0,0,0,{tot},2,1.0,0.5,{run},3,4,0.1,2,2\n' for pid, op, tot, run in rows)
        return text + f"HOSTMON_HEALTH,{health}\n"

    def run(a, b, threaded=()):
        with tempfile.TemporaryDirectory() as tmp:
            pa, pb = Path(tmp, "a"), Path(tmp, "b")
            pa.write_text(a)
            pb.write_text(b)
            return compare(pa, pb, threaded)

    same = out([[(10, 1, 100, "2.0")], [(10, 0, 50, "1.0")]])
    assert run(same, same)["verdict"] == "PASS"
    shifted = out([[(10, 1, 99, "2.1")], [(10, 0, 51, "1.1")]])
    r = run(same, shifted)
    assert r["verdict"] == "PASS" and r["boundary_shift_rows"] == 2, r
    assert run(same, out([[(10, 1, 100, "2.0")], [(10, 0, 49, "1.0")]]))["verdict"] == "FAIL"   # lost event
    assert run(same, out([[(10, 1, 100, "9.0")], [(10, 0, 50, "1.0")]]))["verdict"] == "FAIL"   # wrong feature
    assert run(same, out([[(10, 1, 100, "9.0")], [(10, 0, 50, "1.0")]]), threaded={"10"})["verdict"] == "PASS"
    assert run(same, out([[(10, 1, 100, "2.0")], [(10, 0, 50, "1.0")]], "0,5,0,0"))["verdict"] == "FAIL"
    assert run(same, out([[(10, 1, 100, "2.0")], [(10, 0, 50, "1.0"), (11, 0, 7, "1.0")]]))["verdict"] == "FAIL"
    print("self-test passed")


def main(argv):
    if argv == ["--self-test"]:
        return self_test()
    threaded, json_out = [], None
    if "--threaded-pids" in argv:
        i = argv.index("--threaded-pids")
        path = Path(argv[i + 1])
        threaded = path.read_text().split() if path.exists() else []
        argv = argv[:i] + argv[i + 2:]
    if "--json" in argv:
        i = argv.index("--json")
        json_out = Path(argv[i + 1])
        argv = argv[:i] + argv[i + 2:]
    if len(argv) != 2:
        sys.exit(__doc__)
    result = compare(argv[0], argv[1], threaded)
    if json_out:
        json_out.write_text(json.dumps(result, indent=2) + "\n")
    print(f'{result["verdict"]}: {result["windows"]} windows, {result["pids"]} PIDs, '
          f'{result["rows_identical"]}/{result["rows"]} rows identical, {result["boundary_shift_rows"]} rows with boundary shifts')
    print(f'health: hostmon {result["health"]["hostmon"]}, hostmon_agg {result["health"]["hostmon_agg"]}')
    for line in result["problems"][:40]:
        print("  MISMATCH", line)
    for line in result["notes"][:20]:
        print("  note", line)
    return 0 if result["verdict"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
