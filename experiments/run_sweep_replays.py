#!/usr/bin/env python3
"""Every dataset capture with traffic through switch/variants/sweep (sweep_replay.py), one after the other.

    run_sweep_replays.py OUT_DIR --asroot ASROOT [--only ID,ID] [--include-oversize] [--rerun]
                         [any sweep_replay.py option, passed on: --switch-ssh, --iface, --port, --mode, ...]

The captures: the 77 of experiments/captures/cohort/ and the 33 of cohort-extra.tar.gz (each extracted into
/dev/shm/sweep_extra/ for its run and deleted after). The three bulk uploads (bulkup_200/400/700) hold frames
over the 1500-byte MTU (the guest's capture had TSO; PC1.md part 4) and are left out unless --include-oversize.
Order: the calm captures (expect_overload 0) first, the cohort's before the extras, then the floods, Chaos last.

OUT_DIR/<execution_id>/ holds each run (sweep_replay.py's files). A run with a summary.json is not repeated
unless --rerun. At the end OUT_DIR/rows.csv holds the rows (execution_id and the 145 network columns: the input
of the committee's score_switch_replay.py) and OUT_DIR/runs.csv one line per run with its checks.
"""
import argparse
import csv
import io
import json
import shutil
import subprocess
import sys
import tarfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
CAPS = REPO / "experiments" / "captures"
OVERSIZE = {"bulkup_200", "bulkup_400", "bulkup_700"}
CHAOS = "d538053ada48405e02cfac24bc145c79bb2ae56470cc1b4bae4ee3c916d772e1"
RUN_FIELDS = ["execution_id", "status", "frames", "frames_sent", "frames_failed", "probes_sent", "switch_probes",
              "model_probes", "exports", "switch_exported", "model_exports", "sweeps", "seq_contiguous",
              "totals_mismatch_windows", "pkts", "pkts_model", "exact_nodur", "model_exact_nodur",
              "equal_model_nodur", "checks_ok", "failed_checks", "mismatch_nodur", "sweep_span_us_max",
              "coll_pkts", "coll_pkts_model", "merged_buckets", "merged_buckets_model", "merged_windows", "seconds"]


def items():
    out = []
    for r in csv.DictReader(open(CAPS / "cohort" / "manifest.csv")):
        out.append(dict(eid=r["execution_id"], anchor=int(r["anchor_us"]), path=CAPS / "cohort" / r["capture"],
                        member=None, overload=r.get("expect_overload", "0") == "1", extra=False))
    with tarfile.open(CAPS / "cohort-extra.tar.gz", "r:gz") as tar:
        man = tar.extractfile("cohort-extra/manifest.csv").read().decode()
    for r in csv.DictReader(io.StringIO(man)):
        out.append(dict(eid=r["execution_id"], anchor=int(r["anchor_us"]), path=None,
                        member="cohort-extra/" + r["capture"], overload=r.get("expect_overload", "0") == "1",
                        extra=True))
    calm = [x for x in out if not x["overload"]]
    flood = sorted((x for x in out if x["overload"]), key=lambda x: x["eid"] == CHAOS)
    return calm + flood


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("out")
    ap.add_argument("--asroot", required=True)
    ap.add_argument("--only", default="")
    ap.add_argument("--include-oversize", action="store_true")
    ap.add_argument("--rerun", action="store_true")
    ap.add_argument("--shm", default="/dev/shm/sweep_extra")
    args, passthrough = ap.parse_known_args()
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    only = set(args.only.split(",")) - {""}
    todo = [x for x in items() if (not only or x["eid"] in only) and (args.include_oversize or x["eid"] not in OVERSIZE)]
    shm = Path(args.shm)
    t_all = time.time()
    tar = tarfile.open(CAPS / "cohort-extra.tar.gz", "r:gz")
    try:
        for n, it in enumerate(todo, 1):
            run = out / it["eid"]
            if (run / "summary.json").exists() and not args.rerun:
                print("[%d/%d] %s: done before" % (n, len(todo), it["eid"][:16]), flush=True)
                continue
            path = it["path"]
            if it["member"]:
                shm.mkdir(parents=True, exist_ok=True)
                path = shm / Path(it["member"]).name
                with tar.extractfile(it["member"]) as src, open(path, "wb") as dst:
                    shutil.copyfileobj(src, dst)
            t0 = time.time()
            try:
                r = subprocess.run([sys.executable, str(REPO / "experiments" / "sweep_replay.py"), str(path),
                                    "--anchor-us", str(it["anchor"]), "--out", str(run), "--asroot", args.asroot,
                                    "--execution-id", it["eid"]] + passthrough,
                                   capture_output=True, text=True, timeout=7200)
            finally:
                if it["member"]:
                    path.unlink(missing_ok=True)
            run.mkdir(parents=True, exist_ok=True)
            (run / "driver.log").write_text(r.stdout + r.stderr)
            last = (r.stdout.strip().splitlines() or [""])[-1]
            print("[%d/%d] %s (%.0f s): %s" % (n, len(todo), it["eid"][:16], time.time() - t0,
                                               last[:300] if r.returncode == 0 else
                                               "FAILED %d: %s" % (r.returncode, (r.stderr or r.stdout)[-300:])),
                  flush=True)
    finally:
        tar.close()
    collect(out, todo)
    print("all done in %.0f s" % (time.time() - t_all), flush=True)


def collect(out, todo):
    rows, runs = [], []
    for it in todo:
        run = out / it["eid"]
        s = json.loads((run / "summary.json").read_text()) if (run / "summary.json").exists() else None
        if s is None:
            runs.append(dict(execution_id=it["eid"], status="missing"))
            continue
        for r in csv.DictReader(open(run / "row.csv")):
            rows.append(r)
        line = dict((k, s.get(k)) for k in RUN_FIELDS if k in s)
        line.update(execution_id=it["eid"], status="ok" if s.get("checks_ok") else "checks_failed",
                    failed_checks=" ".join(k for k, v in (s.get("checks") or {}).items() if not v),
                    mismatch_nodur=" ".join(s.get("mismatch_nodur") or []),
                    seconds=round(s.get("end", 0) - s.get("start", 0), 1))
        runs.append(line)
    if rows:
        with open(out / "rows.csv", "w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=list(rows[0]))
            w.writeheader()
            w.writerows(rows)
    with open(out / "runs.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=RUN_FIELDS)
        w.writeheader()
        for line in runs:
            w.writerow(dict((k, line.get(k, "")) for k in RUN_FIELDS))
    ok = sum(1 for x in runs if x.get("status") == "ok")
    equal = sum(1 for x in runs if x.get("exact_nodur") == 135)
    print("runs: %d, checks ok %d, rows equal to the published one in the 135 non-duration columns %d; rows in %s"
          % (len(runs), ok, equal, out / "rows.csv"), flush=True)


if __name__ == "__main__":
    main()
