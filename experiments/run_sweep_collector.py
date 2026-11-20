#!/usr/bin/env python3
"""Replay the dataset's captures through hybrid_collector.py --switch-program sweep (switch/variants/sweep), one run each.

    python3 experiments/run_sweep_collector.py OUT --asroot ASROOT --probes inband|generator [--ipg-ns N]
        [--only ID[,ID...]] [--include-oversize]

Each capture goes through experiments/replay_capture.py --profile dataset --sweep PROBES: the collector's windows
K..K+39 are the dataset's 40 (--align-window K, default 6), the anchor offset is the manifest's anchor_us minus the
capture's first frame. --only takes
execution ids or their prefixes (the captures of experiments/run_sweep_replays.py: the cohort's 77 and the 33 of
cohort-extra.tar.gz, extracted into /dev/shm/sweep_extra/ for their run). OUT/runs.csv gets one line per run from
its summary.json (sweep_check): windows equal to the program's model, the packets, and the row against the model's
and the published row in the 135 non-duration columns. The switch must run the sweep build with its ports set up.
"""
import argparse
import csv
import json
import subprocess
import sys
import tarfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "experiments"))
sys.path.insert(0, str(REPO / "switch" / "control"))
import run_sweep_replays as rsr      # noqa: E402  (the capture list)
import sweep_features as sf          # noqa: E402

FIELDS = ["execution_id", "probes", "ipg_ns", "collector_exit_code", "windows_model", "windows_collector",
          "windows_equal_nodur", "pkts_collector", "pkts_model", "coll_pkts_collector", "coll_pkts_model",
          "totals_mismatch_windows", "sweep_span_us_max", "row_equal_model_nodur", "row_equal_published_nodur",
          "row_model_equal_published_nodur", "row_mismatch_published", "alignment_error_ms", "seconds"]


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("out")
    ap.add_argument("--asroot", required=True, help="runs a command as root (replay_capture.py)")
    ap.add_argument("--probes", choices=["inband", "generator"], required=True)
    ap.add_argument("--ipg-ns", type=int, help="--probes generator: the gap between two probes")
    ap.add_argument("--only", default="")
    ap.add_argument("--include-oversize", action="store_true")
    ap.add_argument("--shm", default="/dev/shm/sweep_extra")
    ap.add_argument("--align-window", type=int, default=6,
                    help="the collector window of the dataset's window 0: the windows before it give the replayer "
                         "time to load the capture (up to 1.9 s for a flood) before its first frame is due")
    args = ap.parse_args()
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    want = [w for w in args.only.split(",") if w]
    todo = [it for it in rsr.items() if (not want or any(it["eid"].startswith(w) for w in want))
            and (args.include_oversize or it["eid"] not in rsr.OVERSIZE)]
    shm = Path(args.shm)
    shm.mkdir(parents=True, exist_ok=True)
    tar = tarfile.open(rsr.CAPS / "cohort-extra.tar.gz", "r:gz")
    runs_csv = out / "runs.csv"
    new = not runs_csv.exists()
    t_all = time.time()
    try:
        for n, it in enumerate(todo, 1):
            run = out / it["eid"]
            if (run / "summary.json").exists():
                print("[%d/%d] %s: done before" % (n, len(todo), it["eid"][:16]), flush=True)
                continue
            path = it["path"]
            if it["member"]:
                path = shm / Path(it["member"]).name
                with tar.extractfile(it["member"]) as src, open(path, "wb") as dst:
                    dst.write(src.read())
            t0 = time.time()
            try:
                first_us = sf.read_pcap_us(str(path))[0][0]
                cmd = [args.asroot, sys.executable, str(REPO / "experiments" / "replay_capture.py"), str(path),
                       "--out", str(run), "--profile", "dataset", "--align-window", str(args.align_window),
                       "--anchor-offset", "%.6f" % ((it["anchor"] - first_us) / 1e6), "--sweep", args.probes,
                       "--execution-id", it["eid"]] + (["--sweep-ipg-ns", str(args.ipg_ns)] if args.ipg_ns else [])
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
            finally:
                if it["member"]:
                    path.unlink(missing_ok=True)
            (out / (it["eid"] + ".log")).write_text(r.stdout + r.stderr)     # the run's directory is root's
            row = {"execution_id": it["eid"], "seconds": round(time.time() - t0, 1)}
            if (run / "summary.json").exists():
                s = json.loads((run / "summary.json").read_text())
                c = s.get("sweep_check") or {}
                row.update({k: c.get(k) for k in FIELDS if k in c})
                row.update(collector_exit_code=s.get("collector_exit_code"),
                           alignment_error_ms=s.get("alignment_error_ms"))
            with open(runs_csv, "a", newline="") as fh:
                w = csv.DictWriter(fh, fieldnames=FIELDS, extrasaction="ignore")
                if new:
                    w.writeheader()
                    new = False
                w.writerow(row)
            last = [l for l in (r.stdout or "").splitlines() if "sweep check" in l]
            print("[%d/%d] %s (%.0f s): %s" % (n, len(todo), it["eid"][:16], time.time() - t0,
                                               last[-1] if last else "FAILED %d: %s" % (r.returncode,
                                                                                        (r.stderr or r.stdout)[-300:])),
                  flush=True)
    finally:
        tar.close()
    print("all done in %.0f s" % (time.time() - t_all), flush=True)


if __name__ == "__main__":
    main()
