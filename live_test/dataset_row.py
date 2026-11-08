#!/usr/bin/env python3
"""One dataset-shaped row from a collector run (RUNBOOK 19.9): the 40 windows of
`hybrid_collector.py --profile dataset` summarized into the 90 host and 145 network columns of the
release's dataset/features.csv, so that validation/hybrid/score.py scores the run with the paper's
detectors.

    python3 live_test/dataset_row.py COLLECTOR.csv --execution-id ID --category CAT --label 0|1 --out ROWS.csv
        [--run-id RUN] [--windows 40] [--durations s|ns] [--release ~/Desktop/p4-ebpf-malware-detection]

The 29 network and 18 host window features are taken by name from the collector's columns
(net_new_conn_dst_max and the collector's extra host columns are ignored). --durations ns divides
the two duration features by 1e9 first (runs made without --duration-unit s). The statistics are
the release's features/summary.py: mean, max, sum, population std and active_windows over the
windows. ROWS.csv is created with the dataset's column names or appended to.
"""
import argparse
import csv
import importlib.util
import sys
from pathlib import Path

DEFAULT_RELEASE = Path.home() / "Desktop/p4-ebpf-malware-detection"
META = ["execution_id", "label", "category", "attack_type", "family", "project", "program", "sha256", "source",
        "mode", "split", "cv_group", "collection_position", "return_code", "syscall_count"]
DURATIONS = ("net_flow_duration_mean", "net_flow_duration_max")


def load_module(path):
    spec = importlib.util.spec_from_file_location(path.stem, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("csv")
    ap.add_argument("--execution-id", required=True)
    ap.add_argument("--category", required=True,
                    help="dataset category: malware, benign, network_attack, network_benign or null")
    ap.add_argument("--label", required=True, choices=["0", "1"])
    ap.add_argument("--out", required=True)
    ap.add_argument("--run-id", help="the run to take when the collector CSV holds several")
    ap.add_argument("--windows", type=int, default=40)
    ap.add_argument("--durations", choices=["s", "ns"], default="s", help="unit of the collector's duration columns")
    ap.add_argument("--release", default=str(DEFAULT_RELEASE))
    ap.add_argument("--return-code", default="")
    args = ap.parse_args()

    release = Path(args.release)
    summary = load_module(release / "features" / "summary.py")
    switch_model = load_module(release / "features" / "switch_model.py")
    host_model = load_module(release / "features" / "host_model.py")

    with open(args.csv, newline="") as f:
        rows = list(csv.DictReader(f))
    run_ids = sorted({r["run_id"] for r in rows})
    if args.run_id:
        rows = [r for r in rows if r["run_id"] == args.run_id]
    elif len(run_ids) != 1:
        sys.exit(f"{args.csv} holds {len(run_ids)} runs; pick one with --run-id: " + ", ".join(run_ids))
    if not rows:
        sys.exit("no rows for that run")
    rows.sort(key=lambda r: int(float(r["window_id"])))
    if len(rows) < args.windows:
        sys.exit(f"the run has {len(rows)} windows, {args.windows} are needed")
    rows = rows[:args.windows]

    windows = []
    for r in rows:
        w = {}
        for feature in switch_model.FEATURES + host_model.FEATURES:
            value = float(r[feature])
            if feature in DURATIONS and args.durations == "ns":
                value /= 1e9
            w[feature] = value
        windows.append(w)
    host = summary.summarize(windows, host_model.FEATURES)
    network = summary.summarize(windows, switch_model.FEATURES)

    row = {k: "" for k in META}
    row.update({"execution_id": args.execution_id, "label": args.label, "category": args.category,
                "return_code": args.return_code,
                "syscall_count": int(host["host_total_syscalls_total__sum"])})
    row.update(host)
    row.update(network)
    # the dataset's column order, when its file is there
    dataset_csv = release / "dataset" / "features.csv"
    if dataset_csv.exists():
        with open(dataset_csv, newline="") as f:
            header = next(csv.reader(f))
        if set(header) == set(row):
            row = {k: row[k] for k in header}

    out = Path(args.out)
    exists = out.exists() and out.stat().st_size > 0
    if exists:
        with open(out, newline="") as f:
            existing = next(csv.reader(f))
        if existing != list(row):
            sys.exit(f"{out} has different columns; write to a new file")
    with open(out, "a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(row.keys()))
        if not exists:
            writer.writeheader()
        writer.writerow(row)
    print(f"{args.execution_id}: {len(rows)} windows -> 1 row with {len(host)} host and {len(network)} network "
          f"columns appended to {out}")


if __name__ == "__main__":
    main()
