#!/usr/bin/env python3
"""Run live_feature_export.summarize_register_window on a real run's register reads.

    check_live_export.py --probe PROBE.json --window-sec 30 [--csv RUN.csv]

For each read k the "before" snapshot is the previous read of the same buckets
(zeros for a bucket read for the first time) and "after" is read k. The
model-sensor fields it returns (net_packets_captured, net_bytes_captured, ...)
are compared with the collector's own window deltas, and every window the
function rejects is counted with its reason. Runs without bucket clears only.
"""
import argparse
import csv
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "thesis-hybrid-ebpf-p4" / "python"))
from live_feature_export import summarize_register_window  # noqa: E402

ZERO = {"pkts": 0, "bytes": 0, "pkts_ab": 0, "bytes_ab": 0}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--probe", required=True)
    ap.add_argument("--window-sec", type=float, required=True)
    ap.add_argument("--csv")
    args = ap.parse_args()
    reads = json.load(open(args.probe))["reads"]
    rows = list(csv.DictReader(open(args.csv))) if args.csv else None
    if any(rd["cleared"] for rd in reads):
        sys.exit("the run cleared buckets; the before/after pairing below assumes it did not")
    last = {}
    rejected = []
    print(" win  export: pkts   bytes  flows | collector: pkts   bytes  rows | match")
    for k, rd in enumerate(reads):
        after = {r["idx"]: {key: int(r[key]) for key in ZERO} for r in rd["rows"]}
        before = {idx: last.get(idx, dict(ZERO)) for idx in after}
        for r in rd["rows"]:
            last[r["idx"]] = {key: int(r[key]) for key in ZERO}
        if not after:
            print(f" {k:3d}  (no buckets)")
            continue
        try:
            out = summarize_register_window(before, after, args.window_sec)
        except ValueError as error:
            rejected.append((k, str(error)))
            print(f" {k:3d}  REJECTED: {error}")
            continue
        line = f" {k:3d}  {out['net_packets_captured']:12d} {out['net_bytes_captured']:7d} {out['net_flow_count']:6d}"
        if rows:
            cp, cb = int(float(rows[k]["net_pkts_total_delta"])), int(float(rows[k]["net_bytes_total_delta"]))
            ok = cp == out["net_packets_captured"] and cb == out["net_bytes_captured"]
            line += f" | {cp:15d} {cb:7d} {int(float(rows[k]['net_flow_count_seen'])):5d} | {'=' if ok else 'DIFF'}"
        print(line)
    print(f"windows rejected by summarize_register_window: {len(rejected)}/{len(reads)}")


if __name__ == "__main__":
    main()
