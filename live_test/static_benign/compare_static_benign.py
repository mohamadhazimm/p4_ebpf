#!/usr/bin/env python3
"""Put each live row of the dataset's static benign programs next to its dataset twin (PC1.md Part 6).

    python3 live_test/static_benign/compare_static_benign.py OUT/rows.csv [--dataset CSV] [--release REL]
        [--json OUT/compare.json]

--dataset is the training and comparison table: the release's dataset/features.csv for rows collected with the
launcher (run_static_benign.py default), live_test/prologuefree/features_05s_prologuefree.csv for rows collected
with --startup-free.

For every live row (run_static_benign.py keeps the dataset execution_id) it reports:
- the host side: live and dataset system-call counts and how many of the 90 host columns agree within 1% and 10%;
- the scores: the paper's detectors (release evaluation/common.py random_forest: host-only, network-only, the
  concatenated hybrid on all 235 columns, and the stacked hybrid of evaluation/combined.py) trained on the 240
  dataset rows WITHOUT the program's project, scoring the live row and its dataset twin with the same models.
  With the project held out, the twin's score is a fair held-out score, so a faithful live pipeline gives the
  live row about the same score; a different one shows here.
Needs NumPy and scikit-learn older than 1.8 (evaluation/requirements.txt).
"""
import argparse
import csv
import json
import sys
from pathlib import Path

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedGroupKFold

INNER_SEED = 7
DETECTORS = ("host", "network", "concat", "stacked")


def detectors(common, Xh, Xn, y, groups, tr):
    """The four fitted detectors on training rows tr, as functions of (host, network) matrices."""
    host = common.random_forest().fit(Xh[tr], y[tr])
    net = common.random_forest().fit(Xn[tr], y[tr])
    concat = common.random_forest().fit(np.hstack([Xh, Xn])[tr], y[tr])
    inner_h, inner_n = np.zeros(len(tr)), np.zeros(len(tr))
    inner = StratifiedGroupKFold(min(5, len(set(groups[tr]))), shuffle=True, random_state=INNER_SEED)
    for itr, ite in inner.split(Xh[tr], y[tr], groups[tr]):
        a, b = tr[itr], tr[ite]
        inner_h[ite] = common.random_forest().fit(Xh[a], y[a]).predict_proba(Xh[b])[:, 1]
        inner_n[ite] = common.random_forest().fit(Xn[a], y[a]).predict_proba(Xn[b])[:, 1]
    stacker = LogisticRegression(max_iter=2000, class_weight="balanced").fit(np.column_stack([inner_h, inner_n]), y[tr])

    def score(H, N):
        ph, pn = host.predict_proba(H)[:, 1], net.predict_proba(N)[:, 1]
        return {"host": ph, "network": pn, "concat": concat.predict_proba(np.hstack([H, N]))[:, 1],
                "stacked": stacker.predict_proba(np.column_stack([ph, pn]))[:, 1]}
    return score


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("rows")
    ap.add_argument("--release", default=str(Path(__file__).resolve().parents[3] / "p4-ebpf-malware-detection"))
    ap.add_argument("--dataset", help="training and comparison rows (default: the release's dataset/features.csv)")
    ap.add_argument("--json")
    args = ap.parse_args()
    sys.path.insert(0, str(Path(args.release) / "evaluation"))
    import common  # noqa: E402  the release's loader and forest

    rows, host_cols, net_cols = common.load(args.dataset) if args.dataset else common.load()
    by_id = {r["execution_id"]: i for i, r in enumerate(rows)}
    with open(args.rows, newline="") as f:
        live = [r for r in csv.DictReader(f)]
    missing = [r["execution_id"] for r in live if r["execution_id"] not in by_id]
    if missing:
        sys.exit("rows without a dataset twin: %s" % ", ".join(missing))
    Xh, Xn, y = common.matrix(rows, host_cols), common.matrix(rows, net_cols), common.labels(rows)
    groups = np.asarray([r["cv_group"] for r in rows])
    Lh, Ln = common.matrix(live, host_cols), common.matrix(live, net_cols)
    twin = np.asarray([by_id[r["execution_id"]] for r in live])
    out = []
    for project in sorted({rows[i]["cv_group"] for i in twin}):
        tr = np.flatnonzero(groups != project)
        score = detectors(common, Xh, Xn, y, groups, tr)
        js = [j for j, i in enumerate(twin) if rows[i]["cv_group"] == project]
        p_live, p_twin = score(Lh[js], Ln[js]), score(Xh[twin[js]], Xn[twin[js]])
        for k, j in enumerate(js):
            d = rows[twin[j]]
            a, b = Lh[j], Xh[twin[j]]
            rel = np.abs(a - b) / np.maximum(np.abs(b), 1e-9)
            out.append({"execution_id": live[j]["execution_id"], "project": project,
                        "syscalls_live": int(float(live[j]["syscall_count"])), "syscalls_dataset": int(float(d["syscall_count"])),
                        "host_within_1pct": int((rel <= 0.01).sum()), "host_within_10pct": int((rel <= 0.10).sum()),
                        "network_nonzero_live": int((Ln[j] != 0).sum()), "network_nonzero_dataset": int((Xn[twin[j]] != 0).sum()),
                        "live": {n: float(p_live[n][k]) for n in DETECTORS},
                        "dataset": {n: float(p_twin[n][k]) for n in DETECTORS}})
    print("%-44s %9s %9s %6s %6s  %s" % ("execution", "calls", "dataset", "1%", "10%",
                                         "  ".join("%-13s" % n for n in DETECTORS)))
    for o in out:
        print("%-44s %9d %9d %3d/90 %3d/90  %s" % (o["execution_id"][:44], o["syscalls_live"], o["syscalls_dataset"],
              o["host_within_1pct"], o["host_within_10pct"],
              "  ".join("%.2f vs %.2f  " % (o["live"][n], o["dataset"][n]) for n in DETECTORS)))
    summary = {n: {"flagged_live": sum(o["live"][n] >= 0.5 for o in out),
                   "flagged_dataset": sum(o["dataset"][n] >= 0.5 for o in out),
                   "mean_abs_difference": float(np.mean([abs(o["live"][n] - o["dataset"][n]) for o in out]))}
               for n in DETECTORS}
    print("\nflagged (probability >= 0.5), live vs dataset twin, of %d:" % len(out))
    for n in DETECTORS:
        s = summary[n]
        print("  %-8s %3d vs %3d   mean |difference| %.3f" % (n, s["flagged_live"], s["flagged_dataset"], s["mean_abs_difference"]))
    if args.json:
        Path(args.json).write_text(json.dumps({"summary": summary, "rows": out}, indent=1) + "\n")


if __name__ == "__main__":
    main()
