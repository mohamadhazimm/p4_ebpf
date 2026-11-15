#!/usr/bin/env python3
"""A verdict after every window of a live run (committee items 5 and 6; PC1.md Part 7).

    python3 live_test/streaming/stream_verdicts.py COLLECTOR.csv [--follow] [--detector network]
        [--threshold 0.5] [--skip-windows K] [--windows 40] [--on-alarm "COMMAND"] [--log OUT.jsonl]

The paper's detectors give one verdict per 20-s run. Here the same forests (release evaluation/common.py
random_forest) are trained on every dataset run at the observation prefixes 1, 2, 4, 6, 10, 16, 20, 30 and 40
windows (live_test/streaming/dataset_windows.csv.gz: the 240 runs' 0.5-s window signals; the summaries of all
40 windows are the published rows), as in the committee analysis (committee-eval-20261113 REPORT.md 2.6). After
each new window k of the collector's CSV the run so far is summarized like a dataset row (mean, max, sum,
population std and active windows of the first k windows) and scored.

--follow waits for the collector to write the windows (a replay or a live run in progress) and stops after
--windows windows or --idle seconds without a new one; without it the finished CSV is scored window by window.
--skip-windows K skips the collector windows before the run's first (a replay anchored on window K).
--on-alarm runs COMMAND once, through the shell, the first time a window's probability reaches --threshold, with
STREAM_WINDOW, STREAM_PROBABILITY and STREAM_DETECTOR in its environment: the hook for a mitigation rule.
--detector: network (default; a replay has no host side), host, concat (one forest on both views) or stacked
(the stacked hybrid of evaluation/combined.py). --hold-out-group G (repeatable) leaves the dataset runs of group G
(features.csv cv_group) out of the training: give the replayed run's group, or the verdict is in-sample.
Needs NumPy and scikit-learn older than 1.8.
"""
import argparse
import csv
import gzip
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedGroupKFold

HERE = Path(__file__).resolve().parent
PREFIXES = [1, 2, 4, 6, 10, 16, 20, 30, 40]
INNER_SEED = 7


def load_windows(path):
    """Per-run arrays (n, 40, signals) from the dataset's window table, with labels and groups."""
    with gzip.open(path, "rt", newline="") as f:
        reader = csv.reader(f)
        header = next(reader)
        rows = list(reader)
    meta = header[:6]
    assert meta == ["execution_id", "label", "category", "cv_group", "split", "window"], meta
    signals = header[6:]
    runs, order = {}, []
    for r in rows:
        if r[0] not in runs:
            runs[r[0]] = (int(r[1]), r[3], [None] * 40)
            order.append(r[0])
        runs[r[0]][2][int(r[5])] = [float(x) for x in r[6:]]
    W = np.asarray([runs[e][2] for e in order])
    y = np.asarray([runs[e][0] for e in order])
    g = np.asarray([runs[e][1] for e in order])
    return signals, W, y, g


def summarize(W, k):
    """Mean, max, sum, population std and active windows of the first k windows (n, signals*5)."""
    W = W[:, :k]
    return np.stack([W.mean(1), W.max(1), W.sum(1), W.std(1), (W != 0).sum(1).astype(float)], axis=2).reshape(len(W), -1)


def train(release, windows_path, detector, hold_out=()):
    sys.path.insert(0, str(Path(release) / "evaluation"))
    import common  # noqa: E402  the release's forest
    signals, W, y, g = load_windows(windows_path)
    keep = ~np.isin(g, list(hold_out))
    if hold_out:
        missing = set(hold_out) - set(g)
        if missing:
            sys.exit("no dataset runs in group(s) %s" % ", ".join(sorted(missing)))
        W, y, g = W[keep], y[keep], g[keep]
    host = [i for i, s in enumerate(signals) if s.startswith("host_")]
    net = [i for i, s in enumerate(signals) if s.startswith("net_")]
    Xh = np.vstack([summarize(W[:, :, host], k) for k in PREFIXES])
    Xn = np.vstack([summarize(W[:, :, net], k) for k in PREFIXES])
    yy, gg = np.tile(y, len(PREFIXES)), np.tile(g, len(PREFIXES))
    fitted = {}
    if detector in ("host", "stacked"):
        fitted["host"] = common.random_forest().fit(Xh, yy)
    if detector in ("network", "stacked"):
        fitted["network"] = common.random_forest().fit(Xn, yy)
    if detector == "concat":
        fitted["concat"] = common.random_forest().fit(np.hstack([Xh, Xn]), yy)
    if detector == "stacked":
        ih, inn = np.zeros(len(yy)), np.zeros(len(yy))
        for a, b in StratifiedGroupKFold(5, shuffle=True, random_state=INNER_SEED).split(Xh, yy, gg):
            ih[b] = common.random_forest().fit(Xh[a], yy[a]).predict_proba(Xh[b])[:, 1]
            inn[b] = common.random_forest().fit(Xn[a], yy[a]).predict_proba(Xn[b])[:, 1]
        fitted["stacker"] = LogisticRegression(max_iter=2000, class_weight="balanced").fit(np.column_stack([ih, inn]), yy)

    def score(wh, wn):
        h, n = summarize(wh[None], wh.shape[0]), summarize(wn[None], wn.shape[0])
        if detector == "host":
            return float(fitted["host"].predict_proba(h)[0, 1])
        if detector == "network":
            return float(fitted["network"].predict_proba(n)[0, 1])
        if detector == "concat":
            return float(fitted["concat"].predict_proba(np.hstack([h, n]))[0, 1])
        ph, pn = fitted["host"].predict_proba(h)[0, 1], fitted["network"].predict_proba(n)[0, 1]
        return float(fitted["stacker"].predict_proba([[ph, pn]])[0, 1])
    return [signals[i] for i in host], [signals[i] for i in net], score


def read_windows(path, skip, run_id):
    """The collector's windows after the first `skip`, sorted by window_id (one run)."""
    try:
        with open(path, newline="") as f:
            rows = list(csv.DictReader(f))
    except (OSError, csv.Error):
        return []
    if not rows:
        return []
    key = "window_id" if "window_id" in rows[0] else "window"
    if "run_id" in rows[0]:
        rid = run_id or rows[-1]["run_id"]
        rows = [r for r in rows if r["run_id"] == rid]
    rows.sort(key=lambda r: int(float(r[key])))
    return rows[skip:]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("csv")
    ap.add_argument("--train", default=str(HERE / "dataset_windows.csv.gz"))
    ap.add_argument("--release", default=str(HERE.parents[2] / "p4-ebpf-malware-detection"))
    ap.add_argument("--detector", choices=["network", "host", "concat", "stacked"], default="network")
    ap.add_argument("--threshold", type=float, default=0.5)
    ap.add_argument("--skip-windows", type=int, default=0)
    ap.add_argument("--windows", type=int, default=40)
    ap.add_argument("--run-id")
    ap.add_argument("--follow", action="store_true")
    ap.add_argument("--poll", type=float, default=0.05)
    ap.add_argument("--idle", type=float, default=30.0)
    ap.add_argument("--on-alarm")
    ap.add_argument("--hold-out-group", action="append", default=[])
    ap.add_argument("--log")
    args = ap.parse_args()
    t_train = time.monotonic()
    host_sig, net_sig, score = train(args.release, args.train, args.detector, args.hold_out_group)
    print("[stream] %s detector trained on %d prefixes of the dataset runs%s in %.1f s" % (
        args.detector, len(PREFIXES), (" without " + ", ".join(args.hold_out_group)) if args.hold_out_group else "",
        time.monotonic() - t_train), flush=True)
    log = open(args.log, "a") if args.log else None
    done, alarm, last_new = 0, None, time.monotonic()
    t0 = None
    while done < args.windows:
        rows = read_windows(args.csv, args.skip_windows, args.run_id)
        if len(rows) > done:
            last_new = time.monotonic()
            for k in range(done + 1, min(len(rows), args.windows) + 1):
                now = time.time()
                t0 = t0 or now
                part = rows[:k]
                wh = np.asarray([[float(r.get(s, 0) or 0) for s in host_sig] for r in part])
                wn = np.asarray([[float(r.get(s, 0) or 0) for s in net_sig] for r in part])
                p = score(wh, wn)
                fired = p >= args.threshold and alarm is None
                rec = {"window": k - 1, "windows_seen": k, "probability": round(p, 4), "detector": args.detector,
                       "alarm": bool(fired), "time": now}
                print("[stream] window %2d: p=%.3f%s" % (k - 1, p, "  ALARM" if fired else ""), flush=True)
                if fired:
                    alarm = rec
                    if args.on_alarm:
                        env = dict(os.environ, STREAM_WINDOW=str(k - 1), STREAM_PROBABILITY="%.4f" % p,
                                   STREAM_DETECTOR=args.detector)
                        rec["on_alarm_started"] = time.time()
                        subprocess.Popen(args.on_alarm, shell=True, env=env)
                if log:
                    log.write(json.dumps(rec) + "\n")
                    log.flush()
            done = min(len(rows), args.windows)
            continue
        if not args.follow or time.monotonic() - last_new > args.idle:
            break
        time.sleep(args.poll)
    print("[stream] %d windows scored; %s" % (done, "first alarm at window %d (p=%.3f)" % (
        alarm["window"], alarm["probability"]) if alarm else "no alarm"), flush=True)
    if log:
        log.write(json.dumps({"summary": True, "windows": done, "alarm": alarm}) + "\n")
        log.close()


if __name__ == "__main__":
    main()
