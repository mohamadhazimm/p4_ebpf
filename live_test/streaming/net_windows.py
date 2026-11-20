#!/usr/bin/env python3
"""The network half of the detectors' window table at another window length, for all 240 dataset runs (PC1.md part 13).

live_test/streaming/dataset_windows.csv.gz holds each run's 40 windows of 0.5 s: 18 host and 29 network signals. This
script computes the 29 network signals at --window seconds (20 s / --window windows per run) with the release's
switch model (features/switch_model.py window_features, unchanged: TTL 3 windows, Ethernet frame bytes, rates over
the nominal window):
- the 110 runs with IPv4 TCP/UDP traffic, from their captures (live_test/captures/cohort/ and cohort-extra.tar.gz),
  with windows from each manifest's anchor_us (the run's sample_started_wall_us, RUNBOOK 19.5.2);
- the other 130 runs carry no TCP/UDP traffic, which is all the model counts, so their windows are zero at every
  length.
Rows follow the training table's run order and layout: execution_id, label, category, cv_group, split, window, then
the network signals in its column order. The host half comes from the runs' raw system calls on the lab workstation
(host_windows.py), which merges the two halves.

Checks, written to OUT.json (the exit status is 1 if one fails):
- at 0.5 s, the same code gives the training table's network columns in every window of all 240 runs;
- when --window divides 0.5 s, each 0.5 s window's packet, byte and flag counts are the sums of its sub-windows'
  counts, and its rates are the mean of their rates.

    .venv/bin/python live_test/streaming/net_windows.py --window 0.25      (Python >= 3.9, as the model; run niced)
"""
import argparse
import csv
import gzip
import io
import json
import math
import os
import sys
import tarfile
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
TABLE = REPO / "live_test" / "streaming" / "dataset_windows.csv.gz"
CAPS = REPO / "live_test" / "captures"
RUN_S = 20.0
BASE_S = 0.5
COUNTS = ("net_pkts_total_delta", "net_bytes_total_delta", "net_pkts_ab_delta", "net_bytes_ab_delta",
          "net_pkts_ba_delta", "net_bytes_ba_delta", "net_syn_delta", "net_ack_delta", "net_rst_delta")
RATES = ("net_bytes_per_sec_delta", "net_pkts_per_sec_delta")


def windows_in_run(window_s):
    n = RUN_S / window_s
    if window_s <= 0 or abs(n - round(n)) > 1e-9:
        raise SystemExit("--window must divide the 20 s of a run")
    return int(round(n))


def load_table(path):
    """The training table: its header, its network columns, and per run the metadata and 0.5 s network windows."""
    with gzip.open(path, "rt", newline="") as f:
        reader = csv.reader(f)
        header = next(reader)
        assert header[:6] == ["execution_id", "label", "category", "cv_group", "split", "window"], header[:6]
        net = [i for i, h in enumerate(header) if h.startswith("net_")]
        runs = {}
        for row in reader:
            run = runs.setdefault(row[0], {"meta": row[:5], "net": {}})
            run["net"][int(row[5])] = [float(row[i]) for i in net]
    return header, [header[i] for i in net], runs


def gzip_writer(path):
    """A gzip text writer with a fixed header time, so that the same rows give the same bytes."""
    raw = open(path, "wb")
    return io.TextIOWrapper(gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0), newline=""), raw


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--window", type=float, required=True, help="window length in seconds (0.25, 0.1, ...)")
    ap.add_argument("--out", help="default live_test/streaming/net_windows_<window>s.csv.gz")
    ap.add_argument("--release", default=str(REPO.parent / "p4-ebpf-malware-detection"))
    ap.add_argument("--table", default=str(TABLE))
    ap.add_argument("--captures", default=str(CAPS))
    ap.add_argument("--tmp", default="/dev/shm" if os.path.isdir("/dev/shm") else tempfile.gettempdir(),
                    help="where cohort-extra captures are unpacked, one at a time")
    args = ap.parse_args()
    sys.path.insert(0, str(Path(args.release) / "features"))
    import switch_model

    ws = args.window
    n = windows_in_run(ws)
    n_base = windows_in_run(BASE_S)
    sub = BASE_S / ws
    sub = int(round(sub)) if abs(sub - round(sub)) < 1e-9 else None
    out = Path(args.out or REPO / "live_test" / "streaming" / ("net_windows_%gs.csv.gz" % ws))
    header, signals, runs = load_table(Path(args.table))
    if sorted(signals) != sorted(switch_model.FEATURES):
        raise SystemExit("the model's network features are not the training table's")
    caps = Path(args.captures)

    # the 110 captures: execution_id -> (anchor_us, capture file in cohort/ or member of cohort-extra.tar.gz)
    todo = {}
    for r in csv.DictReader(open(caps / "cohort" / "manifest.csv", newline="")):
        todo[r["execution_id"]] = (int(r["anchor_us"]), caps / "cohort" / r["capture"], None)
    tar_path = caps / "cohort-extra.tar.gz"
    with tarfile.open(tar_path, "r:gz") as tar:
        for r in csv.DictReader(io.TextIOWrapper(tar.extractfile("cohort-extra/manifest.csv"), newline="")):
            todo[r["execution_id"]] = (int(r["anchor_us"]), None, "cohort-extra/" + r["capture"])
    unknown = sorted(set(todo) - set(runs))
    if unknown:
        raise SystemExit("captures of runs that are not in the training table: %s" % unknown[:5])

    check = {"window_s": ws, "windows": n, "runs": len(runs), "runs_with_capture": len(todo),
             "base_equal_runs": 0, "base_exact_runs": 0, "base_differing": {},
             "runs_without_capture": 0, "runs_without_capture_zero": 0,
             "subwindows_per_base": sub, "additive_runs": 0, "additive_failures": {}}
    result = {}

    def compute(eid, anchor, path):
        rows = switch_model.window_features(str(path), anchor, ws, n)
        base = rows if sub == 1 else switch_model.window_features(str(path), anchor, BASE_S, n_base)
        ref = runs[eid]["net"]
        bad, exact = [], True
        for w in range(n_base):
            for s, v in zip(signals, ref[w]):
                a = float(base[w][s])
                exact &= a == v
                if not math.isclose(a, v, rel_tol=1e-9, abs_tol=1e-9):
                    bad.append([w, s, a, v])
        if bad:
            check["base_differing"][eid] = bad[:5] + [len(bad)]
        else:
            check["base_equal_runs"] += 1
            check["base_exact_runs"] += exact
        if sub:
            fails = []
            for w in range(n_base):
                part = rows[w * sub:(w + 1) * sub]
                for s in COUNTS:
                    if sum(p[s] for p in part) != base[w][s]:
                        fails.append([w, s, [p[s] for p in part], base[w][s]])
                for s in RATES:
                    if not math.isclose(sum(p[s] for p in part) / sub, base[w][s], rel_tol=1e-9, abs_tol=1e-9):
                        fails.append([w, s, [p[s] for p in part], base[w][s]])
            if fails:
                check["additive_failures"][eid] = fails[:5] + [len(fails)]
            else:
                check["additive_runs"] += 1
        result[eid] = [[float(r[s]) for s in signals] for r in rows]
        print("[%d/%d] %s" % (len(result), len(todo), eid[:24]), flush=True)

    for eid, (anchor, path, member) in todo.items():
        if path is not None:
            compute(eid, anchor, path)
    members = {member: eid for eid, (_, path, member) in todo.items() if path is None}
    with tarfile.open(tar_path, "r:gz") as tar:          # one pass, in the archive's order
        for info in tar:
            eid = members.pop(info.name, None)
            if eid is None:
                continue
            fd, tmp = tempfile.mkstemp(suffix=".pcap", dir=args.tmp)
            try:
                with os.fdopen(fd, "wb") as dst, tar.extractfile(info) as src:
                    while True:
                        block = src.read(1 << 20)
                        if not block:
                            break
                        dst.write(block)
                compute(eid, todo[eid][0], tmp)
            finally:
                os.unlink(tmp)
    if members:
        raise SystemExit("not in %s: %s" % (tar_path, sorted(members)))

    zeros = [0.0] * len(signals)
    for eid, run in runs.items():
        if eid in result:
            continue
        check["runs_without_capture"] += 1
        check["runs_without_capture_zero"] += all(v == 0.0 for w in range(n_base) for v in run["net"][w])
        result[eid] = [zeros] * n

    text, raw = gzip_writer(out)
    with raw, text:
        writer = csv.writer(text, lineterminator="\n")
        writer.writerow(header[:6] + signals)
        for eid, run in runs.items():
            for w, values in enumerate(result[eid]):
                writer.writerow(run["meta"] + [w] + [repr(v) for v in values])
    check["out"] = os.path.relpath(str(out.resolve()), str(REPO)) if REPO in out.resolve().parents else str(out)
    ok = (check["base_equal_runs"] == len(todo) and check["runs_without_capture_zero"] == check["runs_without_capture"]
          and (sub is None or check["additive_runs"] == len(todo)))
    check["ok"] = ok
    Path(str(out).replace(".csv.gz", "") + ".json").write_text(json.dumps(check, indent=1) + "\n")
    print("0.5 s: %d of %d captures equal to the training table in every window (%d bit for bit); %d of %d runs "
          "without a capture zero there" % (check["base_equal_runs"], len(todo), check["base_exact_runs"],
                                            check["runs_without_capture_zero"], check["runs_without_capture"]))
    if sub:
        print("%g s: %d of %d captures add up to their 0.5 s windows" % (ws, check["additive_runs"], len(todo)))
    print("wrote %s: %d runs x %d windows" % (out, len(runs), n))
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
