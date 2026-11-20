#!/usr/bin/env python3
"""Offline check of switch/variants/sweep: the dataset captures through the program's software model with in-band probes.

    sweep_offline_check.py OUT_DIR [--extras] [--mode changed|all] [--only ID,ID] [--release DIR]

For each capture (experiments/captures/cohort/, and with --extras the 33 of cohort-extra.tar.gz, read from the archive
in memory) the frames go through sweep_features.SweepModel (the program's registers, frame_len toward 10.0.0.10) and,
at each of the 41 window boundaries, the probes probe_plan() puts there, before the next frame: what the switch would
export with in-band probes (PC1.md part 9) if the replay were perfect. The exports go through the receiver's code
(group_sweeps, SweepWindows, summarize) into the release's row, compared with the published one
(dataset/features.csv). p4_perf.md 5.7's gap analysis predicts 106 of 110 rows equal in the 135 non-duration
columns: the bucket table, read in full at each boundary, fails only where flows share buckets (Chaos and the three
SYN fan-outs).

OUT_DIR/rows.csv (one row per capture), OUT_DIR/check.csv (per capture: equal columns, the mismatched features, the
windows whose totals disagree with the buckets, the probes and exports), OUT_DIR/summary.json.
"""
import argparse
import csv
import io
import json
import sys
import tarfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
PYDIR = REPO / "switch" / "control"
sys.path.insert(0, str(PYDIR))
import sweep_features as sf  # noqa: E402

CAPS = REPO / "experiments" / "captures"


def frames_from_bytes(data):
    """read_pcap_us on bytes (a member of the archive)."""
    import struct
    head = data[:24]
    order, digits = {b"\xd4\xc3\xb2\xa1": ("<", 6), b"\xa1\xb2\xc3\xd4": (">", 6),
                     b"\x4d\x3c\xb2\xa1": ("<", 9), b"\xa1\xb2\x3c\x4d": (">", 9)}[head[:4]]
    rec = struct.Struct(order + "IIII")
    out, off = [], 24
    while off + 16 <= len(data):
        sec, frac, incl, _ = rec.unpack_from(data, off)
        off += 16
        out.append((sec * 1000000 + (frac if digits == 6 else frac // 1000), data[off:off + incl]))
        off += incl
    return out


def items(extras):
    out = [dict(eid=r["execution_id"], anchor=int(r["anchor_us"]), path=CAPS / "cohort" / r["capture"], member=None,
                overload=r.get("expect_overload", "0"))
           for r in csv.DictReader(open(CAPS / "cohort" / "manifest.csv"))]
    if extras:
        with tarfile.open(CAPS / "cohort-extra.tar.gz", "r:gz") as tar:
            man = tar.extractfile("cohort-extra/manifest.csv").read().decode()
        for r in csv.DictReader(io.StringIO(man)):
            out.append(dict(eid=r["execution_id"], anchor=int(r["anchor_us"]), path=None,
                            member="cohort-extra/" + r["capture"], overload=r.get("expect_overload", "0")))
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("out")
    ap.add_argument("--extras", action="store_true")
    ap.add_argument("--mode", default="changed", choices=("changed", "all"))
    ap.add_argument("--only", default="")
    ap.add_argument("--release", default=str(REPO.parent / "p4-ebpf-malware-detection"))
    args = ap.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    published = {r["execution_id"]: r for r in csv.DictReader(open(Path(args.release) / "dataset" / "features.csv"))}
    only = set(args.only.split(",")) - {""}
    todo = [it for it in items(args.extras) if not only or it["eid"] in only]
    tar = tarfile.open(CAPS / "cohort-extra.tar.gz", "r:gz") if args.extras else None
    rows, checks = [], []
    t_all = time.time()
    for n, it in enumerate(todo, 1):
        t0 = time.time()
        if it["member"]:
            frames = frames_from_bytes(tar.extractfile(it["member"]).read())
        else:
            frames = sf.read_pcap_us(it["path"])
        exports, model = sf.simulate_inband(frames, it["anchor"], mode=args.mode)
        sweeps = sf.group_sweeps(exports)
        windows = sf.windows_from_sweeps(sweeps)
        row = sf.summarize(windows)
        bad, bad_nodur = sf.compare_row(row, published[it["eid"]])
        rows.append(dict(execution_id=it["eid"], **row))
        checks.append(dict(execution_id=it["eid"], overload=it["overload"], frames=len(frames), sweeps=len(sweeps),
                           windows=len(windows), probes=model.probes, exports=model.exported,
                           equal_nodur=135 - len(bad_nodur), equal_all=145 - len(bad),
                           totals_mismatch_windows=sum(1 for w in windows if w["net_sweep_totals_mismatch"] == 1),
                           pkts=sum(w["net_pkts_total_delta"] for w in windows),
                           mismatch=" ".join(sorted({c.split("__")[0] for c in bad_nodur})),
                           seconds=round(time.time() - t0, 2)))
        c = checks[-1]
        print("[%d/%d] %s %s/135 probes %d exports %d totals-mismatch %d %s (%.1f s)" % (
            n, len(todo), it["eid"][:16], c["equal_nodur"], c["probes"], c["exports"], c["totals_mismatch_windows"],
            c["mismatch"][:80], c["seconds"]), flush=True)
    if tar:
        tar.close()
    with open(out / "rows.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    with open(out / "check.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(checks[0]))
        w.writeheader()
        w.writerows(checks)
    summary = dict(captures=len(checks), mode=args.mode,
                   rows_equal_nodur=sum(1 for c in checks if c["equal_nodur"] == 135),
                   calm_equal=sum(1 for c in checks if c["overload"] == "0" and c["equal_nodur"] == 135),
                   calm=sum(1 for c in checks if c["overload"] == "0"),
                   windows_totals_mismatch=sum(c["totals_mismatch_windows"] for c in checks),
                   probes=sum(c["probes"] for c in checks), exports=sum(c["exports"] for c in checks),
                   not_equal=[(c["execution_id"], c["equal_nodur"], c["mismatch"]) for c in checks
                              if c["equal_nodur"] != 135],
                   seconds=round(time.time() - t_all, 1))
    (out / "summary.json").write_text(json.dumps(summary, indent=1))
    print(json.dumps({k: v for k, v in summary.items() if k != "not_equal"}))
    for x in summary["not_equal"]:
        print("  not equal:", x)


if __name__ == "__main__":
    main()
