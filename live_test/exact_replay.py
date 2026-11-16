#!/usr/bin/env python3
"""Replay one dataset capture through perf/variants/exact and compare its row with the published one.

    exact_replay.py CAPTURE --anchor-us A --out DIR --asroot ASROOT [--execution-id EID]
        [--switch-ssh root@172.168.1.2] [--iface eth1] [--frame-min 10.0.0.10/32] [--windows 40]

The switch must run the exact build with its ports set up (forwarding 132 <-> 140). Steps:
 1. window_reader.py --reset --frame-min ... on the switch: every register cleared, the frame_len
    entry installed (packets toward the monitored host count at least the 60-byte frame minimum, as
    its own capture saw them);
 2. window_reader.py --follow --until-epoch N+1 on the switch, its lines into DIR/reads.jsonl;
 3. live_test/replay_absolute.py --markers as root (ASROOT): the capture's frames at their recorded
    times with a window marker at each of the N+1 window boundaries from the anchor, epochs 1..N+1;
 4. window_features.py on the reads of epochs 1..N: DIR/windows.csv, the row (the release's
    summary: mean, max, sum, std, active_windows of each feature) in DIR/row.csv, and against the
    published row (dataset/features.csv, --execution-id) DIR/summary.json.
Nothing here depends on the replay's timing except the durations: the markers travel with the
frames, so each frame counts in the window of its recorded time.
"""
import argparse
import csv
import json
import shlex
import subprocess
import sys
import time
from pathlib import Path

import numpy as np

REPO = Path(__file__).resolve().parents[1]
PYDIR = REPO / "thesis-hybrid-ebpf-p4" / "python"
sys.path.insert(0, str(PYDIR))
from window_features import FEATURES, WindowFeatures  # noqa: E402

RELEASE = REPO.parent / "p4-ebpf-malware-detection"
REMOTE_SDE = "/root/bf-sde-9.6.0/install"
STATS = ("mean", "max", "sum", "std", "active_windows")
DUR = [f for f in FEATURES if "duration" in f]


def remote_cmd(script, args):
    sde = shlex.quote(REMOTE_SDE)
    inner = (f"SDE_INSTALL={sde}; export SDE_INSTALL; export LD_LIBRARY_PATH=/usr/local/lib:$SDE_INSTALL/lib; "
             "py=python2.7; command -v python2.7 >/dev/null || py=python3; "
             f"exec $py {script} " + " ".join(shlex.quote(a) for a in args))
    return "bash -c %s" % shlex.quote(inner)


def summarize(windows):
    out = {}
    for f in FEATURES:
        v = np.asarray([float(w[f]) for w in windows])
        st = {"mean": v.mean(), "max": v.max(), "sum": v.sum(), "std": v.std(),
              "active_windows": float((v != 0).sum())}
        for s in STATS:
            out["%s__%s" % (f, s)] = float(st[s])
    return out


def exact(a, b):
    a, b = float(a), float(b)
    return abs(a - b) <= 1e-9 * max(1.0, abs(a), abs(b))


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("capture")
    ap.add_argument("--anchor-us", type=int, required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--asroot", required=True, help="runs a command as root (the replay's raw socket)")
    ap.add_argument("--execution-id")
    ap.add_argument("--switch-ssh", default="root@172.168.1.2")
    ap.add_argument("--iface", default="eth1")
    ap.add_argument("--frame-min", action="append", default=None,
                    help="DST/PREFIX toward which packets count at least the frame minimum (default 10.0.0.10/32)")
    ap.add_argument("--windows", type=int, default=40)
    ap.add_argument("--window-us", type=int, default=500000)
    ap.add_argument("--lead-s", type=float, default=3.0, help="the replay starts this long after the reader")
    args = ap.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    frame_min = args.frame_min if args.frame_min is not None else ["10.0.0.10/32"]
    ssh = ["ssh", "-o", "BatchMode=yes", "-T", args.switch_ssh]
    remote = "/tmp/window_reader_%d.py" % (time.time() * 1000 % 1e9)
    subprocess.run(ssh + ["cat > %s" % remote], input=(PYDIR / "window_reader.py").read_bytes(), check=True)
    summary = dict(capture=str(args.capture), anchor_us=args.anchor_us, windows=args.windows,
                   execution_id=args.execution_id, frame_min=frame_min, start=time.time())
    try:
        reset_args = ["--reset"] + sum((["--frame-min", f] for f in frame_min), [])
        r = subprocess.run(ssh + [remote_cmd(remote, reset_args)], capture_output=True, text=True, timeout=300)
        if r.returncode != 0:
            raise SystemExit("reset failed: %s" % (r.stderr or r.stdout)[-2000:])
        summary["reset"] = [json.loads(l) for l in r.stdout.splitlines() if l.startswith("{")]
        reads = open(out / "reads.jsonl", "w")
        follow = subprocess.Popen(ssh + [remote_cmd(remote, ["--follow", "--until-epoch", str(args.windows + 1)])],
                                  stdout=subprocess.PIPE, stderr=open(out / "reader.log", "w"), text=True, bufsize=1)
        first = follow.stdout.readline()
        if not first.startswith("{"):
            raise SystemExit("the reader did not start: %r" % first)
        reads.write(first)
        start_epoch = json.loads(first)["start_epoch"]
        if start_epoch != 0:
            raise SystemExit("reg_epoch is %d after the reset" % start_epoch)
        start_at = time.time() + args.lead_s
        replay = subprocess.run([args.asroot, sys.executable, str(REPO / "live_test" / "replay_absolute.py"),
                                 args.capture, "--iface", args.iface, "--start-at", "%.6f" % start_at, "--markers",
                                 "--marker-anchor-us", str(args.anchor_us), "--marker-window-us", str(args.window_us),
                                 "--marker-windows", str(args.windows)],
                                capture_output=True, text=True, timeout=3600)
        (out / "replay.log").write_text(replay.stdout + replay.stderr)
        summary["replay"] = (replay.stdout.strip().splitlines() or [""])[-1]
        if replay.returncode != 0:
            follow.terminate()
            raise SystemExit("replay failed (%d): %s" % (replay.returncode, replay.stderr[-2000:]))
        deadline = time.time() + 60
        lines = []
        while time.time() < deadline:
            line = follow.stdout.readline()
            if not line:
                break
            reads.write(line)
            lines.append(json.loads(line))
            if lines[-1].get("epoch") == args.windows:
                break
        follow.terminate()
        try:
            follow.wait(10)
        except subprocess.TimeoutExpired:
            follow.kill()
        reads.close()
    finally:
        subprocess.run(ssh + ["rm -f %s" % remote])
    got = {l["epoch"]: l for l in lines if "epoch" in l}
    wf = WindowFeatures(window_sec=args.window_us / 1e6)
    rows = []
    for e in range(0, args.windows + 1):
        if e not in got:
            raise SystemExit("no read of window %d (reads of %s)" % (e, sorted(got)))
        f = wf.add(got[e])
        if e >= 1:
            rows.append(dict(window=e - 1, **f))
    with open(out / "windows.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    row = summarize(rows)
    with open(out / "row.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["execution_id"] + list(row))
        w.writeheader()
        w.writerow(dict(execution_id=args.execution_id or "", **row))
    summary.update(untracked_pkts=sum(r["net_untracked_pkts"] for r in rows),
                   windows_lost=sum(r["net_window_lost"] for r in rows),
                   epoch0_pkts=wf_epoch0(got.get(0)),
                   read_ms_max=max(l.get("read_ms", 0) for l in got.values()),
                   pkts=sum(r["net_pkts_total_delta"] for r in rows))
    if args.execution_id:
        pub = {r["execution_id"]: r for r in csv.DictReader(open(RELEASE / "dataset" / "features.csv"))}[
            args.execution_id]
        bad = [c for c in row if not exact(row[c], pub[c])]
        summary.update(exact145=145 - len(bad), exact_nodur=135 - len([c for c in bad if c.split("__")[0] not in DUR]),
                       mismatch=sorted({c.split("__")[0] for c in bad}),
                       mismatch_nodur=[c for c in bad if c.split("__")[0] not in DUR])
    summary["end"] = time.time()
    (out / "summary.json").write_text(json.dumps(summary, indent=1))
    print(json.dumps({k: summary.get(k) for k in ("execution_id", "pkts", "exact145", "exact_nodur", "untracked_pkts",
                                                   "windows_lost", "epoch0_pkts", "read_ms_max", "mismatch",
                                                   "replay")}))


def wf_epoch0(line):
    """Packets counted before the first marker (epoch 0): 0 when the markers frame the whole replay."""
    if not line:
        return None
    return sum(v[0] for v in line["regs"]["reg_w_tot"].values())


if __name__ == "__main__":
    main()
