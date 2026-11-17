#!/usr/bin/env python3
"""Replay one dataset capture through perf/variants/sweep with in-band probes; compare its row with the published one.

    sweep_replay.py CAPTURE --anchor-us A --out DIR --asroot ASROOT [--execution-id EID]
        [--switch-ssh root@172.168.1.2] [--iface eth1] [--port 132] [--frame-min 10.0.0.10/32] [--mode changed]
        [--windows 40] [--window-us 500000] [--p4-name basic]

The switch must run the sweep build with its ports set up (forwarding 132 <-> 140). Steps:
 1. sweep_reader.py --setup --reset --frame-min ... --sweep-ports PORT --export-port PORT on the switch: every
    register and the probe counters cleared, the frame_len entry installed (packets toward the monitored host
    count at least the 60-byte frame minimum, as its own capture saw them), the replay host's port made the
    only probe port, and the exports sent back out of it;
 2. tcpdump (as root, ASROOT) on --iface for EtherType 0x88B6 inbound: the exports, into DIR/exports.pcap;
 3. live_test/replay_absolute.py --probes MODE as root: the capture's frames at their recorded times with the
    probes of each of the N+1 window boundaries from the anchor among them;
 4. sweep_reader.py --state (the switch's counts of probes and exports, the sweep number);
 5. the exports through sweep_features.py: DIR/windows.csv, the row (the release's summary) in DIR/row.csv,
    against the published row (dataset/features.csv, --execution-id) and against the program's software model
    on the same capture and probes (sweep_features.simulate_inband), DIR/summary.json.
As with the exact build's markers, nothing depends on the replay's timing except the durations: the probes travel
with the frames, so each frame counts in the window of its recorded time.

ASROOT runs a command as root (a raw socket, tcpdump) and must pass SIGTERM on to it (sudo does): tcpdump is
stopped that way after the replay, with `timeout` as a backstop.
"""
import argparse
import csv
import json
import os
import re
import shlex
import subprocess
import sys
import threading
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
PYDIR = REPO / "thesis-hybrid-ebpf-p4" / "python"
sys.path.insert(0, str(PYDIR))
import sweep_features as sf  # noqa: E402

RELEASE = REPO.parent / "p4-ebpf-malware-detection"
REMOTE_SDE = "/root/bf-sde-9.6.0/install"


def remote_cmd(script, args):
    sde = shlex.quote(REMOTE_SDE)
    inner = (f"SDE_INSTALL={sde}; export SDE_INSTALL; export LD_LIBRARY_PATH=/usr/local/lib:$SDE_INSTALL/lib; "
             "py=python2.7; command -v python2.7 >/dev/null || py=python3; "
             f"exec $py {script} " + " ".join(shlex.quote(a) for a in args))
    return "bash -c %s" % shlex.quote(inner)


def json_lines(text):
    return [json.loads(l) for l in text.splitlines() if l.startswith("{")]


def pipe_value(v, pipe):
    """A per-pipe value from BF Runtime (a list) or one number."""
    if isinstance(v, list):
        return v[pipe] if pipe < len(v) else None
    return v


class Capture:
    """tcpdump as root for the exports; ready() once it listens."""

    def __init__(self, asroot, iface, path, limit_s, buffer_kib):
        self.path = path
        cmd = [asroot, "timeout", "-s", "INT", str(int(limit_s)), "tcpdump", "-i", iface, "-Q", "in", "-n", "-U",
               "-Z", "root", "-s", "256", "-B", str(int(buffer_kib)), "-w", str(path), "ether proto 0x88b6"]
        self.proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True, bufsize=1)
        self.lines = []
        self.listening = threading.Event()
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self):
        for line in self.proc.stderr:
            self.lines.append(line.rstrip("\n"))
            if "listening on" in line:
                self.listening.set()

    def stop(self):
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(15)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(5)
        time.sleep(0.2)
        stats = {}
        for line in self.lines:
            m = re.match(r"\s*(\d+) packets? (captured|received by filter|dropped by kernel)", line)
            if m:
                stats[m.group(2).replace(" ", "_")] = int(m.group(1))
        return stats


def parse_args(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("capture")
    ap.add_argument("--anchor-us", type=int, required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--asroot", help="runs a command as root (the replay's raw socket, tcpdump)")
    ap.add_argument("--execution-id")
    ap.add_argument("--switch-ssh", default="root@172.168.1.2")
    ap.add_argument("--p4-name", default="basic")
    ap.add_argument("--iface", default="eth1")
    ap.add_argument("--port", type=int, default=132, help="the dev_port the replay host's frames enter; the probe "
                    "port and the export port")
    ap.add_argument("--pipe", type=int, help="the pipe of --port (default: port // 128)")
    ap.add_argument("--frame-min", action="append", default=None,
                    help="DST/PREFIX toward which packets count at least the frame minimum (default 10.0.0.10/32)")
    ap.add_argument("--mode", default="changed", choices=("changed", "all"))
    ap.add_argument("--windows", type=int, default=40)
    ap.add_argument("--window-us", type=int, default=500000)
    ap.add_argument("--lead-s", type=float, default=3.0, help="the replay starts this long after tcpdump listens")
    ap.add_argument("--drain-s", type=float, default=2.0, help="wait this long after the replay for the last exports")
    ap.add_argument("--capture-buffer-kib", type=int, default=131072)
    ap.add_argument("--analyse-only", action="store_true",
                    help="no switch: analyse DIR/exports.pcap again, with the switch's figures of DIR/summary.json")
    ap.add_argument("--release", default=str(RELEASE))
    args = ap.parse_args(argv)
    if not args.analyse_only and not args.asroot:
        ap.error("--asroot is needed (or --analyse-only)")
    return args


def run_switch(args, out, frames, summary):
    """Steps 1-4: setup, tcpdump, the replay with its probes, the switch's state. Fills `summary`."""
    ssh = ["ssh", "-o", "BatchMode=yes", "-T", args.switch_ssh]
    remote = "/tmp/sweep_reader_%d.py" % (time.time() * 1000 % 1e9)
    subprocess.run(ssh + ["cat > %s" % remote], input=(PYDIR / "sweep_reader.py").read_bytes(), check=True)
    capture = None
    try:
        setup_args = ["--p4-name", args.p4_name, "--setup", "--reset", "--sweep-ports", str(args.port),
                      "--export-port", str(args.port)] + sum((["--frame-min", f] for f in summary["frame_min"]), [])
        r = subprocess.run(ssh + [remote_cmd(remote, setup_args)], capture_output=True, text=True, timeout=300)
        lines = json_lines(r.stdout)
        if r.returncode != 0 or not lines or "error" in lines[-1]:
            raise SystemExit("setup failed: %s" % (r.stdout + r.stderr)[-2000:])
        summary["setup"] = lines
        before = json_lines(subprocess.run(ssh + [remote_cmd(remote, ["--p4-name", args.p4_name, "--state"])],
                                           capture_output=True, text=True, timeout=120).stdout)
        summary["state_before"] = before[-1] if before else None

        span_s = (frames[-1][0] - frames[0][0]) / 1e6
        capture = Capture(args.asroot, args.iface, out / "exports.pcap", args.lead_s + span_s + 600,
                          args.capture_buffer_kib)
        if not capture.listening.wait(20):
            raise SystemExit("tcpdump did not start: %s" % capture.lines[-5:])
        start_at = time.time() + args.lead_s
        replay = subprocess.run([args.asroot, sys.executable, str(REPO / "live_test" / "replay_absolute.py"),
                                 args.capture, "--iface", args.iface, "--start-at", "%.6f" % start_at,
                                 "--probes", args.mode, "--probe-anchor-us", str(args.anchor_us),
                                 "--probe-window-us", str(args.window_us), "--probe-windows", str(args.windows)],
                                capture_output=True, text=True, timeout=3600)
        (out / "replay.log").write_text(replay.stdout + replay.stderr)
        summary["replay"] = (replay.stdout.strip().splitlines() or [""])[-1]
        if replay.returncode != 0:
            raise SystemExit("replay failed (%d): %s" % (replay.returncode, replay.stderr[-2000:]))
        m = re.search(r"(\d+) frames sent, (\d+) failed, (\d+) sweep probes", summary["replay"])
        if m:
            summary.update(frames_sent=int(m.group(1)), frames_failed=int(m.group(2)), probes_sent=int(m.group(3)))
        time.sleep(args.drain_s)
        after = json_lines(subprocess.run(ssh + [remote_cmd(remote, ["--p4-name", args.p4_name, "--state"])],
                                          capture_output=True, text=True, timeout=120).stdout)
        summary["state_after"] = after[-1] if after else None
    finally:
        if capture is not None:
            summary["tcpdump"] = capture.stop()
            (out / "tcpdump.log").write_text("\n".join(capture.lines) + "\n")
            subprocess.run([args.asroot, "chown", "%d:%d" % (os.getuid(), os.getgid()), str(out / "exports.pcap")],
                           capture_output=True)
        subprocess.run(ssh + ["rm -f %s" % remote])


def analyse(args, out, frames, summary):
    """Step 5: the exports into windows and the row, compared with the model's and the published row."""
    frame_min = summary["frame_min"]
    pipe = summary["pipe"]
    # the program's software model on the same frames and probes: what the switch should export
    exports_m, model = sf.simulate_inband(frames, args.anchor_us, args.window_us, args.windows, args.mode,
                                          tuple(frame_min))
    windows_m = sf.windows_from_sweeps(sf.group_sweeps(exports_m), args.window_us / 1e6)
    row_m = sf.summarize(windows_m)
    exports = sf.read_exports(out / "exports.pcap")
    sweeps = sf.group_sweeps(exports)
    windows = sf.windows_from_sweeps(sweeps, args.window_us / 1e6)
    if not windows:
        raise SystemExit("no windows from %d exports" % len(exports))
    with open(out / "windows.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(windows[0]))
        w.writeheader()
        w.writerows(windows)
    row = sf.summarize(windows)
    with open(out / "row.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["execution_id"] + list(row))
        w.writeheader()
        w.writerow(dict(execution_id=args.execution_id or "", **row))

    st = summary.get("state_after") or {}
    seqs = [s["seq"] for s in sweeps]
    summary.update(
        exports=len(exports), sweeps=len(sweeps), seq_first=seqs[0] if seqs else None,
        seq_last=seqs[-1] if seqs else None,
        seq_contiguous=bool(seqs) and seqs == list(range(seqs[0], seqs[0] + len(seqs))),
        duplicate_records=sum(s["duplicates"] for s in sweeps),
        switch_probes=pipe_value(st.get("sweep_probes"), pipe),
        switch_exported=pipe_value(st.get("sweep_exported"), pipe),
        switch_seq=pipe_value(st.get("sweep_seq"), pipe),
        model_probes=model.probes, model_exports=model.exported,
        totals_mismatch_windows=sum(1 for x in windows if x["net_sweep_totals_mismatch"] == 1),
        totals_missing_windows=sum(1 for x in windows if x["net_sweep_totals_mismatch"] == -1),
        pkts=sum(x["net_pkts_total_delta"] for x in windows),
        pkts_model=sum(x["net_pkts_total_delta"] for x in windows_m),
        sweep_span_us_max=max(x["net_sweep_span_us"] for x in windows))
    bad_m, bad_m_nodur = sf.compare_row(row, row_m)
    summary.update(equal_model=145 - len(bad_m), equal_model_nodur=135 - len(bad_m_nodur),
                   mismatch_model=sorted({c.split("__")[0] for c in bad_m_nodur}))
    if args.execution_id:
        with open(Path(args.release) / "dataset" / "features.csv") as fh:
            pub = dict((r["execution_id"], r) for r in csv.DictReader(fh))[args.execution_id]
        bad, bad_nodur = sf.compare_row(row, pub)
        _, bad_mp_nodur = sf.compare_row(row_m, pub)
        summary.update(exact145=145 - len(bad), exact_nodur=135 - len(bad_nodur),
                       mismatch=sorted({c.split("__")[0] for c in bad}),
                       mismatch_nodur=sorted({c.split("__")[0] for c in bad_nodur}),
                       model_exact_nodur=135 - len(bad_mp_nodur))
    checks = {
        "probes": summary.get("probes_sent") == summary["model_probes"] == summary["switch_probes"],
        "exports": summary["exports"] == summary["model_exports"] == summary["switch_exported"],
        "sweeps": summary["sweeps"] == args.windows + 1 and summary["seq_contiguous"],
        "totals": summary["totals_mismatch_windows"] == 0 and summary["totals_missing_windows"] == 0,
        "tcpdump_drops": (summary.get("tcpdump") or {}).get("dropped_by_kernel", 0) == 0,
        "frames_failed": summary.get("frames_failed", 0) == 0,
        "model": summary["equal_model_nodur"] == 135,
    }
    summary["checks"] = checks
    summary["checks_ok"] = all(checks.values())
    summary["end"] = time.time()
    (out / "summary.json").write_text(json.dumps(summary, indent=1))
    return summary


def main(argv=None):
    args = parse_args(argv)
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    frames = sf.read_pcap_us(args.capture)
    if not frames:
        raise SystemExit("%s holds no frames" % args.capture)
    if args.analyse_only:
        summary = json.loads((out / "summary.json").read_text())
    else:
        summary = dict(capture=str(args.capture), execution_id=args.execution_id, anchor_us=args.anchor_us,
                       windows=args.windows, window_us=args.window_us, mode=args.mode,
                       frame_min=args.frame_min if args.frame_min is not None else ["10.0.0.10/32"],
                       port=args.port, pipe=args.port // 128 if args.pipe is None else args.pipe,
                       frames=len(frames), start=time.time())
        run_switch(args, out, frames, summary)
    summary = analyse(args, out, frames, summary)
    print(json.dumps({k: summary.get(k) for k in ("execution_id", "pkts", "exports", "sweeps", "exact_nodur",
                                                   "model_exact_nodur", "equal_model_nodur", "checks_ok", "checks",
                                                   "mismatch_nodur", "replay")}))
    return summary


if __name__ == "__main__":
    main()
