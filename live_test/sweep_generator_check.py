#!/usr/bin/env python3
"""The sweep build's deployment path: the packet generator sends the probes, every window, with no host involved.

    sweep_generator_check.py --out DIR --asroot ASROOT [--switch-ssh root@172.168.1.2] [--p4-name basic]
        [--iface eth1] [--port 132] [--period-ns 500000000] [--ipg-ns 2000] [--buckets 65536]
        [--local-port 68] [--app 0] [--flows 200] [--idle-s 2] [--after-s 3]

The switch must run the sweep build (forwarding 132 <-> 140). Steps:
 1. sweep_reader.py --setup --reset --frame-min 10.0.0.10/32 --sweep-ports PORT --export-port PORT;
 2. tcpdump (as root) on --iface for the exports;
 3. sweep_reader.py --generator start: the generator of the port's pipe sends --buckets probes (packet ids
    0..N-1, --ipg-ns apart) every --period-ns, one sweep per period; its port joins sweep_ports;
 4. --idle-s of nothing, then known traffic (sweep_features.test_traffic: --flows TCP and UDP flows over 1 s)
    from this host with replay_absolute.py (no probes), then --after-s of nothing;
 5. the generator stopped, sweep_reader.py --state, tcpdump stopped.
Checks (DIR/summary.json, "checks"):
  - every sweep exports bucket 0 and every used bucket, and nothing else: before the traffic 1 record, after it
    1 + the buckets the traffic used (the software model's);
  - after the traffic, every sweep's records equal the model's registers in all fields but the two timestamps,
    and its totals equal the model's;
  - the switch's counts: probes = buckets x sweeps (its reg_sweep_seq), exports = the records captured, the
    generator's packet counter = probes; tcpdump dropped nothing;
  - the sweeps come one period apart (bucket 0's probe times, the switch's clock), each in about buckets x ipg.
Also reported: the windows between sweeps (sweep_features.SweepWindows) and how many of them have totals equal to
the sum of the buckets' differences. A generator sweep is not an instant: a packet that comes while a sweep is under
way counts in one window for the buckets probed after it and in the next for those before, so during traffic the
totals (read at the sweep's start) can disagree; an in-band replay (sweep_replay.py) cuts exactly.
"""
import argparse
import csv
import json
import os
import shlex
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
PYDIR = REPO / "thesis-hybrid-ebpf-p4" / "python"
sys.path.insert(0, str(PYDIR))
sys.path.insert(0, str(REPO / "live_test"))
import sweep_features as sf  # noqa: E402
from sweep_replay import Capture, json_lines, pipe_value, remote_cmd  # noqa: E402

REG_FIELDS = [f for f in sf.BUCKET_REGS if f not in ("first_ts", "last_ts")]


def parse_args(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--out", required=True)
    ap.add_argument("--asroot")
    ap.add_argument("--switch-ssh", default="root@172.168.1.2")
    ap.add_argument("--p4-name", default="basic")
    ap.add_argument("--iface", default="eth1")
    ap.add_argument("--port", type=int, default=132)
    ap.add_argument("--frame-min", default="10.0.0.10/32")
    ap.add_argument("--period-ns", type=int, default=500000000)
    ap.add_argument("--ipg-ns", type=int, default=2000)
    ap.add_argument("--buckets", type=int, default=65536)
    ap.add_argument("--local-port", type=int, default=68)
    ap.add_argument("--app", type=int, default=0)
    ap.add_argument("--buffer-offset", type=int, default=0)
    ap.add_argument("--flows", type=int, default=200)
    ap.add_argument("--idle-s", type=float, default=2.0)
    ap.add_argument("--after-s", type=float, default=3.0)
    ap.add_argument("--capture-buffer-kib", type=int, default=131072)
    ap.add_argument("--analyse-only", action="store_true",
                    help="no switch: analyse DIR/exports.pcap again, with the figures of DIR/summary.json")
    args = ap.parse_args(argv)
    if not args.analyse_only and not args.asroot:
        ap.error("--asroot is needed (or --analyse-only)")
    return args


def expected_state(args):
    """The test traffic and the program's registers after it (software model)."""
    traffic = sf.test_traffic(args.flows)
    model = sf.SweepModel(frame_min=(args.frame_min,))
    for t, frame in traffic:
        model.packet(frame, int(t * 1e9))
    return traffic, model, dict((i, r) for i, r in model.b.items() if r["dir_valid"] != 0)


def run_switch(args, out, traffic, summary):
    """Steps 1-5: setup, tcpdump, the generator, idle / traffic / idle, the generator stopped, the state."""
    sf.write_pcap(out / "traffic.pcap", traffic)
    pipe = summary["pipe"]
    ssh = ["ssh", "-o", "BatchMode=yes", "-T", args.switch_ssh]
    remote = "/tmp/sweep_reader_%d.py" % (time.time() * 1000 % 1e9)
    subprocess.run(ssh + ["cat > %s" % remote], input=(PYDIR / "sweep_reader.py").read_bytes(), check=True)
    gen_args = ["--p4-name", args.p4_name, "--pipes", str(pipe), "--local-port", str(args.local_port),
                "--app", str(args.app), "--buffer-offset", str(args.buffer_offset)]
    sw = lambda extra, timeout=300: subprocess.run(ssh + [remote_cmd(remote, extra)], capture_output=True,  # noqa: E731
                                                   text=True, timeout=timeout)
    capture = None
    started = False
    try:
        r = sw(["--p4-name", args.p4_name, "--setup", "--reset", "--frame-min", args.frame_min,
                "--sweep-ports", str(args.port), "--export-port", str(args.port)])
        lines = json_lines(r.stdout)
        if r.returncode != 0 or not lines or "error" in lines[-1]:
            raise SystemExit("setup failed: %s" % (r.stdout + r.stderr)[-2000:])
        summary["setup"] = lines
        capture = Capture(args.asroot, args.iface, out / "exports.pcap", args.idle_s + args.after_s + 900,
                          args.capture_buffer_kib)
        if not capture.listening.wait(20):
            raise SystemExit("tcpdump did not start: %s" % capture.lines[-5:])
        r = sw(gen_args + ["--generator", "start", "--period-ns", str(args.period_ns), "--buckets", str(args.buckets),
                           "--ipg-ns", str(args.ipg_ns)])
        lines = json_lines(r.stdout)
        if r.returncode != 0 or not lines or "error" in lines[-1]:
            raise SystemExit("generator start failed: %s" % (r.stdout + r.stderr)[-2000:])
        started = True
        summary["generator"] = lines[-1]
        time.sleep(args.idle_s)
        t_traffic = time.time() + 1.0
        replay = subprocess.run([args.asroot, sys.executable, str(REPO / "live_test" / "replay_absolute.py"),
                                 str(out / "traffic.pcap"), "--iface", args.iface, "--start-at", "%.6f" % t_traffic],
                                capture_output=True, text=True, timeout=600)
        (out / "replay.log").write_text(replay.stdout + replay.stderr)
        summary["replay"] = (replay.stdout.strip().splitlines() or [""])[-1]
        if replay.returncode != 0:
            raise SystemExit("replay failed (%d): %s" % (replay.returncode, replay.stderr[-2000:]))
        summary["traffic_host_s"] = [t_traffic, time.time()]
        time.sleep(args.after_s)
    finally:
        if started:
            r = sw(gen_args + ["--generator", "stop"])
            summary["generator_stop"] = (json_lines(r.stdout) or [None])[-1]
            time.sleep(max(1.0, 2 * args.buckets * args.ipg_ns / 1e9))
            r = sw(gen_args + ["--state"], timeout=120)
            summary["state_after"] = (json_lines(r.stdout) or [None])[-1]
            sw(["--p4-name", args.p4_name, "--setup", "--sweep-ports", str(args.port)])
        if capture is not None:
            summary["tcpdump"] = capture.stop()
            (out / "tcpdump.log").write_text("\n".join(capture.lines) + "\n")
            subprocess.run([args.asroot, "chown", "%d:%d" % (os.getuid(), os.getgid()), str(out / "exports.pcap")],
                           capture_output=True)
        subprocess.run(ssh + ["rm -f %s" % remote])


def analyse(args, out, traffic, model, expected, summary):
    pipe = summary["pipe"]
    exports = sf.read_exports(out / "exports.pcap")
    sweeps = sf.group_sweeps(exports)
    st = summary.get("state_after") or {}
    seq_sw = pipe_value(st.get("sweep_seq"), pipe)
    probes_sw = pipe_value(st.get("sweep_probes"), pipe)
    exported_sw = pipe_value(st.get("sweep_exported"), pipe)
    gen_ctr = ((st.get("generator") or {}).get(str(pipe)) or {}).get("pkt_counter")
    # the generator may have been stopped during a sweep: that sweep is left out of the checks of whole sweeps
    partial_last = None not in (probes_sw, seq_sw) and probes_sw < args.buckets * seq_sw
    t0, t1 = summary["traffic_host_s"]
    whole = [s for s in sweeps if not (partial_last and s["seq"] == seq_sw)]
    pre = [s for s in whole if s["host_last"] < t0 - 0.05]
    post = [s for s in whole if s["host_first"] > t1 + 0.05]
    bad_post = []
    totals = dict((k, model.g[k]) for k in sf.TOTALS)
    for s in post:
        if set(s["buckets"]) - {0} != set(expected) - {0}:
            bad_post.append([s["seq"], "buckets %d vs %d" % (len(s["buckets"]), len(expected))])
            continue
        for idx, ref in expected.items():
            diff = [f for f in REG_FIELDS if s["buckets"][idx][f] != ref[f]]
            if diff:
                bad_post.append([s["seq"], idx, diff])
                break
        if s["totals"] != totals:
            bad_post.append([s["seq"], "totals", s["totals"]])
    t_zero = [s["t_first"] for s in sweeps]
    periods = [((b - a) & sf.M32) for a, b in zip(t_zero, t_zero[1:])]
    windows = sf.windows_from_sweeps(sweeps, args.period_ns / 1e9)
    with open(out / "windows.csv", "w", newline="") as fh:
        if windows:
            w = csv.DictWriter(fh, fieldnames=list(windows[0]))
            w.writeheader()
            w.writerows(windows)
    summary.update(
        exports=len(exports), sweeps=len(sweeps), seqs=[sweeps[0]["seq"], sweeps[-1]["seq"]] if sweeps else None,
        sweeps_before_traffic=len(pre), sweeps_after_traffic=len(post),
        records_before=sorted(set(s["records"] for s in pre)), records_after=sorted(set(s["records"] for s in post)),
        bad_after=bad_post[:20], switch_seq=seq_sw, switch_probes=probes_sw, switch_exported=exported_sw,
        generator_pkt_counter=gen_ctr, last_sweep_partial=partial_last,
        period_ns_min=min(periods) if periods else None, period_ns_max=max(periods) if periods else None,
        span_ns_max=max(s["span_ns"] for s in sweeps) if sweeps else None,
        windows=len(windows), windows_totals_equal=sum(1 for x in windows if x["net_sweep_totals_mismatch"] == 0),
        pkts_windows=sum(x["net_pkts_total_delta"] for x in windows))
    checks = {
        "sweeps_before": bool(pre) and summary["records_before"] == [1],
        "sweeps_after": len(post) >= 2 and not bad_post and
                        summary["records_after"] == [len(expected) + (0 not in expected)],
        "seq": bool(sweeps) and seq_sw == sweeps[-1]["seq"] and sweeps[-1]["seq"] - sweeps[0]["seq"] + 1 == len(sweeps),
        "probes_per_sweep": None not in (seq_sw, probes_sw) and
                            args.buckets * (seq_sw - 1) < probes_sw <= args.buckets * seq_sw,
        "probes_generated": gen_ctr is None or gen_ctr == probes_sw,
        "exports": exported_sw == len(exports),
        "tcpdump_drops": (summary.get("tcpdump") or {}).get("dropped_by_kernel", 0) == 0,
        "period": bool(periods) and max(abs(p - args.period_ns) for p in periods) < 0.001 * args.period_ns,
        "pkts": summary["pkts_windows"] == len(traffic),
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
    traffic, model, expected = expected_state(args)
    if args.analyse_only:
        summary = json.loads((out / "summary.json").read_text())
    else:
        summary = dict(period_ns=args.period_ns, ipg_ns=args.ipg_ns, buckets=args.buckets, port=args.port,
                       pipe=args.port // 128, flows=args.flows, frames=len(traffic), model_buckets=len(expected),
                       start=time.time())
        run_switch(args, out, traffic, summary)
    summary = analyse(args, out, traffic, model, expected, summary)
    print(json.dumps({k: summary.get(k) for k in ("checks_ok", "checks", "sweeps", "exports", "model_buckets",
                                                   "records_after", "switch_probes", "switch_exported",
                                                   "windows_totals_equal", "windows", "period_ns_min",
                                                   "period_ns_max", "span_ns_max")}))
    return summary


if __name__ == "__main__":
    main()
