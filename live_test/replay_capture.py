#!/usr/bin/env python3
"""Replay one capture through the Wedge100BF-32X with the collector, and record what a
window-by-window comparison with an offline extractor needs (RUNBOOK 19.6).

    sudo python3 live_test/replay_capture.py CAPTURE --out DIR [--profile switch|dataset]
        [--anchor-offset S] [--align-window K] [--start-latency S] [--report-latency S]
        [--tx-iface eth1] [--switch-ssh root@172.168.1.2] [-- extra hybrid_collector.py options]

--profile switch (the default) runs the collector with 1 s windows (RUNBOOK 19.6). --profile
dataset runs it with the dataset's definitions (RUNBOOK 19.9: 0.5 s windows, frame bytes,
durations in seconds, dormant reads) for K + 40 windows, so that collector windows K..K+39 are
the dataset's 40 windows; live_test/dataset_row.py --skip-windows K turns them into a row. The
replay has no program to launch, so the collector's launcher stays the shell one.

Steps:
 1. The run's window anchor is --anchor-offset seconds after the capture's first frame: the
    dataset's sample_started_wall_us minus the first frame's time (about 1 s: the first frame is
    the pre-window probe).
 2. What this host sends on --tx-iface is captured (tcpdump -Q out), so that the comparison uses
    the replayed timing, not the capture's: tcpreplay does not reproduce it exactly.
 3. hybrid_collector.py --profile switch (1 s windows, TTL 3, --clear-expired, immediate-mode
    report capture; or --profile dataset, above) runs the replay as its scenario, so that the anchor falls on the start of
    collector window K: collector window K + j is dataset window j. The default replayer
    (live_test/replay_absolute.py) sends every frame at its recorded time from a start computed
    from the collector's window origin (HYBRID_T0); --replayer tcpreplay runs
    "sleep D; exec tcpreplay -i IFACE CAPTURE" with D = K x window - anchor offset - start
    latency, but tcpreplay's per-frame overhead adds up (bulk2000: 254 ms late after 22 s).
 4. DIR/summary.json gets the capture's sha256 and first frame, the collector's t0, where the
    anchor really fell (alignment error), the replay's timing error, the clock offset between this
    host and the switch, and per window its start, the interval in which the switch took the
    register snapshot that ends it (mapped onto this host's clock), and a self-check.

The self-check counts IPv4 TCP/UDP first fragments in the sent capture (bytes = IPv4 total
length), as ingress.p4 does; under --profile dataset it adds 14 B per packet to the sent bytes,
because that profile's collector reports Ethernet frame bytes (byte_layer frame). A window k's register values are cut in the snapshot interval
[s_k_lo, s_k_hi] after its end, not at its boundary, and a new flow's first packets count in the
window of its CPU report, which arrives up to L (--report-latency) after the packet. So, with b_k
the window's start:
    certainly in window k:   sent in [s_(k-1)_hi, b_(k+1) - L)
    possibly in window k:    sent in [b_k - L, s_k_hi)
and the switch's net_pkts_total_delta and net_bytes_total_delta of the window must lie between the
two. Windows in overload (net_overload 1) are not checked: there only the buckets read count.

Outputs in DIR: windows.csv, timing.jsonl, collector.log, tx.pcap, hostmon_stub, summary.json.
"""
import argparse
import bisect
import hashlib
import json
import os
import shlex
import signal
import statistics
import struct
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
PYDIR = REPO / "thesis-hybrid-ebpf-p4" / "python"


def read_pcap(path, snap=None):
    """(timestamp, frame bytes) of every record of a classic pcap file (us or ns)."""
    out = []
    with open(path, "rb") as f:
        head = f.read(24)
        if len(head) < 24:
            raise ValueError("%s: not a pcap file" % path)
        magic = head[:4]
        table = {b"\xd4\xc3\xb2\xa1": ("<", 1e-6), b"\xa1\xb2\xc3\xd4": (">", 1e-6),
                 b"\x4d\x3c\xb2\xa1": ("<", 1e-9), b"\xa1\xb2\x3c\x4d": (">", 1e-9)}
        if magic not in table:
            raise ValueError("%s: not a classic pcap file (pcapng is not supported)" % path)
        endian, frac = table[magic]
        rec = struct.Struct(endian + "IIII")
        while True:
            h = f.read(16)
            if len(h) < 16:
                break
            sec, sub, incl, _orig = rec.unpack(h)
            data = f.read(incl)
            out.append((sec + sub * frac, data if snap is None else data[:snap]))
    return out


def ipv4_l4_len(frame):
    """IPv4 total length if the frame is an IPv4 TCP/UDP first fragment (what ingress.p4 counts), else None."""
    if len(frame) < 34 or frame[12:14] != b"\x08\x00" or frame[14] >> 4 != 4:
        return None
    if frame[23] not in (6, 17):
        return None
    if struct.unpack("!H", frame[20:22])[0] & 0x1FFF:
        return None
    return struct.unpack("!H", frame[16:18])[0]


WINDOW_ETHERTYPE = b"\x88\xb5"


def exact_check(tx, rows, header_bytes=0, frame_min=(), max_frame=None):
    """--exact: frames in sending order with the window markers among them, split at the markers, against
    the switch's window totals: collector window k is the marker epoch k + 1, and its packets and bytes must
    equal those sent between marker k + 1 and marker k + 2, exactly. `tx`: (time, frame) pairs, e.g. the
    replayer's schedule (replay_absolute.with_markers on the capture) or the send capture tx.pcap (which
    tcpdump can drop frames from under a burst); frames longer than max_frame (the interface refuses them)
    are left out. Bytes as perf/variants/exact counts them in the collector's layer: the IPv4 length, at
    least 46 toward a frame_min address, plus header_bytes."""
    import socket
    mins = {socket.inet_aton(a.split("/")[0]) for a in frame_min}
    sent, epoch = {}, None
    for _t, f in tx:
        if max_frame is not None and len(f) > max_frame:
            continue
        if f[12:14] == WINDOW_ETHERTYPE and len(f) >= 20:
            epoch = struct.unpack("!I", f[16:20])[0]
            continue
        n = ipv4_l4_len(f)
        if n is None or epoch is None:
            continue
        if f[30:34] in mins:
            n = max(n, 46)
        p, b = sent.get(epoch, (0, 0))
        sent[epoch] = (p + 1, b + n + header_bytes)
    windows, exact = [], 0
    for k in sorted(rows):
        r = rows[k]
        sw = (int(float(r.get("net_pkts_total_delta") or 0)), int(float(r.get("net_bytes_total_delta") or 0)))
        want = sent.get(k + 1, (0, 0))
        ok = sw == want
        exact += int(ok)
        windows.append({"window": k, "epoch": k + 1, "switch_pkts": sw[0], "switch_bytes": sw[1], "sent_pkts": want[0],
                        "sent_bytes": want[1], "check": "exact" if ok else "differs",
                        "untracked_pkts": int(float(r.get("net_untracked_pkts") or 0)),
                        "lost": int(float(r.get("net_window_lost") or 0))})
    return {"windows_checked": len(windows), "windows_exact": exact,
            "switch_pkts_total": sum(w["switch_pkts"] for w in windows),
            "sent_pkts_total": sum(w["sent_pkts"] for w in windows),
            "switch_bytes_total": sum(w["switch_bytes"] for w in windows),
            "sent_bytes_total": sum(w["sent_bytes"] for w in windows),
            "sent_before_first_marker_or_after_last": sum(p for e, (p, _b) in sent.items()
                                                           if e - 1 not in rows),
            "untracked_pkts": sum(w["untracked_pkts"] for w in windows),
            "windows_lost": sum(w["lost"] for w in windows), "per_window": windows}


def wait_listening(proc, timeout):
    """True once tcpdump has printed "listening on" on stderr."""
    deadline = time.time() + timeout
    seen = []
    while time.time() < deadline:
        line = proc.stderr.readline()
        if not line:
            break
        text = line.decode("ascii", "replace").strip()
        seen.append(text)
        if "listening on" in text:
            return True, seen
    return False, seen


def match_replay(cap, tx, prefix=54, lookahead=2000):
    """For each capture frame, the time this host sent it: tcpreplay sends the frames in order,
    and other frames from this host may lie between them. Frames are compared by their first
    `prefix` bytes, at most `lookahead` sent frames ahead. Returns a list of send times (None
    where no match was found)."""
    sent, j = [], 0
    for _t, frame in cap:
        key = frame[:prefix]
        k, end = j, min(len(tx), j + lookahead)
        while k < end and tx[k][1][:len(key)] != key:
            k += 1
        if k < end:
            sent.append(tx[k][0])
            j = k + 1
        else:
            sent.append(None)
    return sent


def clock_offset(records):
    """Offset reader clock - this host's clock, from the reads with the shortest round trip
    (NTP's method: ((t1 - t0) + (t2 - t3)) / 2), and that round trip."""
    samples = []
    for r in records:
        c = r.get("clock") or {}
        if all(k in c for k in ("collector_t_sent", "reader_t_recv", "reader_t_send", "collector_t_reply")):
            t0, t1, t2, t3 = c["collector_t_sent"], c["reader_t_recv"], c["reader_t_send"], c["collector_t_reply"]
            samples.append((((t1 - t0) + (t2 - t3)) / 2.0, (t3 - t0) - (t2 - t1)))
    if not samples:
        return None, None, None
    samples.sort(key=lambda s: s[1])
    best = samples[:max(3, len(samples) // 4)]
    return statistics.median(s[0] for s in best), best[0][1], statistics.median(s[1] for s in samples)


def count_between(times, lens, lo, hi):
    """Packets and bytes sent in [lo, hi)."""
    a, b = bisect.bisect_left(times, lo), bisect.bisect_left(times, hi)
    return b - a, sum(lens[a:b])


def analyse(out, capture, anchor_offset, align_window, delay, report_latency, window_sec, header_bytes=0):
    """header_bytes: added to each sent packet's IPv4 length, so that the sent bytes are counted as the
    collector reports them (self_check_header_bytes)."""
    cap = read_pcap(capture, snap=96)
    tx = read_pcap(out / "tx.pcap")
    records = [json.loads(l) for l in open(out / "timing.jsonl") if l.strip()]
    import csv
    csv.field_size_limit(sys.maxsize)
    rows = {int(float(r["net_window_id"])): r for r in csv.DictReader(open(out / "windows.csv"))}
    ends = [r["t_window_end"] for r in records if r.get("t_window_end") is not None]
    t0 = records[0]["t_window_end"] - (records[0]["window"] + 1) * window_sec
    sent = match_replay(cap, tx)
    matched = [s for s in sent if s is not None]
    summary = {"capture": str(capture), "capture_sha256": hashlib.sha256(open(capture, "rb").read()).hexdigest(),
               "capture_frames": len(cap), "capture_first_frame": cap[0][0] if cap else None,
               "anchor_offset_s": anchor_offset, "align_window": align_window, "sleep_s": delay,
               "window_sec": window_sec, "t0": t0, "windows": len(ends),
               "dataset_window_of_collector_window": "collector window %d + j = dataset window j" % align_window,
               "frames_matched_in_tx": len(matched)}
    if matched and sent[0] is not None:
        first_sent = sent[0]
        summary["first_frame_sent"] = first_sent
        if delay is not None:
            summary["start_latency_measured_s"] = round(first_sent - t0 - delay, 4)
        # the anchor on this host's clock: the first capture frame at or after it, sent at s_j
        cap_anchor = cap[0][0] + anchor_offset
        j = next((i for i, (t, _f) in enumerate(cap) if t >= cap_anchor and sent[i] is not None), None)
        if j is not None:
            anchor_here = sent[j] - (cap[j][0] - cap_anchor)
            summary["anchor_on_this_clock"] = anchor_here
            summary["alignment_error_ms"] = round((anchor_here - (t0 + align_window * window_sec)) * 1000.0, 2)
        errs = [abs((sent[i] - sent[0]) - (cap[i][0] - cap[0][0])) * 1000.0 for i in range(len(cap)) if sent[i] is not None]
        summary["replay_timing_error_ms"] = {"median": round(statistics.median(errs), 3),
                                             "p95": round(sorted(errs)[int(0.95 * (len(errs) - 1))], 3),
                                             "max": round(max(errs), 3)}
    theta, delta_min, delta_med = clock_offset(records)
    summary["clock_offset_reader_minus_here_s"] = theta
    summary["round_trip_min_ms"] = None if delta_min is None else round(delta_min * 1000.0, 3)
    summary["round_trip_median_ms"] = None if delta_med is None else round(delta_med * 1000.0, 3)
    # sent IPv4 TCP/UDP packets, as ingress.p4 counts them, in the collector's byte layer
    pk = [(t, ipv4_l4_len(f)) for t, f in tx]
    pk = [(t, n + header_bytes) for t, n in pk if n is not None]
    times, lens = [t for t, _ in pk], [n for _, n in pk]
    u = 0.0 if delta_min is None else delta_min / 2.0
    snaps, tots = {}, {}
    for r in records:
        c = r.get("clock") or {}
        if theta is not None and "reader_t_sync_start" in c and "reader_t_sync_end" in c:
            snaps[r["window"]] = (c["reader_t_sync_start"] - theta - u, c["reader_t_sync_end"] - theta + u)
        if theta is not None and "reader_t_totals_start" in c and "reader_t_totals_end" in c:
            tots[r["window"]] = (c["reader_t_totals_start"] - theta - u, c["reader_t_totals_end"] - theta + u)
    windows, checked, inside = [], 0, 0
    prev_hi = t0
    for k in sorted(rows):
        r = rows[k]
        b_k, b_next = t0 + k * window_sec, t0 + (k + 1) * window_sec
        # --global-totals (PC1.md part 4e): a window's totals came from the global totals, so they are cut where
        # those were read, whatever the buckets read; then an overloaded window is checked too
        gtot = int(float(r.get("net_gtot_used") or 0)) == 1 and k in tots
        snap = tots.get(k) if gtot else snaps.get(k)
        sw_p, sw_b = int(float(r.get("net_pkts_total_delta") or 0)), int(float(r.get("net_bytes_total_delta") or 0))
        w = {"window": k, "start": b_k, "snapshot": snap, "switch_pkts": sw_p, "switch_bytes": sw_b,
             "overload": int(float(r.get("net_overload") or 0)), "cut": "totals" if gtot else "snapshot"}
        w["sent_in_window_pkts"], w["sent_in_window_bytes"] = count_between(times, lens, b_k, b_next)
        if snap is not None:
            lo = count_between(times, lens, prev_hi, b_next - report_latency)
            hi = count_between(times, lens, b_k - report_latency, snap[1])
            w["certain_pkts"], w["certain_bytes"], w["possible_pkts"], w["possible_bytes"] = lo[0], lo[1], hi[0], hi[1]
            if not w["overload"] or gtot:
                checked += 1
                ok = lo[0] <= sw_p <= hi[0] and lo[1] <= sw_b <= hi[1]
                inside += int(ok)
                w["check"] = "ok" if ok else "outside"
            else:
                w["check"] = "overload"
            prev_hi = snap[1]
        windows.append(w)
    summary["self_check"] = {"report_latency_bound_s": report_latency,
                             "byte_layer": "frame" if header_bytes else "ipv4", "header_bytes_per_packet": header_bytes,
                             "windows_checked": checked,
                             "windows_inside_bounds": inside,
                             "switch_pkts_total": sum(w["switch_pkts"] for w in windows),
                             "sent_pkts_total": len(times),
                             "switch_bytes_total": sum(w["switch_bytes"] for w in windows),
                             "sent_bytes_total": sum(lens),
                             "snapshot_interval_ms": None if not snaps else {
                                 "median": round(statistics.median((b - a) * 1000.0 for a, b in snaps.values()), 2),
                                 "max": round(max((b - a) * 1000.0 for a, b in snaps.values()), 2)},
                             "snapshot_start_after_window_end_ms": None if not snaps else {
                                 "median": round(statistics.median((snaps[k][0] - (t0 + (k + 1) * window_sec)) * 1000.0
                                                                   for k in snaps), 2)}}
    if tots:
        after = [(tots[k][1] - (t0 + (k + 1) * window_sec)) * 1000.0 for k in tots]
        summary["self_check"]["windows_cut_by_the_totals"] = sum(1 for w in windows if w["cut"] == "totals")
        summary["self_check"]["totals_read_end_after_window_end_ms"] = {
            "median": round(statistics.median(after), 2), "max": round(max(after), 2)}
    summary["per_window"] = windows
    return summary


def sweep_check(capture, rows, anchor_us, window_us, n_windows, frame_min, header_bytes=0, max_frame=None,
                skip=0, published=None):
    """--sweep: the collector's windows (rows, by net_window_id) against perf/variants/sweep's software model on the
    replayer's frames with in-band probes at the collector's window boundaries (sweep_features.simulate_inband,
    perfect cuts): every non-duration window feature must be equal with --sweep inband. With --sweep generator the
    same comparison measures what the generator's spread cut (a bucket is cut when its probe passes) changes.
    Frames longer than max_frame are left out (the interface refuses them). skip: the windows before the dataset's
    40 (--align-window); published: the release's row of this capture, compared with the row of windows
    skip..skip+39 (sweep_features.summarize, the release's statistics)."""
    sys.path.insert(0, str(PYDIR))
    import sweep_features as sf
    frames = [(t, f) for t, f in sf.read_pcap_us(str(capture)) if max_frame is None or len(f) <= max_frame]
    exports, model = sf.simulate_inband(frames, anchor_us, window_us, n_windows, "changed", tuple(frame_min))
    model_windows = sf.windows_from_sweeps(sf.group_sweeps(exports), window_us / 1e6, header=header_bytes)
    feats = [f for f in sf.FEATURES if f not in sf.DURATION_FEATURES]
    equal, missing, differing = 0, [], {}
    for k, wm in enumerate(model_windows):
        r = rows.get(k)
        if r is None:
            missing.append(k)
            continue
        bad = [f for f in feats if not sf.exact(r.get(f) or 0, wm[f])]
        equal += int(not bad)
        for f in bad:
            differing[f] = differing.get(f, 0) + 1
    num = lambda r, k: float(r.get(k) or 0)
    out = {"against": "perf/variants/sweep's software model, in-band probes at the collector's window boundaries "
                      "(perfect cuts), on the capture's frames up to the MTU",
           "windows_model": len(model_windows), "windows_collector": len(rows),
           "windows_equal_nodur": equal, "windows_missing": missing,
           "features_differing": dict(sorted(differing.items(), key=lambda kv: -kv[1])),
           "pkts_collector": int(sum(num(r, "net_pkts_total_delta") for r in rows.values())),
           "pkts_model": int(sum(w["net_pkts_total_delta"] for w in model_windows)),
           "probes_model": model.probes, "exports_model": model.exported,
           "totals_mismatch_windows": sum(1 for r in rows.values() if num(r, "net_sweep_totals_mismatch") != 0),
           "coll_pkts_collector": int(sum(num(r, "net_sweep_coll_pkts") for r in rows.values())),
           "coll_pkts_model": int(sum(w["net_sweep_coll_pkts"] for w in model_windows)),
           "sweep_span_us_max": max((num(r, "net_sweep_span_us") for r in rows.values()), default=0.0)}
    if published is not None or skip:
        ks = list(range(skip, skip + DATASET_WINDOWS))
        if all(k in rows for k in ks) and len(model_windows) >= skip + DATASET_WINDOWS:
            row = sf.summarize([rows[k] for k in ks])
            row_m = sf.summarize(model_windows[skip:skip + DATASET_WINDOWS])
            _bad, bad_nodur = sf.compare_row(row, row_m)
            out["row_equal_model_nodur"] = 135 - len(bad_nodur)
            if published is not None:
                _bad, bad_nodur = sf.compare_row(row, published)
                _bad_m, bad_m_nodur = sf.compare_row(row_m, published)
                out["row_equal_published_nodur"] = 135 - len(bad_nodur)
                out["row_model_equal_published_nodur"] = 135 - len(bad_m_nodur)
                out["row_mismatch_published"] = sorted({c.split("__")[0] for c in bad_nodur})
    return out


def published_row(release, execution_id):
    """The release's dataset/features.csv row of this execution id."""
    import csv
    csv.field_size_limit(sys.maxsize)
    with open(Path(release) / "dataset" / "features.csv") as fh:
        for r in csv.DictReader(fh):
            if r["execution_id"] == execution_id:
                return r
    sys.exit("execution id %s is not in %s" % (execution_id, Path(release) / "dataset" / "features.csv"))


DATASET_WINDOWS = 40


def profile_settings(profile, align_window):
    """The collector window and the collector options of a replay with this profile."""
    if profile == "switch":
        return 1.0, ["--profile", "switch"]
    if profile == "dataset":
        # K windows before the anchor, then the dataset's 40; the shell launcher, because the
        # scenario is the replayer, not a program whose start-up the dataset rows include
        return 0.5, ["--profile", "dataset", "--launcher", "shell", "--windows", str(align_window + DATASET_WINDOWS)]
    raise ValueError("unknown profile %r" % profile)


def self_check_header_bytes(profile):
    """Bytes per packet the profile's collector adds to the IPv4 lengths the switch counts: the dataset
    profile reports Ethernet frame bytes (hybrid_collector.py PROFILES["dataset"]["byte_layer"] "frame",
    ETHERNET_HEADER_BYTES 14), the switch profile IPv4 bytes."""
    if profile == "dataset":
        return 14
    if profile == "switch":
        return 0
    raise ValueError("unknown profile %r" % profile)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("capture")
    ap.add_argument("--out", required=True, help="new directory for this replay's files")
    ap.add_argument("--profile", choices=["switch", "dataset"], default="switch",
                    help="collector definitions: switch (1 s windows) or dataset (0.5 s windows, RUNBOOK 19.9)")
    ap.add_argument("--anchor-offset", type=float, default=1.0,
                    help="seconds from the capture's first frame to the run's window anchor (sample_started_wall_us)")
    ap.add_argument("--align-window", type=int, default=2, help="collector window whose start the anchor should hit")
    ap.add_argument("--start-latency", type=float, default=0.10,
                    help="seconds from the scenario's start to tcpreplay's first frame, besides the sleep "
                         "(summary.json reports the measured value for the next run)")
    ap.add_argument("--report-latency", type=float, default=0.02, help="bound on a CPU report's delay (self-check)")
    ap.add_argument("--replayer", choices=["absolute", "tcpreplay"], default="absolute")
    ap.add_argument("--tx-iface", default="eth1")
    ap.add_argument("--switch-ssh", default="root@172.168.1.2")
    ap.add_argument("--int-port", default="132")
    ap.add_argument("--ext-port", default="140")
    ap.add_argument("--cpu-iface", default="enp5s0")
    ap.add_argument("--label", default="replay")
    ap.add_argument("--exact", action="store_true",
                    help="the switch runs perf/variants/exact: the collector reads its window registers "
                         "(--switch-program exact --window-markers inband), the replayer sends a window marker at "
                         "each collector window boundary in order with the frames, and the self-check compares "
                         "every window exactly with the frames sent between its markers")
    ap.add_argument("--sweep", choices=["inband", "generator"],
                    help="the switch runs perf/variants/sweep: the collector builds the windows from its export "
                         "records (--switch-program sweep). 'inband': the replayer sends the probes at each collector "
                         "window boundary in order with the frames (--sweep-probes inband); 'generator': the switch's "
                         "packet generator sweeps every bucket every window (the deployment). The self-check compares "
                         "every window with the program's software model on the same frames (exact with inband)")
    ap.add_argument("--sweep-ipg-ns", type=int, default=None,
                    help="--sweep generator: the gap between two probes (the collector's default: 2000)")
    ap.add_argument("--execution-id", help="--sweep, --profile dataset: compare the row of the dataset's 40 windows "
                                           "with this execution id's published row")
    ap.add_argument("--release", default=str(REPO.parent / "p4-ebpf-malware-detection"))
    ap.add_argument("--send-log", action="store_true",
                    help="--replayer absolute: DIR/send_log.txt gets this host's clock just after each capture frame was "
                         "sent (replay_absolute.py --send-log; one line per frame in capture order, \"-\" if refused)")
    ap.add_argument("--frame-min", action="append", default=None,
                    help="--exact, --sweep: DST/PREFIX toward which the switch counts the frame minimum (default with "
                         "--profile dataset: 10.0.0.10/32, the dataset's guest)")
    argv, extra = sys.argv[1:], []
    if "--" in argv:                        # after --: extra hybrid_collector.py options
        extra, argv = argv[argv.index("--") + 1:], argv[:argv.index("--")]
    args = ap.parse_args(argv)
    if os.geteuid() != 0:
        sys.exit("run as root (tcpdump, tcpreplay, the collector)")
    capture = Path(args.capture).resolve()
    out = Path(args.out).resolve()
    if (out / "windows.csv").exists():
        sys.exit("%s already holds a replay; use a new --out" % out)
    out.mkdir(parents=True, exist_ok=True)
    window_sec, profile_args = profile_settings(args.profile, args.align_window)
    frame_min = args.frame_min if args.frame_min is not None else (["10.0.0.10/32"] if args.profile == "dataset" else [])
    n_windows = None
    if args.exact and args.sweep:
        sys.exit("--exact (perf/variants/exact) or --sweep (perf/variants/sweep), not both")
    if args.execution_id and not (args.sweep and args.profile == "dataset"):
        sys.exit("--execution-id needs --sweep and --profile dataset")
    if args.exact or args.sweep:
        if args.replayer != "absolute":
            sys.exit("--exact and --sweep need --replayer absolute (it schedules from the collector's window origin "
                     "and sends the markers or probes)")
        if args.profile == "dataset":
            n_windows = args.align_window + DATASET_WINDOWS
        else:
            frames = read_pcap(capture, snap=1)
            span = frames[-1][0] - (frames[0][0] + args.anchor_offset) if frames else 0.0
            n_windows = args.align_window + int(span // window_sec) + 2
    if args.exact:
        profile_args = profile_args + ["--switch-program", "exact", "--window-markers", "inband",
                                       "--marker-port", args.int_port, "--windows", str(n_windows)] + \
            sum((["--frame-min", f] for f in frame_min), [])
    if args.sweep:
        profile_args = profile_args + ["--switch-program", "sweep", "--sweep-probes", args.sweep,
                                       "--sweep-export-port", args.int_port, "--sweep-export-iface", args.tx_iface,
                                       "--windows", str(n_windows)] + \
            (["--sweep-probe-port", args.int_port] if args.sweep == "inband" else []) + \
            (["--sweep-ipg-ns", str(args.sweep_ipg_ns)] if args.sweep_ipg_ns is not None else []) + \
            (sum((["--frame-min", f] for f in frame_min), []) if frame_min else ["--frame-min", "none"])
    delay = None
    if args.replayer == "tcpreplay":
        delay = args.align_window * window_sec - args.anchor_offset - args.start_latency
        if delay < 0:
            sys.exit("the anchor cannot reach window %d: raise --align-window" % args.align_window)
        scenario = "sleep %.3f; exec tcpreplay -i %s %s" % (delay, shlex.quote(args.tx_iface), shlex.quote(str(capture)))
    else:
        if args.align_window * window_sec - args.anchor_offset < 0.5:
            sys.exit("the anchor cannot reach window %d: raise --align-window" % args.align_window)
        scenario = "exec %s %s --iface %s --align-window %d --anchor-offset %.6f --window-sec %s %s%s" % (
            shlex.quote(sys.executable), shlex.quote(str(REPO / "live_test" / "replay_absolute.py")),
            shlex.quote(args.tx_iface), args.align_window, args.anchor_offset, repr(window_sec),
            shlex.quote(str(capture)), " --markers --marker-windows %d" % n_windows if args.exact else
            " --probes changed --probe-windows %d" % n_windows if args.sweep == "inband" else "")
        if args.send_log:
            scenario += " --send-log %s" % shlex.quote(str(out / "send_log.txt"))
    stub = out / "hostmon_stub"
    stub.write_text("#!/bin/sh\n# stand-in HostMon: the host side of a replay comes from the recorded run\nexec sleep 86400\n")
    stub.chmod(0o755)

    tcpdump = subprocess.Popen(["tcpdump", "-i", args.tx_iface, "-Q", "out", "-s", "96", "-w", str(out / "tx.pcap")],
                               stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    ok, said = wait_listening(tcpdump, 10)
    if not ok:
        tcpdump.kill()
        sys.exit("the send capture did not start: %s" % "; ".join(said))
    cmd = [sys.executable, str(REPO / "hybrid_collector.py")] + profile_args + ["--mode", "command",
           "--scenario-name", capture.stem, "--label", args.label, "--command", scenario,
           "--out-csv", str(out / "windows.csv"), "--switch-ssh", args.switch_ssh,
           "--forward-int-port", args.int_port, "--forward-ext-port", args.ext_port, "--cpu-iface", args.cpu_iface,
           "--reader-timing", "--reader-timing-file", str(out / "timing.jsonl"),
           "--hostmon", str(stub), "--hostmon-log", str(out / "hostmon.log"),
           "--p4-reader", str(PYDIR / "read_registers_with_index.py"),
           "--p4-forwarder", str(PYDIR / "program_forwarding.py")] + extra
    print("[replay] %s -> %s (%s, profile %s, %.1f s windows, anchor at collector window %d)" % (
        capture.name, out, "absolute replay" if delay is None else "tcpreplay after %.3f s" % delay, args.profile,
        window_sec, args.align_window))
    with open(out / "collector.log", "w") as log:
        rc = subprocess.call(cmd, cwd=str(out), stdout=log, stderr=subprocess.STDOUT)
    time.sleep(0.5)
    tcpdump.send_signal(signal.SIGINT)
    try:
        tcpdump.wait(timeout=10)
    except subprocess.TimeoutExpired:
        tcpdump.kill()
    if rc != 0:
        print("[replay] the collector exited with %d; see %s" % (rc, out / "collector.log"))
    summary = analyse(out, capture, args.anchor_offset, args.align_window, delay, args.report_latency, window_sec,
                      header_bytes=self_check_header_bytes(args.profile))
    summary["collector_exit_code"] = rc
    if args.exact:
        import csv
        csv.field_size_limit(sys.maxsize)
        rows = {int(float(r["net_window_id"])): r for r in csv.DictReader(open(out / "windows.csv"))}
        # the replayer's own sending order: the capture's frames and its markers (replay_absolute.py's defaults
        # inside the collector), less the frames the interface refuses (over its MTU)
        sys.path.insert(0, str(REPO / "live_test"))
        import replay_absolute
        window_us = int(round(window_sec * 1e6))
        first_us = replay_absolute.read_pcap_us(str(capture))[0][0]
        events = replay_absolute.with_markers(str(capture), b"\x00" * 6,
                                              first_us + int(round(args.anchor_offset * 1e6)) - args.align_window * window_us,
                                              window_us, n_windows, 1)
        mtu = int(open("/sys/class/net/%s/mtu" % args.tx_iface).read())
        hb = self_check_header_bytes(args.profile)
        summary["exact_check"] = exact_check([(t, f) for t, f, _m in events], rows, header_bytes=hb,
                                             frame_min=frame_min, max_frame=mtu + 14)
        summary["exact_check"]["frame_min"] = frame_min
        summary["exact_check"]["against"] = "the replayer's schedule (capture frames up to the MTU, and the markers)"
        tx_side = exact_check(read_pcap(out / "tx.pcap"), rows, header_bytes=hb, frame_min=frame_min)
        summary["exact_check"]["tx_capture"] = {k: tx_side[k] for k in ("windows_exact", "sent_pkts_total",
                                                                        "sent_bytes_total")}
    if args.sweep:
        import csv
        csv.field_size_limit(sys.maxsize)
        rows = {int(float(r["net_window_id"])): r for r in csv.DictReader(open(out / "windows.csv"))}
        window_us = int(round(window_sec * 1e6))
        first_us = int(round(read_pcap(capture, snap=1)[0][0] * 1e6))
        mtu = int(open("/sys/class/net/%s/mtu" % args.tx_iface).read())
        pub = published_row(args.release, args.execution_id) if args.execution_id else None
        summary["sweep_check"] = sweep_check(
            capture, rows, first_us + int(round(args.anchor_offset * 1e6)) - args.align_window * window_us, window_us,
            n_windows, frame_min, header_bytes=self_check_header_bytes(args.profile), max_frame=mtu + 14,
            skip=args.align_window if args.profile == "dataset" else 0, published=pub)
        summary["sweep_check"].update(probes=args.sweep, frame_min=frame_min, execution_id=args.execution_id,
                                      ipg_ns=args.sweep_ipg_ns)
    (out / "summary.json").write_text(json.dumps(summary, indent=1) + "\n")
    uid, gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
    if uid and gid:
        for p in [out] + list(out.iterdir()):
            os.chown(p, int(uid), int(gid))
    sc = summary["self_check"]
    print("[replay] alignment error %s ms, measured start latency %s s, replay timing error %s ms" % (
        summary.get("alignment_error_ms"), summary.get("start_latency_measured_s"), summary.get("replay_timing_error_ms")))
    print("[replay] snapshot interval %s ms, starting %s ms after the window end; clock offset round trip min %s ms" % (
        sc["snapshot_interval_ms"], sc["snapshot_start_after_window_end_ms"], summary["round_trip_min_ms"]))
    if args.exact:
        ec = summary["exact_check"]
        print("[replay] exact check: %d of %d windows equal to the frames sent between their markers; packets "
              "switch %d / sent %d, bytes switch %d / sent %d; packets without a slot %d, windows lost %d; "
              "send capture: %d packets" % (
                  ec["windows_exact"], ec["windows_checked"], ec["switch_pkts_total"], ec["sent_pkts_total"],
                  ec["switch_bytes_total"], ec["sent_bytes_total"], ec["untracked_pkts"], ec["windows_lost"],
                  ec["tx_capture"]["sent_pkts_total"]))
    elif args.sweep:
        c = summary["sweep_check"]
        print("[replay] sweep check (%s probes): %d of %d windows equal to the model's in the 27 non-duration features; "
              "packets collector %d / model %d; colliding packets %d / %d; windows whose totals disagree %d; longest "
              "sweep %.1f ms%s%s" % (
                  c["probes"], c["windows_equal_nodur"], c["windows_model"], c["pkts_collector"], c["pkts_model"],
                  c["coll_pkts_collector"], c["coll_pkts_model"], c["totals_mismatch_windows"],
                  c["sweep_span_us_max"] / 1000.0,
                  "; row equal to the model's in %d of 135" % c["row_equal_model_nodur"]
                  if "row_equal_model_nodur" in c else "",
                  "; to the published row in %d (the model's: %d)" % (c["row_equal_published_nodur"],
                                                                      c["row_model_equal_published_nodur"])
                  if "row_equal_published_nodur" in c else ""))
    else:
        print("[replay] self-check: %d of %d windows inside the bounds; packets switch %d / sent %d, bytes switch %d / "
              "sent %d" % (sc["windows_inside_bounds"], sc["windows_checked"], sc["switch_pkts_total"],
                           sc["sent_pkts_total"], sc["switch_bytes_total"], sc["sent_bytes_total"]))
    sys.exit(0 if rc == 0 else rc)


if __name__ == "__main__":
    main()
