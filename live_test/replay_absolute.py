#!/usr/bin/env python3
"""Send a capture's frames at their recorded times from an absolute start (RUNBOOK 19.6).

    replay_absolute.py --iface eth1 CAPTURE [--start-at T]
    replay_absolute.py --iface eth1 CAPTURE --align-window K --anchor-offset A   (inside hybrid_collector)

tcpreplay times each frame relative to the previous one, so its per-frame overhead adds up: on
PC1 bulk2000's 22 s ran 254 ms late by the end with the default timer (156 ms with -K; 2.7-2.9 s
with --timer=nano or select). Here frame i is sent at start + (t_i - t_0), so lateness does not
add up, and the start can be placed on the collector's window grid: inside a hybrid_collector
scenario HYBRID_T0 holds the window origin, and the run's anchor (A seconds after the first
frame) is put on the start of collector window K: start = HYBRID_T0 + K x window - A.

--markers (perf/variants/exact): a window marker frame (EtherType 0x88B5, magic 0x5745, the epoch of
the window it starts) is sent at each window boundary of the capture, --marker-anchor-us + k x
--marker-window-us for k = 0..--marker-windows, carrying epoch --marker-first-epoch + k. It goes in
order with the capture's frames, before every frame whose whole-microsecond time is at or after the
boundary (the window rule of features/switch_model.py), so the switch's windows are the capture's
windows whatever the replay's timing; a late start (loading a big capture) shifts the whole schedule instead
of sending the markers due by then at once. Inside hybrid_collector (--window-markers inband) the defaults put
marker k at the start of collector window k: the anchor (--anchor-offset after the first frame) minus
--align-window windows of --window-sec. Frames keep their times relative to the first capture frame.

Needs root (a raw packet socket). Frames the interface refuses (larger than its MTU) are counted
as failed and skipped, as tcpreplay does. Prints one line of statistics at the end.
"""
import argparse
import os
import socket
import statistics
import struct
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from replay_capture import read_pcap  # noqa: E402


WINDOW_ETHERTYPE = 0x88B5
WINDOW_MAGIC = 0x5745


def read_pcap_us(path):
    """(whole microseconds, frame) of every record, as features/switch_model.py times them."""
    out = []
    with open(path, "rb") as f:
        head = f.read(24)
        order, digits = {b"\xd4\xc3\xb2\xa1": ("<", 6), b"\xa1\xb2\xc3\xd4": (">", 6),
                         b"\x4d\x3c\xb2\xa1": ("<", 9), b"\xa1\xb2\x3c\x4d": (">", 9)}[head[:4]]
        rec = struct.Struct(order + "IIII")
        while True:
            h = f.read(16)
            if len(h) < 16:
                break
            sec, frac, incl, _ = rec.unpack(h)
            out.append((sec * 1000000 + (frac if digits == 6 else frac // 1000), f.read(incl)))
    return out


def marker_frame(src_mac, epoch):
    frame = b"\xff" * 6 + src_mac + struct.pack("!HHI", WINDOW_ETHERTYPE, WINDOW_MAGIC, epoch)
    return frame + b"\x00" * (60 - len(frame))


def with_markers(path, src_mac, anchor_us, window_us, windows, first_epoch):
    """[(seconds, frame, is_marker)] in sending order: the capture's frames and the window markers."""
    frames = read_pcap_us(path)
    events, k, i = [], 0, 0
    while i < len(frames) or k <= windows:
        boundary = anchor_us + k * window_us
        if k <= windows and (i >= len(frames) or frames[i][0] >= boundary):
            events.append((boundary / 1e6, marker_frame(src_mac, first_epoch + k), True))
            k += 1
        else:
            events.append((frames[i][0] / 1e6, frames[i][1], False))
            i += 1
    return events


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("capture")
    ap.add_argument("--iface", required=True)
    ap.add_argument("--start-at", type=float, help="absolute start time (this host's clock) of the first frame")
    ap.add_argument("--t0-env", default="HYBRID_T0", help="environment variable with the collector's window origin")
    ap.add_argument("--align-window", type=int, default=2)
    ap.add_argument("--anchor-offset", type=float, default=1.0)
    ap.add_argument("--window-sec", type=float, default=1.0)
    ap.add_argument("--spin", type=float, default=0.001, help="busy-wait this long before each frame instead of sleeping")
    ap.add_argument("--markers", action="store_true", help="send window markers (perf/variants/exact)")
    ap.add_argument("--marker-anchor-us", type=int, help="the capture time of the first window's start (us; "
                    "default: the anchor minus --align-window windows)")
    ap.add_argument("--marker-window-us", type=int, help="default: --window-sec")
    ap.add_argument("--marker-windows", type=int, default=40, help="windows: markers 0..N, the last one ends window N-1")
    ap.add_argument("--marker-first-epoch", type=int, default=1)
    ap.add_argument("--send-log", help="write this host's clock just after each capture frame was sent, one line per "
                    "capture frame in order (\"-\" for a frame the interface refused); markers are not listed")
    args = ap.parse_args()
    if args.markers:
        window_us = args.marker_window_us or int(round(args.window_sec * 1e6))
        anchor_us = args.marker_anchor_us
        if anchor_us is None:
            first = read_pcap_us(args.capture)[:1]
            if not first:
                sys.exit("%s holds no frames" % args.capture)
            anchor_us = first[0][0] + int(round(args.anchor_offset * 1e6)) - args.align_window * window_us
        mac = bytes.fromhex(Path("/sys/class/net/%s/address" % args.iface).read_text().strip().replace(":", ""))
        events = with_markers(args.capture, mac, anchor_us, window_us, args.marker_windows, args.marker_first_epoch)
        frames = [(t, f) for t, f, _ in events]
        is_marker = [m for _, _, m in events]
    else:
        frames = read_pcap(args.capture)
        is_marker = [False] * len(frames)
    if not frames:
        sys.exit("%s holds no frames" % args.capture)
    if args.start_at is not None:
        start = args.start_at
    elif args.t0_env in os.environ:
        start = float(os.environ[args.t0_env]) + args.align_window * args.window_sec - args.anchor_offset
    else:
        sys.exit("give --start-at, or run inside hybrid_collector (%s)" % args.t0_env)
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    sock.bind((args.iface, 0))
    # times relative to the first capture frame (markers before it go out at once, in order)
    c0 = next((t for (t, _f), m in zip(frames, is_marker) if not m), frames[0][0])
    late_start = time.time() - start
    if args.markers:
        # late against the first event (the first marker comes before the first frame)
        late_start = time.time() - (start + (frames[0][0] - c0))
    if late_start > 0 and args.markers:
        # the windows are the markers' (perf/variants/exact): shift the whole schedule rather than send the markers
        # due by now in one burst (a burst ends windows faster than the reader can read them)
        start += late_start + 0.05
        print("[replay_absolute] started %.3f s after the requested start (loading the capture): the schedule, "
              "markers included, is shifted by %.3f s" % (late_start, late_start + 0.05), flush=True)
    elif late_start > 0:
        print("[replay_absolute] WARNING: started %.3f s after the requested start; frames until then go out at once"
              % late_start, flush=True)
    late, failed, markers_sent = [], 0, 0
    sent_at = [] if args.send_log else None
    for (t, frame), marker in zip(frames, is_marker):
        target = start + (t - c0)
        gap = target - time.time()
        if gap > args.spin:
            time.sleep(gap - args.spin)
        while time.time() < target:
            pass
        try:
            sock.send(frame)
        except OSError:
            if marker:
                sys.exit("[replay_absolute] the window marker could not be sent")
            failed += 1
            if sent_at is not None:
                sent_at.append(None)
            continue
        if marker:
            markers_sent += 1
            continue
        now = time.time()
        late.append(now - target)
        if sent_at is not None:
            sent_at.append(now)
    sock.close()
    if sent_at is not None:
        with open(args.send_log, "w") as fh:
            fh.write("".join("-\n" if x is None else "%.6f\n" % x for x in sent_at))
    late.sort()
    print("[replay_absolute] %d frames sent, %d failed, %d window markers, in %.2f s; lateness median %.3f ms, "
          "p99 %.3f ms, max %.3f ms"
          % (len(late), failed, markers_sent, frames[-1][0] - c0, statistics.median(late) * 1e3 if late else 0.0,
             late[int(0.99 * (len(late) - 1))] * 1e3 if late else 0.0, late[-1] * 1e3 if late else 0.0), flush=True)


if __name__ == "__main__":
    main()
