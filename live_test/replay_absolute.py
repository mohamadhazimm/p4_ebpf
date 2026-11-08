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

Needs root (a raw packet socket). Frames the interface refuses (larger than its MTU) are counted
as failed and skipped, as tcpreplay does. Prints one line of statistics at the end.
"""
import argparse
import os
import socket
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from replay_capture import read_pcap  # noqa: E402


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
    args = ap.parse_args()
    frames = read_pcap(args.capture)
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
    c0 = frames[0][0]
    late_start = time.time() - start
    if late_start > 0:
        print("[replay_absolute] WARNING: started %.3f s after the requested start; frames until then go out at once"
              % late_start, flush=True)
    late, failed = [], 0
    for t, frame in frames:
        target = start + (t - c0)
        gap = target - time.time()
        if gap > args.spin:
            time.sleep(gap - args.spin)
        while time.time() < target:
            pass
        try:
            sock.send(frame)
        except OSError:
            failed += 1
            continue
        late.append(time.time() - target)
    sock.close()
    late.sort()
    print("[replay_absolute] %d frames sent, %d failed, in %.2f s; lateness median %.3f ms, p99 %.3f ms, max %.3f ms"
          % (len(late), failed, frames[-1][0] - c0, statistics.median(late) * 1e3 if late else 0.0,
             late[int(0.99 * (len(late) - 1))] * 1e3 if late else 0.0, late[-1] * 1e3 if late else 0.0), flush=True)


if __name__ == "__main__":
    main()
