#!/usr/bin/env python3
"""Check the collector's dataset-profile byte rule against the switch's own register readouts
(RUNBOOK 19.9.4, step 1).

    python3 live_test/check_frame_bytes.py [RESULTS_DIR]

RESULTS_DIR is a folder of the release repository's P4 validation (validation/run_validation.sh):
per capture NAME, NAME.after.json holds the register rows the switch gave after the whole capture
was replayed, and NAME.result.json the 29 features computed from them (features_from_registers.py,
"live") next to the offline extractor's (features/switch_model.py, "offline"). Default: the
2026-11-04 run on this VM.

Two comparisons per capture, both through hybrid_collector.NetSummarizer on the register rows as
one window (the window length is recovered from the live packets-per-second figure):
  ipv4   byte_layer "ipv4": the collector must give the validation's 29 live values exactly, so
         that what is checked below is the collector's own code path;
  frame  byte_layer "frame": the collector must give the offline extractor's 27 non-duration
         features exactly (the dataset counts Ethernet frame bytes; the only residual is Ethernet
         padding on frames under 60 B that the capture recorded and the switch cannot see). The two
         durations are reported only: the replay's timing is not the capture's.
Exit status 0 when every ipv4 value and every frame count feature match and the frame byte
mismatches are explained by padding (the capture's padded bytes are counted from the pcap when it
is next to RESULTS_DIR in ../../pcaps/ or given with --pcaps).
"""
import argparse
import json
import struct
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "thesis-hybrid-ebpf-p4" / "python"))
import hybrid_collector as hc  # noqa: E402

DEFAULT_RESULTS = Path.home() / "Desktop/p4-ebpf-malware-detection/validation/results/20261104_111459"
DURATIONS = ("net_flow_duration_mean", "net_flow_duration_max")
COUNTS = ("net_flow_count_seen", "net_pkts_total_delta", "net_pkts_ab_delta", "net_pkts_ba_delta",
          "net_pkts_per_sec_delta", "net_ab_ratio_pkt_delta", "net_ba_ratio_pkt_delta", "net_syn_delta",
          "net_ack_delta", "net_rst_delta", "net_flows_with_ab", "net_flows_with_ba", "net_dir_valid_count")
FEATURES = [f for f in hc.NET_ZERO if f != "net_new_conn_dst_max"]


def close(a, b, rtol=1e-9, atol=1e-6):
    return abs(a - b) <= atol + rtol * max(abs(a), abs(b))


def padded_bytes(pcap):
    """Ethernet padding the capture recorded: frame bytes beyond 14 + IPv4 totalLen, over IPv4 frames."""
    total = 0
    with open(pcap, "rb") as f:
        head = f.read(24)
        magic = head[:4]
        endian = "<" if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
        while True:
            rec = f.read(16)
            if len(rec) < 16:
                break
            _s, _f, incl, _orig = struct.unpack(endian + "IIII", rec)
            frame = f.read(incl)
            if len(frame) >= 34 and frame[12:14] == b"\x08\x00" and frame[14] >> 4 == 4:
                ipv4_len = (frame[16] << 8) | frame[17]
                total += max(0, len(frame) - 14 - ipv4_len)
    return total


def summarize(rows, window_sec, byte_layer):
    s = hc.NetSummarizer(window_sec, byte_layer=byte_layer, duration_unit="s")
    return s.add({"rows": rows})


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("results", nargs="?", default=str(DEFAULT_RESULTS))
    ap.add_argument("--pcaps", help="folder with the captures (default: RESULTS_DIR/../../pcaps)")
    args = ap.parse_args()
    results = Path(args.results)
    pcaps = Path(args.pcaps) if args.pcaps else results.parents[1] / "pcaps"
    names = sorted(p.name[:-len(".after.json")] for p in results.glob("*.after.json"))
    if not names:
        sys.exit(f"no *.after.json in {results}")

    failures = 0
    print(f"{'capture':14s} {'rows':>5s} {'ipv4=live':>9s} {'frame=offline':>13s}  byte mismatches (collector vs offline)")
    for name in names:
        after = json.loads((results / f"{name}.after.json").read_text())
        rows = after.get("rows") or []
        result = json.loads((results / f"{name}.result.json").read_text())
        live = {r["feature"]: float(r["live"]) for r in result["rows"]}
        offline = {r["feature"]: float(r["offline"]) for r in result["rows"]}
        if live["net_pkts_per_sec_delta"] > 0:
            window_sec = live["net_pkts_total_delta"] / live["net_pkts_per_sec_delta"]
        else:
            window_sec = 1.0

        ipv4 = summarize(rows, window_sec, "ipv4")
        ipv4_bad = [f for f in FEATURES if not close(float(ipv4[f]), live[f])]

        frame = summarize(rows, window_sec, "frame")
        compare = [f for f in FEATURES if f not in DURATIONS]
        frame_bad = [f for f in compare if not close(float(frame[f]), offline[f])]
        count_bad = [f for f in frame_bad if f in COUNTS]
        pad = padded_bytes(pcaps / f"{name}.pcap") if (pcaps / f"{name}.pcap").exists() else None
        # padding explains a byte mismatch when the collector's total is lower by exactly the padded bytes
        explained = (pad is not None and pad > 0 and not count_bad
                     and close(float(frame["net_bytes_total_delta"]) + pad, offline["net_bytes_total_delta"]))
        ok = not ipv4_bad and (not frame_bad or explained)
        failures += 0 if ok else 1
        detail = "; ".join(f"{f} {float(frame[f]):.6g} vs {offline[f]:.6g}" for f in frame_bad[:4])
        if frame_bad and explained:
            detail = f"{len(frame_bad)} features, all from {pad} B of Ethernet padding in the capture: " + detail
        elif frame_bad and len(frame_bad) > 4:
            detail += f" (+{len(frame_bad) - 4} more)"
        print(f"{name:14s} {len(rows):5d} {len(FEATURES) - len(ipv4_bad):>6d}/{len(FEATURES):<2d} "
              f"{len(compare) - len(frame_bad):>8d}/{len(compare):<2d}    {detail or '-'}")
        if ipv4_bad:
            print("    ipv4 route differs from the validation's live values: " + ", ".join(ipv4_bad))
        dur = ", ".join(f"{f.split('_')[-1]} {float(frame[f]):.4g} s vs {offline[f]:.4g} s" for f in DURATIONS)
        print(f"    durations (not comparable under replay): {dur}")
    print("PASS" if failures == 0 else f"FAIL: {failures} capture(s)")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
