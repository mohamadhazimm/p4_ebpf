#!/usr/bin/env python3
"""Ground truth of an existing PCAP for replay through the P4 data plane.

    pcap_truth.py CAPTURE.pcap --truth TRUTH.json [--internal-cidr 10.0.0.10/32] [--max-flows-listed 5000]

The same JSON as make_benign_pcap.py --truth (so live_test/analyze_run.py --truth reads
it), computed from a capture instead of generated traffic. Per flow (unordered
5-tuple, IPv4 TCP/UDP, first fragments only), what the data plane must count:
packets, bytes as IPv4 totalLen (what ingress.p4 adds), the same split by the
direction of the flow's first packet as ingress.p4 decides it (ports compared with
the first packet's ports), min/max totalLen, TCP SYN/ACK/RST, the L2 frame bytes;
plus SYN-without-ACK counts per reg_newconn_dst key, the totals, and what the
collector will see: distinct flow buckets, buckets shared by several flows, new
flows and active buckets per 1 s window (the collector's 3-window TTL).

Flows that share a bucket are added up in the same registers, and the direction
split then follows the bucket's first packet, not each flow's: "totals" are per
flow, "totals_bucket_model" follow the bucket (they are equal when no bucket is
shared, and the switch's sums equal the latter when no shared bucket is cleared
between its flows). The per-flow list is written only up to --max-flows-listed
flows (a flood's list would be megabytes; its per-flow check is not meaningful
under the read budget anyway).

Standard library only (no scapy): classic PCAP, Ethernet with at most one 802.1Q tag.
"""
import argparse
import collections
import hashlib
import ipaddress
import json
import socket
import struct
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "thesis-hybrid-ebpf-p4" / "python"))
from flow_index import compute_flow_index, compute_newconn_dst_index  # noqa: E402

TTL_WINDOWS = 3


def read_pcap(path):
    """Yield (time_s, frame_bytes, orig_len) of every record."""
    with open(path, "rb") as f:
        head = f.read(24)
        if len(head) < 24:
            raise ValueError("%s: not a PCAP file" % path)
        magic = struct.unpack("<I", head[:4])[0]
        if magic in (0xA1B2C3D4, 0xA1B23C4D):
            end, nano = "<", magic == 0xA1B23C4D
        elif magic in (0xD4C3B2A1, 0x4D3CB2A1):
            end, nano = ">", magic == 0x4D3CB2A1
        else:
            raise ValueError("%s: not a classic PCAP file (pcapng is not supported)" % path)
        linktype = struct.unpack(end + "I", head[20:24])[0]
        if linktype != 1:
            raise ValueError("%s: link type %d, expected Ethernet (1)" % (path, linktype))
        while True:
            rec = f.read(16)
            if len(rec) < 16:
                return
            sec, frac, incl, orig = struct.unpack(end + "IIII", rec)
            data = f.read(incl)
            if len(data) < incl:
                return
            yield sec + frac / (1e9 if nano else 1e6), data, orig


def parse(frame):
    """(src, dst, sport, dport, proto, total_len, tcp_flags) of an IPv4 TCP/UDP first
    fragment, else None."""
    off, ethertype = 14, struct.unpack("!H", frame[12:14])[0] if len(frame) >= 14 else 0
    if ethertype == 0x8100 and len(frame) >= 18:
        off, ethertype = 18, struct.unpack("!H", frame[16:18])[0]
    if ethertype != 0x0800 or len(frame) < off + 20:
        return None
    ihl = (frame[off] & 0x0F) * 4
    total_len = struct.unpack("!H", frame[off + 2:off + 4])[0]
    frag_offset = struct.unpack("!H", frame[off + 6:off + 8])[0] & 0x1FFF
    proto = frame[off + 9]
    if proto not in (6, 17) or frag_offset or len(frame) < off + ihl + 4:
        return None
    src = socket.inet_ntoa(frame[off + 12:off + 16])
    dst = socket.inet_ntoa(frame[off + 16:off + 20])
    sport, dport = struct.unpack("!HH", frame[off + ihl:off + ihl + 4])
    flags = frame[off + ihl + 13] if proto == 6 and len(frame) >= off + ihl + 14 else 0
    return src, dst, sport, dport, proto, total_len, flags


def is_ab(sport, dport, ref_sp, ref_dp):
    """ingress.p4's direction: ports equal to the reference ports count as "ab",
    and so does anything that is not exactly the reverse of them."""
    return (sport == ref_sp and dport == ref_dp) or not (sport == ref_dp and dport == ref_sp)


def truth_of(path, internal, max_listed):
    flows = {}
    buckets = {}            # flow_index -> {"ref": (sport, dport), "pkts_ab", "bytes_ab", "flows": set()}
    newconn = collections.Counter()
    frames = eligible = int_side = 0
    t_first = t_last = None
    pkt_times = []          # (time, flow_index) of every eligible packet
    for t, frame, orig in read_pcap(path):
        frames += 1
        t_first = t if t_first is None else t_first
        t_last = t
        p = parse(frame)
        if p is None:
            continue
        eligible += 1
        src, dst, sport, dport, proto, tot, flags = p
        int_side += ipaddress.ip_address(src) in internal
        key = (proto,) + tuple(sorted(((src, sport), (dst, dport))))
        f = flows.get(key)
        if f is None:
            f = flows[key] = {
                "first": [src, dst, sport, dport, proto],
                "flow_index": compute_flow_index(src, dst, sport, dport, proto),
                "pkts": 0, "bytes": 0, "pkts_ab": 0, "bytes_ab": 0, "pkts_ab_ip": 0, "bytes_ab_ip": 0,
                "min_len": tot, "max_len": tot, "syn": 0, "ack": 0, "rst": 0,
                "frame_bytes": 0, "first_t": t, "last_t": t,
                "inject_side_first": "int" if ipaddress.ip_address(src) in internal else "ext",
            }
        f["pkts"] += 1
        f["bytes"] += tot
        f["frame_bytes"] += orig
        if is_ab(sport, dport, f["first"][2], f["first"][3]):
            f["pkts_ab"] += 1
            f["bytes_ab"] += tot
        if (src, sport) == (f["first"][0], f["first"][2]):     # the offline extractor's direction
            f["pkts_ab_ip"] += 1
            f["bytes_ab_ip"] += tot
        f["min_len"] = min(f["min_len"], tot)
        f["max_len"] = max(f["max_len"], tot)
        f["last_t"] = t
        if proto == 6:
            f["syn"] += int(bool(flags & 0x02))
            f["ack"] += int(bool(flags & 0x10))
            f["rst"] += int(bool(flags & 0x04))
            if flags & 0x12 == 0x02:
                newconn[(src, dst, dport, proto)] += 1
        b = buckets.get(f["flow_index"])
        if b is None:
            b = buckets[f["flow_index"]] = {"ref": (sport, dport), "pkts_ab": 0, "bytes_ab": 0, "flows": set()}
        b["flows"].add(key)
        if is_ab(sport, dport, *b["ref"]):
            b["pkts_ab"] += 1
            b["bytes_ab"] += tot
        pkt_times.append((t, f["flow_index"]))

    flow_list = []
    for _key, f in sorted(flows.items(), key=lambda kv: kv[1]["first_t"]):
        f = dict(f)
        f["pkts_ba"] = f["pkts"] - f["pkts_ab"]
        f["bytes_ba"] = f["bytes"] - f["bytes_ab"]
        flow_list.append(f)
    totals = {k: sum(f[k] for f in flow_list) for k in
              ("pkts", "bytes", "pkts_ab", "bytes_ab", "syn", "ack", "rst", "frame_bytes")}
    shared = {idx: b for idx, b in buckets.items() if len(b["flows"]) > 1}

    # What the collector sees per 1 s window from the first eligible packet: new flow
    # buckets (CPU reports, if no bucket is cleared) and active buckets (a packet
    # within the last TTL_WINDOWS + 1 windows).
    per_window = collections.defaultdict(set)
    first_window = {}
    t0 = pkt_times[0][0] if pkt_times else 0.0
    for t, idx in pkt_times:
        w = int(t - t0)
        per_window[w].add(idx)
        first_window.setdefault(idx, w)
    n_windows = (max(per_window) + 1) if per_window else 0
    new_per_window = collections.Counter(first_window.values())
    active = []
    for w in range(n_windows + TTL_WINDOWS):
        seen = set()
        for k in range(max(0, w - TTL_WINDOWS), w + 1):
            seen |= per_window.get(k, set())
        active.append(len(seen))
    data = Path(path).read_bytes()
    listed = len(flow_list) <= max_listed
    return {
        "source": {"file": Path(path).name, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)},
        "frames": frames,
        "packets": eligible,                       # IPv4 TCP/UDP first fragments: what the data plane counts
        "packets_int_side": int_side,              # packets whose source is in --internal-cidr
        "flow_count": len(flow_list),
        "flows_listed": listed,
        "flows": flow_list if listed else [],
        "newconn_dst": ([{"key": list(k), "dst_index": compute_newconn_dst_index(*k), "count": c}
                         for k, c in sorted(newconn.items())] if listed else []),
        "newconn_dst_summary": {"keys": len(newconn), "syn_without_ack": sum(newconn.values()),
                                "dst_buckets": len({compute_newconn_dst_index(*k) for k in newconn})},
        "totals": totals,
        "totals_bucket_model": {"pkts_ab": sum(b["pkts_ab"] for b in buckets.values()),
                                "bytes_ab": sum(b["bytes_ab"] for b in buckets.values())},
        "buckets": {"distinct": len(buckets), "shared": len(shared),
                    "flows_in_shared": sum(len(b["flows"]) for b in shared.values()),
                    "max_flows_in_one": max((len(b["flows"]) for b in buckets.values()), default=0)},
        "per_1s_window": {"windows": n_windows,
                          "new_buckets_max": max(new_per_window.values(), default=0),
                          "new_buckets_median": sorted(new_per_window[w] for w in range(n_windows))[n_windows // 2]
                          if n_windows else 0,
                          "active_buckets_max": max(active, default=0),
                          "active_buckets_median": sorted(active[:n_windows])[n_windows // 2] if n_windows else 0,
                          "ttl_windows": TTL_WINDOWS},
        "duration_s": (pkt_times[-1][0] - pkt_times[0][0]) if pkt_times else 0.0,
        "capture_duration_s": (t_last - t_first) if frames else 0.0,
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("pcap")
    ap.add_argument("--truth", required=True)
    ap.add_argument("--internal-cidr", default="10.0.0.10/32",
                    help="addresses whose packets count as the internal side (default: the lab guest)")
    ap.add_argument("--max-flows-listed", type=int, default=5000)
    args = ap.parse_args()
    truth = truth_of(args.pcap, ipaddress.ip_network(args.internal_cidr), args.max_flows_listed)
    Path(args.truth).write_text(json.dumps(truth, indent=1) + "\n")
    t, b, w = truth["totals"], truth["buckets"], truth["per_1s_window"]
    print("[OK] %s: %d frames, %d IPv4 TCP/UDP packets in %d flows over %.1f s; %d buckets (%d shared by %d flows); "
          "pkts %d, bytes %d, SYN %d, ACK %d, RST %d; per 1 s window up to %d new and %d active buckets -> %s"
          % (truth["source"]["file"], truth["frames"], truth["packets"], truth["flow_count"], truth["duration_s"],
             b["distinct"], b["shared"], b["flows_in_shared"], t["pkts"], t["bytes"], t["syn"], t["ack"], t["rst"],
             w["new_buckets_max"], w["active_buckets_max"], args.truth))


if __name__ == "__main__":
    main()
