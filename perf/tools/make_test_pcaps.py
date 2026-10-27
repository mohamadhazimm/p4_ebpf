#!/usr/bin/env python3
"""Build the Phase 2 test pcaps and the register values they should produce.

    make_test_pcaps.py portmap OUT_DIR [--count 1000] [--frame 128]
    make_test_pcaps.py sanity  OUT_DIR

portmap: COUNT identical UDP frames of FRAME bytes on the wire (FCS included,
so the pcap frame is FRAME - 4 bytes), for matching switch port counters with
PC1's NIC counters.

sanity: one TCP connection of 100 packets in both directions (handshake, data
with varied lengths, FIN, RST), all sent from PC1. expected.json gives, for
every register, the value each bucket should hold under three index models:
  compiled  CRC-16/ARC over the raw 5-tuple: what bf-p4c 9.6.0 built (Phase 1)
  collector compute_flow_index_symmetric() of listen_cpu_reports.py
  symfix    CRC-16/ARC over (0, sip^dip, 0, sp^dp, proto): the @symmetric variant
The register semantics follow ingress.p4: pkt_len is the IPv4 totalLen; the
first packet seen in a bucket stores its ports as the reference direction.
Addresses are test-only (10.99.0.0/16) and the destination MAC is locally
administered, so PC2 neither owns nor answers any of these packets.
"""
import argparse
import json
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from hash_matrix_check import crc16_arc, crc16_tofino_collector  # noqa: E402

from scapy.all import Ether, IP, TCP, UDP, Raw, wrpcap  # noqa: E402

SRC_MAC = "04:3f:72:d2:ec:5e"   # PC1 eth1
DST_MAC = "02:00:00:00:00:02"   # locally administered; not PC2's MAC
FLAG_BITS = {"F": 0x001, "S": 0x002, "R": 0x004, "P": 0x008, "A": 0x010}
TS_MASK = 0xFFFFFFFF


def ip2int(ip):
    return struct.unpack("!I", bytes(int(x) for x in ip.split(".")))[0]


def index_models(sip, dip, sp, dp, pr):
    a, b = ip2int(sip), ip2int(dip)
    raw = struct.pack("!IIHHB", a, b, sp, dp, pr)
    sym = struct.pack("!IIHHB", a ^ b, (a + b) & 0xFFFFFFFF, sp ^ dp, (sp + dp) & 0xFFFF, pr)
    fix = struct.pack("!IIHHB", 0, a ^ b, 0, sp ^ dp, pr)
    return {"compiled": crc16_arc(raw), "collector": crc16_tofino_collector(sym),
            "symfix": crc16_arc(fix)}


def simulate(packets, model):
    """Register contents per bucket after the packets, under one index model."""
    buckets = {}
    for p in packets:
        idx = index_models(p["sip"], p["dip"], p["sp"], p["dp"], 6)[model]
        b = buckets.setdefault(idx, None)
        L = p["total_len"]
        if b is None:
            b = buckets[idx] = {"reg_dir_valid": 1, "reg_ref_src_port": p["sp"],
                                "reg_ref_dst_port": p["dp"], "reg_pkts": 0, "reg_bytes": 0,
                                "reg_pkts_ab": 0, "reg_bytes_ab": 0, "reg_min_len": 0,
                                "reg_max_len": 0, "reg_syn": 0, "reg_ack": 0, "reg_rst": 0,
                                "n_dir_ba": 0, "first_pkt": p["n"]}
            ab = True
        else:
            if (p["sp"], p["dp"]) == (b["reg_ref_src_port"], b["reg_ref_dst_port"]):
                ab = True
            elif (p["sp"], p["dp"]) == (b["reg_ref_dst_port"], b["reg_ref_src_port"]):
                ab = False
            else:
                ab = True       # collision fallback in ingress.p4
        b["reg_pkts"] += 1
        b["reg_bytes"] += L
        if ab:
            b["reg_pkts_ab"] += 1
            b["reg_bytes_ab"] += L
        else:
            b["n_dir_ba"] += 1
        if b["reg_min_len"] == 0 or L < b["reg_min_len"]:
            b["reg_min_len"] = L
        b["reg_max_len"] = max(b["reg_max_len"], L)
        f = p["flags_value"]
        b["reg_syn"] += 1 if f & 0x002 else 0
        b["reg_rst"] += 1 if f & 0x004 else 0
        b["reg_ack"] += 1 if f & 0x010 else 0
        b["last_pkt"] = p["n"]
    return {str(k): v for k, v in sorted(buckets.items())}


def sanity_packets():
    A, B, SP, DP = "10.99.0.1", "10.99.0.2", 40001, 5001
    sizes = [0, 1, 100, 500, 1000, 1460]
    seq = [("AB", "S", 0), ("BA", "SA", 0), ("AB", "A", 0)]
    for i in range(92):
        if i % 2 == 0:
            seq.append(("AB", "PA", sizes[(i // 2) % len(sizes)]))
        else:
            seq.append(("BA", "A", (i * 7) % 300))
    seq += [("AB", "FA", 0), ("BA", "FA", 0), ("AB", "A", 0), ("BA", "RA", 0), ("AB", "R", 0)]
    assert len(seq) == 100
    pkts, meta = [], []
    for n, (d, flags, plen) in enumerate(seq):
        sip, dip, sp, dp = (A, B, SP, DP) if d == "AB" else (B, A, DP, SP)
        pkt = (Ether(src=SRC_MAC, dst=DST_MAC) / IP(src=sip, dst=dip, ttl=64) /
               TCP(sport=sp, dport=dp, flags=flags, seq=1000 + n, ack=2000 + n, window=8192))
        if plen:
            pkt = pkt / Raw(bytes((n + k) & 0xFF for k in range(plen)))
        pkt = Ether(bytes(pkt))  # freeze lengths and checksums
        pkts.append(pkt)
        meta.append({"n": n, "dir": d, "sip": sip, "dip": dip, "sp": sp, "dp": dp,
                     "flags": flags, "flags_value": sum(FLAG_BITS[c] for c in flags),
                     "payload": plen, "total_len": pkt[IP].len, "frame_len": len(pkt)})
    return pkts, meta


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("kind", choices=["portmap", "sanity"])
    ap.add_argument("out_dir")
    ap.add_argument("--count", type=int, default=1000)
    ap.add_argument("--frame", type=int, default=128, help="wire size incl. FCS")
    a = ap.parse_args()
    os.makedirs(a.out_dir, exist_ok=True)

    if a.kind == "portmap":
        sip, dip, sp, dp = "10.99.1.1", "10.99.1.2", 30000, 30001
        base = Ether(src=SRC_MAC, dst=DST_MAC) / IP(src=sip, dst=dip, ttl=64) / UDP(sport=sp, dport=dp)
        pad = a.frame - 4 - len(base)
        pkt = Ether(bytes(base / Raw(b"\x00" * pad)))
        wrpcap(os.path.join(a.out_dir, "portmap.pcap"), [pkt] * a.count)
        info = {"count": a.count, "wire_frame_bytes": a.frame, "pcap_frame_bytes": len(pkt),
                "tuple": [sip, dip, sp, dp, 17], "index": index_models(sip, dip, sp, dp, 17)}
        json.dump(info, open(os.path.join(a.out_dir, "portmap.json"), "w"), indent=2)
        print(json.dumps(info))
        return

    pkts, meta = sanity_packets()
    wrpcap(os.path.join(a.out_dir, "sanity.pcap"), pkts)
    exp = {"packets": meta, "models": {}}
    for model in ("compiled", "collector", "symfix"):
        exp["models"][model] = simulate(meta, model)
    ab = index_models("10.99.0.1", "10.99.0.2", 40001, 5001, 6)
    ba = index_models("10.99.0.2", "10.99.0.1", 5001, 40001, 6)
    exp["indices"] = {"A_to_B": ab, "B_to_A": ba}
    exp["note"] = ("first_ts/last_ts are not predicted; they must be non-zero with "
                   "last_ts - first_ts (mod 2^32 ns) close to the send time between the "
                   "bucket's first and last packet at the replay rate")
    json.dump(exp, open(os.path.join(a.out_dir, "expected.json"), "w"), indent=2)
    for model, buckets in exp["models"].items():
        summary = {k: {f: v[f] for f in ("reg_pkts", "reg_pkts_ab", "reg_bytes", "reg_syn",
                                          "reg_ack", "reg_rst", "reg_min_len", "reg_max_len")}
                   for k, v in buckets.items()}
        print(model, json.dumps(summary))
    print("indices A->B:", ab, " B->A:", ba)


if __name__ == "__main__":
    main()
