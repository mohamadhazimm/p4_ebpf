#!/usr/bin/env python3
"""Build the register-fill traffic for the readout tests (Phase 3.1-3.2).

    make_fill_pcap.py OUT_DIR [--flows 30000] [--seed 1]

FLOWS distinct UDP flows from PC1 (source 10.100.0.0 + i, destination
10.101.0.1, varied ports), flow i sending 1 + (i % 4) packets of 64 B on the wire.
Packets are interleaved round by round, so a flow's packets are spread out.
expected.json gives, for every bucket the compiled hash (CRC-16/ARC over the
raw 5-tuple, Phase 1) selects, what the detector's registers must then hold:
reg_pkts, reg_bytes (pkts x IPv4 totalLen), reg_pkts_ab (= pkts: one direction
only, and the collision fallback also counts as A->B), reg_min_len =
reg_max_len = totalLen, reg_dir_valid = 1, the reference ports of the first
packet that reached the bucket, and the number of flows sharing it.
"""
import argparse
import json
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from hash_matrix_check import crc16_arc  # noqa: E402

from scapy.all import Ether, IP, UDP, Raw, PcapWriter  # noqa: E402

SRC_MAC, DST_MAC = "04:3f:72:d2:ec:5e", "02:00:00:00:00:02"
SIP0 = (10 << 24) | (100 << 16)
DIP = "10.101.0.1"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("out_dir")
    ap.add_argument("--flows", type=int, default=30000)
    a = ap.parse_args()
    os.makedirs(a.out_dir, exist_ok=True)
    dip_int = struct.unpack("!I", bytes(int(x) for x in DIP.split(".")))[0]
    flows = []
    for i in range(a.flows):
        sip = SIP0 + i
        sp, dp = 40000 + (i % 20000), 5000 + (i % 13)
        idx = crc16_arc(struct.pack("!IIHHB", sip, dip_int, sp, dp, 17))
        flows.append({"i": i, "sip": sip, "sp": sp, "dp": dp, "pkts": 1 + (i % 4), "bucket": idx})
    template = Ether(bytes(Ether(src=SRC_MAC, dst=DST_MAC) / IP(src="0.0.0.0", dst=DIP, ttl=64) /
                           UDP(sport=0, dport=0) / Raw(b"\x00" * 18)))
    total_len = template[IP].len
    buckets = {}
    w = PcapWriter(os.path.join(a.out_dir, "fill.pcap"), sync=False)
    n = 0
    for rnd in range(4):
        for f in flows:
            if f["pkts"] <= rnd:
                continue
            ip_s = "%d.%d.%d.%d" % tuple(struct.pack("!I", f["sip"]))
            pkt = Ether(src=SRC_MAC, dst=DST_MAC) / IP(src=ip_s, dst=DIP, ttl=64) / \
                UDP(sport=f["sp"], dport=f["dp"]) / Raw(b"\x00" * 18)
            w.write(pkt)
            n += 1
            b = buckets.setdefault(f["bucket"], {"reg_pkts": 0, "flows": set(),
                                                 "reg_ref_src_port": f["sp"],
                                                 "reg_ref_dst_port": f["dp"]})
            b["reg_pkts"] += 1
            b["flows"].add(f["i"])
    w.close()
    exp = {}
    for idx, b in buckets.items():
        exp[str(idx)] = {"reg_pkts": b["reg_pkts"], "reg_bytes": b["reg_pkts"] * total_len,
                         "reg_pkts_ab": b["reg_pkts"], "reg_bytes_ab": b["reg_pkts"] * total_len,
                         "reg_min_len": total_len, "reg_max_len": total_len, "reg_dir_valid": 1,
                         "reg_ref_src_port": b["reg_ref_src_port"],
                         "reg_ref_dst_port": b["reg_ref_dst_port"],
                         "reg_syn": 0, "reg_ack": 0, "reg_rst": 0, "flows": len(b["flows"])}
    shared = sum(len(b["flows"]) for b in buckets.values() if len(b["flows"]) > 1)
    info = {"flows": a.flows, "packets": n, "ipv4_total_len": total_len,
            "buckets_used": len(buckets), "flows_sharing_a_bucket": shared,
            "flows_sharing_fraction": shared / a.flows}
    json.dump({"info": info, "buckets": exp}, open(os.path.join(a.out_dir, "fill_expected.json"), "w"))
    print(json.dumps(info))


if __name__ == "__main__":
    main()
