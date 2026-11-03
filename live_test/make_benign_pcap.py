#!/usr/bin/env python3
"""Synthetic benign traffic with exact ground truth, for replay through the P4 model.

    make_benign_pcap.py --out benign.pcap --truth benign_truth.json [--seed 7] [--sessions 60]

Internal clients 172.16.11.10-12 (inside the collector's default
--internal-cidr 172.16.11.0/24) talk to services in the documentation ranges
198.51.100.0/24 and 203.0.113.0/24:

  * HTTP (TCP 80): three-way handshake, a request, a response of 1-12
    MSS-sized segments with ACKs, FIN teardown
  * DNS (UDP 53): query and answer
  * NTP (UDP 123 -> 123): request and answer. Source and destination port are
    equal, which the data plane's port-based direction check cannot split
  * a connection attempt to a closed port (TCP 8443) answered by RST+ACK

Every packet fits a 1500-byte MTU (MSS 1460). No two flows share a register
bucket (flow_index.compute_flow_index) and no two new-connection keys share a
reg_newconn_dst bucket, so every register can be checked exactly.

The truth file lists, per flow, what the data plane must count: packets, bytes
as IPv4 totalLen (L3, what ingress.p4 adds), the same split by the direction of
the flow's first packet ("ab"), min/max totalLen, and the TCP SYN/ACK/RST
counts; plus SYN-without-ACK counts per reg_newconn_dst key and the L2 (frame)
byte totals.
"""
import argparse
import ipaddress
import json
import random
import sys
from pathlib import Path

from scapy.all import IP, TCP, UDP, Ether, Raw, wrpcap

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "thesis-hybrid-ebpf-p4" / "python"))
from flow_index import compute_flow_index, compute_newconn_dst_index  # noqa: E402

MSS = 1460
CLIENTS = ["172.16.11.10", "172.16.11.11", "172.16.11.12"]
HTTP_SERVERS = ["198.51.100.10", "198.51.100.11", "203.0.113.80"]
DNS_SERVER = "198.51.100.53"
NTP_SERVER = "203.0.113.123"
CLOSED_HOST = "203.0.113.20"
INTERNAL = ipaddress.ip_network("172.16.11.0/24")


def mac_for(ip: str) -> str:
    a, b, c, d = (int(x) for x in ip.split("."))
    return "02:%02x:%02x:%02x:%02x:%02x" % (0x10 if ipaddress.ip_address(ip) in INTERNAL else 0x20, a, b, c, d)


class Builder:
    def __init__(self, seed: int):
        self.rng = random.Random(seed)
        self.t = 1_700_000_000.0
        self.packets = []
        self.flows = {}          # canonical key -> truth
        self.used_buckets = {}
        self.used_dst_buckets = {}
        self.newconn = {}        # (src, dst, dport, proto) -> count
        self.ip_id = 1

    def free_port(self, client, server, dport, proto):
        """An ephemeral port whose flow and new-connection buckets are unused."""
        for _ in range(10000):
            sport = self.rng.randint(32768, 60999)
            idx = compute_flow_index(client, server, sport, dport, proto)
            if idx in self.used_buckets:
                continue
            if proto == 6:
                ndx = compute_newconn_dst_index(client, server, dport, proto)
                owner = self.used_dst_buckets.get(ndx)
                if owner is not None and owner != (client, server, dport, proto):
                    continue
            return sport
        raise RuntimeError("no free bucket")

    def claim(self, src, dst, sport, dport, proto):
        idx = compute_flow_index(src, dst, sport, dport, proto)
        key = (proto,) + tuple(sorted(((src, sport), (dst, dport))))
        if idx in self.used_buckets and self.used_buckets[idx] != key:
            raise RuntimeError("bucket collision")
        self.used_buckets[idx] = key
        if proto == 6:
            ndx = compute_newconn_dst_index(src, dst, dport, proto)
            self.used_dst_buckets.setdefault(ndx, (src, dst, dport, proto))

    def emit(self, src, dst, l4, payload_len=0, gap=0.002):
        self.t += gap
        ip = IP(src=src, dst=dst, ttl=64, id=self.ip_id & 0xFFFF)
        self.ip_id += 1
        pkt = Ether(src=mac_for(src), dst=mac_for(dst)) / ip / l4
        if payload_len:
            pkt = pkt / Raw(bytes(self.rng.getrandbits(8) for _ in range(payload_len)))
        pkt = Ether(bytes(pkt))          # fill in lengths and checksums
        pkt.time = self.t
        self.packets.append(pkt)

        proto = pkt[IP].proto
        sport, dport = int(pkt[IP].payload.sport), int(pkt[IP].payload.dport)
        key = (proto,) + tuple(sorted(((src, sport), (dst, dport))))
        tot = int(pkt[IP].len)
        f = self.flows.get(key)
        if f is None:
            f = self.flows[key] = {
                "first": [src, dst, sport, dport, proto],
                "flow_index": compute_flow_index(src, dst, sport, dport, proto),
                "pkts": 0, "bytes": 0, "pkts_ab": 0, "bytes_ab": 0,
                "min_len": tot, "max_len": tot, "syn": 0, "ack": 0, "rst": 0,
                "frame_bytes": 0, "first_t": self.t, "last_t": self.t,
                "inject_side_first": "int" if ipaddress.ip_address(src) in INTERNAL else "ext",
            }
        f["pkts"] += 1
        f["bytes"] += tot
        f["frame_bytes"] += len(bytes(pkt))
        # The data plane's direction: ports equal to the reference ports of the
        # first packet count as "ab" (ingress.p4 compares ports only).
        ref_sp, ref_dp = f["first"][2], f["first"][3]
        if (sport == ref_sp and dport == ref_dp) or not (sport == ref_dp and dport == ref_sp):
            f["pkts_ab"] += 1
            f["bytes_ab"] += tot
        # The offline extractor's direction: (src IP, src port) of the first packet.
        if (src, sport) == (f["first"][0], f["first"][2]):
            f["pkts_ab_ip"] = f.get("pkts_ab_ip", 0) + 1
            f["bytes_ab_ip"] = f.get("bytes_ab_ip", 0) + tot
        f["min_len"] = min(f["min_len"], tot)
        f["max_len"] = max(f["max_len"], tot)
        f["last_t"] = self.t
        if proto == 6:
            flags = int(pkt[TCP].flags)
            f["syn"] += int(bool(flags & 0x02))
            f["ack"] += int(bool(flags & 0x10))
            f["rst"] += int(bool(flags & 0x04))
            if flags & 0x12 == 0x02:
                nk = (src, dst, dport, proto)
                self.newconn[nk] = self.newconn.get(nk, 0) + 1

    # ---------------------------------------------------------------- sessions
    def http(self, client):
        server = self.rng.choice(HTTP_SERVERS)
        sport = self.free_port(client, server, 80, 6)
        self.claim(client, server, sport, 80, 6)
        cs, ss = self.rng.getrandbits(32), self.rng.getrandbits(32)
        c2s = lambda flags, n=0, **kw: self.emit(client, server, TCP(sport=sport, dport=80, flags=flags,
                                                                       seq=cs, ack=ss, window=64240), n, **kw)
        s2c = lambda flags, n=0, **kw: self.emit(server, client, TCP(sport=80, dport=sport, flags=flags,
                                                                       seq=ss, ack=cs, window=65160), n, **kw)
        rtt = self.rng.uniform(0.004, 0.030)
        self.emit(client, server, TCP(sport=sport, dport=80, flags="S", seq=cs, window=64240),
                  gap=self.rng.uniform(0.05, 0.6))
        cs += 1
        self.emit(server, client, TCP(sport=80, dport=sport, flags="SA", seq=ss, ack=cs, window=65160), gap=rtt)
        ss += 1
        c2s("A", gap=0.0005)
        req = self.rng.randint(90, 600)
        c2s("PA", req, gap=0.0005)
        cs += req
        segments = self.rng.randint(1, 12)
        for k in range(segments):
            n = MSS if k < segments - 1 else self.rng.randint(80, MSS)
            s2c("PA" if k == segments - 1 else "A", n, gap=rtt if k == 0 else 0.0004)
            ss += n
            if k % 2 == 1 or k == segments - 1:
                c2s("A", gap=0.0003)
        c2s("FA", gap=self.rng.uniform(0.01, 0.2))
        cs += 1
        s2c("FA", gap=rtt)
        ss += 1
        c2s("A", gap=rtt / 2)

    def dns(self, client):
        sport = self.free_port(client, DNS_SERVER, 53, 17)
        self.claim(client, DNS_SERVER, sport, 53, 17)
        self.emit(client, DNS_SERVER, UDP(sport=sport, dport=53), self.rng.randint(28, 60),
                  gap=self.rng.uniform(0.05, 0.4))
        self.emit(DNS_SERVER, client, UDP(sport=53, dport=sport), self.rng.randint(60, 220),
                  gap=self.rng.uniform(0.002, 0.02))

    def ntp(self, client):
        self.claim(client, NTP_SERVER, 123, 123, 17)
        self.emit(client, NTP_SERVER, UDP(sport=123, dport=123), 48, gap=self.rng.uniform(0.05, 0.4))
        self.emit(NTP_SERVER, client, UDP(sport=123, dport=123), 48, gap=self.rng.uniform(0.005, 0.03))

    def closed_port(self, client):
        sport = self.free_port(client, CLOSED_HOST, 8443, 6)
        self.claim(client, CLOSED_HOST, sport, 8443, 6)
        seq = self.rng.getrandbits(32)
        self.emit(client, CLOSED_HOST, TCP(sport=sport, dport=8443, flags="S", seq=seq, window=64240),
                  gap=self.rng.uniform(0.05, 0.4))
        self.emit(CLOSED_HOST, client, TCP(sport=8443, dport=sport, flags="RA", seq=0, ack=seq + 1, window=0),
                  gap=self.rng.uniform(0.001, 0.01))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--truth", required=True)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--sessions", type=int, default=60, help="HTTP sessions (DNS/NTP/RST added around them)")
    args = ap.parse_args()

    b = Builder(args.seed)
    b.ntp(CLIENTS[0])
    for i in range(args.sessions):
        client = CLIENTS[i % len(CLIENTS)]
        if i % 3 == 0:
            b.dns(client)
        b.http(client)
        if i % 20 == 7:
            b.closed_port(client)

    wrpcap(args.out, b.packets)
    flows = []
    for key, f in sorted(b.flows.items(), key=lambda kv: kv[1]["first_t"]):
        f = dict(f)
        f["pkts_ba"] = f["pkts"] - f["pkts_ab"]
        f["bytes_ba"] = f["bytes"] - f["bytes_ab"]
        flows.append(f)
    newconn = [{"key": list(k), "dst_index": compute_newconn_dst_index(*k), "count": c}
               for k, c in sorted(b.newconn.items())]
    truth = {
        "seed": args.seed,
        "packets": len(b.packets),
        "packets_int_side": sum(1 for p in b.packets if ipaddress.ip_address(p[IP].src) in INTERNAL),
        "flows": flows,
        "newconn_dst": newconn,
        "totals": {k: sum(f[k] for f in flows) for k in
                   ("pkts", "bytes", "pkts_ab", "bytes_ab", "syn", "ack", "rst", "frame_bytes")},
        "duration_s": b.packets[-1].time - b.packets[0].time,
    }
    Path(args.truth).write_text(json.dumps(truth, indent=1))
    print(f"[OK] {len(b.packets)} packets, {len(flows)} flows, {sum(c for c in b.newconn.values())} "
          f"new connections in {len(newconn)} destination buckets -> {args.out}")


if __name__ == "__main__":
    main()
