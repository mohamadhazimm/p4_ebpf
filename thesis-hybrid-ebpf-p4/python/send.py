#!/usr/bin/env python3
"""
send_packets.py — Send packets and predict flow_index from CRC16 hash.
Usage:
  sudo python3 send_packets.py --iface veth0 --mode udp --src-ip 10.0.0.1 --dst-ip 10.0.0.2 --sport 5555 --dport 9999
  sudo python3 send_packets.py --iface veth0 --mode tcp --src-ip 10.0.0.1 --dst-ip 10.0.0.2 --sport 12345 --dport 443 --flags S --count 5
"""
import argparse
from scapy.all import Ether, IP, TCP, UDP, sendp

# The bucket index as the data plane computes it: CRC-16/ARC over the
# @symmetric input (see flow_index.py), the same for both directions.
from flow_index import compute_flow_index


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iface",     default="veth0")
    ap.add_argument("--mode",      choices=["udp", "tcp"], required=True)
    ap.add_argument("--src-ip",    default="10.0.0.1")
    ap.add_argument("--dst-ip",    default="10.0.0.2")
    ap.add_argument("--sport",     type=int, default=12345)
    ap.add_argument("--dport",     type=int, default=443)
    ap.add_argument("--count",     type=int, default=1)
    ap.add_argument("--interval",  type=float, default=0.0)
    ap.add_argument("--flags",     default="S", help="TCP flags (e.g. S, A, FA, R)")
    args = ap.parse_args()

    proto = 17 if args.mode == "udp" else 6
    idx   = compute_flow_index(args.src_ip, args.dst_ip, args.sport, args.dport, proto)

    print("=== Flow index prediction ===")
    print(f"  iface      : {args.iface}")
    print(f"  5-tuple    : {args.src_ip}:{args.sport} → {args.dst_ip}:{args.dport}  proto={proto}")
    print(f"  flow_index : {idx}  (0x{idx:04X})")
    print("=============================")

    if args.mode == "udp":
        pkt = Ether() / IP(src=args.src_ip, dst=args.dst_ip) / UDP(sport=args.sport, dport=args.dport)
    else:
        pkt = Ether() / IP(src=args.src_ip, dst=args.dst_ip) / TCP(sport=args.sport, dport=args.dport, flags=args.flags)

    sendp(pkt, iface=args.iface, count=args.count, inter=args.interval, verbose=False)
    print(f"Sent {args.count} packet(s).")


if __name__ == "__main__":
    main()

#sudo python3 send.py --iface veth0 --mode udp --sport 5555 --dport 9999 --count 1
#sudo python3 .py --mode tcp --sport 12346 --dport 443