#!/usr/bin/env python3
import argparse
import time
import ipaddress
from scapy.all import rdpcap, sendp, Ether, IP, TCP, UDP

# The bucket index as the data plane computes it (see flow_index.py).
from flow_index import compute_flow_index as compute_flow_index_symmetric


def extract_5tuple(pkt):
    if IP not in pkt:
        return None
    ip = pkt[IP]
    if TCP in pkt:
        t = pkt[TCP]
        return (ip.src, ip.dst, int(t.sport), int(t.dport), 6)
    if UDP in pkt:
        u = pkt[UDP]
        return (ip.src, ip.dst, int(u.sport), int(u.dport), 17)
    return None


def ensure_ether(pkt):
    return pkt if Ether in pkt else (Ether() / pkt)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap", required=True)
    ap.add_argument("--int-iface", default="veth1")
    ap.add_argument("--ext-iface", default="veth3")
    ap.add_argument("--internal-cidr", default="172.16.11.0/24")
    ap.add_argument("--limit", type=int, default=0, help="0=all, else first N packets")
    ap.add_argument("--interval", type=float, default=0.0)
    ap.add_argument("--index-file", default="indexes_unique.txt")
    ap.add_argument("--unique-only", action="store_true")
    args = ap.parse_args()

    internal_net = ipaddress.ip_network(args.internal_cidr, strict=False)

    pkts = rdpcap(args.pcap)
    total = len(pkts)
    n = total if args.limit == 0 else min(args.limit, total)

    print(f"\nLoaded {total} packets from {args.pcap}")
    print(f"Replaying {n} packets with split injection:")
    print(f"  internal src in {internal_net} -> {args.int_iface}")
    print(f"  external src               -> {args.ext_iface}\n")

    seen = set()
    indexes_out = []

    for i in range(n):
        pkt = ensure_ether(pkts[i])
        tup = extract_5tuple(pkt)

        if tup is None:
            sendp(pkt, iface=args.int_iface, count=1, verbose=False)
            if not args.unique_only:
                indexes_out.append("NA")
            if args.interval > 0:
                time.sleep(args.interval)
            continue

        src, dst, sport, dport, proto = tup
        idx = compute_flow_index_symmetric(src, dst, sport, dport, proto)

        try:
            src_ip = ipaddress.ip_address(src)
            iface = args.int_iface if (src_ip in internal_net) else args.ext_iface
        except Exception:
            iface = args.int_iface

        sendp(pkt, iface=iface, count=1, verbose=False)
        print(f"[{i+1}/{n}] via {iface:11s} {src}:{sport}->{dst}:{dport} proto={proto} idx={idx}")

        if args.unique_only:
            if idx not in seen:
                seen.add(idx)
                indexes_out.append(str(idx))
        else:
            indexes_out.append(str(idx))

        if args.interval > 0:
            time.sleep(args.interval)

    with open(args.index_file, "w") as f:
        for x in indexes_out:
            f.write(f"{x}\n")

    print(f"\nDone. Saved {len(indexes_out)} {'unique ' if args.unique_only else ''}indexes to {args.index_file}")


if __name__ == "__main__":
    main()

# sudo python3 replay_pcaps_with_index.py \
#   --pcap /home/ubuntu/Desktop/p4_ebpf/thesis-hybrid-ebpf-p4/pcaps/test.pcap \
#   --internal-cidr 172.16.11.0/24 \
#   --int-iface veth0 \
#   --ext-iface veth2 \
#   --limit 150 --unique-only \
#   --index-file /home/ubuntu/Desktop/p4_ebpf/thesis-hybrid-ebpf-p4/python/indexes_unique.txt