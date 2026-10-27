#!/usr/bin/env python3
"""Hardware test of reg_newconn_dst, the new connections per destination.

    newconn_test.py make  OUT_DIR [--index-bits 16]
    newconn_test.py check OUT_DIR/newconn_expected.json REPORTS_PCAP READ_JSON [--out RESULT_JSON]

make writes OUT_DIR/newconn_test.pcap and newconn_expected.json. Per destination
key (client, server, server port, protocol) the pcap holds:
  flood     40 handshakes 10.99.6.1 -> 10.99.6.2:80, a new source port each
            (SYN, SYN+ACK back, ACK)                          -> 40
  retrans   one SYN sent 3 times (same source port)           -> 3
  ecn       2 SYNs with ECE and CWR set (ECN setup)            -> 2
  port8080  5 SYNs from the flood client to port 8080         -> 5
  synfin    1 SYN+FIN                                         -> 1
  reverse   the key of the flood's SYN+ACKs (server -> client) -> 0
  no_syn    ACK, FIN+ACK and RST only                         -> 0
  udp       UDP packets, keyed with protocol 17 (TCP only)    -> 0
In the flow bucket of the first flood handshake it also expects reg_pkts = 3
and reg_syn = 2: reg_syn keeps counting the SYN+ACK. All frames come from PC1
to a MAC and addresses PC2 does not own. --index-bits 14 is for a build with
16,384 destination buckets (the low 14 bits of the same CRC).

check compares the CPU reports captured on enp5s0, and the JSON payload of
`read_registers_with_index.py --format json --indexes FLOW --dst-indexes DST`
(pipe 1 holds the test ports), with the expectation. It also checks that the
destination buckets the collector derives from the reports cover every key
with a non-zero count.
"""
import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(HERE)), "thesis-hybrid-ebpf-p4", "python"))
from flow_index import compute_flow_index, compute_newconn_dst_index  # noqa: E402

SRC_MAC, DST_MAC = "04:3f:72:d2:ec:5e", "02:00:00:00:00:02"
PIPE = 1
CLIENT, SERVER = "10.99.6.1", "10.99.6.2"


def make(out_dir, index_bits):
    from scapy.all import IP, TCP, UDP, Ether, Raw, wrpcap
    mask = (1 << index_bits) - 1

    def tcp(s, d, sp, dp, flags):
        return Ether(src=SRC_MAC, dst=DST_MAC) / IP(src=s, dst=d) / TCP(sport=sp, dport=dp, flags=flags) / Raw(b"\0" * 6)

    def udp(s, d, sp, dp):
        return Ether(src=SRC_MAC, dst=DST_MAC) / IP(src=s, dst=d) / UDP(sport=sp, dport=dp) / Raw(b"\0" * 18)

    pkts = []
    for i in range(40):
        sp = 30000 + i
        pkts += [tcp(CLIENT, SERVER, sp, 80, "S"), tcp(SERVER, CLIENT, 80, sp, "SA"), tcp(CLIENT, SERVER, sp, 80, "A")]
    pkts += [tcp("10.99.6.3", SERVER, 41000, 443, "S") for _ in range(3)]
    pkts += [tcp("10.99.6.4", SERVER, 41001 + k, 443, "SEC") for k in range(2)]
    pkts += [tcp(CLIENT, SERVER, 42000 + k, 8080, "S") for k in range(5)]
    pkts += [tcp("10.99.6.7", SERVER, 43000, 22, "SF")]
    pkts += [tcp("10.99.6.5", SERVER, 44000, 80, "A") for _ in range(10)]
    pkts += [tcp("10.99.6.5", SERVER, 44000, 80, "FA") for _ in range(2)] + [tcp("10.99.6.5", SERVER, 44000, 80, "R")]
    pkts += [udp("10.99.6.6", SERVER, 45000, 80) for _ in range(10)]

    keys = {  # name -> ((client, server, server port, protocol), expected count)
        "flood": ((CLIENT, SERVER, 80, 6), 40),
        "retrans": (("10.99.6.3", SERVER, 443, 6), 3),
        "ecn": (("10.99.6.4", SERVER, 443, 6), 2),
        "port8080": ((CLIENT, SERVER, 8080, 6), 5),
        "synfin": (("10.99.6.7", SERVER, 22, 6), 1),
        "reverse": ((SERVER, CLIENT, 30000, 6), 0),
        "no_syn": (("10.99.6.5", SERVER, 80, 6), 0),
        "udp": (("10.99.6.6", SERVER, 80, 17), 0),
    }
    dst = {name: compute_newconn_dst_index(*key) & mask for name, (key, _) in keys.items()}
    assert len(set(dst.values())) == len(dst), dst

    # One report per distinct flow bucket, sent by the bucket's first packet.
    def five(p):
        l4 = p[TCP] if p.haslayer(TCP) else p[UDP]
        return (p[IP].src, p[IP].dst, l4.sport, l4.dport, p[IP].proto)
    reports, seen = [], set()
    for p in pkts:
        t = five(p)
        b = compute_flow_index(*t)
        if b not in seen:
            seen.add(b)
            reports.append([1, list(t)])
    first = (CLIENT, SERVER, 30000, 80, 6)
    b_first = compute_flow_index(*first)
    assert sum(compute_flow_index(*five(p)) == b_first for p in pkts) == 3

    os.makedirs(out_dir, exist_ok=True)
    wrpcap(os.path.join(out_dir, "newconn_test.pcap"), pkts)
    exp = {
        "index_bits": index_bits,
        "packets": len(pkts),
        "keys": {name: {"key": list(key), "dst_index": dst[name], "new_conn": n} for name, (key, n) in keys.items()},
        "reports": reports,
        "flow_buckets": {str(b_first): {"pkts": 3, "syn": 2, "ack": 2, "rst": 0}},
    }
    json.dump(exp, open(os.path.join(out_dir, "newconn_expected.json"), "w"), indent=2)
    print("%d packets, %d reports due; destination buckets: %s" % (len(pkts), len(reports), dst))
    print("flow buckets to read: %d" % b_first)
    print("destination buckets to read: %s" % ",".join(str(dst[k]) for k in keys))


def check(exp_path, reports_pcap, read_json, out_path):
    from listen_cpu_reports import iter_pcap_stream, parse_cpu_report
    exp = json.load(open(exp_path))
    mask = (1 << exp["index_bits"]) - 1
    results = []

    def ok(name, cond, detail):
        results.append({"check": name, "pass": bool(cond), "detail": detail})
        print("%s  %s: %s" % ("PASS" if cond else "FAIL", name, detail))

    reps = [r for r in (parse_cpu_report(f) for _, f in iter_pcap_stream(open(reports_pcap, "rb"))) if r]
    got = [[r["reason"], [r["src_ip"], r["dst_ip"], r["sport"], r["dport"], r["proto"]]] for r in reps]
    ok("reports", got == exp["reports"], "%d received, %d expected" % (len(got), len(exp["reports"])))
    # What the collector does: one destination bucket per TCP report.
    derived = {compute_newconn_dst_index(r["src_ip"], r["dst_ip"], r["dport"], r["proto"]) & mask
               for r in reps if r["proto"] == 6}
    wanted = {k["dst_index"] for k in exp["keys"].values() if k["new_conn"]}
    ok("report-derived destination buckets cover every counted key", wanted <= derived,
       "missing %s" % sorted(wanted - derived))

    payload = None
    for line in open(read_json):
        line = line.strip()
        if line.startswith("{") and '"rows"' in line:
            payload = json.loads(line)
    ok("read without errors", payload is not None and not payload["errors"],
       payload["errors"] if payload else "no payload")
    dst_rows = {r["idx"]: r for r in (payload or {}).get("dst_rows", [])}
    for name, k in exp["keys"].items():
        row = dst_rows.get(k["dst_index"], {})
        pipes = [PIPE] if k["new_conn"] else []
        ok("reg_newconn_dst %s [%d]" % (name, k["dst_index"]),
           row.get("new_conn") == k["new_conn"] and row.get("pipes") == pipes,
           "hardware %s in pipes %s, expected %d in %s" % (row.get("new_conn"), row.get("pipes"), k["new_conn"], pipes))
    rows = {str(r["idx"]): r for r in (payload or {}).get("rows", [])}
    for bucket, want in exp["flow_buckets"].items():
        row = rows.get(bucket, {})
        ok("flow bucket %s" % bucket, all(row.get(f) == v for f, v in want.items()) and row.get("pipes") == [PIPE],
           "hardware %s in pipes %s, expected %s" % ({f: row.get(f) for f in want}, row.get("pipes"), want))
    passed = sum(r["pass"] for r in results)
    print("%d/%d checks passed" % (passed, len(results)))
    if out_path:
        json.dump({"passed": passed, "total": len(results), "checks": results}, open(out_path, "w"), indent=2)
    return passed == len(results)


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("make")
    p.add_argument("out_dir")
    p.add_argument("--index-bits", type=int, default=16)
    p = sub.add_parser("check")
    p.add_argument("expected")
    p.add_argument("reports_pcap")
    p.add_argument("read_json")
    p.add_argument("--out")
    a = ap.parse_args()
    if a.cmd == "make":
        make(a.out_dir, a.index_bits)
    else:
        sys.exit(0 if check(a.expected, a.reports_pcap, a.read_json, a.out) else 1)


if __name__ == "__main__":
    main()
