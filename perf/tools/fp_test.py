#!/usr/bin/env python3
"""Hardware test of the flow-fingerprint variant (perf/variants/fingerprint).

    fp_test.py make  OUT_DIR SANITY_PCAP
    fp_test.py check OUT_DIR/fp_expected.json REPORTS_PCAP READ_REGS_JSON [--out RESULT_JSON]

make writes OUT_DIR/fp_test.pcap and fp_expected.json. The pcap is, in order:
  owner    the Phase 2.1 test connection (SANITY_PCAP, 100 packets, both directions)
  collide1 a UDP flow between the same hosts, ports chosen so that it lands in
           the owner's bucket                     -> collision report (reason 2)
  collide2 another such flow                       -> nothing (bucket already shared)
  xor_own  a TCP flow, both directions             -> new-flow report (reason 1)
  xor_evil both ports XOR-shifted by the same mask, i.e. equal sip^dip and sp^dp:
           same bucket, different fingerprint      -> collision report (reason 2)
  control  a UDP flow, both directions             -> new-flow report, never shared
All frames come from PC1 to a MAC and addresses PC2 does not own.

check compares the CPU reports captured on enp5s0 and the registers read with
`bfrt_gen.py read-regs --extra-registers reg_fp,reg_shared` (pipe 1 holds the
test ports) with the expectation.
"""
import argparse
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(HERE)), "thesis-hybrid-ebpf-p4", "python"))
from flow_index import compute_flow_index, ip_to_u32  # noqa: E402
from hash_quality import reflected_crc16  # noqa: E402

SRC_MAC, DST_MAC = "04:3f:72:d2:ec:5e", "02:00:00:00:00:02"
PIPE = 1
crc_fp = reflected_crc16(0x8BB7)


def fingerprint(sip, dip, sp, dp, pr):
    return crc_fp(struct.pack("!IIHHB", ip_to_u32(sip), ip_to_u32(dip), sp, dp, pr))


def port_for_bucket(sip, dip, dport, pr, bucket):
    """The one source port that puts (sip, sport, dip, dport, pr) into bucket."""
    hits = [sp for sp in range(65536) if compute_flow_index(sip, dip, sp, dport, pr) == bucket]
    assert len(hits) == 1, hits
    return hits[0]


def make(out_dir, sanity_pcap):
    from scapy.all import IP, TCP, UDP, Ether, Raw, rdpcap, wrpcap
    owner_pkts = list(rdpcap(sanity_pcap))
    first = owner_pkts[0]
    owner = (first[IP].src, first[IP].dst, first[TCP].sport, first[TCP].dport, 6)
    b_owner = compute_flow_index(*owner)
    a, b = owner[0], owner[1]

    def eth():
        return Ether(src=SRC_MAC, dst=DST_MAC)

    def udp(s, d, sp, dp, n=26):
        return eth() / IP(src=s, dst=d) / UDP(sport=sp, dport=dp) / Raw(b"\0" * n)

    def tcp(s, d, sp, dp, flags):
        return eth() / IP(src=s, dst=d) / TCP(sport=sp, dport=dp, flags=flags) / Raw(b"\0" * 6)

    c1 = (a, b, port_for_bucket(a, b, 7000, 17, b_owner), 7000, 17)
    c2 = (a, b, port_for_bucket(a, b, 7001, 17, b_owner), 7001, 17)
    own = ("10.99.4.1", "10.99.4.2", 41000, 443, 6)
    t = 443 ^ 8443
    evil = (own[0], own[1], own[2] ^ t, own[3] ^ t, 6)
    ctrl = ("10.99.5.1", "10.99.5.2", 5353, 6000, 17)
    b_xor, b_ctrl = compute_flow_index(*own), compute_flow_index(*ctrl)
    assert compute_flow_index(*evil) == b_xor and fingerprint(*evil) != fingerprint(*own)
    assert len({b_owner, b_xor, b_ctrl}) == 3

    pkts = owner_pkts[:]
    pkts += [udp(*c1[:4]) for _ in range(5)]
    pkts += [udp(*c2[:4]) for _ in range(5)]
    s, d, sp, dp, _ = own
    for k in range(5):
        pkts.append(tcp(s, d, sp, dp, "S" if k == 0 else "A"))
        pkts.append(tcp(d, s, dp, sp, "SA" if k == 0 else "A"))
    pkts += [tcp(evil[0], evil[1], evil[2], evil[3], "S" if k == 0 else "A") for k in range(5)]
    s, d, sp, dp, _ = ctrl
    for k in range(10):
        pkts.append(udp(s, d, sp, dp))
        pkts.append(udp(d, s, dp, sp))
    os.makedirs(out_dir, exist_ok=True)
    wrpcap(os.path.join(out_dir, "fp_test.pcap"), pkts)

    flows = {"owner": owner, "collide1": c1, "collide2": c2, "xor_own": own, "xor_evil": evil, "control": ctrl}
    exp = {
        "flows": {k: list(v) for k, v in flows.items()},
        "packets": len(pkts),
        "reports": [  # (reason, flow) in send order
            [1, "owner"], [2, "collide1"], [1, "xor_own"], [2, "xor_evil"], [1, "control"]],
        "buckets": {
            str(b_owner): {"reg_pkts": len(owner_pkts) + 10, "reg_shared": 1, "reg_dir_valid": 1,
                           "reg_fp": fingerprint(*owner)},
            str(b_xor): {"reg_pkts": 15, "reg_shared": 1, "reg_dir_valid": 1, "reg_fp": fingerprint(*own)},
            str(b_ctrl): {"reg_pkts": 20, "reg_shared": 0, "reg_dir_valid": 1, "reg_fp": fingerprint(*ctrl)},
        },
    }
    json.dump(exp, open(os.path.join(out_dir, "fp_expected.json"), "w"), indent=2)
    print("%d packets; buckets: owner %d, xor %d, control %d; collide1 sport %d, collide2 sport %d, "
          "xor_evil %s:%d -> %s:%d" % (len(pkts), b_owner, b_xor, b_ctrl, c1[2], c2[2], evil[0], evil[2],
                                       evil[1], evil[3]))
    print("buckets to read: %d,%d,%d" % (b_owner, b_xor, b_ctrl))


def check(exp_path, reports_pcap, read_json, out_path):
    from listen_cpu_reports import iter_pcap_stream, parse_cpu_report
    exp = json.load(open(exp_path))
    flows = {k: tuple(v) for k, v in exp["flows"].items()}
    results = []

    def ok(name, cond, detail):
        results.append({"check": name, "pass": bool(cond), "detail": detail})
        print("%s  %s: %s" % ("PASS" if cond else "FAIL", name, detail))

    reps = [r for r in (parse_cpu_report(f) for _, f in iter_pcap_stream(open(reports_pcap, "rb"))) if r]
    got = [(r["reason"], (r["src_ip"], r["dst_ip"], r["sport"], r["dport"], r["proto"]), r["idx"]) for r in reps]
    want = [(reason, flows[f], compute_flow_index(*flows[f])) for reason, f in exp["reports"]]
    ok("reports", got == want, "%d received, %d expected; received: %s" % (len(got), len(want), got))
    ok("report index = flow_index.py", all(r["idx"] == r["idx_computed"] for r in reps),
       "%d reports" % len(reps))
    rows = None
    for line in open(read_json):
        line = line.strip()
        if line.startswith("{"):
            rows = json.loads(line).get("values", rows)
    for bucket, regs in exp["buckets"].items():
        row = rows.get(bucket, {})
        for name, val in regs.items():
            hw = row.get(name)
            v = hw[PIPE] if isinstance(hw, list) else hw
            others = [x for k, x in enumerate(hw) if k != PIPE] if isinstance(hw, list) else []
            ok("bucket %s %s" % (bucket, name), v == val and not any(others),
               "hardware %s (pipe %d; all pipes %s), expected %s" % (v, PIPE, hw, val))
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
    p.add_argument("sanity_pcap")
    p = sub.add_parser("check")
    p.add_argument("expected")
    p.add_argument("reports_pcap")
    p.add_argument("read_json")
    p.add_argument("--out")
    a = ap.parse_args()
    if a.cmd == "make":
        make(a.out_dir, a.sanity_pcap)
    else:
        sys.exit(0 if check(a.expected, a.reports_pcap, a.read_json, a.out) else 1)


if __name__ == "__main__":
    main()
