#!/usr/bin/env python3
"""Offline check of the flow-index hash on synthetic traffic patterns.

    python3 perf/tools/hash_quality.py [--sizes 20000,50000]

For every pattern, prints the share of flows that get no bucket of their own
(1 - distinct buckets / flows) under:
  random      the birthday expectation for a uniformly random 16-bit hash
  compiled    the deployed index (flow_index.py): CRC-16/ARC over
              (0, sip^dip, 0, sp^dp, proto)
  T10-DIF     the same XOR input with CRC polynomial 0x8BB7 (reflected)
  minmax ARC  CRC-16/ARC over (min ip, max ip, min port, max port, proto)
  minmax T10  the min/max input with polynomial 0x8BB7 (reflected)
  blake2b     a non-linear hash over the XOR input, for comparison
A Tofino hash unit can only compute XOR matrices (any CRC polynomial), so
blake2b is not deployable; it shows what a random hash would do.
"""
import argparse
import hashlib
import os
import random
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                                "thesis-hybrid-ebpf-p4", "python"))
from flow_index import FLOW_BUCKETS, compute_flow_index  # noqa: E402


def reflected_crc16(poly):
    rpoly = int("{:016b}".format(poly)[::-1], 2)
    tab = []
    for b in range(256):
        c = b
        for _ in range(8):
            c = (c >> 1) ^ rpoly if c & 1 else c >> 1
        tab.append(c)

    def crc(data):
        c = 0
        for b in data:
            c = (c >> 8) ^ tab[(c ^ b) & 0xFF]
        return c
    return crc


crc_arc, crc_t10 = reflected_crc16(0x8005), reflected_crc16(0x8BB7)
assert crc_arc(b"123456789") == 0xBB3D


def xor_input(s, d, sp, dp, pr):
    return struct.pack("!IIHHB", 0, s ^ d, 0, (sp ^ dp) & 0xFFFF, pr)


def minmax_input(s, d, sp, dp, pr):
    return struct.pack("!IIHHB", min(s, d), max(s, d), min(sp, dp), max(sp, dp), pr)


HASHES = [
    ("compiled", lambda t: compute_flow_index(*t)),
    ("T10-DIF", lambda t: crc_t10(xor_input(*t))),
    ("minmax ARC", lambda t: crc_arc(minmax_input(*t))),
    ("minmax T10", lambda t: crc_t10(minmax_input(*t))),
    ("blake2b", lambda t: int.from_bytes(hashlib.blake2b(xor_input(*t), digest_size=2).digest(), "big")),
]


def ip(a, b, c, d):
    return (a << 24) | (b << 16) | (c << 8) | d


def distinct(gen, n):
    seen, out = set(), []
    for t in gen:
        if t not in seen:
            seen.add(t)
            out.append(t)
            if len(out) == n:
                break
    return out


def forever(make):
    while True:
        yield make()


PATTERNS = [
    # Section 2.5 traffic (run_report_capacity.py) and Section 2.4 fill (make_fill_pcap.py)
    ("Sec. 2.5 test flows", lambda n, r: [(ip(10, 120, 0, 0) + i, ip(10, 121, 0, 1), 1024 + i % 50000, 4000 + i % 7, 17)
                                          for i in range(n)]),
    ("Sec. 2.4 fill flows", lambda n, r: [(ip(10, 100, 0, 0) + i, ip(10, 101, 0, 1), 40000 + i % 20000, 5000 + i % 13, 17)
                                          for i in range(n)]),
    ("uniform random", lambda n, r: distinct(forever(lambda: (r.getrandbits(32), r.getrandbits(32), r.getrandbits(16),
                                                              r.getrandbits(16), 6)), n)),
    ("vertical port scan", lambda n, r: [(ip(10, 0, 0, 1), ip(10, 0, 0, 2), 61000, 1 + i, 6) for i in range(min(n, 65535))]),
    ("horizontal scan of a /16", lambda n, r: [(ip(10, 0, 0, 1), ip(10, 1, 0, 0) + i, r.randrange(32768, 61000), 445, 6)
                                               for i in range(min(n, 65536))]),
    ("clients of one server", lambda n, r: distinct(forever(lambda: (ip(10, 2, 0, 0) + r.getrandbits(16), ip(10, 0, 0, 80),
                                                                     r.randrange(32768, 61000), 443, 6)), n)),
    ("SYN flood, spoofed sources", lambda n, r: distinct(forever(lambda: (r.getrandbits(32), ip(10, 0, 0, 80),
                                                                          r.getrandbits(16), 80, 6)), n)),
    ("one /24 all-to-all, ports 137", lambda n, r: r.sample([(ip(192, 168, 1, a), ip(192, 168, 1, b), 137, 137, 17)
                                                             for a in range(256) for b in range(a + 1, 256)],
                                                            min(n, 32640))),
]


def birthday(n):
    return 1 - FLOW_BUCKETS * (1 - (1 - 1 / FLOW_BUCKETS) ** n) / n


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sizes", default="20000,50000")
    a = ap.parse_args()
    print("| Pattern | Flows | random | " + " | ".join(h for h, _ in HASHES) + " |")
    print("|---|---|---|" + "---|" * len(HASHES))
    for name, make in PATTERNS:
        for n in (int(x) for x in a.sizes.split(",")):
            flows = make(n, random.Random(7))
            if len(flows) < n and n != int(a.sizes.split(",")[0]):
                continue
            k = len(flows)
            shares = ["%.1f%%" % (100 * (1 - len({f(t) for t in flows}) / k)) for _, f in HASHES]
            print("| %s | %d | %.1f%% | %s |" % (name, k, 100 * birthday(k), " | ".join(shares)), flush=True)


if __name__ == "__main__":
    main()
