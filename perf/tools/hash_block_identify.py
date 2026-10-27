#!/usr/bin/env python3
"""Identify every compiled 5-tuple hash of a build against known software functions.

    python3 perf/tools/hash_block_identify.py BUILD_DIR [--samples 2000]

In pipe/logs/mau.hashes.log, each function over the 5-tuple appears as a pair of
consecutive "Hash N" entries with the same output bits: one over the addresses,
one over ports and protocol. Their XOR is the function. An entry can be wider
than 16 bits and then carries several 16-bit functions side by side, one per
aligned 16-bit slice. Every slice is evaluated on random 5-tuples and named
after the candidate it equals on all samples, or "unknown".
"""
import argparse
import os
import random
import re
import struct
import sys
from pathlib import Path

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(HERE)), "thesis-hybrid-ebpf-p4", "python"))
from flow_index import compute_flow_index  # noqa: E402
from hash_matrix_check import FIELDS, eval_func  # noqa: E402
from hash_quality import reflected_crc16  # noqa: E402

crc_t10 = reflected_crc16(0x8BB7)


def raw(t, swap=False):
    if swap:
        return struct.pack("!IIHHB", t["dip"], t["sip"], t["dp"], t["sp"], t["pr"])
    return struct.pack("!IIHHB", t["sip"], t["dip"], t["sp"], t["dp"], t["pr"])


CANDIDATES = {
    "flow index (flow_index.py)": lambda t: compute_flow_index(t["sip"], t["dip"], t["sp"], t["dp"], t["pr"]),
    "fingerprint fwd: CRC 0x8BB7 refl over (sip,dip,sp,dp,pr)": lambda t: crc_t10(raw(t)),
    "fingerprint rev: CRC 0x8BB7 refl over (dip,sip,dp,sp,pr)": lambda t: crc_t10(raw(t, swap=True)),
}


def entries(stage_text):
    out = []
    for hm in re.finditer(r"^Hash (\d+)\n((?:result\[\d+\] = .*\n?)+)", stage_text, re.M):
        bits = {}
        for line in hm.group(2).splitlines():
            rm = re.match(r"result\[(\d+)\] = (.*)$", line)
            terms = set()
            for term in rm.group(2).split(" ^ "):
                tm = re.match(r"([\w.$]+)\[(\d+)\]$", term.strip())
                if tm and tm.group(1) in FIELDS:
                    terms ^= {(tm.group(1), int(tm.group(2)))}
            bits[int(rm.group(1))] = terms
        if any(bits.values()):
            out.append((int(hm.group(1)), bits))
    return out


def functions(stage_text):
    """Yield (tables, slice base, 16 term sets) for every paired 16-bit slice."""
    ent = entries(stage_text)
    i = 0
    while i + 1 < len(ent):
        (na, a), (nb, b) = ent[i], ent[i + 1]
        if sorted(a) != sorted(b):
            i += 1
            continue
        lo, hi = min(a), max(a)
        for base in range(lo - lo % 16, hi + 1, 16):
            if all(base + k in a for k in range(16)):
                yield (na, nb), base, [a[base + k] ^ b[base + k] for k in range(16)]
        i += 2


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("build_dir")
    ap.add_argument("--samples", type=int, default=2000)
    ap.add_argument("--seed", type=int, default=1)
    a = ap.parse_args()
    log = Path(a.build_dir, "pipe", "logs", "mau.hashes.log").read_text()
    parts = re.split(r"^\s*Stage (\d+)\s*$", log, flags=re.M)
    rng = random.Random(a.seed)
    tuples = [{"sip": rng.getrandbits(32), "dip": rng.getrandbits(32), "sp": rng.getrandbits(16),
               "dp": rng.getrandbits(16), "pr": rng.choice((6, 17))} for _ in range(a.samples)]
    counts = {}
    for k in range(1, len(parts), 2):
        for tables, base, func in functions(parts[k + 1]):
            hw = [eval_func(func, t) for t in tuples]
            match = [n for n, f in CANDIDATES.items() if all(f(t) == h for t, h in zip(tuples, hw))]
            name = match[0] if match else "unknown"
            counts[name] = counts.get(name, 0) + 1
            print("stage %s, hash tables %s, result[%d..%d]: %s" % (parts[k], list(tables), base, base + 15, name))
    print("summary: " + "; ".join("%s x%d" % (n, c) for n, c in counts.items()))


if __name__ == "__main__":
    main()
