#!/usr/bin/env python3
"""Check which software hash matches the flow-index hash bf-p4c compiled.

    python3 perf/tools/hash_matrix_check.py BUILD_DIR [--stage 0] [--samples 20000]

bf-p4c --log-hashes writes pipe/logs/mau.hashes.log: for every hash table of a
stage, each output bit as an XOR of input-field bits. Within a block, the
tables that together produce one index (in stage 0 of the detector: "Hash 2",
over the IPv4 addresses, and "Hash 3", over ports and protocol) are XORed.
This tool rebuilds that GF(2) function, evaluates it on random 5-tuples, and
compares it with candidate software functions, including the collector's
compute_flow_index_symmetric() as written in listen_cpu_reports.py. It also
reports whether the compiled function is symmetric (swapping src and dst, and
sport and dport, leaves the index unchanged).
"""
import argparse
import random
import re
import struct
import sys
from pathlib import Path

# Hash-input field (as named in mau.hashes.log) -> its value for a 5-tuple t.
FIELDS = {
    "hdr.ipv4.srcAddr": lambda t: t["sip"],
    "hdr.ipv4.dstAddr": lambda t: t["dip"],
    "meta.l4_sport": lambda t: t["sp"],
    "meta.l4_dport": lambda t: t["dp"],
    "hdr.ipv4.protocol": lambda t: t["pr"],
    # The same headers inside the latency wrapper (perf/variants/lat), passed as hdr.det.
    "hdr.det.ipv4.srcAddr": lambda t: t["sip"],
    "hdr.det.ipv4.dstAddr": lambda t: t["dip"],
    "hdr.det.ipv4.protocol": lambda t: t["pr"],
    # Materialised symmetric inputs (fix variant basic_symfix_meta).
    "meta.sym_ip_x": lambda t: t["sip"] ^ t["dip"],
    "meta.sym_ip_s": lambda t: (t["sip"] + t["dip"]) & 0xFFFFFFFF,
    "meta.sym_p_x": lambda t: t["sp"] ^ t["dp"],
    "meta.sym_p_s": lambda t: (t["sp"] + t["dp"]) & 0xFFFF,
}


def parse_blocks(log_text, stage):
    """Return the list of index functions of one stage.

    Each function is a list of 16 sets of (field, bit) terms. The hash tables
    that together produce one index are listed consecutively with the same
    16-bit slice of the hash output (result[0..15], [16..31] or [32..47]);
    they are XORed and rebased to bits 0..15. Tables without any 5-tuple
    input (e.g. the forwarding table's ingress_port hash) are skipped.
    """
    m = re.search(rf"Stage {stage}\n\+-+\+\n(.*?)(?:\n\+-+\+\n   Stage |\Z)", log_text, re.S)
    if not m:
        sys.exit(f"stage {stage} not found")
    tables = []
    for hm in re.finditer(r"^Hash (\d+)\n((?:result\[\d+\] = .*\n?)+)", m.group(1), re.M):
        bits = {}
        for line in hm.group(2).splitlines():
            rm = re.match(r"result\[(\d+)\] = (.*)$", line)
            terms = set()
            for t in rm.group(2).split(" ^ "):
                tm = re.match(r"([\w.$]+)\[(\d+)\]$", t.strip())
                if tm and tm.group(1) in FIELDS:
                    terms ^= {(tm.group(1), int(tm.group(2)))}
            bits[int(rm.group(1))] = terms
        if any(bits.values()):
            tables.append((int(hm.group(1)), min(bits) // 16 * 16, bits))
    blocks = []
    for num, base, bits in tables:
        if blocks and blocks[-1]["base"] == base and num not in blocks[-1]["tables"]:
            blocks[-1]["tables"].append(num)
        else:
            blocks.append({"tables": [num], "base": base, "func": [set() for _ in range(16)]})
        for i, terms in bits.items():
            if base <= i < base + 16:
                blocks[-1]["func"][i - base] ^= terms
    return blocks


def eval_func(func, t):
    vals = {name: get(t) for name, get in FIELDS.items()}
    out = 0
    for i, terms in enumerate(func):
        v = 0
        for f, b in terms:
            v ^= (vals[f] >> b) & 1
        out |= v << i
    return out


def reflect(val, width):
    r = 0
    for i in range(width):
        if val >> i & 1:
            r |= 1 << (width - 1 - i)
    return r


def crc16_msb(data, poly=0x8005, init=0):
    crc = init
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ poly) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def crc16_tofino_collector(data):   # listen_cpu_reports.crc16_tofino, verbatim logic
    # Each input byte is reflected before the MSB-first update and the result
    # is reflected at the end, i.e. this is CRC-16/ARC. (An earlier copy here
    # omitted the input reflection; corrected 2026-10-26.)
    return reflect(crc16_msb(bytes(reflect(b, 8) for b in data)), 16)


def crc16_arc(data):                # reflected in and out, poly 0x8005 (0xA001), init 0
    crc = 0
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
    return crc


def blob_symmetric(t):
    return struct.pack("!IIHHB", t["sip"] ^ t["dip"], (t["sip"] + t["dip"]) & 0xFFFFFFFF,
                       t["sp"] ^ t["dp"], (t["sp"] + t["dp"]) & 0xFFFF, t["pr"])


def blob_raw(t):
    return struct.pack("!IIHHB", t["sip"], t["dip"], t["sp"], t["dp"], t["pr"])


CANDIDATES = {
    "collector: crc16_tofino(symmetric blob)  [compute_flow_index_symmetric]":
        lambda t: crc16_tofino_collector(blob_symmetric(t)),
    "crc16_tofino(raw 5-tuple blob)": lambda t: crc16_tofino_collector(blob_raw(t)),
    "CRC-16/ARC(symmetric blob)": lambda t: crc16_arc(blob_symmetric(t)),
    "CRC-16/ARC(raw 5-tuple blob)": lambda t: crc16_arc(blob_raw(t)),
    "CRC-16/BUYPASS(symmetric blob)": lambda t: crc16_msb(blob_symmetric(t)),
    "CRC-16/BUYPASS(raw 5-tuple blob)": lambda t: crc16_msb(blob_raw(t)),
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("build_dir")
    ap.add_argument("--stage", type=int, default=0)
    ap.add_argument("--samples", type=int, default=20000)
    ap.add_argument("--seed", type=int, default=1)
    args = ap.parse_args()
    log = Path(args.build_dir, "pipe", "logs", "mau.hashes.log").read_text()
    blocks = parse_blocks(log, args.stage)
    print(f"stage {args.stage}: {len(blocks)} index function(s) over the 5-tuple "
          f"(hash tables {[b['tables'] for b in blocks]})")
    funcs = [b["func"] for b in blocks]
    identical = all(f == funcs[0] for f in funcs)
    print(f"all blocks identical: {identical}")
    func = funcs[0]
    print("terms per output bit:", [len(s) for s in func])
    rng = random.Random(args.seed)
    tuples = [{"sip": rng.getrandbits(32), "dip": rng.getrandbits(32),
               "sp": rng.getrandbits(16), "dp": rng.getrandbits(16),
               "pr": rng.choice((6, 17))} for _ in range(args.samples)]
    hw = [eval_func(func, t) for t in tuples]
    sym = sum(hw[i] == eval_func(func, {"sip": t["dip"], "dip": t["sip"], "sp": t["dp"],
                                         "dp": t["sp"], "pr": t["pr"]})
              for i, t in enumerate(tuples))
    print(f"compiled function symmetric under (src,dst) and (sport,dport) swap: "
          f"{sym}/{len(tuples)} samples")
    print("agreement of candidates with the compiled function (first block):")
    for name, fn in CANDIDATES.items():
        ok = sum(fn(t) == h for t, h in zip(tuples, hw))
        print(f"  {ok:6d}/{len(tuples)}  {name}")
    # Blocks can differ as term sets (byte placement on the crossbar) while
    # computing the same function; check every block by evaluation.
    for k, f in enumerate(funcs[1:], start=2):
        ok = sum(eval_func(f, t) == h for t, h in zip(tuples, hw))
        print(f"block {k} (hash tables {blocks[k - 1]['tables']}) equals block 1 on "
              f"{ok}/{len(tuples)} samples")


if __name__ == "__main__":
    main()
