#!/usr/bin/env python3
"""Compare register reads from the sanity test with the predicted values.

    check_sanity.py EXPECTED_JSON READ_JSON [--pipe 1] [--pps 100] [--out RESULT_JSON]

EXPECTED_JSON comes from make_test_pcaps.py sanity, READ_JSON from
`run_bfrt.sh ... read-regs` (one HZJSON object per line; the last one is used).
For each index model (compiled, collector, symfix) every predicted bucket is
compared register by register on the given pipe (the one holding the test
ports), and the other pipes must read zero. Timestamps are not predicted;
last_ts - first_ts (mod 2^32 ns) must be within 5 % of the time between the
bucket's first and last packet at the replay rate.
"""
import argparse
import json

REGS = ["reg_pkts", "reg_bytes", "reg_pkts_ab", "reg_bytes_ab", "reg_ref_src_port",
        "reg_ref_dst_port", "reg_dir_valid", "reg_min_len", "reg_max_len", "reg_syn",
        "reg_ack", "reg_rst"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("expected")
    ap.add_argument("read")
    ap.add_argument("--pipe", type=int, default=1)
    ap.add_argument("--pps", type=float, default=100.0)
    ap.add_argument("--out")
    a = ap.parse_args()
    exp = json.load(open(a.expected))
    read = json.loads(open(a.read).read().splitlines()[-1])["values"]
    result = {"pipe": a.pipe, "models": {}}
    for model, buckets in exp["models"].items():
        mres = {"buckets": {}, "match": True}
        for idx, want in buckets.items():
            got = read.get(idx)
            if got is None:
                mres["buckets"][idx] = {"error": "index not read"}
                mres["match"] = False
                continue
            diffs = {}
            for r in REGS:
                vals = got[r]
                if vals[a.pipe] != want[r]:
                    diffs[r] = {"want": want[r], "got": vals[a.pipe]}
                other = [v for p, v in enumerate(vals) if p != a.pipe and v]
                if other:
                    diffs[r + "_other_pipes"] = {"want": 0, "got": other}
            first, last = got["reg_first_ts"][a.pipe], got["reg_last_ts"][a.pipe]
            span_ns = (last - first) % (1 << 32)
            want_ns = (want["last_pkt"] - want["first_pkt"]) / a.pps * 1e9
            ts_ok = first != 0 and last != 0 and abs(span_ns - want_ns) <= 0.05 * want_ns
            if not ts_ok:
                diffs["timestamps"] = {"span_ns": span_ns, "expected_ns": want_ns}
            mres["buckets"][idx] = {"match": not diffs, "diffs": diffs,
                                    "ts_span_ns": span_ns, "ts_expected_ns": want_ns}
            mres["match"] = mres["match"] and not diffs
        result["models"][model] = mres
    verdict = [m for m, r in result["models"].items() if r["match"]]
    result["models_matching"] = verdict
    for model, r in result["models"].items():
        print(f"{model:9s}: {'MATCH' if r['match'] else 'no match'}")
        for idx, b in r["buckets"].items():
            extra = "" if b.get("match") else "  diffs: " + json.dumps(b.get("diffs", b))[:300]
            span = b.get("ts_span_ns")
            span_s = f"  ts span {span / 1e9:.4f} s (expected {b['ts_expected_ns'] / 1e9:.4f} s)" if span is not None else ""
            print(f"    bucket {idx}: {'ok' if b.get('match') else 'MISMATCH'}{span_s}{extra}")
    print("models matching the hardware:", verdict or "none")
    if a.out:
        json.dump(result, open(a.out, "w"), indent=2)


if __name__ == "__main__":
    main()
