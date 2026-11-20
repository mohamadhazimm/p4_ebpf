#!/usr/bin/env python3
"""Validate and summarise the Phase 3.1-3.2 readout runs.

    check_readout.py RUN_DIR

Expects RUN_DIR/pcap/fill_expected.json (make_fill_pcap.py), the readout result
lines RUN_DIR/bfrt/bfrt_readout_r*.json and the dump files
RUN_DIR/dumps/readout_r*_{hw,sync}.json.gz copied from the switch. For every
dump it checks all 65,536 buckets of the 14 registers against the fill's
expected values (pipe 1; pipe 0 must be all zero), that the "hw" and "sync"
dumps are identical, and that the per-cell reads equal the dumps. Timestamps
are checked only for being non-zero exactly where traffic went. Writes
RUN_DIR/readout_check.json and RUN_DIR/readout_summary.md.
"""
import glob
import gzip
import json
import os
import re
import statistics
import sys

NB = 65536
VALUE_REGS = ["reg_pkts", "reg_bytes", "reg_pkts_ab", "reg_bytes_ab", "reg_min_len", "reg_max_len",
              "reg_dir_valid", "reg_ref_src_port", "reg_ref_dst_port", "reg_syn", "reg_ack", "reg_rst"]
TS_REGS = ["reg_first_ts", "reg_last_ts"]


def check_dump(arrays, exp):
    res = {}
    for reg in VALUE_REGS + TS_REGS:
        pipes = arrays.get(reg)
        if not pipes:
            res[reg] = {"error": "missing"}
            continue
        other = sum(1 for p, v in enumerate(pipes) if p != 1 for x in v if x)
        bad, unexpected = 0, 0
        for i, x in enumerate(pipes[1]):
            e = exp.get(str(i))
            if e is None:
                unexpected += 1 if x else 0
            elif reg in TS_REGS:
                bad += 0 if x else 1
            elif x != e[reg]:
                bad += 1
        res[reg] = {"wrong_in_filled_buckets": bad, "nonzero_outside_filled": unexpected,
                    "nonzero_other_pipes": other}
    res["all_ok"] = all(v.get("wrong_in_filled_buckets") == 0 and v.get("nonzero_outside_filled") == 0
                        and v.get("nonzero_other_pipes") == 0 for v in res.values() if isinstance(v, dict))
    return res


def main():
    run = sys.argv[1]
    exp = json.load(open(os.path.join(run, "pcap", "fill_expected.json")))["buckets"]
    out = {"reps": {}}
    for path in sorted(glob.glob(os.path.join(run, "bfrt", "bfrt_readout_r*.json"))):
        rep = re.search(r"_r(\d+)\.json$", path).group(1)
        r = json.loads(open(path).read().splitlines()[-1])
        dumps = {}
        for m in r["bulk"]:
            f = os.path.join(run, "dumps", os.path.basename(r["bulk"][m]["file"]))
            dumps[m] = json.load(gzip.open(f, "rt"))
        rr = {"errors": r["errors"], "percell": r["percell"], "bulk": {}}
        for m, d in dumps.items():
            rr["bulk"][m] = {"timing": r["bulk"][m]["total_s"],
                             "per_register": r["bulk"][m]["registers"],
                             "check": check_dump(d, exp)}
        if "hw" in dumps and "sync" in dumps:
            rr["hw_equals_sync"] = all(dumps["hw"][k] == dumps["sync"][k] for k in dumps["hw"])
        mism = 0
        for pc in r["percell"]:
            for reg, vals in pc["check_values"].items():
                for i, v in vals.items():
                    for m, d in dumps.items():
                        if [d[reg][p][int(i)] for p in range(len(v))] != v:
                            mism += 1
        rr["percell_vs_dump_mismatches"] = mism
        out["reps"][rep] = rr
    json.dump(out, open(os.path.join(run, "readout_check.json"), "w"), indent=2)

    reps = out["reps"]
    lines = ["# Readout benchmark summary", "", "## Correctness", ""]
    for rep, rr in sorted(reps.items()):
        for m, b in rr["bulk"].items():
            lines.append("- rep %s, %s dump: all 14 registers × 65,536 buckets as expected: **%s**" % (
                rep, m, b["check"]["all_ok"]))
        lines.append("- rep %s: hw dump == sync dump: %s; per-cell reads vs dumps: %d mismatches; errors: %s" % (
            rep, rr.get("hw_equals_sync"), rr["percell_vs_dump_mismatches"], rr["errors"] or "none"))
    lines += ["", "## Per-cell reads from hardware (collector method)", "",
              "| indices × 14 registers | cells | seconds (median of reps) | µs per cell |", "|---|---|---|---|"]
    ns = sorted({pc["n_indices"] for rr in reps.values() for pc in rr["percell"]})
    for n in ns:
        s = [pc["s"] for rr in reps.values() for pc in rr["percell"] if pc["n_indices"] == n]
        u = [pc["us_per_cell"] for rr in reps.values() for pc in rr["percell"] if pc["n_indices"] == n]
        lines.append("| %d | %d | %.3f | %.1f |" % (n, n * 14, statistics.median(s), statistics.median(u)))
    u_all = statistics.median(pc["us_per_cell"] for rr in reps.values() for pc in rr["percell"]
                              if pc["n_indices"] == max(ns))
    lines += ["", "Full table via per-cell reads (65,536 × 14 cells) at %.1f µs/cell: **%.0f s** (extrapolated)."
              % (u_all, u_all * NB * 14 / 1e6), "",
              "## Whole-register reads (all 65,536 entries, 14 registers)", "",
              "| method | read s (median) | convert s (median) | sync s (median) | per register read s |",
              "|---|---|---|---|---|"]
    for m in ("hw", "sync"):
        t = [rr["bulk"][m]["timing"] for rr in reps.values() if m in rr["bulk"]]
        if not t:
            continue
        per = [v["get_s"] for rr in reps.values() for v in rr["bulk"][m]["per_register"].values()]
        lines.append("| %s | %.2f | %.2f | %.2f | %.2f–%.2f |" % (
            m, statistics.median(x["get"] for x in t), statistics.median(x["convert"] for x in t),
            statistics.median(x["sync"] for x in t), min(per), max(per)))
    open(os.path.join(run, "readout_summary.md"), "w").write("\n".join(lines) + "\n")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
