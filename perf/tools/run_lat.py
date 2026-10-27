#!/usr/bin/env python3
"""Phase 2.5: ASIC latency of the *_lat builds (see perf/variants/lat/lat_wrapper.p4).

    run_lat.py RUN_DIR --prog basic_lat [--reps 3] [--low-pps 1000] [--low-s 10]
               [--high-s 20] [--seed 1] [--sizes 64,...]
    run_lat.py RUN_DIR --summarize-only

Per repetition, every (frame size, rate) pair runs once, in a shuffled order
(seeded, recorded in plan_<prog>.json). One measurement:
  1. lat-clear: clear the latency registers (with a port-stats snapshot)
  2. tcpreplay of the size's UDP flow from PC1 (the Phase 2.3 flows):
     "low" = --pps=LOW_PPS for LOW_S s, "high" = --topspeed for HIGH_S s
  3. lat-read: count/min/max/overflow and both 1024-bin histograms (with port stats)
Measured are the packets leaving on dev_port 140; their count must equal the
frames dev_port 140 transmitted between steps 1 and 3. Percentiles and means
come from the 8 ns histogram bins (bin centre); min and max are exact. All
latencies are on the ASIC clock in ns; host clocks only stamp the logs.
"""
import argparse
import json
import os
import random
import statistics
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import run_pktrate  # noqa: E402  (pcaps, tcpreplay wrapper, PC1 counters)

BIN_NS = 8
METRICS = ("mac", "prsr")   # from ingress MAC timestamp / from ingress parser timestamp


def bfrt(run_dir, label, *args):
    r = subprocess.run([os.path.join(HERE, "run_bfrt.sh"), run_dir, label] + list(args),
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True,
                       env=dict(os.environ, SHOW_LINES="1"))
    path = os.path.join(run_dir, "bfrt", label + ".json")
    lines = open(path).read().splitlines() if os.path.exists(path) else []
    if r.returncode != 0 or not lines:
        raise RuntimeError("%s failed: %s" % (label, r.stdout[-500:]))
    out = json.loads(lines[-1])
    if out.get("errors"):
        raise RuntimeError("%s reported errors: %s" % (label, out["errors"][:5]))
    return out


def hist_stats(bins):
    """bins: {bin index: count} -> count, mean and percentiles (bin centres, ns)."""
    items = sorted((int(b), c) for b, c in bins.items())
    total = sum(c for _, c in items)
    if not total:
        return {"n": 0}
    out = {"n": total,
           "mean_ns": sum((b * BIN_NS + BIN_NS / 2) * c for b, c in items) / total}
    for p in (50, 90, 95, 99, 99.9):
        need, acc = p / 100.0 * total, 0
        for b, c in items:
            acc += c
            if acc >= need:
                out["p%s_ns" % str(p).replace(".", "_")] = b * BIN_NS + BIN_NS / 2
                break
    return out


def measure(run_dir, prog, rep, size, mode, info, a):
    label = "r%d_s%d_%s" % (rep, size, mode)
    c = bfrt(run_dir, label + "_clear", "lat-clear", "--prog", prog)
    if mode == "low":
        rp = run_pktrate.replay(run_dir, label + "_replay", info["pcap"], a.low_s,
                                "--pps=%d" % a.low_pps)
    else:
        rp = run_pktrate.replay(run_dir, label + "_replay", info["pcap"], a.high_s)
    time.sleep(0.5)
    r = bfrt(run_dir, label + "_read", "lat-read", "--prog", prog)
    tx140 = r["stats"]["140"]["$FramesTransmittedOK"] - c["stats"]["140"]["$FramesTransmittedOK"]
    rx132 = r["stats"]["132"]["$FramesReceivedOK"] - c["stats"]["132"]["$FramesReceivedOK"]
    sc = r["scalars"]
    pipe = max(range(len(sc["lat_count"])), key=lambda p: sc["lat_count"][p])
    res = {"prog": prog, "rep": rep, "size": size, "mode": mode, "label": label,
           "pipe": pipe, "count": sc["lat_count"][pipe], "tx140": tx140, "rx132": rx132,
           "count_matches_tx140": sc["lat_count"][pipe] == tx140,
           "other_pipes_count": [v for p, v in enumerate(sc["lat_count"]) if p != pipe],
           "pc1_tx": rp["pc1_phy_delta"]["tx_packets_phy"], "send_s": rp.get("send_s"),
           "offered_pps": rp["pc1_phy_delta"]["tx_packets_phy"] / (rp.get("send_s") or 1),
           "pc1_cpu_busy": rp["pc1_cpu_busy"], "hist_read_s": r.get("hist_read_s")}
    for m in METRICS:
        st = hist_stats(r["hists"]["lat_%s_hist" % m].get(str(pipe), {}))
        st.update({"min_ns": sc["lat_%s_min" % m][pipe], "max_ns": sc["lat_%s_max" % m][pipe],
                   "overflow": sc["lat_%s_ovf" % m][pipe]})
        st["hist_n_matches_count"] = st["n"] == res["count"]
        res[m] = st
    return res


def summarize(run_dir):
    rows = [json.loads(l) for l in open(os.path.join(run_dir, "results.jsonl"))]
    keys = ("p50_ns", "p99_ns", "mean_ns", "min_ns", "max_ns")
    out = {}
    for r in rows:
        out.setdefault(r["prog"], {}).setdefault(r["mode"], {}).setdefault(str(r["size"]), []).append(r)
    summ = {}
    for prog, modes in out.items():
        for mode, sizes in modes.items():
            for size, rs in sizes.items():
                s = {"n_runs": len(rs), "packets": sum(r["count"] for r in rs),
                     "count_matches": sum(1 for r in rs if r["count_matches_tx140"]),
                     "offered_mpps_median": statistics.median(r["offered_pps"] for r in rs) / 1e6,
                     "overflow_total": {m: sum(r[m]["overflow"] for r in rs) for m in METRICS}}
                for m in METRICS:
                    for k in keys:
                        vals = [r[m][k] for r in rs if k in r[m]]
                        s["%s_%s_median" % (m, k)] = statistics.median(vals) if vals else None
                    s["%s_min_ns_all" % m] = min(r[m]["min_ns"] for r in rs)
                    s["%s_max_ns_all" % m] = max(r[m]["max_ns"] for r in rs)
                summ.setdefault(prog, {}).setdefault(mode, {})[size] = s
    json.dump(summ, open(os.path.join(run_dir, "summary.json"), "w"), indent=2)
    md = ["| program | rate | frame B | runs | packets | count = port count | offered Mpps | "
          "parser→egress p50 / p99 / max (ns) | MAC→egress p50 / p99 / max (ns) |",
          "|---|---|---|---|---|---|---|---|---|"]
    for prog in sorted(summ):
        for mode in ("low", "high"):
            for size in sorted(summ[prog].get(mode, {}), key=int):
                s = summ[prog][mode][size]
                md.append("| %s | %s | %s | %d | %d | %d/%d | %.3f | %s / %s / %s | %s / %s / %s |" % (
                    prog, mode, size, s["n_runs"], s["packets"], s["count_matches"], s["n_runs"],
                    s["offered_mpps_median"],
                    *("%g" % s[k] if s[k] is not None else "–" for k in (
                        "prsr_p50_ns_median", "prsr_p99_ns_median", "prsr_max_ns_all",
                        "mac_p50_ns_median", "mac_p99_ns_median", "mac_max_ns_all"))))
    if "basic_lat" in summ and "baseline_lat" in summ:
        md += ["", "Detector cost = basic_lat − baseline_lat (ns). Minimum latency is exact (no "
               "binning) and excludes queueing; p50 and mean come from 8 ns bins.", "",
               "| rate | frame B | Δ min parser→egress | Δ min MAC→egress | Δ p50 parser→egress "
               "| Δ mean parser→egress |", "|---|---|---|---|---|---|"]
        comp = {}
        for mode in ("low", "high"):
            for size in sorted(summ["basic_lat"].get(mode, {}), key=int):
                d, b = summ["basic_lat"][mode][size], summ["baseline_lat"].get(mode, {}).get(size)
                if not b:
                    continue
                c = {"d_min_prsr": d["prsr_min_ns_all"] - b["prsr_min_ns_all"],
                     "d_min_mac": d["mac_min_ns_all"] - b["mac_min_ns_all"],
                     "d_p50_prsr": d["prsr_p50_ns_median"] - b["prsr_p50_ns_median"],
                     "d_mean_prsr": d["prsr_mean_ns_median"] - b["prsr_mean_ns_median"]}
                comp.setdefault(mode, {})[size] = c
                md.append("| %s | %s | %d | %d | %g | %.1f |" % (
                    mode, size, c["d_min_prsr"], c["d_min_mac"], c["d_p50_prsr"], c["d_mean_prsr"]))
        summ["comparison"] = comp
        json.dump(summ, open(os.path.join(run_dir, "summary.json"), "w"), indent=2)
    open(os.path.join(run_dir, "summary.md"), "w").write("\n".join(md) + "\n")
    print("\n".join(md))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("run_dir")
    ap.add_argument("--prog", default="basic_lat")
    ap.add_argument("--reps", type=int, default=3)
    ap.add_argument("--low-pps", type=int, default=1000)
    ap.add_argument("--low-s", type=int, default=10)
    ap.add_argument("--high-s", type=int, default=20)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--sizes", default=",".join(map(str, run_pktrate.SIZES)))
    ap.add_argument("--modes", default="low,high")
    ap.add_argument("--summarize-only", action="store_true")
    a = ap.parse_args()
    if a.summarize_only:
        summarize(a.run_dir)
        return
    if not run_pktrate.ASROOT:
        sys.exit("set ASROOT to the sudo wrapper (tcpreplay needs root)")
    info = run_pktrate.make_pcaps(os.path.join(a.run_dir, "pcap"))
    sizes = [int(s) for s in a.sizes.split(",")]
    modes = a.modes.split(",")
    rng = random.Random(a.seed)
    plan = []
    for rep in range(1, a.reps + 1):
        order = [(s, m) for s in sizes for m in modes]
        rng.shuffle(order)
        plan.append({"rep": rep, "order": order})
    json.dump({"prog": a.prog, "low_pps": a.low_pps, "low_s": a.low_s, "high_s": a.high_s,
               "seed": a.seed, "plan": plan, "flows": info},
              open(os.path.join(a.run_dir, "plan_%s.json" % a.prog), "w"), indent=2)
    with open(os.path.join(a.run_dir, "results.jsonl"), "a") as out:
        for p in plan:
            for size, mode in p["order"]:
                res = measure(a.run_dir, a.prog, p["rep"], size, mode, info[size], a)
                out.write(json.dumps(res) + "\n")
                out.flush()
                print("%s rep %d %4d B %-4s: %.3f Mpps, n=%d (=tx140 %s), parser->egress p50 %s "
                      "p99 %s max %d ns, MAC->egress p50 %s max %d ns, ovf %d/%d" % (
                          a.prog, p["rep"], size, mode, res["offered_pps"] / 1e6, res["count"],
                          res["count_matches_tx140"], res["prsr"].get("p50_ns"),
                          res["prsr"].get("p99_ns"), res["prsr"]["max_ns"], res["mac"].get("p50_ns"),
                          res["mac"]["max_ns"], res["prsr"]["overflow"], res["mac"]["overflow"]),
                      flush=True)
    summarize(a.run_dir)


if __name__ == "__main__":
    main()
