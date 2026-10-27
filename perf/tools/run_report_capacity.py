#!/usr/bin/env python3
"""Phase 3.3: how many first-seen CPU reports reach the collector at rising new-flow rates.

    run_report_capacity.py RUN_DIR [--rates 1000,5000,...,0] [--reps 3] [--max-flows 50000]
    run_report_capacity.py RUN_DIR --summarize-only

Every run clears all registers and sends K distinct one-packet UDP flows from
PC1 at R packets/s (R = 0: tcpreplay --topspeed), K = min(max_flows, 20 s x R).
A report is due for every bucket the flows reach, so the expected number of
reports is the number of distinct buckets (flow_index.py). Reports are counted
along the whole path:

    tm_drops        mirrored copies dropped by the traffic manager towards
                    the CPU port 192 (tf1.tm.counter.eg_port drop_count_packets)
    kernel_rx       frames the switch kernel received on enp5s0 (bf_kpkt), and
                    rx_dropped/rx_missed_errors/rx_fifo_errors
    raw_captured    frames with magic 0xBEF1 in a tcpdump file written on the switch
    collector       reports seen by listen_cpu_reports.ReportCollector over SSH
                    on PC1, the collector's own path (distinct indexes too)

Both captures run at the same time and each costs switch CPU. Results go to
RUN_DIR/results.jsonl, summary.json and summary.md.
"""
import argparse
import json
import os
import random
import re
import statistics
import struct
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_PY = os.path.join(os.path.dirname(os.path.dirname(HERE)), "thesis-hybrid-ebpf-p4", "python")
sys.path.insert(0, REPO_PY)
from flow_index import compute_flow_index  # noqa: E402
from listen_cpu_reports import ReportCollector, iter_pcap_stream, parse_cpu_report  # noqa: E402

SWITCH = "root@172.168.1.2"
SRC_MAC, DST_MAC = "04:3f:72:d2:ec:5e", "02:00:00:00:00:02"
SIP0, DIP = (10 << 24) | (120 << 16), (10 << 24) | (121 << 16) | 1
ASROOT = os.environ.get("ASROOT", "")


def flow(i):
    return SIP0 + i, DIP, 1024 + (i % 50000), 4000 + (i % 7), 17


def make_pcap(path, n):
    from scapy.all import Ether, IP, UDP, Raw, PcapWriter
    w = PcapWriter(path, sync=False)
    for i in range(n):
        s, d, sp, dp, _ = flow(i)
        ip_s = "%d.%d.%d.%d" % tuple(struct.pack("!I", s))
        ip_d = "%d.%d.%d.%d" % tuple(struct.pack("!I", d))
        w.write(Ether(src=SRC_MAC, dst=DST_MAC) / IP(src=ip_s, dst=ip_d) / UDP(sport=sp, dport=dp) / Raw(b"\0" * 18))
    w.close()


def sh(args, **kw):
    return subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True, **kw)


def ssh(cmd, timeout=60):
    return sh(["ssh", "-o", "BatchMode=yes", SWITCH, cmd], timeout=timeout).stdout


def bfrt(run_dir, label, *args):
    r = sh([os.path.join(HERE, "run_bfrt.sh"), run_dir, label] + list(args), env=dict(os.environ, SHOW_LINES="1"))
    path = os.path.join(run_dir, "bfrt", label + ".json")
    lines = open(path).read().splitlines() if os.path.exists(path) else []
    if r.returncode != 0 or not lines:
        raise RuntimeError("%s failed: %s" % (label, r.stdout[-400:]))
    return json.loads(lines[-1])


def kernel_counters():
    keys = ["rx_packets", "rx_dropped", "rx_missed_errors", "rx_fifo_errors"]
    out = ssh("cd /sys/class/net/enp5s0/statistics && cat " + " ".join(keys))
    return dict(zip(keys, (int(x) for x in out.split())))


def run_one(run_dir, rid, pcap, buckets, rate, k, rep):
    label = "r%d_rate%d" % (rep, rate)
    expected = set(buckets[:k])
    bfrt(run_dir, label + "_clear", "clear-regs", "--prog", "basic", "--sample", "20")
    c0 = bfrt(run_dir, label + "_ctr0", "cpu-counters")
    k0 = kernel_counters()
    raw = "/root/hazim_perf/runs/%s/%s.pcap" % (rid, label)
    ssh("(timeout 120 tcpdump -i enp5s0 -U -s 128 -w %s 'ether[0:2] = 0xbef1' > %s.log 2>&1 &)" % (raw, raw))
    collector = ReportCollector("enp5s0", ssh_host=SWITCH).start()
    time.sleep(2.5)
    speed = "--topspeed" if rate == 0 else "--pps=%d" % rate
    t0 = time.time()
    rp = sh([ASROOT, "tcpreplay", "-i", "eth1", speed, "--limit=%d" % k, pcap]).stdout
    send_s = time.time() - t0
    time.sleep(4)
    collector.stop()
    ssh("pkill -INT -f 'tcpdump -i enp5s0 -U -s 128 -w %s'; sleep 1" % raw)
    c1 = bfrt(run_dir, label + "_ctr1", "cpu-counters")
    k1 = kernel_counters()
    log = ssh("cat %s.log" % raw)
    local = os.path.join(run_dir, "raw", label + ".pcap")
    os.makedirs(os.path.dirname(local), exist_ok=True)
    sh(["scp", "-q", "-o", "BatchMode=yes", "%s:%s" % (SWITCH, raw), local])
    raw_reports = [parse_cpu_report(f) for _, f in iter_pcap_stream(open(local, "rb"))]
    raw_idx = [r["idx"] for r in raw_reports if r]
    coll = collector.take(0, float("inf"))
    coll_idx = set(r["idx"] for r in coll)
    m = re.search(r"Actual: (\d+) packets .* sent in ([\d.]+) seconds", rp)
    sent, secs = (int(m.group(1)), float(m.group(2))) if m else (None, None)
    drop = lambda c: c["tm_eg_port"]["192"]["drop_count_packets"]
    tcpdump_drop = re.search(r"(\d+) packets dropped by kernel", log)
    res = {
        "rep": rep, "rate_pps": rate, "flows": k, "expected_reports": len(expected),
        "pc1_sent": sent, "pc1_send_s": secs, "achieved_pps": (sent / secs) if sent and secs else None,
        "switch_rx132": c1["stats"]["132"]["$FramesReceivedOK"] - c0["stats"]["132"]["$FramesReceivedOK"],
        "tm_drops_cpu_port": drop(c1) - drop(c0),
        "tm_watermark_cells": c1["tm_eg_port"]["192"].get("watermark_cells"),
        "kernel_rx": k1["rx_packets"] - k0["rx_packets"],
        "kernel_drops": sum(k1[x] - k0[x] for x in ("rx_dropped", "rx_missed_errors", "rx_fifo_errors")),
        "raw_captured": len(raw_idx), "raw_distinct": len(set(raw_idx)),
        "raw_tcpdump_kernel_drops": int(tcpdump_drop.group(1)) if tcpdump_drop else None,
        "collector_reports": len(coll), "collector_distinct": len(coll_idx),
        "collector_missing_buckets": len(expected - coll_idx),
        "collector_unexpected_buckets": len(coll_idx - expected),
        "index_mismatches": sum(1 for r in coll if r["idx"] != r["idx_computed"]),
        "wall_s": round(send_s, 3),
    }
    return res


def summarize(run_dir):
    rows = [json.loads(l) for l in open(os.path.join(run_dir, "results.jsonl"))]
    out = {}
    for r in rows:
        out.setdefault(r["rate_pps"], []).append(r)
    summ = {}
    lines = ["| rate (new flows/s) | achieved | flows | expected reports | TM drops | kernel rx | raw capture | "
             "collector (distinct) | collector coverage |", "|---|---|---|---|---|---|---|---|---|"]
    for rate in sorted(out, key=lambda x: (x == 0, x)):
        rs = out[rate]
        med = lambda k: statistics.median(r[k] for r in rs)
        cov = [r["collector_distinct"] / r["expected_reports"] for r in rs]
        summ[rate] = {"runs": len(rs), "expected_reports_median": med("expected_reports"),
                      "achieved_pps_median": med("achieved_pps"), "tm_drops_median": med("tm_drops_cpu_port"),
                      "kernel_rx_median": med("kernel_rx"), "raw_captured_median": med("raw_captured"),
                      "collector_distinct_median": med("collector_distinct"),
                      "collector_coverage_min": min(cov), "collector_coverage_median": statistics.median(cov),
                      "index_mismatches_total": sum(r["index_mismatches"] for r in rs)}
        s = summ[rate]
        lines.append("| %s | %.0f | %d | %d | %d | %d | %d | %d | %.1f%% (min %.1f%%) |" % (
            "max (topspeed)" if rate == 0 else str(rate), s["achieved_pps_median"], med("flows"),
            s["expected_reports_median"], s["tm_drops_median"], s["kernel_rx_median"], s["raw_captured_median"],
            s["collector_distinct_median"], 100 * s["collector_coverage_median"], 100 * s["collector_coverage_min"]))
    json.dump(summ, open(os.path.join(run_dir, "summary.json"), "w"), indent=2)
    open(os.path.join(run_dir, "summary.md"), "w").write("\n".join(lines) + "\n")
    print("\n".join(lines))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("run_dir")
    ap.add_argument("--rates", default="1000,5000,10000,20000,50000,100000,200000,0")
    ap.add_argument("--reps", type=int, default=3)
    ap.add_argument("--max-flows", type=int, default=50000)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--summarize-only", action="store_true")
    a = ap.parse_args()
    if a.summarize_only:
        summarize(a.run_dir)
        return
    if not ASROOT:
        sys.exit("set ASROOT to the sudo wrapper (tcpreplay needs root)")
    rid = os.path.basename(os.path.normpath(a.run_dir))
    pcap = os.path.join(a.run_dir, "pcap", "new_flows.pcap")
    os.makedirs(os.path.dirname(pcap), exist_ok=True)
    if not os.path.exists(pcap):
        make_pcap(pcap, a.max_flows)
    buckets = [compute_flow_index(*flow(i)) for i in range(a.max_flows)]
    rates = [int(x) for x in a.rates.split(",")]
    rng = random.Random(a.seed)
    plan = []
    for rep in range(1, a.reps + 1):
        order = rates[:]
        rng.shuffle(order)
        plan.append({"rep": rep, "order": order})
    json.dump({"plan": plan, "max_flows": a.max_flows, "flow": "src 10.120.0.0+i, dst 10.121.0.1, "
               "sport 1024+i%50000, dport 4000+i%7, UDP, 64 B", "seed": a.seed},
              open(os.path.join(a.run_dir, "plan.json"), "w"), indent=2)
    with open(os.path.join(a.run_dir, "results.jsonl"), "a") as out:
        for p in plan:
            for rate in p["order"]:
                k = a.max_flows if rate == 0 else min(a.max_flows, rate * 20)
                res = run_one(a.run_dir, rid, pcap, buckets, rate, k, p["rep"])
                out.write(json.dumps(res) + "\n")
                out.flush()
                print("rep %d rate %s: %d flows, expected %d reports | TM drops %d | kernel rx %d | raw %d | "
                      "collector %d distinct (%.1f%%) | achieved %.0f pps" % (
                          p["rep"], rate or "max", k, res["expected_reports"], res["tm_drops_cpu_port"],
                          res["kernel_rx"], res["raw_captured"], res["collector_distinct"],
                          100.0 * res["collector_distinct"] / res["expected_reports"], res["achieved_pps"] or 0),
                      flush=True)
    summarize(a.run_dir)


if __name__ == "__main__":
    main()
