#!/usr/bin/env python3
"""Phase 2.3: packet rate and loss through the switch at RFC 2544 frame sizes.

    run_pktrate.py RUN_DIR --prog basic [--regs] [--reps 5] [--duration 20] [--seed 1]
    run_pktrate.py RUN_DIR --summarize-only

Every repetition replays all frame sizes in a shuffled order (seeded; the order
is recorded). One measurement is:
  1. switch snapshot: port counters of dev_port 132 (from PC1) and 140 (to PC2),
     and with --regs reg_pkts/reg_bytes/reg_pkts_ab of this size's flow bucket
  2. PC1: /proc/stat and eth1 PHY counters, `tcpreplay --topspeed --preload-pcap
     --loop=0 --duration=D` (as root), PHY counters and /proc/stat again
  3. a second switch snapshot
Each size has its own UDP flow (source port 32000 + size), hence its own
register bucket, so with --regs the detector's per-flow packet count is checked
against the switch's port counter under load. Offered load is PC1's PHY
counter (on the wire, FCS included), not tcpreplay's own count. Commands are
logged by logrun.sh/run_bfrt.sh; one JSON object per measurement goes to
RUN_DIR/results.jsonl, the summary to RUN_DIR/summary.json and summary.md.
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
sys.path.insert(0, HERE)
from hash_matrix_check import crc16_arc  # noqa: E402

SIZES = [64, 128, 256, 512, 1024, 1280, 1518]        # wire bytes, FCS included
SRC_MAC, DST_MAC = "04:3f:72:d2:ec:5e", "02:00:00:00:00:02"
SIP, DIP, DPORT = "10.99.2.1", "10.99.2.2", 9
ASROOT = os.environ.get("ASROOT", "")
PHY_KEYS = ["tx_packets_phy", "tx_bytes_phy", "tx_discards_phy", "tx_errors_phy",
            "tx_queue_dropped", "rx_packets_phy"]
LINE_RATE = 100e9


def flow_index(size):
    a = struct.unpack("!I", bytes(int(x) for x in SIP.split(".")))[0]
    b = struct.unpack("!I", bytes(int(x) for x in DIP.split(".")))[0]
    return crc16_arc(struct.pack("!IIHHB", a, b, 32000 + size, DPORT, 17))


def make_pcaps(pcap_dir, frames=2000):
    from scapy.all import Ether, IP, UDP, Raw, wrpcap
    os.makedirs(pcap_dir, exist_ok=True)
    info = {}
    for size in SIZES:
        path = os.path.join(pcap_dir, "udp_%d.pcap" % size)
        base = Ether(src=SRC_MAC, dst=DST_MAC) / IP(src=SIP, dst=DIP, ttl=64) / \
            UDP(sport=32000 + size, dport=DPORT)
        pkt = Ether(bytes(base / Raw(b"\x00" * (size - 4 - len(base)))))
        assert len(pkt) == size - 4
        if not os.path.exists(path):
            wrpcap(path, [pkt] * frames)
        info[size] = {"pcap": path, "frames": frames, "pcap_frame_bytes": len(pkt),
                      "ipv4_total_len": pkt[IP].len, "flow": [SIP, DIP, 32000 + size, DPORT, 17],
                      "bucket": flow_index(size)}
    return info


def sh(args, **kw):
    return subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          universal_newlines=True, **kw)


def snapshot(run_dir, label, prog, idx):
    args = [os.path.join(HERE, "run_bfrt.sh"), run_dir, label, "snapshot",
            "--ports", "132,140", "--prog", prog]
    if idx is not None:
        args += ["--idx", str(idx)]
    r = sh(args, env=dict(os.environ, SHOW_LINES="1"))
    path = os.path.join(run_dir, "bfrt", label + ".json")
    lines = open(path).read().splitlines() if os.path.exists(path) else []
    if r.returncode != 0 or not lines:
        raise RuntimeError("snapshot %s failed: %s" % (label, r.stdout[-500:]))
    return json.loads(lines[-1])


def parse_replay(text):
    def phy(tag):
        return {k: int(v) for k, v in re.findall(r"^%s\s+(\w+): (\d+)$" % tag, text, re.M)}

    def cpu(tag):
        out = {}
        for name, *vals in re.findall(r"^%s (cpu\d*) (\d+) (\d+) (\d+) (\d+) (\d+) (\d+) (\d+) (\d+)"
                                      % tag, text, re.M):
            v = [int(x) for x in vals]
            out[name] = {"busy": sum(v) - v[3] - v[4], "total": sum(v)}
        return out

    m = re.search(r"Actual: (\d+) packets \((\d+) bytes\) sent in ([\d.]+) seconds", text)
    rep = {"tcpreplay_packets": int(m.group(1)), "tcpreplay_bytes": int(m.group(2)),
           "send_s": float(m.group(3))} if m else {}
    for key, pat in (("failed", r"Failed packets:\s+(\d+)"),
                     ("retried_enobufs", r"Retried packets \(ENOBUFS\):\s+(\d+)"),
                     ("retried_eagain", r"Retried packets \(EAGAIN\):\s+(\d+)")):
        mm = re.search(pat, text)
        if mm:
            rep[key] = int(mm.group(1))
    b, a = phy("BEFORE"), phy("AFTER")
    rep["pc1_phy_delta"] = {k: a.get(k, 0) - b.get(k, 0) for k in PHY_KEYS}
    cb, ca = cpu("BEFORE"), cpu("AFTER")
    rep["pc1_cpu_busy"] = {c: round((ca[c]["busy"] - cb[c]["busy"]) /
                                    max(1, ca[c]["total"] - cb[c]["total"]), 3) for c in ca}
    return rep


def replay(run_dir, label, pcap, duration, rate_opt="--topspeed"):
    cmd = ("sed 's/^/BEFORE /' /proc/stat | grep '^BEFORE cpu'; "
           "ethtool -S eth1 | sed -n 's/^ *\\(%s\\): /BEFORE \\1: /p'; "
           "%s tcpreplay -i eth1 %s --preload-pcap --loop=0 --duration=%d %s 2>&1 "
           "| grep -vE '^Warning|interface.c'; "
           "ethtool -S eth1 | sed -n 's/^ *\\(%s\\): /AFTER \\1: /p'; "
           "sed 's/^/AFTER /' /proc/stat | grep '^AFTER cpu'"
           % ("\\|".join(PHY_KEYS), ASROOT, rate_opt, duration, pcap, "\\|".join(PHY_KEYS)))
    r = sh([os.path.join(HERE, "logrun.sh"), run_dir, label, cmd],
           env=dict(os.environ, SHOW_LINES="0"))
    log = sorted(f for f in os.listdir(run_dir) if f.endswith("_%s.txt" % label))[-1]
    return parse_replay(open(os.path.join(run_dir, log)).read())


def stat_delta(before, after, dp, key):
    return (after["stats"][dp][key] or 0) - (before["stats"][dp][key] or 0)


def measure(run_dir, prog, regs, rep, size, info, duration):
    label = "r%d_s%d" % (rep, size)
    idx = info["bucket"] if regs else None
    s0 = snapshot(run_dir, label + "_snap0", prog, idx)
    rp = replay(run_dir, label + "_replay", info["pcap"], duration)
    time.sleep(0.5)
    s1 = snapshot(run_dir, label + "_snap1", prog, idx)
    res = {"prog": prog, "rep": rep, "size": size, "label": label, "t_utc": time.time()}
    res.update(rp)
    sw = {"rx132_ok": stat_delta(s0, s1, "132", "$FramesReceivedOK"),
          "rx132_all": stat_delta(s0, s1, "132", "$FramesReceivedAll"),
          "rx132_fcs_err": stat_delta(s0, s1, "132", "$FramesReceivedwithFCSError"),
          "rx132_drop_buffer_full": stat_delta(s0, s1, "132", "$FramesDroppedBufferFull"),
          "tx140_ok": stat_delta(s0, s1, "140", "$FramesTransmittedOK"),
          "tx140_err": stat_delta(s0, s1, "140", "$FramesTransmittedwithError"),
          "rx132_octets": stat_delta(s0, s1, "132", "$OctetsReceivedinGoodFrames"),
          "tx140_octets": stat_delta(s0, s1, "140", "$OctetsTransmittedwithouterror")}
    res["switch"] = sw
    res["snapshot_errors"] = s0["errors"] + s1["errors"]
    tx = rp["pc1_phy_delta"]["tx_packets_phy"]
    t = rp.get("send_s") or float(duration)
    res["offered_pps"] = tx / t
    res["offered_l2_gbps"] = rp["pc1_phy_delta"]["tx_bytes_phy"] * 8 / t / 1e9
    res["offered_l1_gbps"] = (rp["pc1_phy_delta"]["tx_bytes_phy"] + 20 * tx) * 8 / t / 1e9
    res["line_rate_pps"] = LINE_RATE / ((size + 20) * 8)
    res["fraction_of_line_rate"] = res["offered_pps"] / res["line_rate_pps"]
    res["link_loss"] = tx - sw["rx132_ok"]
    res["switch_loss"] = sw["rx132_ok"] - sw["tx140_ok"]
    if regs:
        i = str(info["bucket"])
        r0, r1 = s0["regs"].get(i, {}), s1["regs"].get(i, {})

        def d(name):
            return (r1[name][1] - r0[name][1]) % (1 << 32)
        try:
            res["regs"] = {"bucket": info["bucket"], "d_reg_pkts": d("reg_pkts"),
                           "d_reg_bytes_mod32": d("reg_bytes"), "d_reg_pkts_ab": d("reg_pkts_ab"),
                           "expected_bytes_mod32": (sw["rx132_ok"] * info["ipv4_total_len"]) % (1 << 32)}
            res["regs"]["pkts_match_rx132"] = res["regs"]["d_reg_pkts"] == sw["rx132_ok"] % (1 << 32)
            res["regs"]["bytes_match"] = res["regs"]["d_reg_bytes_mod32"] == res["regs"]["expected_bytes_mod32"]
        except (KeyError, IndexError) as e:
            res["regs"] = {"error": "register values missing: %s" % e}
    return res


def summarize(run_dir):
    rows = [json.loads(l) for l in open(os.path.join(run_dir, "results.jsonl"))]
    out = {}
    for prog in sorted({r["prog"] for r in rows}):
        out[prog] = {}
        for size in SIZES:
            rs = [r for r in rows if r["prog"] == prog and r["size"] == size]
            if not rs:
                continue

            def med(key):
                return statistics.median(r[key] for r in rs)
            out[prog][size] = {
                "n": len(rs),
                "offered_mpps_median": med("offered_pps") / 1e6,
                "offered_mpps_min": min(r["offered_pps"] for r in rs) / 1e6,
                "offered_mpps_max": max(r["offered_pps"] for r in rs) / 1e6,
                "offered_l1_gbps_median": med("offered_l1_gbps"),
                "fraction_of_line_rate_median": med("fraction_of_line_rate"),
                "switch_loss_total": sum(r["switch_loss"] for r in rs),
                "link_loss_total": sum(r["link_loss"] for r in rs),
                "drop_buffer_full_total": sum(r["switch"]["rx132_drop_buffer_full"] for r in rs),
                "frames_through_switch": sum(r["switch"]["tx140_ok"] for r in rs),
                "pc1_cpu_busy_max_median": statistics.median(
                    max(v for k, v in r["pc1_cpu_busy"].items() if k != "cpu") for r in rs),
                "tcpreplay_failed_total": sum(r.get("failed", 0) for r in rs),
                "regs_pkts_match": (sum(1 for r in rs if r.get("regs", {}).get("pkts_match_rx132"))
                                    if any("regs" in r for r in rs) else None),
                "regs_bytes_match": (sum(1 for r in rs if r.get("regs", {}).get("bytes_match"))
                                     if any("regs" in r for r in rs) else None),
            }
    json.dump(out, open(os.path.join(run_dir, "summary.json"), "w"), indent=2)
    md = ["| program | frame B | n | offered Mpps median (min–max) | offered Gb/s L1 | % of 100G line rate "
          "| switch loss | link loss | buffer-full drops | PC1 busiest vCPU | detector count = port count |",
          "|---|---|---|---|---|---|---|---|---|---|---|"]
    for prog, sizes in out.items():
        for size, s in sizes.items():
            regs = ("%d/%d pkts, %d/%d bytes" % (s["regs_pkts_match"], s["n"], s["regs_bytes_match"], s["n"])
                    if s["regs_pkts_match"] is not None else "–")
            md.append("| %s | %d | %d | %.3f (%.3f–%.3f) | %.2f | %.2f%% | %d | %d | %d | %.0f%% | %s |" % (
                prog, size, s["n"], s["offered_mpps_median"], s["offered_mpps_min"],
                s["offered_mpps_max"], s["offered_l1_gbps_median"],
                100 * s["fraction_of_line_rate_median"], s["switch_loss_total"], s["link_loss_total"],
                s["drop_buffer_full_total"], 100 * s["pc1_cpu_busy_max_median"], regs))
    open(os.path.join(run_dir, "summary.md"), "w").write("\n".join(md) + "\n")
    print("\n".join(md))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("run_dir")
    ap.add_argument("--prog", default="basic")
    ap.add_argument("--regs", action="store_true")
    ap.add_argument("--reps", type=int, default=5)
    ap.add_argument("--duration", type=int, default=20)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--sizes", default=",".join(map(str, SIZES)))
    ap.add_argument("--summarize-only", action="store_true")
    a = ap.parse_args()
    sizes = [int(s) for s in a.sizes.split(",")]
    if a.summarize_only:
        summarize(a.run_dir)
        return
    if not ASROOT:
        sys.exit("set ASROOT to the sudo wrapper (tcpreplay needs root)")
    info = make_pcaps(os.path.join(a.run_dir, "pcap"))
    rng = random.Random(a.seed)
    plan = []
    for rep in range(1, a.reps + 1):
        order = sizes[:]
        rng.shuffle(order)
        plan.append({"rep": rep, "order": order})
    json.dump({"prog": a.prog, "regs": a.regs, "duration_s": a.duration, "seed": a.seed,
               "plan": plan, "flows": info},
              open(os.path.join(a.run_dir, "plan_%s.json" % a.prog), "w"), indent=2)
    with open(os.path.join(a.run_dir, "results.jsonl"), "a") as out:
        for p in plan:
            for size in p["order"]:
                res = measure(a.run_dir, a.prog, a.regs, p["rep"], size, info[size], a.duration)
                out.write(json.dumps(res) + "\n")
                out.flush()
                rg = res.get("regs", {})
                print("%s rep %d size %4d: %.3f Mpps offered (%.2f%% of line rate), switch loss %d, "
                      "link loss %d, cpu %s%s" % (
                          a.prog, p["rep"], size, res["offered_pps"] / 1e6,
                          100 * res["fraction_of_line_rate"], res["switch_loss"], res["link_loss"],
                          res["pc1_cpu_busy"],
                          (", regs pkts %s bytes %s" % (rg.get("pkts_match_rx132"), rg.get("bytes_match")))
                          if a.regs else ""), flush=True)
    summarize(a.run_dir)


if __name__ == "__main__":
    main()
