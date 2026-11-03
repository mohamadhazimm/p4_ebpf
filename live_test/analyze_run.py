#!/usr/bin/env python3
"""Compare one live collector run with what actually crossed the switch.

    analyze_run.py --csv RUN.csv --probe PROBE.json --ingress CAP1.pcap [CAP2.pcap ...]
                   --window-sec 10 [--truth TRUTH.json] --out ANALYSIS.json

Inputs: the collector's CSV and the collector_probe.py log of the same run, and
packet captures taken at the switch ingress (frames entering model ports 0
and 1). Optionally the ground truth of a replayed synthetic PCAP.

1. Packet accounting: truth, captured at the switch ingress, counted by P4.
2. Per flow (with --truth): the register totals of every flow bucket, summed
   over the clears the collector made, against the truth (exact).
3. Per window, additive counters: the CSV against the ingress capture cut at
   the moments the collector's reads actually snapshotted the registers
   (t_switch), and at the nominal window bounds global_t0 + k * window.
4. Per window, all 30 net_* features: the CSV against the offline extractor
   that built the dataset (analyze_p4_pcap_ablation.derive_p4_features) on the
   ingress capture, at the nominal bounds, with its default active TTL (3)
   and with the collector's (5).
"""
import argparse
import csv
import json
import math
import sys
import tempfile
import types
from datetime import datetime, timezone
from pathlib import Path

from scapy.all import IP, TCP, UDP, PcapReader, wrpcap

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "thesis-hybrid-ebpf-p4" / "python"))
from flow_index import compute_flow_index  # noqa: E402


def import_offline_extractor():
    """analyze_p4_pcap_ablation imports scikit-learn at module level for its
    model code; derive_p4_features does not use it. Without scikit-learn the
    names are stubbed so the extractor itself can run unchanged."""
    try:
        import sklearn  # noqa: F401
    except ImportError:
        names = {
            "sklearn.ensemble": ["RandomForestClassifier"],
            "sklearn.feature_selection": ["SelectKBest", "mutual_info_classif"],
            "sklearn.impute": ["SimpleImputer"],
            "sklearn.metrics": ["accuracy_score", "balanced_accuracy_score", "confusion_matrix", "f1_score",
                                "precision_score", "recall_score", "roc_auc_score"],
            "sklearn.model_selection": ["StratifiedGroupKFold"],
            "sklearn.pipeline": ["make_pipeline"],
        }
        sys.modules["sklearn"] = types.ModuleType("sklearn")
        for mod, attrs in names.items():
            m = types.ModuleType(mod)
            for a in attrs:
                setattr(m, a, None)
            sys.modules[mod] = m
    import analyze_p4_pcap_ablation as ab
    return ab


ADDITIVE = {
    "net_pkts_total_delta": "pkts", "net_bytes_total_delta": "bytes",
    "net_pkts_ab_delta": "pkts_ab", "net_bytes_ab_delta": "bytes_ab",
    "net_pkts_ba_delta": "pkts_ba", "net_bytes_ba_delta": "bytes_ba",
    "net_syn_delta": "syn", "net_ack_delta": "ack", "net_rst_delta": "rst",
}


def iso(t):
    return datetime.fromtimestamp(t, tz=timezone.utc).isoformat()


def load_ingress(paths):
    frames = []
    for p in paths:
        with PcapReader(str(p)) as r:
            for pk in r:
                frames.append(pk)
    frames.sort(key=lambda pk: float(pk.time))
    return frames


def eligible(pk):
    return IP in pk and (TCP in pk or UDP in pk)


def p4_view(pk, ref):
    """Counters one packet adds in the data plane (bytes = IPv4 totalLen);
    ref holds the first packet's ports per flow bucket (ingress.p4 direction)."""
    ip = pk[IP]
    l4 = pk[TCP] if TCP in pk else pk[UDP]
    sp, dp = int(l4.sport), int(l4.dport)
    idx = compute_flow_index(ip.src, ip.dst, sp, dp, int(ip.proto))
    r = ref.setdefault(idx, (sp, dp))
    ab = (sp == r[0] and dp == r[1]) or not (sp == r[1] and dp == r[0])
    tot = int(ip.len)
    flags = int(pk[TCP].flags) if TCP in pk else 0
    return idx, {"pkts": 1, "bytes": tot, "pkts_ab": int(ab), "bytes_ab": tot if ab else 0,
                 "pkts_ba": int(not ab), "bytes_ba": 0 if ab else tot,
                 "syn": int(bool(flags & 2)), "ack": int(bool(flags & 16)), "rst": int(bool(flags & 4))}


def per_window_counts(frames, edges):
    """Additive counters of the eligible frames in [edges[k], edges[k+1])."""
    out = [{k: 0 for k in ADDITIVE.values()} for _ in range(len(edges) - 1)]
    ref = {}
    for pk in frames:
        if not eligible(pk):
            continue
        idx, v = p4_view(pk, ref)
        t = float(pk.time)
        for k in range(len(edges) - 1):
            if edges[k] <= t < edges[k + 1]:
                for key, val in v.items():
                    out[k][key] += val
                break
    return out


REG_ORDER = ["reg_pkts", "reg_bytes", "reg_pkts_ab", "reg_bytes_ab", "reg_ref_src_port", "reg_ref_dst_port",
             "reg_dir_valid", "reg_min_len", "reg_max_len", "reg_first_ts", "reg_last_ts", "reg_syn",
             "reg_ack", "reg_rst"]
COUNTER_REG = {"pkts": "reg_pkts", "bytes": "reg_bytes", "syn": "reg_syn", "ack": "reg_ack", "rst": "reg_rst"}


def cell_read_time(rd, pos, reg):
    """Estimated moment a read took register reg of the bucket at position pos
    (read_registers_with_index.py: sync copies the registers one after the
    other, then reads the copy; hw reads bucket by bucket, register by register)."""
    j = REG_ORDER.index(reg)
    if rd["snapshot"] == "sync" and rd["sync_s"]:
        n_sync = len(REG_ORDER) + (1 if rd["dst_rows"] else 0)
        return rd["t_switch"] + (j + 0.5) * rd["sync_s"] / n_sync
    n = max(1, len(rd["rows"]))
    cell = (rd["read_s"] or 0) / (n * len(REG_ORDER))
    return rd["t_switch"] + (pos * len(REG_ORDER) + j + 0.5) * cell


def per_window_read_model(frames, reads):
    """What the collector's per-window deltas must be: for every bucket a read
    includes, the packets that arrived between the moment the previous read
    of that bucket took the register and the moment this read took it.
    Assumes no bucket was cleared (--clear-idle-windows 0)."""
    times = {}
    ref = {}
    for pk in frames:
        if eligible(pk):
            idx, v = p4_view(pk, ref)
            times.setdefault(idx, []).append((float(pk.time), v))
    out = []
    last_read = {}
    for rd in reads:
        acc = {k: 0 for k in COUNTER_REG}
        for pos, row in enumerate(rd["rows"]):
            idx = row["idx"]
            for key, reg in COUNTER_REG.items():
                t_now = cell_read_time(rd, pos, reg)
                prev = last_read.get(idx)
                t_prev = cell_read_time(prev[0], prev[1], reg) if prev else -math.inf
                acc[key] += sum(v[key] for t, v in times.get(idx, []) if t_prev < t <= t_now)
        for pos, row in enumerate(rd["rows"]):
            last_read[row["idx"]] = (rd, pos)
        out.append(acc)
    return out


def flow_totals_from_reads(reads):
    """Per bucket, the counters summed over the segments between clears."""
    totals = {}
    last = {}
    for rd in reads:
        rows = {r["idx"]: r for r in rd["rows"]}
        for idx, r in rows.items():
            last[idx] = r
        for idx in rd.get("cleared", []):
            seg = rows[idx]
            acc = totals.setdefault(idx, {"segments": 0})
            add_segment(acc, seg)
            last.pop(idx, None)
    for idx, r in last.items():
        acc = totals.setdefault(idx, {"segments": 0})
        add_segment(acc, r)
    return totals


def add_segment(acc, r):
    acc["segments"] += 1
    for k in ("pkts", "bytes", "pkts_ab", "bytes_ab", "syn", "ack", "rst"):
        acc[k] = acc.get(k, 0) + int(r.get(k, 0))
    if r.get("min_len"):
        acc["min_len"] = min(acc.get("min_len", 1 << 30), int(r["min_len"]))
    acc["max_len"] = max(acc.get("max_len", 0), int(r.get("max_len", 0)))


def fmt(x):
    if isinstance(x, float):
        return f"{x:.4g}"
    return str(x)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", help="the run's CSV; if absent, the net_* rows are rebuilt from the probe log")
    ap.add_argument("--probe", required=True)
    ap.add_argument("--ingress", nargs="+", required=True)
    ap.add_argument("--window-sec", type=float, required=True)
    ap.add_argument("--truth")
    ap.add_argument("--workload-match", default="replay_pcaps_with_index.py",
                    help="substring of the workload's argv in the probe's process log")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    probe = json.load(open(args.probe))
    W = args.window_sec
    if args.csv and Path(args.csv).exists():
        rows = list(csv.DictReader(open(args.csv)))
    else:
        # The run aborted before writing its CSV: rebuild the net_* columns
        # from the logged reads with the collector's own summary function.
        import hybrid_collector as hc
        net_windows = [{"rows": rd["rows"], "dst_rows": rd["dst_rows"], "cleared_indexes": rd["cleared"]}
                       for rd in probe["reads"]]
        rows = [{**{k: str(v) for k, v in s.items()}, "cpu_index_count": "0"}
                for s in hc.build_net_summaries(net_windows, W)]
        print(f"[analyze] no CSV: {len(rows)} windows rebuilt from the probe log with build_net_summaries")
    starts = [p["t"] for p in probe["popen"] if any(args.workload_match in a for a in
                                                     (p["args"] if isinstance(p["args"], list) else [p["args"]]))]
    if not starts:
        sys.exit("workload start not found in the probe log")
    t0 = starts[0]
    reads = probe["reads"]
    n = len(reads)
    if len(rows) != n:
        # build_rows pairs host and net windows by index; rows past the last
        # register read carry host features and NET_ZERO network features.
        extra = rows[n:]
        print(f"[analyze] {len(rows)} CSV rows for {n} register reads: rows {n}..{len(rows) - 1} have "
              f"host features and all-zero net features "
              f"(net_pkts_total_delta={[r.get('net_pkts_total_delta') for r in extra]})")
        rows = rows[:n]
    frames = load_ingress(args.ingress)
    elig = [pk for pk in frames if eligible(pk)]
    res = {"global_t0": t0, "windows": n, "window_sec": W}

    # ---- 1. accounting
    p4_pkts = sum(int(float(r["net_pkts_total_delta"])) for r in rows)
    last_snap = reads[-1]["t_switch"]
    acc = {
        "ingress_frames": len(frames),
        "ingress_eligible_ipv4_tcp_udp": len(elig),
        "ingress_eligible_before_last_snapshot": sum(1 for pk in elig if float(pk.time) < last_snap),
        "p4_csv_pkts_total": p4_pkts,
        "csv_report_indexes": sum(int(r["cpu_index_count"]) for r in rows),
    }
    if args.truth:
        truth = json.load(open(args.truth))
        acc["truth_packets"] = truth["packets"]
        acc["truth_flows"] = len(truth["flows"])
    res["accounting"] = acc
    print("== packet accounting")
    for k, v in acc.items():
        print(f"  {k:42s} {v}")

    # ---- timing of the reads
    timing = []
    for k, rd in enumerate(reads):
        nominal_end = t0 + (k + 1) * W
        timing.append({"window": k, "call_delay_s": rd["call_start"] - nominal_end,
                       "snapshot_delay_s": (rd["t_switch"] - nominal_end) if rd["t_switch"] else None,
                       "read_wall_s": rd["call_end"] - rd["call_start"], "sync_s": rd["sync_s"],
                       "rows": len(rd["rows"]), "cleared": len(rd["cleared"]), "errors": len(rd["errors"])})
    res["read_timing"] = timing
    print("== register reads (delays after the nominal window end)")
    print("  win  snapshot_delay_s  read_wall_s  sync_s  rows  cleared  errors")
    for t in timing:
        print(f"  {t['window']:3d}  {fmt(t['snapshot_delay_s']):>16s}  {t['read_wall_s']:11.2f}  "
              f"{fmt(t['sync_s']):>6s}  {t['rows']:4d}  {t['cleared']:7d}  {t['errors']:6d}")

    # ---- 2. per flow
    if args.truth:
        got = flow_totals_from_reads(reads)
        flow_res = {"exact": 0, "mismatch": [], "never_read": []}
        for f in truth["flows"]:
            g = got.get(f["flow_index"])
            if g is None:
                flow_res["never_read"].append(f["first"])
                continue
            keys = ("pkts", "bytes", "pkts_ab", "bytes_ab", "syn", "ack", "rst", "min_len", "max_len")
            diff = {k: (g.get(k), f[k]) for k in keys if g.get(k) != f[k]}
            if diff:
                flow_res["mismatch"].append({"flow": f["first"], "idx": f["flow_index"], "diff": diff,
                                             "segments": g["segments"]})
            else:
                flow_res["exact"] += 1
        res["per_flow"] = flow_res
        print(f"== per flow: {flow_res['exact']}/{len(truth['flows'])} flows exact, "
              f"{len(flow_res['mismatch'])} mismatched, {len(flow_res['never_read'])} never read")
        for m in flow_res["mismatch"][:8]:
            print(f"  mismatch {m['flow']} idx={m['idx']} segments={m['segments']} (got, truth): {m['diff']}")
        for f in flow_res["never_read"][:8]:
            print(f"  never read: {f}")

    # ---- 3. per window additive counters
    snap_edges = [t0] + [rd["t_switch"] for rd in reads]
    nominal_edges = [t0 + k * W for k in range(n + 1)]
    by_snap = per_window_counts(frames, snap_edges)
    by_nominal = per_window_counts(frames, nominal_edges)
    pw = []
    print("== per window, additive counters: CSV | capture cut at snapshots | capture cut at nominal bounds")
    print("  win   pkts: csv  snap  nominal    bytes: csv    snap  nominal    syn: csv snap nom")
    exact_snap = True
    for k, r in enumerate(rows):
        csvv = {key: int(float(r[col])) for col, key in ADDITIVE.items()}
        ok = all(csvv[key] == by_snap[k][key] for key in ADDITIVE.values())
        exact_snap &= ok
        pw.append({"window": k, "csv": csvv, "snapshot_cut": by_snap[k], "nominal_cut": by_nominal[k],
                   "csv_equals_snapshot_cut": ok})
        print(f"  {k:3d}  {csvv['pkts']:9d} {by_snap[k]['pkts']:5d} {by_nominal[k]['pkts']:8d}  "
              f"{csvv['bytes']:12d} {by_snap[k]['bytes']:7d} {by_nominal[k]['bytes']:8d}  "
              f"{csvv['syn']:8d} {by_snap[k]['syn']:4d} {by_nominal[k]['syn']:3d}  {'=' if ok else 'DIFF'}")
    res["per_window_additive"] = pw
    res["csv_equals_capture_at_snapshots"] = exact_snap
    print(f"  CSV equals the capture cut at the snapshot moments in every window: {exact_snap}")

    if not any(rd["cleared"] for rd in reads):
        model = per_window_read_model(frames, reads)
        print("== per window: CSV against the capture cut at each bucket's own read moments")
        print("  win   pkts csv/model   bytes csv/model        syn csv/model  ack csv/model  rst csv/model")
        exact_model = True
        for k, r in enumerate(rows):
            csvv = {key: int(float(r[col])) for col, key in ADDITIVE.items()}
            ok = all(csvv[key] == model[k][key] for key in COUNTER_REG)
            exact_model &= ok
            pw[k]["read_model"] = model[k]
            print(f"  {k:3d}  {csvv['pkts']:5d}/{model[k]['pkts']:<5d}  {csvv['bytes']:8d}/{model[k]['bytes']:<8d}  "
                  f"{csvv['syn']:6d}/{model[k]['syn']:<6d} {csvv['ack']:6d}/{model[k]['ack']:<6d} "
                  f"{csvv['rst']:4d}/{model[k]['rst']:<4d} {'=' if ok else 'DIFF'}")
        res["csv_equals_read_model"] = exact_model
        print(f"  CSV equals the per-bucket read model in every window: {exact_model}")

    # ---- 4. offline extractor
    ab = import_offline_extractor()
    with tempfile.TemporaryDirectory() as d:
        merged = Path(d) / "ingress.pcap"
        wrpcap(str(merged), frames)
        tele = []
        for k in range(n):
            lo, hi = nominal_edges[k], nominal_edges[k + 1]
            tele.append({"window_start_utc": iso(lo), "window_end_utc": iso(hi),
                         "net_packets_captured": str(sum(1 for pk in frames if lo <= float(pk.time) < hi))})
        meta = {"window_seconds": W, "started_at_utc": iso(t0), "finished_at_utc": iso(nominal_edges[-1]),
                "sample_started_at_utc": iso(t0)}
        offline = {}
        for ttl in (3, 5):
            _, per_window, diag = ab.derive_p4_features(merged, tele, meta, active_ttl_windows=ttl)
            offline[ttl] = (per_window, diag)
    feats = ab.P4_FEATURES
    cmp_rows = []
    for feat in feats:
        live = [float(r[feat]) for r in rows]
        entry = {"feature": feat, "live_sum": sum(live)}
        for ttl, (per_window, diag) in offline.items():
            off = [float(w[feat]) for w in per_window] if per_window else [math.nan] * n
            entry[f"offline_ttl{ttl}_sum"] = sum(off)
            entry[f"windows_equal_ttl{ttl}"] = sum(1 for a, b in zip(live, off) if math.isclose(a, b, rel_tol=1e-9, abs_tol=1e-9))
            denom = sum(abs(b) for b in off)
            entry[f"rel_diff_ttl{ttl}"] = (sum(abs(a - b) for a, b in zip(live, off)) / denom) if denom else (
                0.0 if not any(live) else math.inf)
        cmp_rows.append(entry)
    res["offline_alignment"] = {ttl: diag.get("alignment_status") for ttl, (_, diag) in offline.items()}
    res["offline_comparison"] = cmp_rows
    print(f"== all 30 features vs the offline extractor at nominal bounds "
          f"(alignment: {res['offline_alignment']})")
    print(f"  {'feature':28s} {'live sum':>14s} {'offline sum':>14s} {'eq win':>6s} {'rel diff':>9s}"
          f" | {'offline ttl5':>13s} {'eq':>3s} {'rel':>8s}")
    for e in cmp_rows:
        print(f"  {e['feature']:28s} {e['live_sum']:14.6g} {e['offline_ttl3_sum']:14.6g} "
              f"{e['windows_equal_ttl3']:3d}/{n:<2d} {e['rel_diff_ttl3']:9.3g} | {e['offline_ttl5_sum']:13.6g} "
              f"{e['windows_equal_ttl5']:3d} {e['rel_diff_ttl5']:8.3g}")
    Path(args.out).write_text(json.dumps(res, indent=1, default=str))
    print(f"-> {args.out}")


if __name__ == "__main__":
    main()
