#!/usr/bin/env python3
"""Check a run of hybrid_collector.py --switch-program sweep --sockowner (PC1.md part 10): do the socket-level
joins partition the window-level rows?

    check_sweep_sockjoin.py --window OUT.csv --socket OUT.socket.csv [--also OUT.socket.NAME.csv ...] [--run-id ID]

Every bucket of a window belongs to at most one cgroup in the socket join (the local 5-tuple with the bucket's
reference ports), so for each window the additive columns of the window-level row (packets, bytes and flags, in
total and per direction, and the flow counts) equal the sum over the socket-joined rows of the monitored cgroup and
of every --also cgroup, plus whatever no listed cgroup owns (other processes, or traffic without a local socket).
That remainder is printed per window; it is zero when the listed cgroups made all the traffic that crossed the
switch. With no --also, a run whose monitored program was alone gives socket rows equal to the window rows in all
29 features, which is also checked.

Prints a table and a JSON summary (--json); exits 0 when every window's remainder is zero (or --allow-remainder).
Python 3, standard library only.
"""
import argparse
import csv
import json
import sys

ADDITIVE = ["net_pkts_total_delta", "net_bytes_total_delta", "net_pkts_ab_delta", "net_bytes_ab_delta",
            "net_pkts_ba_delta", "net_bytes_ba_delta", "net_syn_delta", "net_ack_delta", "net_rst_delta",
            "net_flow_count_seen", "net_flows_with_ab", "net_flows_with_ba", "net_dir_valid_count"]
FEATURES = [
    "net_flow_count_seen", "net_pkts_total_delta", "net_bytes_total_delta", "net_pkts_ab_delta",
    "net_bytes_ab_delta", "net_pkts_ba_delta", "net_bytes_ba_delta", "net_min_len_mean", "net_max_len_mean",
    "net_min_len_min", "net_max_len_max", "net_avg_pkt_size_delta", "net_avg_pkt_size_ab_delta",
    "net_avg_pkt_size_ba_delta", "net_flow_duration_mean", "net_flow_duration_max", "net_bytes_per_sec_delta",
    "net_pkts_per_sec_delta", "net_down_up_ratio_delta", "net_ab_ratio_pkt_delta", "net_ba_ratio_pkt_delta",
    "net_ab_ratio_byte_delta", "net_ba_ratio_byte_delta", "net_syn_delta", "net_ack_delta", "net_rst_delta",
    "net_flows_with_ab", "net_flows_with_ba", "net_dir_valid_count",
]
DIAGNOSTICS = ["net_sock_owned_buckets", "net_sock_shared_active", "net_sock_hidden_flows", "net_sweep_merged_active",
               "net_sweep_coll_pkts", "net_sweep_totals_mismatch"]


def read_rows(path, run_id=None):
    """{window_id: row} of one run (the last run in the file without run_id)."""
    with open(path, newline="") as f:
        rows = list(csv.DictReader(f))
    if not rows:
        raise SystemExit("%s: no rows" % path)
    run = run_id if run_id is not None else rows[-1]["run_id"]
    out = {int(r["window_id"]): r for r in rows if r["run_id"] == run}
    if not out:
        raise SystemExit("%s: no rows of run %s" % (path, run))
    return run, out


def num(row, key):
    try:
        return float(row.get(key, 0) or 0)
    except ValueError:
        return 0.0


def close(a, b):
    return abs(a - b) <= 1e-9 * max(1.0, abs(a), abs(b))


def check(window_rows, socket_rows, also_rows):
    """Per-window comparison: dict(window -> {col: (window, socket, also..., remainder)}), and the summary."""
    windows = sorted(window_rows)
    per = []
    for w in windows:
        wr = window_rows[w]
        parts = [socket_rows.get(w, {})] + [a.get(w, {}) for a in also_rows]
        rec = {"window": w, "remainder": {}, "diagnostics": {}}
        for col in ADDITIVE:
            total = num(wr, col)
            joined = sum(num(p, col) for p in parts)
            rec["remainder"][col] = total - joined
        rec["diagnostics"] = {k: num(socket_rows.get(w, {}), k) for k in DIAGNOSTICS}
        if not also_rows:
            rec["equal_features"] = all(close(num(wr, f), num(socket_rows.get(w, {}), f)) for f in FEATURES)
        per.append(rec)
    nonzero = [r["window"] for r in per if any(abs(v) > 1e-9 for v in r["remainder"].values())]
    summary = {
        "windows": len(per),
        "windows_with_a_remainder": len(nonzero),
        "remainder_windows": nonzero[:40],
        "packets": {"window": sum(num(window_rows[w], "net_pkts_total_delta") for w in windows),
                    "socket": sum(num(socket_rows.get(w, {}), "net_pkts_total_delta") for w in windows),
                    "also": [sum(num(a.get(w, {}), "net_pkts_total_delta") for w in windows) for a in also_rows]},
        "owned_buckets_at_end": num(socket_rows.get(windows[-1], {}), "net_sock_owned_buckets") if windows else 0,
        "windows_with_shared_buckets": sum(1 for r in per if r["diagnostics"]["net_sock_shared_active"] > 0),
        "hidden_flows_at_end": per[-1]["diagnostics"]["net_sock_hidden_flows"] if per else 0,
        "windows_with_merged_owned_buckets": sum(1 for r in per if r["diagnostics"]["net_sweep_merged_active"] > 0),
        "windows_with_a_totals_mismatch": sum(1 for r in per if r["diagnostics"]["net_sweep_totals_mismatch"] == 1),
    }
    if not also_rows:
        summary["windows_with_equal_features"] = sum(1 for r in per if r["equal_features"])
    return per, summary


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--window", required=True, help="the collector's --out-csv (window-level rows)")
    ap.add_argument("--socket", required=True, help="the socket-join CSV of the monitored cgroup")
    ap.add_argument("--also", action="append", default=[], help="a --socket-join-also CSV (repeatable)")
    ap.add_argument("--run-id", help="the run to check (default: the last run of --window)")
    ap.add_argument("--json", help="write the per-window comparison and the summary here")
    ap.add_argument("--allow-remainder", action="store_true",
                    help="exit 0 even when traffic of unlisted sockets remains in some window")
    a = ap.parse_args(argv)
    run, window_rows = read_rows(a.window, a.run_id)
    _, socket_rows = read_rows(a.socket, run)
    also_rows = [read_rows(p, run)[1] for p in a.also]
    per, summary = check(window_rows, socket_rows, also_rows)
    print("run %s: %d windows" % (run, summary["windows"]))
    print("%6s %10s %10s %s %10s" % ("window", "pkts", "socket", " ".join("%10s" % ("also%d" % i)
                                                                         for i in range(len(also_rows))), "remainder"))
    for r in per:
        w = r["window"]
        print("%6d %10.0f %10.0f %s %10.0f" % (w, num(window_rows[w], "net_pkts_total_delta"),
                                               num(socket_rows.get(w, {}), "net_pkts_total_delta"),
                                               " ".join("%10.0f" % num(x.get(w, {}), "net_pkts_total_delta")
                                                        for x in also_rows),
                                               r["remainder"]["net_pkts_total_delta"]))
    print(json.dumps(summary, indent=1))
    if a.json:
        with open(a.json, "w") as f:
            json.dump({"run_id": run, "summary": summary, "windows": per}, f, indent=1)
    return 0 if (summary["windows_with_a_remainder"] == 0 or a.allow_remainder) else 1


if __name__ == "__main__":
    sys.exit(main())
