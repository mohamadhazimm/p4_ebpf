#!/usr/bin/env python3
"""A/B of the legacy and the batched register reader on the same live traffic.

    # on the Tofino model of this machine (testbed up, traffic running)
    sudo python3 live_test/reader_ab.py --windows 20 --window-sec 10 --cpu-iface veth5 \
        --out live_test/results/reader_ab.json

    # on the Wedge100BF-32X from the control host (reports and both readers on the switch)
    python3 live_test/reader_ab.py --switch-ssh root@172.168.1.2 --cpu-iface enp5s0 \
        --windows 20 --window-sec 10 --out reader_ab_switch.json

Per window, like hybrid_collector.collect_windows_live: the CPU reports of the
window name the new buckets, an index stays active for --active-ttl-windows
windows after its last report or counter change, and the active set is read
at the window end: first with one reader, then with the other (--order). Idle
clearing is off for both: a clear by one reader would change what the other
reads next. For every bucket the two rows are compared field by field:

  identical       all fields equal
  traffic between the packet counter differs: packets arrived between the two
                  snapshots (the legacy read starts a bfshell session, ~1.5 s,
                  so the second snapshot is later); the later snapshot must
                  have the larger counters, which is checked
  MISMATCH        a field differs although the packet counter is the same,
                  i.e. the readers disagree

The reg_newconn_dst rows (connections per destination, which grow with every
new connection) are classified the same way on their count: identical,
"traffic between" when the later read is larger, MISMATCH otherwise. The
verdict is PASS when neither the flow rows nor the dst rows have a MISMATCH or
a row that only one reader returned.

The legacy reader is read_registers_with_index.py through
hybrid_collector.run_p4_reader_json (one bfshell session per read); the batched
reader is one BatchedReaderProcess for the whole run (over SSH it runs on the
switch with the SDE's client against 127.0.0.1:50052). Wall times of both are
recorded, with the batched reader's per-phase timing. The summary is printed
and written as JSON (--out).
"""
import argparse
import json
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "thesis-hybrid-ebpf-p4" / "python"))
import hybrid_collector as hc  # noqa: E402
from flow_index import compute_newconn_dst_index  # noqa: E402
from listen_cpu_reports import ReportCollector  # noqa: E402

COUNTERS = ("pkts", "bytes", "pkts_ab", "bytes_ab", "syn", "ack", "rst")


def compare_rows(first, second, earlier_is_first):
    """Classify the difference between two rows of one bucket."""
    diff = {k: [first.get(k), second.get(k)] for k in first if k != "bpp" and first.get(k) != second.get(k)}
    if not diff:
        return "identical", {}
    if first["pkts"] != second["pkts"]:
        earlier, later = (first, second) if earlier_is_first else (second, first)
        monotonic = all(later[c] >= earlier[c] for c in COUNTERS)
        return ("traffic between" if monotonic else "MISMATCH"), diff
    return "MISMATCH", diff


def compare_dst_rows(first, second, earlier_is_first):
    """Classify the difference between two reg_newconn_dst rows of one bucket."""
    diff = {k: [first.get(k), second.get(k)] for k in ("new_conn", "pipes") if first.get(k) != second.get(k)}
    if not diff:
        return "identical", {}
    if first["new_conn"] != second["new_conn"]:
        earlier, later = (first, second) if earlier_is_first else (second, first)
        return ("traffic between" if later["new_conn"] >= earlier["new_conn"] else "MISMATCH"), diff
    return "MISMATCH", diff


def classify(rows_first, rows_second, order, compare, max_diffs):
    """Per bucket of either payload: counts per kind and the kept differences."""
    counts = {"identical": 0, "traffic between": 0, "MISMATCH": 0, "only_in_one": 0}
    diffs = []
    for idx in sorted(set(rows_first) | set(rows_second)):
        a, b = rows_first.get(idx), rows_second.get(idx)
        if a is None or b is None:
            counts["only_in_one"] += 1
            diffs.append({"idx": idx, "kind": "only_in_one", "missing_in": order[0] if a is None else order[1]})
            continue
        kind, diff = compare(a, b, True)
        counts[kind] += 1
        if diff and len(diffs) < max_diffs:
            diffs.append({"idx": idx, "kind": kind, "order": order, "diff": diff})
    return counts, diffs


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--windows", type=int, default=20)
    ap.add_argument("--window-sec", type=float, default=10.0,
                    help="long enough for both reads (the legacy session alone takes ~1.5 s on the switch)")
    ap.add_argument("--cpu-iface", default="veth5", help="veth5 on the model, enp5s0 on the switch")
    ap.add_argument("--switch-ssh", help="run bfshell, the batched reader and the capture on this switch")
    ap.add_argument("--grpc-addr", default="127.0.0.1:50052",
                    help="BF Runtime gRPC server (as seen from where the batched reader runs)")
    ap.add_argument("--remote-sde-install", default=hc.DEFAULT_REMOTE_SDE_INSTALL)
    ap.add_argument("--reader-local", action="store_true",
                    help="with --switch-ssh: run the batched reader here against --grpc-addr, not on the switch")
    ap.add_argument("--p4-reader", default=hc.DEFAULT_P4_READER)
    ap.add_argument("--batched-reader", default=hc.DEFAULT_BATCHED_READER)
    ap.add_argument("--raw-wire", action="store_true", help="batched reader: the wire-format route (--raw-wire)")
    ap.add_argument("--sync-batched", action="store_true", help="batched reader: the register Syncs in one Write RPC")
    ap.add_argument("--snapshot", choices=["sync", "hw"], default="sync")
    ap.add_argument("--active-ttl-windows", type=int, default=5)
    ap.add_argument("--order", choices=["batched-first", "legacy-first", "alternate"], default="batched-first")
    ap.add_argument("--legacy-timeout", type=float, default=600.0)
    ap.add_argument("--out", required=True)
    ap.add_argument("--max-diffs", type=int, default=50, help="row differences kept in the JSON per window")
    args = ap.parse_args()

    batched = hc.BatchedReaderProcess(args.batched_reader, grpc_addr=args.grpc_addr,
                                      switch_ssh=None if args.reader_local else args.switch_ssh,
                                      remote_sde_install=args.remote_sde_install,
                                      sync_batched=args.sync_batched, raw_wire=args.raw_wire)
    ready = batched.start()
    print(f"[ab] batched reader ready: {json.dumps(ready)}", flush=True)
    reports = ReportCollector(args.cpu_iface, ssh_host=args.switch_ssh).start()
    print(f"[ab] capturing CPU reports on {args.cpu_iface}; {args.windows} windows of {args.window_sec} s", flush=True)

    result = {"args": vars(args), "ready": ready, "windows": [], "totals": {}, "dst_totals": {}}
    active_last_seen, last_pkts = {}, {}
    totals = {"identical": 0, "traffic between": 0, "MISMATCH": 0, "only_in_one": 0, "rows": 0}
    dst_totals = {"identical": 0, "traffic between": 0, "MISMATCH": 0, "only_in_one": 0, "rows": 0}
    t0 = time.time()
    try:
        for w in range(args.windows):
            end = t0 + (w + 1) * args.window_sec
            if time.time() < end:
                time.sleep(end - time.time())
            reps = reports.take(t0 + w * args.window_sec, end)
            idxs = sorted({int(r["idx"]) for r in reps})
            for idx in idxs:
                active_last_seen[idx] = w
            active = sorted(i for i, seen in active_last_seen.items() if w - seen <= args.active_ttl_windows)
            dst = sorted({compute_newconn_dst_index(r["src_ip"], r["dst_ip"], int(r["dport"]), 6)
                          for r in reps if int(r["proto"]) == 6})
            order = ["batched", "legacy"] if args.order == "batched-first" else ["legacy", "batched"]
            if args.order == "alternate" and w % 2:
                order.reverse()
            payloads, walls = {}, {}
            for name in order:
                t_read = time.time()
                if name == "batched":
                    payloads[name] = batched.read(active, dst, {}, args.snapshot, timeout=args.legacy_timeout)
                else:
                    payloads[name] = hc.run_p4_reader_json(args.p4_reader, active, switch_ssh=args.switch_ssh,
                                                           snapshot=args.snapshot, dst_indexes=dst,
                                                           timeout=args.legacy_timeout) if active or dst else \
                        {"rows": [], "dst_rows": [], "sync_s": 0, "read_s": 0, "clear_s": 0}
                walls[name] = round(time.time() - t_read, 3)
            rows = {name: {r["idx"]: r for r in payloads[name]["rows"]} for name in order}
            for r in payloads["batched"]["rows"]:   # the batched snapshot drives the active set, like the collector
                if last_pkts.get(r["idx"]) != r["pkts"]:
                    active_last_seen[r["idx"]] = w
                last_pkts[r["idx"]] = r["pkts"]
            counts, diffs = classify(rows[order[0]], rows[order[1]], order, compare_rows, args.max_diffs)
            dst_rows = {name: {r["idx"]: r for r in payloads[name].get("dst_rows", [])} for name in order}
            dst_counts, dst_diffs = classify(dst_rows[order[0]], dst_rows[order[1]], order, compare_dst_rows,
                                             args.max_diffs)
            for k, v in counts.items():
                totals[k] += v
            totals["rows"] += len(active)
            for k, v in dst_counts.items():
                dst_totals[k] += v
            dst_totals["rows"] += len(dst)
            legacy = payloads["legacy"]
            win = {"window": w, "reports": len(reps), "active": len(active), "dst": len(dst), "order": order,
                   "counts": counts, "dst_counts": dst_counts, "wall_s": walls,
                   "legacy": {k: legacy.get(k) for k in ("snapshot", "sync_s", "read_s", "clear_s")},
                   "batched": payloads["batched"].get("timing"), "diffs": diffs, "dst_diffs": dst_diffs}
            result["windows"].append(win)
            print(f"[ab] window {w}: active {len(active)} (+{len(dst)} dst) order {'>'.join(order)}; "
                  f"identical {counts['identical']}, traffic between {counts['traffic between']}, "
                  f"MISMATCH {counts['MISMATCH']}, only in one {counts['only_in_one']}; "
                  f"dst identical {dst_counts['identical']}, later larger {dst_counts['traffic between']}, "
                  f"MISMATCH {dst_counts['MISMATCH']}, only in one {dst_counts['only_in_one']}; "
                  f"wall batched {walls['batched']} s, legacy {walls['legacy']} s", flush=True)
    finally:
        reports.stop()
        batched.stop()
    result["totals"] = totals
    result["dst_totals"] = dst_totals
    result["verdict"] = "PASS" if totals["MISMATCH"] == 0 and totals["only_in_one"] == 0 and \
        dst_totals["MISMATCH"] == 0 and dst_totals["only_in_one"] == 0 else "FAIL"
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(result, indent=1))
    print(f"[ab] {result['verdict']}: flow rows {totals}; dst rows {dst_totals} -> {args.out}")
    sys.exit(0 if result["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()
