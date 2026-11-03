#!/usr/bin/env python3
"""Who the host features of a run come from.

    analyze_host.py --run-dir results/cmd_...    (hostmon_capture.log, probe.json[, gate/modelmon.jsonl])

hostmon traces the whole machine and the collector sums every process row it
prints. Its rows are attributed here by PID and command name:

  collector  the collector process, the processes it started (register
             reader, forwarding programmer) and bfshell
  capture    tcpdump (the test's ingress captures)
  servers    p4ext-srv, the benign servers behind the switch (a separate host
             in a real deployment)
  workload   the command's process tree (gate.py's PID and its children; a
             child is a PID first seen after the workload started whose
             command name is the workload's: bash, python3, true, ...)
  other      everything else that hostmon's name filter lets through

For every window: the collector's host features (summarize_host_window over
all rows, as in the CSV) next to the same features over the workload's rows
only. With modelmon output from collector_probe.py --modelmon-gate, also the
workload tree's host__ebpf_* counts per window.
"""
import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
from hybrid_collector import parse_host_windows, summarize_host_window  # noqa: E402

SHOW = ["host_active_processes", "host_total_syscalls_total", "host_exec_total", "host_open_total",
        "host_rename_total", "host_unlink_total", "host_connect_total", "host_unique_ip_total"]
WORKLOAD_COMMS = {"bash", "python3", "true", "sleep", "sh"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-dir", required=True)
    args = ap.parse_args()
    d = Path(args.run_dir)
    probe = json.load(open(d / "probe.json"))
    windows = parse_host_windows((d / "hostmon_capture.log").read_text(errors="replace"))
    collector = {probe["collector_pid"]} | {p.get("pid") for p in probe["popen"]
                                            if "gate.py" not in " ".join(p["args"] if isinstance(p["args"], list) else [p["args"]])}
    gate_pid = probe.get("modelmon", {}).get("target_pid")
    workload_start = next((p["t"] for p in probe["popen"]
                           if "gate.py" in " ".join(p["args"] if isinstance(p["args"], list) else [p["args"]])), None)

    def category(row, seen_before_start):
        pid, comm = row["pid"], row["comm"]
        if pid in collector or comm == "bfshell":
            return "collector"
        if comm == "tcpdump":
            return "capture"
        if comm == "p4ext-srv":
            return "servers"
        if pid == gate_pid or (comm in WORKLOAD_COMMS and pid not in seen_before_start):
            return "workload"
        return "other"

    # hostmon windows use CLOCK_MONOTONIC: processes of the first window that
    # are not workload-like are taken as pre-existing
    seen_before = set()
    if workload_start is not None and windows:
        seen_before = {r["pid"] for r in windows[0]["rows"] if r["comm"] not in WORKLOAD_COMMS}
    report = []
    other_comms = Counter()
    print(" win | rows: collector capture servers workload other | syscalls: all      workload  "
          "| CSV host features (all rows) -> workload rows only")
    for w in windows:
        cats = defaultdict(list)
        for r in w["rows"]:
            c = category(r, seen_before)
            cats[c].append(r)
            if c == "other":
                other_comms[r["comm"]] += r["total_syscalls"]
        all_f = summarize_host_window(w["rows"])
        wl_f = summarize_host_window(cats["workload"])
        report.append({"window": w["host_window_id"], "rows": {k: len(v) for k, v in cats.items()},
                       "syscalls": {k: sum(r["total_syscalls"] for r in v) for k, v in cats.items()},
                       "features_all": all_f, "features_workload": wl_f})
        feats = "  ".join(f"{k.replace('host_', '').replace('_total', '')}={all_f[k]}->{wl_f[k]}" for k in SHOW)
        print(f" {w['host_window_id']:3d} | {len(cats['collector']):9d} {len(cats['capture']):7d} "
              f"{len(cats['servers']):7d} {len(cats['workload']):8d} {len(cats['other']):5d} | "
              f"{sum(r['total_syscalls'] for r in w['rows']):9d} {sum(r['total_syscalls'] for r in cats['workload']):9d} | {feats}")
    print("largest 'other' processes by syscalls:", other_comms.most_common(8))

    mm = d / "gate" / "modelmon.jsonl"
    if mm.exists():
        print("modelmon (workload tree only), per window:")
        for line in mm.read_text().splitlines():
            if line.startswith("{"):
                rec = json.loads(line)
                c = {k.replace("host__ebpf_", ""): v for k, v in rec["counts"].items() if v}
                print(f"  {rec['window_id']:3d} {rec['duration_sec']:6.1f}s lost={rec['ringbuf_lost_window']} {c}")
    (d / "host_analysis.json").write_text(json.dumps({"windows": report, "other_comms": other_comms.most_common(30)},
                                                     indent=1))


if __name__ == "__main__":
    main()
