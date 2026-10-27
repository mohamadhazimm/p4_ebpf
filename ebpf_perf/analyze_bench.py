#!/usr/bin/env python3
"""Summarize a HostMon benchmark results directory (stdlib only).

Usage: analyze_bench.py RESULTS_DIR | --self-test
Writes RESULTS_DIR/summary.json and RESULTS_DIR/summary.md.
"""
import csv
import json
import statistics
import sys
import tempfile
from pathlib import Path

SYSCALLS_PER_OP = {"getppid": 1, "openclose": 3}
HOSTMON_PROGS = {"handle_sys_enter", "handle_execve", "handle_openat", "handle_renameat", "handle_unlinkat", "handle_connect"}
FEATURES = ["TOTAL_SYSCALLS", "UNIQUE_SYSCALLS", "ENTROPY", "TOP_SYSCALL_FREQ", "AVG_RUN_LENGTH",
            "MAX_RUN_LENGTH", "TRANSITION_COUNT", "RARE_SYSCALL_RATIO", "FIRST50_UNIQUE", "FIRST100_UNIQUE"]


def parse_hostmon(path):
    rows, health, header = [], None, None
    window = None
    for line in path.read_text().splitlines():
        if line.startswith("==== HOST WINDOW"):
            window = int(line.split()[3])
        elif line.startswith("COMM,PID"):
            header = line.split(",")
        elif line.startswith("HOSTMON_HEALTH,"):
            lost, capacity, late, failed = line.split(",")[1:5]
            health = {"lost": int(lost), "capacity_errors": int(capacity), "late_events": int(late), "failed": int(failed)}
        elif header and line and not line.startswith("HOSTMON_"):
            values = next(csv.reader([line]))
            if len(values) == len(header):
                row = dict(zip(header, values))
                row["WINDOW"] = window
                rows.append(row)
    return rows, health


def prog_stats(before, after):
    def index(path):
        progs = json.loads(path.read_text())
        return {p["id"]: p for p in progs if p.get("name") in HOSTMON_PROGS}
    first, second = index(before), index(after)
    out = {}
    for prog_id, prog in second.items():
        if prog_id not in first:
            continue
        runs = (prog.get("run_cnt") or 0) - (first[prog_id].get("run_cnt") or 0)
        ns = (prog.get("run_time_ns") or 0) - (first[prog_id].get("run_time_ns") or 0)
        out[prog["name"]] = {"run_cnt": runs, "run_time_ns": ns, "ns_per_run": ns / runs if runs else None}
    return out


def analyze_run(directory):
    meta = json.loads((directory / "meta.json").read_text())
    meta.setdefault("procs", 1)
    benches = [json.loads(line) for line in (directory / "bench.json").read_text().splitlines() if line.strip()]
    run = dict(meta, bench=None, bench_pids=[b["pid"] for b in benches])
    if len(benches) == meta["procs"]:
        elapsed = max(b["elapsed_ns"] for b in benches)
        total = sum(b["count"] for b in benches)
        run["bench"] = {"elapsed_ns": elapsed, "count": total, "ops_per_sec": total * 1e9 / elapsed,
                        "failures": sum(b["failures"] for b in benches)}
    if meta["cond"] == "base":
        return run
    rows, health = parse_hostmon(directory / "hostmon.out")
    run["health"] = health
    pids = {str(pid) for pid in run["bench_pids"]}
    bench_rows = [r for r in rows if r["PID"] in pids]
    run["recorded_bench_syscalls"] = sum(int(r["TOTAL_SYSCALLS"]) for r in bench_rows)
    run["recorded_all_syscalls"] = sum(int(r["TOTAL_SYSCALLS"]) for r in rows)
    run["bench_windows"] = [{k: r[k] for k in ["PID", "WINDOW"] + FEATURES} for r in bench_rows]
    per_op = SYSCALLS_PER_OP.get(meta["mode"])
    if per_op and meta["cond"] == "mon_in":
        expected = meta["count"] * meta["procs"] * per_op
        run["expected_bench_syscalls"] = expected
        run["coverage"] = run["recorded_bench_syscalls"] / expected
    if (directory / "progs_before.json").exists():
        run["bpf_progs"] = prog_stats(directory / "progs_before.json", directory / "progs_after.json")
    if (directory / "hostmon.mem").exists():
        run["hostmon_mem_kb"] = {line.split(":")[0]: int(line.split()[1]) for line in (directory / "hostmon.mem").read_text().splitlines()}
    if run["bench"]:
        run["hostmon_cpu_fraction"] = meta["hostmon_cpu_ns"] / run["bench"]["elapsed_ns"]
        run["recorded_events_per_sec"] = run["recorded_bench_syscalls"] * 1e9 / run["bench"]["elapsed_ns"]
    return run


def median(values):
    values = [v for v in values if v is not None]
    return statistics.median(values) if values else None


def summarize(runs):
    groups = {}
    for run in runs:
        groups.setdefault((run["mode"], run["rate"], run["procs"], run["count"]), {}).setdefault(run["cond"], []).append(run)
    table = []
    for (mode, rate, procs, count), conds in sorted(groups.items()):
        elapsed = {c: median([r["bench"]["elapsed_ns"] for r in rs if r["bench"]]) for c, rs in conds.items()}
        base = elapsed.get("base")
        mon = conds.get("mon_in", [])
        lost = [r["health"]["lost"] for r in mon if r.get("health")]
        recorded = [r["recorded_bench_syscalls"] for r in mon]
        sys_enter = [r.get("bpf_progs", {}).get("handle_sys_enter", {}).get("ns_per_run") for r in mon]
        sys_enter_out = [r.get("bpf_progs", {}).get("handle_sys_enter", {}).get("ns_per_run") for r in conds.get("mon_out", [])]
        entry = {
            "mode": mode, "rate": rate, "procs": procs, "count": count, "reps": {c: len(rs) for c, rs in conds.items()},
            "median_elapsed_ms": {c: v / 1e6 for c, v in elapsed.items() if v},
            "median_ops_per_sec": {c: median([r["bench"]["ops_per_sec"] for r in rs if r["bench"]]) for c, rs in conds.items()},
            "overhead_mon_in_pct": 100 * (elapsed["mon_in"] / base - 1) if base and elapsed.get("mon_in") else None,
            "overhead_mon_out_pct": 100 * (elapsed["mon_out"] / base - 1) if base and elapsed.get("mon_out") else None,
            "added_ns_per_op_mon_in": (elapsed["mon_in"] - base) / count if base and elapsed.get("mon_in") else None,
            "added_ns_per_op_mon_out": (elapsed["mon_out"] - base) / count if base and elapsed.get("mon_out") else None,
            "median_lost_events": median(lost),
            "max_lost_events": max(lost) if lost else None,
            "median_loss_fraction": median([l / (l + r) if l + r else 0 for l, r in zip(lost, recorded)]),
            "median_coverage": median([r.get("coverage") for r in mon]),
            "median_hostmon_cpu_fraction": median([r.get("hostmon_cpu_fraction") for r in mon]),
            "median_hostmon_vmhwm_kb": median([r.get("hostmon_mem_kb", {}).get("VmHWM") for r in mon]),
            "median_sys_enter_ns_per_run": median(sys_enter),
            "median_sys_enter_ns_per_run_mon_out": median(sys_enter_out),
            "median_recorded_events_per_sec": median([r.get("recorded_events_per_sec") for r in mon]),
            "any_hostmon_failure": any(r.get("health", {}).get("failed") for r in mon + conds.get("mon_out", [])),
        }
        clean = [r for r in mon if r.get("health") and r["health"]["lost"] == 0 and r.get("coverage") is not None]
        if clean:
            entry["exact_when_lossless"] = all(0.999 <= r["coverage"] <= 1 + 40 / r["expected_bench_syscalls"] for r in clean)
        table.append(entry)
    return table


def fmt(value, spec):
    return "-" if value is None else format(value, spec)


def markdown(table, runs):
    lines = ["# HostMon eBPF benchmark", "",
             "| mode | target rate/s per proc | procs | ops/proc | base ms | mon_in ms | mon_out ms | overhead in | overhead out | +ns/op in | sys_enter ns/run (in/out) | recorded events/s | lost (median/max) | loss frac | coverage | hostmon CPU | VmHWM KB |",
             "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for e in table:
        ms = e["median_elapsed_ms"]
        lines.append("| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {}/{} | {} | {}/{} | {} | {} | {} | {} |".format(
            e["mode"], e["rate"] or "unlimited", e["procs"], e["count"], fmt(ms.get("base"), ".1f"), fmt(ms.get("mon_in"), ".1f"),
            fmt(ms.get("mon_out"), ".1f"), fmt(e["overhead_mon_in_pct"], "+.1f") + ("%" if e["overhead_mon_in_pct"] is not None else ""),
            fmt(e["overhead_mon_out_pct"], "+.1f") + ("%" if e["overhead_mon_out_pct"] is not None else ""),
            fmt(e["added_ns_per_op_mon_in"], ".0f"), fmt(e["median_sys_enter_ns_per_run"], ".0f"),
            fmt(e["median_sys_enter_ns_per_run_mon_out"], ".0f"), fmt(e["median_recorded_events_per_sec"], ",.0f"),
            fmt(e["median_lost_events"], ".0f"), fmt(e["max_lost_events"], "d"), fmt(e["median_loss_fraction"], ".3f"),
            fmt(e["median_coverage"], ".4f"), fmt(e["median_hostmon_cpu_fraction"], ".2f"), fmt(e["median_hostmon_vmhwm_kb"], ".0f")))
    sample = next((r for r in runs if r["mode"] == "getppid" and r["procs"] == 1 and r["cond"] == "mon_in" and r.get("bench_windows")), None)
    if sample:
        lines += ["", "## ADFA features for one getppid run (bench PID, per window)", "",
                  "| " + " | ".join(["PID", "WINDOW"] + FEATURES) + " |", "|" + "---|" * (len(FEATURES) + 2)]
        for w in sample["bench_windows"]:
            lines.append("| " + " | ".join(str(w[k]) for k in ["PID", "WINDOW"] + FEATURES) + " |")
    lines += ["", "Overheads compare median elapsed time against `base` (same workload, no HostMon). "
              "`mon_out` is the cost to a process outside the monitored cgroup (the tracepoint still fires and filters). "
              "Coverage = recorded syscalls for the bench PID / issued syscalls; below 1 means ring-buffer loss. "
              "hostmon CPU = collector CPU time / workload wall time (1.00 = one full core)."]
    return "\n".join(lines) + "\n"


def analyze(results):
    runs = [analyze_run(d) for d in sorted((results / "runs").iterdir()) if (d / "meta.json").exists()]
    table = summarize(runs)
    (results / "summary.json").write_text(json.dumps({"summary": table, "runs": runs}, indent=2) + "\n")
    (results / "summary.md").write_text(markdown(table, runs))
    print(markdown(table, runs))


def self_test():
    with tempfile.TemporaryDirectory() as tmp:
        results = Path(tmp)
        header = "COMM,PID,EXEC,OPEN,REN,DEL,CONN,UNIQIP,UNIQPRT,TOTAL_SYSCALLS,UNIQUE_SYSCALLS,ENTROPY,TOP_SYSCALL_FREQ,AVG_RUN_LENGTH,MAX_RUN_LENGTH,TRANSITION_COUNT,RARE_SYSCALL_RATIO,FIRST50_UNIQUE,FIRST100_UNIQUE"
        progs = lambda cnt, ns: json.dumps([{"id": 7, "name": "handle_sys_enter", "run_cnt": cnt, "run_time_ns": ns},
                                            {"id": 9, "name": "handle_renameat", "run_cnt": None, "run_time_ns": None},
                                            {"id": 8, "name": "other", "run_cnt": 5, "run_time_ns": 5}])
        for cond, elapsed, lost, total in [("base", 100_000_000, 0, 0), ("mon_in", 150_000_000, 0, 500_002), ("mon_out", 110_000_000, 0, 0)]:
            d = results / "runs" / f"getppid_r0_{cond}_1"
            d.mkdir(parents=True)
            (d / "meta.json").write_text(json.dumps({"mode": "getppid", "count": 500_000, "rate": 0, "procs": 2, "cond": cond, "rep": 1, "hostmon_rc": 0, "hostmon_cpu_ns": 75_000_000, "hostmon_pid_cpu": 4}))
            (d / "bench.json").write_text("".join(json.dumps({"mode": "getppid", "count": 500_000, "rate": 0, "elapsed_ns": elapsed - k, "ops_per_sec": 5e14 / elapsed, "failures": 0, "pid": pid}) + "\n" for k, pid in [(0, 4242), (5, 4243)]))
            if cond != "base":
                rows = "".join(f'"bench_load",{pid},0,0,0,0,0,0,0,{total},4,0.000040,0.999996,250000.0,999990,4,0.000003,4,4\n' for pid in (4242, 4243)) if total else ""
                (d / "hostmon.out").write_text(f"HOSTMON_READY,123\n\n==== HOST WINDOW 0 START=0 END=1 DUR=1 ====\n{header}\n{rows}HOSTMON_HEALTH,{lost},0,0,0\n")
                (d / "progs_before.json").write_text(progs(10, 1000))
                (d / "progs_after.json").write_text(progs(1_000_010, 40_001_000))
                (d / "hostmon.mem").write_text("VmHWM:\t 5000 kB\nVmRSS:\t 4000 kB\n")
        analyze(results)
        summary = json.loads((results / "summary.json").read_text())["summary"][0]
        assert abs(summary["overhead_mon_in_pct"] - 50) < 1e-9, summary
        assert abs(summary["overhead_mon_out_pct"] - 10) < 1e-9
        assert abs(summary["added_ns_per_op_mon_in"] - 100) < 1e-9 and summary["procs"] == 2
        assert summary["median_sys_enter_ns_per_run"] == 40.0 and summary["median_sys_enter_ns_per_run_mon_out"] == 40.0
        assert abs(summary["median_recorded_events_per_sec"] - 1_000_004 / 0.15) < 1e-3
        assert summary["median_coverage"] == 1.000004 and summary["exact_when_lossless"] is True
        assert summary["median_hostmon_vmhwm_kb"] == 5000 and summary["median_lost_events"] == 0
    print("self-test passed")


if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test"]:
        self_test()
    elif len(sys.argv) == 2:
        analyze(Path(sys.argv[1]))
    else:
        sys.exit(__doc__)
