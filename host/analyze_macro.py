#!/usr/bin/env python3
"""Summarize run_macro.sh results with the metrics used in the literature.

Usage: analyze_macro.py RESULTS_DIR [RESULTS_DIR ...] [--out PREFIX] | --self-test

Per experiment (one results/macro-* directory) and condition (base / mon_in / mon_out):
  wall_overhead      wall(mon_in) / wall(base) - 1          eAudit Fig. 21, kernel-build papers
  idle_overhead      wall(mon_out) / wall(base) - 1         hooks attached, workload unmonitored
  cpu_overhead       cpu(mon_in) / cpu(base) - 1            Houssel et al. 2026 (benchmark user+sys)
  agent_overhead     hostmon_cpu(mon_in) / cpu(base)        eAudit Fig. 18/20 (t_a / t_b)
  agent_ns_per_event hostmon_cpu / events consumed          eAudit Fig. 19 (consumed = attributed + unattributed)
  ringbuf_loss       lost / (consumed + lost)               dropped in the kernel (ring buffer full)
  attribution_loss   unattributed / (consumed + lost)       read, but no PID slot (128-PID table) -> not in features
LMbench RESULT lines, wrk Requests/sec and redis-benchmark throughput are parsed from stdout.
Warm-up runs (runs/warmup_*) are excluded.
"""
import csv
import json
import re
import statistics
import sys
import tempfile
from pathlib import Path

EVENT_COLUMNS = ["TOTAL_SYSCALLS", "EXEC", "OPEN", "REN", "DEL", "CONN"]


def median(values):
    values = [v for v in values if v is not None]
    return statistics.median(values) if values else None


def parse_hostmon(path):
    rows, health, header = [], None, None
    for line in path.read_text(errors="replace").splitlines():
        if line.startswith("COMM,PID"):
            header = line.split(",")
        elif line.startswith("HOSTMON_HEALTH,"):
            lost, capacity, late, failed = (int(x) for x in line.split(",")[1:5])
            health = {"lost": lost, "capacity_errors": capacity, "late_events": late, "failed": failed}
        elif header and line and not line.startswith(("HOSTMON_", "====")):
            values = next(csv.reader([line]))
            if len(values) == len(header):
                rows.append(dict(zip(header, values)))
    return rows, health


def prog_stats(before, after):
    def index(path):
        return {p["id"]: p for p in json.loads(path.read_text()) if str(p.get("name", "")).startswith("handle_")}
    first, second = index(before), index(after)
    out = {}
    for prog_id, prog in second.items():
        if prog_id in first:
            runs = (prog.get("run_cnt") or 0) - (first[prog_id].get("run_cnt") or 0)
            ns = (prog.get("run_time_ns") or 0) - (first[prog_id].get("run_time_ns") or 0)
            out[prog["name"]] = {"run_cnt": runs, "ns_per_run": ns / runs if runs else None}
    return out


def parse_stdout(text):
    metrics = {}
    for name, value in re.findall(r"^RESULT (\S+) ([0-9.eE+-]+)$", text, re.M):
        metrics["lm_" + name] = float(value)
    m = re.search(r"^Requests/sec:\s+([0-9.]+)", text, re.M)
    if m:
        metrics["wrk_requests_per_sec"] = float(m.group(1))
    for test, value in re.findall(r'^"?([A-Z_ ]+)"?,"?([0-9.]+)"?', text, re.M):
        metrics["redis_" + test.strip().lower().replace(" ", "_") + "_rps"] = float(value)
    return metrics


def analyze_run(d):
    meta = json.loads((d / "meta.json").read_text())
    run = {"cond": meta["cond"], "rep": str(meta["rep"]), "rc": meta["rc"], "wall_s": meta["wall_ns"] / 1e9}
    rusage = (d / "rusage.txt").read_text().split() if (d / "rusage.txt").exists() else []
    if len(rusage) >= 4:
        run["cpu_s"] = float(rusage[1]) + float(rusage[2])
        run["user_s"], run["sys_s"], run["maxrss_kb"] = float(rusage[1]), float(rusage[2]), int(rusage[3])
    run.update(parse_stdout((d / "stdout.txt").read_text(errors="replace")) if (d / "stdout.txt").exists() else {})
    if meta["cond"] != "base" and (d / "hostmon.out").exists():
        rows, health = parse_hostmon(d / "hostmon.out")
        run["health"] = health
        run["attributed"] = sum(int(r[c]) for r in rows for c in EVENT_COLUMNS)
        run["events"] = run["attributed"] + (health["capacity_errors"] if health else 0)
        run["syscalls"] = sum(int(r["TOTAL_SYSCALLS"]) for r in rows)
        run["hostmon_cpu_s"] = meta["hostmon_cpu_ns"] / 1e9
        run["hostmon_rc"] = meta["hostmon_rc"]
        if (d / "progs_before.json").exists() and (d / "progs_after.json").exists():
            run["bpf"] = prog_stats(d / "progs_before.json", d / "progs_after.json")
        if (d / "hostmon.mem").exists():
            run["hostmon_vmhwm_kb"] = next((int(l.split()[1]) for l in (d / "hostmon.mem").read_text().splitlines()
                                            if l.startswith("VmHWM")), None)
    return run


def summarize(results):
    env = json.loads((results / "environment.json").read_text())
    runs = [analyze_run(d) for d in sorted((results / "runs").iterdir())
            if (d / "meta.json").exists() and not d.name.startswith("warmup_")]
    by = {c: [r for r in runs if r["cond"] == c] for c in ("base", "mon_in", "mon_out")}
    med = {c: {k: median([r.get(k) for r in rs]) for k in ("wall_s", "cpu_s", "hostmon_cpu_s", "events")}
           for c, rs in by.items()}

    def ratio(a, b):
        return a / b - 1 if a is not None and b else None

    mon = by["mon_in"]
    events = med["mon_in"]["events"]
    lost = median([r["health"]["lost"] for r in mon if r.get("health")])
    capacity = median([r["health"]["capacity_errors"] for r in mon if r.get("health")])
    out = {
        "name": env["name"], "command": env["command"], "results": str(results),
        "reps": {c: len(rs) for c, rs in by.items()},
        "failed_runs": [f'{r["cond"]}_{r["rep"]}' for r in runs if r["rc"] != 0],
        "median": med,
        "spread_wall_s": {c: [min(r["wall_s"] for r in rs), max(r["wall_s"] for r in rs)] if rs else None for c, rs in by.items()},
        "wall_overhead": ratio(med["mon_in"]["wall_s"], med["base"]["wall_s"]),
        "idle_overhead": ratio(med["mon_out"]["wall_s"], med["base"]["wall_s"]),
        "cpu_overhead": ratio(med["mon_in"]["cpu_s"], med["base"]["cpu_s"]),
        "agent_overhead": (med["mon_in"]["hostmon_cpu_s"] / med["base"]["cpu_s"]
                           if med["mon_in"]["hostmon_cpu_s"] is not None and med["base"]["cpu_s"] else None),
        "agent_ns_per_event": median([r["hostmon_cpu_s"] * 1e9 / r["events"] for r in mon if r.get("events")]),
        "events_per_sec": median([r["events"] / r["wall_s"] for r in mon if r.get("events")]),
        "median_lost": lost, "median_capacity_errors": capacity,
        "ringbuf_loss": lost / (events + lost) if events is not None and lost is not None and events + lost else None,
        "attribution_loss": capacity / (events + lost) if events and capacity is not None and lost is not None else None,
        "sys_enter_ns_per_run": {c: median([r.get("bpf", {}).get("handle_sys_enter", {}).get("ns_per_run") for r in by[c]])
                                 for c in ("mon_in", "mon_out")},
        "hostmon_vmhwm_kb": median([r.get("hostmon_vmhwm_kb") for r in mon]),
    }
    metric_keys = sorted({k for r in runs for k in r if k.startswith(("lm_", "wrk_", "redis_"))})
    out["workload_metrics"] = {k: {c: median([r.get(k) for r in by[c]]) for c in by} for k in metric_keys}
    return out, runs


def pct(value):
    return "-" if value is None else f"{100 * value:+.1f}%"


def num(value, spec=".1f"):
    return "-" if value is None else format(value, spec)


def markdown(summaries):
    lines = ["# HostMon literature-replication benchmarks", "",
             "| experiment | base wall s | mon_in wall s | wall overhead | idle (mon_out) | CPU-time overhead | agent CPU / bench CPU | agent ns/event | events/s | ring-buffer loss | attribution loss |",
             "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for s in summaries:
        m = s["median"]
        lines.append(f'| {s["name"]} | {num(m["base"]["wall_s"], ".2f")} | {num(m["mon_in"]["wall_s"], ".2f")} | {pct(s["wall_overhead"])} | '
                     f'{pct(s["idle_overhead"])} | {pct(s["cpu_overhead"])} | {pct(s["agent_overhead"])} | {num(s["agent_ns_per_event"], ".0f")} | '
                     f'{num(s["events_per_sec"], ",.0f")} | {num(s["ringbuf_loss"], ".4f")} | {num(s["attribution_loss"], ".4f")} |')
    for s in summaries:
        wm = s["workload_metrics"]
        if not wm:
            continue
        lines += ["", f'## {s["name"]}: workload-reported metrics (median)', "",
                  "| metric | base | mon_in | mon_out | delta in | % in | % out |", "|---|---:|---:|---:|---:|---:|---:|"]
        for k, v in wm.items():
            b, i, o = v.get("base"), v.get("mon_in"), v.get("mon_out")
            lines.append(f"| {k} | {num(b, '.4f')} | {num(i, '.4f')} | {num(o, '.4f')} | "
                         f"{num(i - b if b is not None and i is not None else None, '+.4f')} | "
                         f"{pct(i / b - 1 if b and i is not None else None)} | {pct(o / b - 1 if b and o is not None else None)} |")
    failed = [f'{s["name"]}: {", ".join(s["failed_runs"])}' for s in summaries if s["failed_runs"]]
    lines += ["", "Failed runs (nonzero exit): " + ("; ".join(failed) if failed else "none")]
    return "\n".join(lines) + "\n"


def main(argv):
    out_prefix = None
    if "--out" in argv:
        i = argv.index("--out")
        out_prefix = Path(argv[i + 1])
        argv = argv[:i] + argv[i + 2:]
    summaries = []
    for path in argv:
        summary, runs = summarize(Path(path))
        summaries.append(summary)
        (Path(path) / "summary.json").write_text(json.dumps({"summary": summary, "runs": runs}, indent=2) + "\n")
        (Path(path) / "summary.md").write_text(markdown([summary]))
    text = markdown(summaries)
    if out_prefix:
        out_prefix.with_suffix(".md").write_text(text)
        out_prefix.with_suffix(".json").write_text(json.dumps(summaries, indent=2) + "\n")
    print(text)


def self_test():
    header = "COMM,PID,EXEC,OPEN,REN,DEL,CONN,UNIQIP,UNIQPRT,TOTAL_SYSCALLS,UNIQUE_SYSCALLS,ENTROPY,TOP_SYSCALL_FREQ,AVG_RUN_LENGTH,MAX_RUN_LENGTH,TRANSITION_COUNT,RARE_SYSCALL_RATIO,FIRST50_UNIQUE,FIRST100_UNIQUE"
    with tempfile.TemporaryDirectory() as tmp:
        r = Path(tmp)
        (r / "environment.json").write_text(json.dumps({"name": "t", "command": ["x"]}))
        for cond, wall, user, sys_, hm in [("base", 10, 4, 6, 0), ("mon_in", 15, 4, 11, 2_000_000_000), ("mon_out", 11, 4, 6.5, 100)]:
            for rep in ("1", "warmup"):
                d = r / "runs" / (f"{cond}_{rep}" if rep != "warmup" else f"warmup_{cond}")
                d.mkdir(parents=True)
                (d / "meta.json").write_text(json.dumps({"cond": cond, "rep": rep, "rc": 0, "wall_ns": int(wall * 1e9 * (9 if rep == "warmup" else 1)),
                                                         "hostmon_rc": 0, "hostmon_cpu_ns": hm}))
                (d / "rusage.txt").write_text(f"{wall} {user} {sys_} 1000\n")
                (d / "stdout.txt").write_text("RESULT null_syscall 0.0700\n" if cond == "base" else "RESULT null_syscall 0.4000\nRequests/sec:  1234.5\n")
                if cond != "base":
                    rows = f'"a",1,1,2,0,0,0,0,0,{9_997 if cond == "mon_in" else 0},3,1.0,0.5,2.0,5,3,0.1,3,3\n'
                    (d / "hostmon.out").write_text(f"HOSTMON_READY,1\n==== HOST WINDOW 0 START=0 END=1 DUR=1 ====\n{header}\n{rows}HOSTMON_HEALTH,0,25,0,0\n")
        summary, _ = summarize(r)
        assert abs(summary["wall_overhead"] - 0.5) < 1e-12 and abs(summary["idle_overhead"] - 0.1) < 1e-12
        assert abs(summary["cpu_overhead"] - 0.5) < 1e-12 and abs(summary["agent_overhead"] - 0.2) < 1e-12
        assert summary["median"]["mon_in"]["events"] == 10_025 and summary["reps"] == {"base": 1, "mon_in": 1, "mon_out": 1}
        assert abs(summary["agent_ns_per_event"] - 2e9 / 10_025) < 1e-6
        assert summary["ringbuf_loss"] == 0 and abs(summary["attribution_loss"] - 25 / 10_025) < 1e-12
        wm = summary["workload_metrics"]
        assert wm["lm_null_syscall"] == {"base": 0.07, "mon_in": 0.4, "mon_out": 0.4} and wm["wrk_requests_per_sec"]["mon_in"] == 1234.5
        print(markdown([summary]))
    print("self-test passed")


if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test"]:
        self_test()
    elif len(sys.argv) >= 2:
        main(sys.argv[1:])
    else:
        sys.exit(__doc__)
