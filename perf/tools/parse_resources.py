#!/usr/bin/env python3
"""Summarise bf-p4c resource usage for one or more build directories (Phase 1.4).

    python3 perf/tools/parse_resources.py OUT_PREFIX BUILD_DIR [BUILD_DIR ...]

Each BUILD_DIR is an output directory of sw_compile.sh (compile_meta.txt,
compile.log, pipe/logs/). Writes OUT_PREFIX.json (machine-readable, all
fields) and OUT_PREFIX.md (comparison tables).

Per-stage usage and per-stage capacity both come from pipe/logs/resources.json,
so no chip limits are hard-coded. Pipe totals are over all MAU stages of the
target (nStages, 12 on Tofino 1), not only the stages in use; MAU stages are
shared by ingress and egress, so per-stage numbers include both. Totals are
cross-checked against pipe/logs/metrics.json. Failed compiles are listed with
their error lines.
"""
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

# resources.json per-stage section -> (list key, capacity function)
STAGE_RESOURCES = {
    "sram": ("rams", "srams", lambda s: s["nRows"] * s["nColumns"]),
    "map_ram": ("map_rams", "maprams", lambda s: s["nRows"] * s["nUnits"]),
    "tcam": ("tcams", "tcams", lambda s: s["nRows"] * s["nColumns"]),
    "stateful_alu": ("meter_alus", "meters", lambda s: s["nAlus"]),
    "stats_alu": ("statistic_alus", "stats", lambda s: s["nAlus"]),
    "hash_bit": ("hash_bits", "bits", lambda s: s["nFunctions"] * s["nBits"]),
    "hash_dist_unit": ("hash_distribution_units", "units",
                       lambda s: s["nUnitIds"] * s["nHashIds"]),
    "gateway": ("gateways", "gateways", lambda s: s["nUnits"] * s["nRows"]),
    "vliw_instr": ("vliw", "instructions", lambda s: s["size"]),
    "logical_table": ("logical_tables", "ids", lambda s: s["size"]),
    "exm_search_bus": ("exm_search_buses", "ids", lambda s: s["size"]),
    "action_bus_byte": ("action_bus_bytes", "bytes", lambda s: s["size"]),
    "stash": ("stashes", "stashes", lambda s: s["nUnits"] * s["nRows"]),
}
# Resources whose items are attributed to tables/registers in the placement table.
ATTRIBUTED = ("sram", "map_ram", "tcam", "stateful_alu", "stats_alu")
OVERVIEW = ("sram", "map_ram", "tcam", "stateful_alu", "hash_bit", "gateway",
            "logical_table")


def parse_meta(path):
    meta = {"sources_sha256": {}}
    if not path.exists():
        return meta
    for line in path.read_text().splitlines():
        m = re.match(r"^  ([0-9a-f]{64})  (\S+)$", line)
        if m:
            meta["sources_sha256"][m.group(2)] = m.group(1)
            continue
        for key, val in re.findall(r"(\w+): (\S+)", line):
            if key in ("wall_s", "user_s", "sys_s"):
                meta[key] = float(val)
        m = re.match(r"^(\w+): (.*)$", line)
        if m and m.group(1) not in ("wall_s", "sources_sha256"):
            meta[m.group(1)] = m.group(2)
    for key in ("exit_code", "peak_rss_kib"):
        if key in meta:
            meta[key] = int(meta[key])
    meta["defines"] = re.findall(r"-D(\S+)", meta.get("cmd", ""))
    return meta


def parse_table_summary(path):
    """Stage counts of the final table-placement round (the one that is used)."""
    attempts = parse_placement_attempts(path)
    if attempts:
        return dict(attempts[-1], rounds=len(attempts))
    return parse_table_summary_text(path.read_text()) if path.exists() else {}


def parse_table_summary_text(text):
    out = {}
    for key, pattern in (
            ("ingress_stages", r"stages for ingress table allocation: (\d+)"),
            ("egress_stages", r"stages for egress table allocation: (\d+)"),
            ("stages", r"Number of stages in table allocation: (\d+)"),
            ("critical_path", r"Critical path length through the table "
                              r"dependency graph: (\d+)")):
        m = re.search(pattern, text)
        if m:
            out[key] = int(m.group(1))
    return out


def parse_placement_attempts(path):
    """Stage counts of every table-placement round (kept for failed compiles)."""
    if not path.exists():
        return []
    attempts = []
    for block in re.split(r"(?=Table allocation done )", path.read_text()):
        m = re.match(r"Table allocation done (\d+) time\(s\), state = (\S+)", block)
        if not m:
            continue
        att = {"round": int(m.group(1)), "state": m.group(2)}
        att.update(parse_table_summary_text(block))
        attempts.append(att)
    return attempts


def item_users(item):
    return sorted({u.get("used_by", "?") for u in item.get("usages", [])})


def parse_stages(resources):
    n_stages = resources["mau"]["nStages"]
    capacity = {}
    per_stage = {}
    placement = defaultdict(lambda: defaultdict(lambda: defaultdict(int)))
    for st in resources["mau"]["mau_stages"]:
        num = st["stage_number"]
        row = {}
        for name, (section, key, cap) in STAGE_RESOURCES.items():
            sec = st[section]
            items = sec.get(key, [])
            row[name] = len(items)
            capacity.setdefault(name, cap(sec))
            if name in ATTRIBUTED:
                for item in items:
                    for user in item_users(item):
                        placement[user][num][name] += 1
        xbar = st["xbar_bytes"]
        row["xbar_exact_byte"] = sum(1 for b in xbar["bytes"]
                                     if b.get("byte_type") == "exact")
        row["xbar_ternary_byte"] = sum(1 for b in xbar["bytes"]
                                       if b.get("byte_type") == "ternary")
        capacity.setdefault("xbar_exact_byte", xbar["exact_size"])
        capacity.setdefault("xbar_ternary_byte", xbar["ternary_size"])
        per_stage[num] = row
    totals = {name: sum(r[name] for r in per_stage.values()) for name in capacity}
    pipe_capacity = {name: c * n_stages for name, c in capacity.items()}
    registers = {}
    for user, stages in placement.items():
        for num, res in stages.items():
            if res.get("stateful_alu"):
                registers.setdefault(user, []).append(
                    {"stage": num, **{k: res.get(k, 0) for k in ATTRIBUTED}})
    return {
        "n_stages": n_stages,
        "stage_capacity": capacity,
        "pipe_capacity": pipe_capacity,
        "per_stage": {str(k): per_stage[k] for k in sorted(per_stage)},
        "totals": totals,
        "registers": dict(sorted(registers.items())),
    }


def parse_phv(metrics, resources):
    units = {}
    for kind in ("normal", "tagalong"):
        for c in resources.get("phv_containers", {}).get(kind, []):
            units[(kind, c["width"])] = c["units"]
    out = {}
    for kind in ("normal", "tagalong"):
        for c in metrics.get("phv", {}).get(kind, []):
            w = c["bit_width"]
            out[f"{kind}_{w}b"] = {
                "containers_occupied": c["containers_occupied"],
                "containers_available": units.get((kind, w)),
                "bits_occupied": c["bits_occupied"],
                "bits_overlaid": c["bits_overlaid"],
            }
    return out


def parse_build(build_dir):
    d = Path(build_dir)
    logs = d / "pipe" / "logs"
    rec = {"variant": d.name, "build_dir": str(d)}
    rec["compile"] = parse_meta(d / "compile_meta.txt")
    ok = rec["compile"].get("exit_code") == 0 and (logs / "resources.json").exists()
    rec["status"] = "ok" if ok else "failed"
    if not ok:
        log = d / "compile.log"
        lines = log.read_text(errors="replace").splitlines() if log.exists() else []
        rec["errors"] = [l for l in lines if re.search(r"error", l, re.I)][:20]
        rec["placement_attempts"] = parse_placement_attempts(logs / "table_summary.log")
        return rec
    metrics = json.loads((logs / "metrics.json").read_text())
    resources = json.loads((logs / "resources.json").read_text())["resources"]
    rec["tables"] = parse_table_summary(logs / "table_summary.log")
    rec["mau"] = parse_stages(resources)
    mau = metrics.get("mau", {})
    rec["latency_cycles"] = {x["gress"]: x["cycles"] for x in mau.get("latency", [])}
    rec["power_estimate"] = {x["gress"]: float(x["estimate"])
                             for x in mau.get("power", [])}
    rec["metrics_totals"] = {k: mau.get(k) for k in (
        "srams", "tcams", "map_rams", "logical_tables", "action_bus_bytes",
        "exact_crossbar_bytes", "ternary_crossbar_bytes")}
    rec["parser_tcam_rows"] = {g: v.get("tcam_rows")
                               for g, v in metrics.get("parser", {}).items()}
    rec["deparser"] = metrics.get("deparser", {})
    rec["phv"] = parse_phv(metrics, resources)
    rec["compiler_compilation_time_s"] = float(metrics.get("compilation_time", "nan"))
    t, m = rec["mau"]["totals"], rec["metrics_totals"]
    rec["crosscheck_vs_metrics_json"] = {
        "sram": (t["sram"], m["srams"]),
        "map_ram": (t["map_ram"], m["map_rams"]),
        "tcam": (t["tcam"], m["tcams"]),
    }
    rec["crosscheck_ok"] = all(a == b for a, b in rec["crosscheck_vs_metrics_json"].values())
    return rec


def frac(used, cap):
    return f"{used}/{cap} ({100.0 * used / cap:.1f}%)" if cap else str(used)


def phv_cell(phv, kind):
    parts = []
    for w in (8, 16, 32):
        c = phv.get(f"{kind}_{w}b")
        if c:
            parts.append(f"{c['containers_occupied']}/{c['containers_available']}×{w}b")
    return ", ".join(parts)


def markdown(recs):
    out = ["# Phase 1: compile-time resources", ""]
    out += ["Usage over the whole pipe (all MAU stages; ingress and egress share them). "
            "MAU latency is the compiler's estimate in pipeline clock cycles.", ""]
    head = ["variant", "status", "-D flags", "stages ig/eg", "crit. path"]
    head += [n.replace("_", " ") for n in OVERVIEW]
    head += ["PHV normal", "PHV tagalong", "parser TCAM ig/eg", "MAU latency ig/eg",
             "power ig/eg (W)", "compile wall s", "peak RSS MiB"]
    out.append("| " + " | ".join(head) + " |")
    out.append("|" + "---|" * len(head))
    for r in recs:
        c = r["compile"]
        defines = " ".join(c.get("defines", [])) or "–"
        if r["status"] != "ok":
            cells = [r["variant"], "**failed**", defines] + ["–"] * (len(head) - 5)
            cells += [str(c.get("wall_s", "–")), f"{c.get('peak_rss_kib', 0) / 1024:.0f}"]
            out.append("| " + " | ".join(cells) + " |")
            continue
        mau, tb = r["mau"], r["tables"]
        cells = [r["variant"], "ok", defines,
                 f"{tb.get('ingress_stages', '?')}/{tb.get('egress_stages', '?')}",
                 str(tb.get("critical_path", "?"))]
        cells += [frac(mau["totals"][n], mau["pipe_capacity"][n]) for n in OVERVIEW]
        cells += [phv_cell(r["phv"], "normal"), phv_cell(r["phv"], "tagalong"),
                  f"{r['parser_tcam_rows'].get('ingress')}/{r['parser_tcam_rows'].get('egress')}",
                  f"{r['latency_cycles'].get('ingress')}/{r['latency_cycles'].get('egress')}",
                  f"{r['power_estimate'].get('ingress', 0):.2f}/"
                  f"{r['power_estimate'].get('egress', 0):.2f}",
                  f"{c.get('wall_s')}", f"{c.get('peak_rss_kib', 0) / 1024:.0f}"]
        out.append("| " + " | ".join(cells) + " |")
    out.append("")

    for r in recs:
        if r["status"] != "ok":
            continue
        mau = r["mau"]
        cols = ["sram", "map_ram", "tcam", "stateful_alu", "stats_alu", "hash_bit",
                "hash_dist_unit", "gateway", "vliw_instr", "xbar_exact_byte",
                "logical_table"]
        out += [f"## {r['variant']}: per-stage usage", ""]
        out.append("| stage | " + " | ".join(c.replace("_", " ") for c in cols) + " |")
        out.append("|" + "---|" * (len(cols) + 1))
        cap = mau["stage_capacity"]
        out.append("| *capacity* | " + " | ".join(str(cap[c]) for c in cols) + " |")
        for num, row in mau["per_stage"].items():
            out.append(f"| {num} | " + " | ".join(
                f"{row[c]} ({100.0 * row[c] / cap[c]:.0f}%)" if row[c] else "0"
                for c in cols) + " |")
        out.append("")
        if mau["registers"]:
            out += [f"### {r['variant']}: register placement", "",
                    "| register | stage | SRAM | map RAM | stateful ALU |", "|---|---|---|---|---|"]
            for name, places in mau["registers"].items():
                for p in places:
                    out.append(f"| {name} | {p['stage']} | {p['sram']} | {p['map_ram']} | "
                               f"{p['stateful_alu']} |")
            out.append("")
        if not r["crosscheck_ok"]:
            out += [f"**Cross-check mismatch** (resources.json vs metrics.json): "
                    f"{r['crosscheck_vs_metrics_json']}", ""]

    failed = [r for r in recs if r["status"] != "ok"]
    if failed:
        out += ["## Failed compiles", ""]
        for r in failed:
            out.append(f"**{r['variant']}** (exit {r['compile'].get('exit_code')}):")
            out.append("```")
            out += r.get("errors", []) or ["(no error lines found in compile.log)"]
            out += ["```", ""]
            if r.get("placement_attempts"):
                out.append("Table-placement rounds before the failure: " + "; ".join(
                    f"round {a['round']} ({a['state']}): {a.get('ingress_stages', '?')} "
                    f"ingress / {a.get('egress_stages', '?')} egress stages"
                    for a in r["placement_attempts"]) + ".")
                out.append("")
    return "\n".join(out)


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    prefix = Path(sys.argv[1])
    recs = [parse_build(b) for b in sys.argv[2:]]
    prefix.with_suffix(".json").write_text(json.dumps(recs, indent=2) + "\n")
    prefix.with_suffix(".md").write_text(markdown(recs) + "\n")
    for r in recs:
        note = "" if r["status"] != "ok" or r["crosscheck_ok"] else "  CROSS-CHECK MISMATCH"
        print(f"{r['variant']:18s} {r['status']}{note}")
    print(f"wrote {prefix.with_suffix('.json')} and {prefix.with_suffix('.md')}")


if __name__ == "__main__":
    main()
