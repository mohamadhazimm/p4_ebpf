#!/usr/bin/env python3
"""Summarise packet-generator runs of perf/tools/sw_pktgen_run.py.

    python3 perf/tools/pktgen_summary.py RUN_DIR LABEL [LABEL ...] [--out PREFIX]

Reads RUN_DIR/LABEL_*.json and prints one table row per run, plus PREFIX.md
and PREFIX.json if --out is given. Checks per run:
- lossless: generated = sink TX = sink RX and no TM drop at the sink;
- pipe 1 exact (detector): the flow's reg_pkts in the generator's pipe grew by
  the generated count, and reg_bytes by generated x IPv4 totalLen (mod 2^32);
- pipe 0 exact (detector): reg_pkts in pipe 0 grew by the looped-back count.
A run at the generator's maximum above line rate is not lossless by design:
the TM drops what one 100G port cannot send.
"""
import argparse
import json
from pathlib import Path

MASK32 = (1 << 32) - 1


def row(d):
    size = d["size"]
    tm_drops = d.get("tm_eg_delta", {}).get("drop_count_packets")
    r = {
        "run": d["_name"], "size": size, "mode": "paced %.1f%%" % d["rate_pct_target"] if d.get("rate_pct_target") else "max",
        "gen_mpps": d.get("gen_mpps", 0.0), "tx_mpps": d["tx_mpps"], "pct_line": d["pct_of_line_rate"],
        "gbps_l1": d["tx_gbps_l1"], "gbps_l2": d["tx_gbps_l2"], "generated": d["generated"],
        "tx": d["sink_tx_frames"], "rx": d["sink_rx_frames"], "tm_drops": tm_drops,
        "tx_errors": d["sink_tx_errors"], "errors": d["errors"],
    }
    r["lossless"] = (r["generated"] == r["tx"] == r["rx"] and tm_drops == 0 and not r["tx_errors"])
    r["drops_explained"] = tm_drops == r["generated"] - r["tx"]
    if "reg_pkts_delta" in d:
        p = d["pipe"]
        r["pipe_exact"] = d["reg_pkts_delta"][p] == r["generated"]
        r["pipe_bytes_exact"] = d["reg_bytes_delta"][p] == (r["generated"] * (size - 18)) & MASK32
        r["pipe0_exact"] = d["reg_pkts_delta"][0] == r["rx"]
    return r


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("run_dir", type=Path)
    ap.add_argument("labels", nargs="+")
    ap.add_argument("--out")
    a = ap.parse_args()
    rows = []
    for label in a.labels:
        for f in sorted(a.run_dir.glob(label + "_*.json"), key=lambda f: (json.loads(f.read_text())["size"], f.name)):
            d = json.loads(f.read_text())
            d["_name"] = f.stem
            rows.append(row(d))
    head = ("| Run | Frame | Mode | Generator Mpps | Sink TX Mpps | % line rate | Gbps L1 | Generated | Sink TX "
            "| TM drops | Lossless | reg_pkts = generated | reg_bytes | pipe 0 = looped |")
    lines = [head, "|" + "---|" * 14]
    yn = lambda v: "–" if v is None else ("yes" if v else "NO")
    for r in rows:
        lines.append("| %s | %d B | %s | %.3f | %.3f | %.3f | %.2f | %d | %d | %s | %s | %s | %s | %s |" % (
            r["run"], r["size"], r["mode"], r["gen_mpps"], r["tx_mpps"], r["pct_line"], r["gbps_l1"],
            r["generated"], r["tx"], r["tm_drops"], yn(r["lossless"]), yn(r.get("pipe_exact")),
            yn(r.get("pipe_bytes_exact")), yn(r.get("pipe0_exact"))))
    bad = [r["run"] for r in rows if r["errors"] or not r["drops_explained"]
           or (r["mode"] != "max" and not r["lossless"])
           or (r["size"] == 64 and not r["lossless"])
           or any(r.get(k) is False for k in ("pipe_exact", "pipe_bytes_exact", "pipe0_exact"))]
    lines.append("")
    lines.append("%d runs; problems: %s" % (len(rows), bad or "none"))
    text = "\n".join(lines)
    print(text)
    if a.out:
        Path(a.out + ".md").write_text(text + "\n")
        Path(a.out + ".json").write_text(json.dumps(rows, indent=2) + "\n")


if __name__ == "__main__":
    main()
