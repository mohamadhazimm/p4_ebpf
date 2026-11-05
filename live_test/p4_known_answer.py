#!/usr/bin/env python3
"""Known-answer test of the P4 data plane on the Tofino model.

    sudo python3 live_test/p4_known_answer.py --int-iface veth0 --ext-iface veth2 --out results/ka.json

Crafted flows with exactly known counts are injected on the internal side
(model port 0) and the external side (model port 1):

  A  TCP client->server :80, handshake, request, two response segments, FIN teardown
  B  UDP DNS-like query and answer
  C  TCP SYN to a closed port, answered by RST+ACK
  D  TCP connection opened from the external side (direction reference = ext)
  E  five SYNs from one client to one service, five source ports (reg_newconn_dst = 5)
  G  UDP with equal source and destination port (123 -> 123), both directions
  -  an ARP request and an ICMP echo, which are forwarded but not counted

Checked:
  forwarding  every injected frame leaves on the other side
  reports     one CPU report per new bucket on --cpu-iface (magic 0xBEF1, the
              first packet's 5-tuple, flow_index = flow_index.py), parsed with
              the collector's own listen_cpu_reports.ReportCollector
  registers   all 14 flow registers and reg_newconn_dst, read with the
              collector's read_registers_with_index.py (--reader legacy, the
              default) or batched_reader.py over BF Runtime gRPC
              (--reader batched --grpc-addr HOST:50052), against the expected
              values (bytes = IPv4 totalLen)
  clear       --clear-if-unchanged zeroes a bucket; its next packet reports again

The test buckets are zeroed first (register mod, as the reader's clear does),
so the test can run on a switch that has seen other traffic.
"""
import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

from scapy.all import ARP, ICMP, IP, TCP, UDP, AsyncSniffer, Ether, Raw, conf

REPO = Path(__file__).resolve().parents[1]
PYDIR = REPO / "thesis-hybrid-ebpf-p4" / "python"
sys.path.insert(0, str(PYDIR))
from bfshell_run import run_bfshell_script  # noqa: E402
from flow_index import compute_flow_index, compute_newconn_dst_index  # noqa: E402
from listen_cpu_reports import ReportCollector  # noqa: E402

READER = PYDIR / "read_registers_with_index.py"
BATCHED_READER = PYDIR / "batched_reader.py"
READER_OPTS = {"reader": "legacy", "grpc_addr": "127.0.0.1:50052", "extra": []}
FLOW_REGS = ["reg_pkts", "reg_bytes", "reg_pkts_ab", "reg_bytes_ab", "reg_ref_src_port",
             "reg_ref_dst_port", "reg_dir_valid", "reg_min_len", "reg_max_len", "reg_first_ts",
             "reg_last_ts", "reg_syn", "reg_ack", "reg_rst"]

C, S = "10.0.0.1", "10.0.0.2"          # client on the internal side, server on the external side
C_MAC, S_MAC = "02:00:0a:00:00:01", "02:00:0a:00:00:02"
GAP = 0.02


class Plan:
    def __init__(self):
        self.packets = []     # (side, frame, flow name or None)
        self.flows = {}
        self.ipid = 100

    def add(self, side, src, dst, l4, payload=0, flow=None):
        smac, dmac = (C_MAC, S_MAC) if side == "int" else (S_MAC, C_MAC)
        self.ipid += 1
        frame = Ether(src=smac, dst=dmac) / IP(src=src, dst=dst, id=self.ipid, ttl=64) / l4
        if payload:
            frame = frame / Raw(b"x" * payload)
        frame = Ether(bytes(frame))
        self.packets.append((side, frame, flow))
        if flow is None:
            return
        proto = frame[IP].proto
        sp, dp = int(frame[IP].payload.sport), int(frame[IP].payload.dport)
        tot = int(frame[IP].len)
        f = self.flows.setdefault(flow, {
            "first": (src, dst, sp, dp, proto), "idx": compute_flow_index(src, dst, sp, dp, proto),
            "pkts": 0, "bytes": 0, "pkts_ab": 0, "bytes_ab": 0, "min_len": tot, "max_len": tot,
            "syn": 0, "ack": 0, "rst": 0})
        f["pkts"] += 1
        f["bytes"] += tot
        rs, rd = f["first"][2], f["first"][3]
        if (sp == rs and dp == rd) or not (sp == rd and dp == rs):
            f["pkts_ab"] += 1
            f["bytes_ab"] += tot
        f["min_len"] = min(f["min_len"], tot)
        f["max_len"] = max(f["max_len"], tot)
        if proto == 6:
            fl = int(frame[TCP].flags)
            f["syn"] += int(bool(fl & 0x02))
            f["ack"] += int(bool(fl & 0x10))
            f["rst"] += int(bool(fl & 0x04))


def build_plan():
    p = Plan()
    # A: HTTP-like session, internal client to external server
    cp = 41001
    p.add("int", C, S, TCP(sport=cp, dport=80, flags="S", seq=1000), flow="A")
    p.add("ext", S, C, TCP(sport=80, dport=cp, flags="SA", seq=5000, ack=1001), flow="A")
    p.add("int", C, S, TCP(sport=cp, dport=80, flags="A", seq=1001, ack=5001), flow="A")
    p.add("int", C, S, TCP(sport=cp, dport=80, flags="PA", seq=1001, ack=5001), 100, flow="A")
    p.add("ext", S, C, TCP(sport=80, dport=cp, flags="A", seq=5001, ack=1101), 1000, flow="A")
    p.add("ext", S, C, TCP(sport=80, dport=cp, flags="PA", seq=6001, ack=1101), 500, flow="A")
    p.add("int", C, S, TCP(sport=cp, dport=80, flags="A", seq=1101, ack=6501), flow="A")
    p.add("int", C, S, TCP(sport=cp, dport=80, flags="FA", seq=1101, ack=6501), flow="A")
    p.add("ext", S, C, TCP(sport=80, dport=cp, flags="FA", seq=6501, ack=1102), flow="A")
    p.add("int", C, S, TCP(sport=cp, dport=80, flags="A", seq=1102, ack=6502), flow="A")
    # B: DNS-like UDP exchange
    p.add("int", C, S, UDP(sport=41002, dport=53), 40, flow="B")
    p.add("ext", S, C, UDP(sport=53, dport=41002), 120, flow="B")
    # C: SYN to a closed port, RST+ACK
    p.add("int", C, S, TCP(sport=41003, dport=8443, flags="S", seq=7000), flow="C")
    p.add("ext", S, C, TCP(sport=8443, dport=41003, flags="RA", seq=0, ack=7001), flow="C")
    # D: opened from the external side
    p.add("ext", S, C, TCP(sport=41004, dport=22, flags="S", seq=9000), flow="D")
    p.add("int", C, S, TCP(sport=22, dport=41004, flags="SA", seq=3000, ack=9001), flow="D")
    p.add("ext", S, C, TCP(sport=41004, dport=22, flags="A", seq=9001, ack=3001), flow="D")
    # E: five new connections to one service
    for k in range(5):
        p.add("int", C, S, TCP(sport=42000 + k, dport=9099, flags="S", seq=100 * k), flow=f"E{k}")
    # G: equal ports, both directions
    p.add("int", C, S, UDP(sport=123, dport=123), 48, flow="G")
    p.add("ext", S, C, UDP(sport=123, dport=123), 48, flow="G")
    # not counted: ARP and ICMP
    p.add("int", C, S, ARP(op=1, hwsrc=C_MAC, psrc=C, pdst=S))
    p.add("int", C, S, ICMP(type=8, id=7, seq=1), 32)
    return p


def bfrt(script, timeout=300):
    return run_bfshell_script(script, timeout=timeout)


def zero_buckets(idxs, dst_idxs):
    script = (
        "ing = bfrt.basic.pipe.Ingress\n"
        "for name in %r:\n"
        "    reg = getattr(ing, name)\n"
        "    for i in %r:\n"
        "        reg.mod(REGISTER_INDEX=i, f1=0)\n"
        "for i in %r:\n"
        "    ing.reg_newconn_dst.mod(REGISTER_INDEX=i, f1=0)\n"
        "bfrt.complete_operations()\n"
        "print('[OK] zeroed')\n" % (FLOW_REGS, sorted(idxs), sorted(dst_idxs)))
    out = bfrt(script)
    if "[OK] zeroed" not in out:
        raise RuntimeError("zeroing failed:\n" + out[-2000:])


def read(idxs, dst_idxs, clear=None):
    if READER_OPTS["reader"] == "batched":
        cmd = [sys.executable, str(BATCHED_READER), "--grpc-addr", READER_OPTS["grpc_addr"]] + READER_OPTS["extra"]
    else:
        cmd = [sys.executable, str(READER)]
    cmd += ["--index-mode", "cli", "--indexes", ",".join(map(str, idxs)),
            "--format", "json", "--snapshot", "sync", "--strict-core-registers"]
    if dst_idxs:
        cmd += ["--dst-indexes", ",".join(map(str, dst_idxs))]
    if clear:
        cmd += ["--clear-if-unchanged", ",".join(f"{i}:{p}" for i, p in clear.items())]
    t0 = time.time()
    res = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    if res.returncode != 0:
        raise RuntimeError(f"reader failed ({res.returncode}):\n{res.stdout[-2000:]}\n{res.stderr[-2000:]}")
    payload = json.loads(res.stdout.strip().splitlines()[-1])
    payload["_wall_s"] = round(time.time() - t0, 3)
    return payload


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--int-iface", default="veth0", help="inject internal-side frames here (reaches model port 0)")
    ap.add_argument("--ext-iface", default="veth2", help="inject external-side frames here (reaches model port 1)")
    ap.add_argument("--int-egress-iface", default=None, help="where port-0 output appears (default: --int-iface)")
    ap.add_argument("--ext-egress-iface", default=None, help="where port-1 output appears (default: --ext-iface)")
    ap.add_argument("--cpu-iface", default="veth5")
    ap.add_argument("--out", required=True)
    ap.add_argument("--reader", choices=["legacy", "batched"], default="legacy",
                    help="register reader under test (legacy = bfshell/bfrt_python, batched = BF Runtime gRPC)")
    ap.add_argument("--grpc-addr", default="127.0.0.1:50052", help="BF Runtime gRPC server for --reader batched")
    ap.add_argument("--raw-wire", action="store_true", help="--reader batched: its wire-format route (--raw-wire)")
    ap.add_argument("--sync-batched", action="store_true", help="--reader batched: the Syncs in one Write RPC")
    args = ap.parse_args()
    READER_OPTS.update(reader=args.reader, grpc_addr=args.grpc_addr,
                       extra=(["--raw-wire"] if args.raw_wire else []) + (["--sync-batched"] if args.sync_batched else []))
    int_out = args.int_egress_iface or args.int_iface
    ext_out = args.ext_egress_iface or args.ext_iface

    plan = build_plan()
    flows = plan.flows
    idxs = sorted({f["idx"] for f in flows.values()})
    if len(idxs) != len(flows):
        sys.exit("test flows collide in the flow index; change the ports")
    newconn = {}
    for side, frame, flow in plan.packets:
        if flow and frame[IP].proto == 6 and int(frame[TCP].flags) & 0x12 == 0x02:
            k = (frame[IP].src, frame[IP].dst, int(frame[TCP].dport), 6)
            newconn[k] = newconn.get(k, 0) + 1
    dst_idx = {k: compute_newconn_dst_index(*k) for k in newconn}
    if len(set(dst_idx.values())) != len(dst_idx):
        sys.exit("new-connection keys collide; change the addresses")

    results = {"checks": [], "flows": {}, "timing": {}, "reader": args.reader}

    def check(name, ok, detail=""):
        results["checks"].append({"name": name, "ok": bool(ok), "detail": detail})
        print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f"  ({detail})" if detail else ""), flush=True)

    t = time.time()
    zero_buckets(idxs, set(dst_idx.values()))
    results["timing"]["zero_s"] = round(time.time() - t, 2)
    before = read(idxs, sorted(set(dst_idx.values())))
    check("test buckets start at zero",
          all(r["pkts"] == 0 and r["dir_valid"] == 0 for r in before["rows"])
          and all(r["new_conn"] == 0 for r in before["dst_rows"]))

    # capture: CPU reports with the collector's own listener, forwarded frames on both sides
    reports = []
    rc = ReportCollector(args.cpu_iface, on_report=reports.append).start()
    sniff = AsyncSniffer(iface=sorted({int_out, ext_out}), store=True,
                         lfilter=lambda pk: IP in pk or ARP in pk)
    sniff.start()
    time.sleep(1.5)

    socks = {"int": conf.L2socket(iface=args.int_iface), "ext": conf.L2socket(iface=args.ext_iface)}
    t_send0 = time.time()
    for side, frame, _ in plan.packets:
        socks[side].send(frame)
        time.sleep(GAP)
    t_send1 = time.time()
    time.sleep(2.0)
    sniff.stop()
    rc.stop()
    for s in socks.values():
        s.close()
    results["timing"]["send_s"] = round(t_send1 - t_send0, 3)

    # forwarding: int-injected frames must appear on the ext egress side and vice versa
    seen = {"int": set(), "ext": set()}   # keyed by the side the frame was injected on
    for pk in sniff.results:
        on = pk.sniffed_on
        if IP in pk:
            key = ("ip", pk[IP].id, pk[IP].src)
        else:
            key = ("arp", pk[ARP].psrc, pk[ARP].pdst)
        if on == ext_out:
            seen["int"].add(key)
        if on == int_out:
            seen["ext"].add(key)
    missing = []
    for side, frame, flow in plan.packets:
        key = ("ip", frame[IP].id, frame[IP].src) if IP in frame else ("arp", frame[ARP].psrc, frame[ARP].pdst)
        if key not in seen[side]:
            missing.append((side, flow, frame.summary()))
    n_int = sum(1 for s, _, _ in plan.packets if s == "int")
    check("forwarding port 0 -> 1 and 1 -> 0", not missing,
          f"{len(plan.packets) - len(missing)}/{len(plan.packets)} frames out the other side "
          f"({n_int} injected on {args.int_iface}, {len(plan.packets) - n_int} on {args.ext_iface})"
          + (f"; missing: {missing[:4]}" if missing else ""))

    # CPU reports: one per bucket, first packet's 5-tuple, data-plane index = flow_index.py
    by_idx = {}
    for r in reports:
        by_idx.setdefault(r["idx"], []).append(r)
    check("one CPU report per new bucket", sorted(by_idx) == idxs and all(len(v) == 1 for v in by_idx.values()),
          f"{len(reports)} reports for {len(idxs)} buckets; ARP/ICMP must not report")
    bad = []
    for name, f in flows.items():
        rs = by_idx.get(f["idx"], [])
        if not rs:
            bad.append(f"{name}: none")
            continue
        r = rs[0]
        got = (r["src_ip"], r["dst_ip"], r["sport"], r["dport"], r["proto"])
        if got != tuple(f["first"]) or r["idx_source"] != "report" or r["idx"] != r["idx_computed"] \
                or r["reason"] != 1:
            bad.append(f"{name}: {got} idx={r['idx']}/{r['idx_computed']} {r['idx_source']} reason={r['reason']}")
    check("report fields: first-packet 5-tuple, magic 0xBEF1, flow_index = flow_index.py", not bad, "; ".join(bad))

    # registers through the collector's reader
    after = read(idxs, sorted(set(dst_idx.values())))
    results["timing"]["read_wall_s"] = after["_wall_s"]
    results["timing"]["read_sync_s"] = after.get("sync_s")
    results["timing"]["read_timing"] = after.get("timing")   # batched reader: per-phase ms and RPC counts
    rows = {r["idx"]: r for r in after["rows"]}
    for name, f in sorted(flows.items()):
        r = rows[f["idx"]]
        exp = {"pkts": f["pkts"], "bytes": f["bytes"], "pkts_ab": f["pkts_ab"], "bytes_ab": f["bytes_ab"],
               "pkts_ba": f["pkts"] - f["pkts_ab"], "bytes_ba": f["bytes"] - f["bytes_ab"],
               "min_len": f["min_len"], "max_len": f["max_len"], "syn": f["syn"], "ack": f["ack"],
               "rst": f["rst"], "dir_valid": 1, "ref_src_port": f["first"][2], "ref_dst_port": f["first"][3]}
        diff = {k: (r.get(k), v) for k, v in exp.items() if r.get(k) != v}
        ts_ok = r["first_ts"] > 0 and r["last_ts"] > 0
        results["flows"][name] = {"expected": exp, "read": r, "diff": {k: list(v) for k, v in diff.items()}}
        check(f"registers of flow {name} (idx {f['idx']})", not diff and ts_ok,
              ("diff (read, expected): " + json.dumps(diff)) if diff else
              f"pkts={r['pkts']} bytes={r['bytes']} ab={r['pkts_ab']} syn/ack/rst={r['syn']}/{r['ack']}/{r['rst']}"
              f" duration_ns={r['duration_ns']}")
    dst_rows = {r["idx"]: r["new_conn"] for r in after["dst_rows"]}
    dst_bad = {f"{k[0]}->{k[1]}:{k[2]}": (dst_rows.get(i), newconn[k]) for k, i in dst_idx.items()
               if dst_rows.get(i) != newconn[k]}
    check("reg_newconn_dst (SYN without ACK per client/server/port)", not dst_bad,
          json.dumps(dst_bad) if dst_bad else
          "; ".join(f"{k[1]}:{k[2]}={newconn[k]}" for k in newconn))

    # timestamps: units and plausibility
    a = rows[flows["A"]["idx"]]
    sent_span = GAP * 9
    results["timing"]["flow_A_duration_ns"] = a["duration_ns"]
    results["timing"]["flow_A_send_span_s"] = sent_span
    check("flow A duration_ns plausible for ~%.2f s of sending" % sent_span,
          0.5 * sent_span * 1e9 <= a["duration_ns"] <= 5 * sent_span * 1e9,
          f"duration_ns={a['duration_ns']} first_ts={a['first_ts']} last_ts={a['last_ts']}")

    # clear-if-unchanged on bucket A, then one more packet of A must report again
    ia = flows["A"]["idx"]
    cleared = read([ia], [], clear={ia: a["pkts"]})
    check("--clear-if-unchanged clears an idle bucket", cleared.get("cleared") == [ia], f"cleared={cleared.get('cleared')}")
    zero = read([ia], [])
    check("cleared bucket reads zero", zero["rows"][0]["pkts"] == 0 and zero["rows"][0]["dir_valid"] == 0)
    reports2 = []
    rc = ReportCollector(args.cpu_iface, on_report=reports2.append).start()
    time.sleep(1.5)
    s = conf.L2socket(iface=args.int_iface)
    s.send(Ether(src=C_MAC, dst=S_MAC) / IP(src=C, dst=S, id=999) / TCP(sport=41001, dport=80, flags="A"))
    s.close()
    time.sleep(2.0)
    rc.stop()
    again = read([ia], [])
    check("next packet after a clear reports again and counts from 1",
          [r["idx"] for r in reports2] == [ia] and again["rows"][0]["pkts"] == 1,
          f"reports={[r['idx'] for r in reports2]} pkts={again['rows'][0]['pkts']}")

    results["reports"] = reports
    results["summary"] = {"passed": sum(c["ok"] for c in results["checks"]), "total": len(results["checks"])}
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(results, indent=1, default=str))
    print(f"\n{results['summary']['passed']}/{results['summary']['total']} checks passed -> {args.out}")
    sys.exit(0 if results["summary"]["passed"] == results["summary"]["total"] else 1)


if __name__ == "__main__":
    main()
