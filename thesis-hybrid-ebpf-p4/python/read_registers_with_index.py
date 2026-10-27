#!/usr/bin/env python3
"""Read the detector's flow registers at given bucket indexes through bfrt_python.

The indexes normally come from the CPU reports (cpu_report_t.flow_index). The
script runs bfshell on this host, or with --ssh on a switch (bfshell_run.py).

All 14 registers of ingress.p4 are read. Values that the data plane does not
keep are derived: pkts_ba = pkts - pkts_ab, bytes_ba = bytes - bytes_ab,
duration_ns = last_ts - first_ts (mod 2^32; the timestamps are the low 32 bits
of a nanosecond clock and wrap every 4.295 s).

Every register exists once per pipe, and a packet updates the copy of the pipe
its ingress port belongs to. Rows combine the pipes: counters are summed,
min_len/first_ts take the smallest non-zero value, max_len/last_ts the
largest; "pipes" lists the pipes that hold data. A flow seen in more than one
pipe (its directions enter on ports of different pipes) has its direction
split per pipe, so pkts_ab is not meaningful for it; "multi_pipe" flags that.

--snapshot sync (default) first copies all 14 registers from the hardware
(operation_register_sync, a few ms each) and then reads that copy, so the
values of one flow are taken at the same moment. --snapshot hw reads every
cell from the hardware directly.

--clear-if-unchanged IDX:PKTS,... clears, after the read and in the same
session, the 14 registers of every listed bucket whose pkts still equals PKTS
(no traffic since the caller's previous read). A cleared bucket is empty
again, so the next packet that lands in it sends a new first-seen CPU report.
The payload lists the cleared buckets under "cleared".
"""
import argparse
import json
import socket
import sys
from pathlib import Path

from bfshell_run import DEFAULT_REMOTE_SDE_INSTALL, default_bfshell, run_bfshell_script

BF_PORT = 9999
INDEX_FILE = "/home/ubuntu/Desktop/p4_ebpf/thesis-hybrid-ebpf-p4/python/indexes_unique.txt"
FLOW_BUCKETS = 65536


def port_open(host: str, port: int, timeout=1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def load_indices_from_file(path: str) -> list:
    idxs = []
    for line in Path(path).read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        for p in line.replace(",", " ").split():
            if p.isdigit():
                idxs.append(int(p))
    return idxs


# Runs inside bfrt_python. SDE 9.6 embeds Python 3.4 (no f-strings) and runs a
# script with separate globals and locals, so top-level functions cannot call
# each other: everything lives in one function and its closures.
INNER_TEMPLATE = r'''
def _read_registers_main():
    import json
    import time
    from collections import OrderedDict

    PARAMS = json.loads(__PARAMS__)
    REG_NAMES = ["reg_pkts", "reg_bytes", "reg_pkts_ab", "reg_bytes_ab",
                 "reg_ref_src_port", "reg_ref_dst_port", "reg_dir_valid",
                 "reg_min_len", "reg_max_len", "reg_first_ts", "reg_last_ts",
                 "reg_syn", "reg_ack", "reg_rst"]
    REQUIRED = ["reg_pkts", "reg_bytes", "reg_pkts_ab", "reg_bytes_ab"]
    SUMMED = ["reg_pkts", "reg_bytes", "reg_pkts_ab", "reg_bytes_ab", "reg_syn", "reg_ack", "reg_rst"]

    ing = bfrt.basic.pipe.Ingress
    regs = {}
    for name in REG_NAMES:
        try:
            regs[name] = getattr(ing, name)
        except AttributeError:
            if PARAMS["strict"] and name in REQUIRED:
                raise RuntimeError("Required register is missing from pipeline: " + name)

    def as_list(r):
        if r is None:
            return []
        if isinstance(r, (list, tuple)):
            return list(r)
        return [r]

    def f1_values(entry):
        for k, v in entry.data.items():
            k = k.decode() if isinstance(k, bytes) else k
            if k.endswith(".f1"):
                return [int(x) for x in as_list(v)]
        raise RuntimeError("no .f1 field in register entry")

    def read_cell(reg, idx, from_hw):
        ents = as_list(reg.get(REGISTER_INDEX=idx, from_hw=from_hw, print_ents=False))
        if not ents:
            raise RuntimeError("empty read")
        return f1_values(ents[0])

    def sync_all(timeout_s):
        for name, reg in regs.items():
            done = []
            def cb(dev_id, pipe_id, direction, parser_id, done=done):
                done.append(1)
            t0 = time.time()
            reg.operation_register_sync(cb)
            while not done:
                if time.time() - t0 > timeout_s:
                    return False
                time.sleep(0.0005)
        return True

    snapshot = PARAMS["snapshot"]
    t_start = time.time()
    sync_s = None
    if snapshot == "sync":
        try:
            ok = sync_all(10.0)
        except Exception:
            ok = False
        sync_s = round(time.time() - t_start, 4)
        if not ok:
            snapshot = "hw"
    from_hw = snapshot == "hw"

    def combine(per_pipe):
        pipes = [p for p in range(len(per_pipe["reg_pkts"]))
                 if per_pipe["reg_pkts"][p] or per_pipe["reg_dir_valid"][p]]
        row = {}
        for name in SUMMED:
            row[name] = sum(per_pipe[name][p] for p in pipes)
        nz = lambda name: [per_pipe[name][p] for p in pipes if per_pipe[name][p]]
        row["reg_min_len"] = min(nz("reg_min_len")) if nz("reg_min_len") else 0
        row["reg_max_len"] = max(nz("reg_max_len")) if nz("reg_max_len") else 0
        row["reg_first_ts"] = min(nz("reg_first_ts")) if nz("reg_first_ts") else 0
        row["reg_last_ts"] = max(nz("reg_last_ts")) if nz("reg_last_ts") else 0
        ref = [p for p in pipes if per_pipe["reg_dir_valid"][p]]
        row["reg_dir_valid"] = 1 if ref else 0
        row["reg_ref_src_port"] = per_pipe["reg_ref_src_port"][ref[0]] if ref else 0
        row["reg_ref_dst_port"] = per_pipe["reg_ref_dst_port"][ref[0]] if ref else 0
        return row, pipes

    rows = []
    errors = []
    for idx in PARAMS["indexes"]:
        per_pipe = {}
        for name in REG_NAMES:
            reg = regs.get(name)
            if reg is None:
                per_pipe[name] = [0]
                continue
            try:
                per_pipe[name] = read_cell(reg, idx, from_hw)
            except Exception as error:
                if PARAMS["strict"] and name in REQUIRED:
                    raise RuntimeError("Could not read required register %s at index %d: %s"
                                       % (name, idx, error))
                errors.append("%s[%d]: %s" % (name, idx, error))
                per_pipe[name] = [0]
        n = max(len(v) for v in per_pipe.values())
        for name in per_pipe:
            per_pipe[name] = (per_pipe[name] + [0] * n)[:n]
        r, pipes = combine(per_pipe)
        pkts, byt = r["reg_pkts"], r["reg_bytes"]
        first_ts, last_ts = r["reg_first_ts"], r["reg_last_ts"]
        rows.append({
            "idx": idx,
            "pkts": pkts,
            "bytes": byt,
            "bpp": (float(byt) / pkts) if pkts else 0.0,
            "pkts_ab": r["reg_pkts_ab"],
            "pkts_ba": max(0, pkts - r["reg_pkts_ab"]),
            "bytes_ab": r["reg_bytes_ab"],
            "bytes_ba": max(0, byt - r["reg_bytes_ab"]),
            "ref_src_port": r["reg_ref_src_port"],
            "ref_dst_port": r["reg_ref_dst_port"],
            "dir_valid": r["reg_dir_valid"],
            "min_len": r["reg_min_len"],
            "max_len": r["reg_max_len"],
            "first_ts": first_ts,
            "last_ts": last_ts,
            "duration_ns": ((last_ts - first_ts) % (1 << 32)) if (first_ts and last_ts) else 0,
            "syn": r["reg_syn"],
            "ack": r["reg_ack"],
            "rst": r["reg_rst"],
            "pipes": pipes,
            "multi_pipe": len(pipes) > 1,
        })

    read_s = round(time.time() - t_start, 4)

    # Clear idle buckets so that the next flow landing in them reports again.
    cleared = []
    pkts_now = dict((r["idx"], r["pkts"]) for r in rows)
    for key, prev_pkts in sorted(PARAMS["clear_if_unchanged"].items()):
        idx = int(key)
        if pkts_now.get(idx) != prev_pkts:
            continue
        try:
            for name, reg in regs.items():
                reg.mod(REGISTER_INDEX=idx, f1=0)
            cleared.append(idx)
        except Exception as error:
            errors.append("clear %d: %s" % (idx, error))
    if cleared:
        try:
            bfrt.complete_operations()
        except Exception as error:
            errors.append("complete_operations: %s" % error)

    # Python 3.4 dicts are unordered; keep "source" first and "rows" last.
    payload = OrderedDict([
        ("source", PARAMS["source"]),
        ("flow_count", len(rows)),
        ("snapshot", snapshot),
        ("sync_s", sync_s),
        ("read_s", read_s),
        ("clear_s", round(time.time() - t_start - read_s, 4)),
        ("t_switch", t_start),
        ("errors", errors),
        ("cleared", cleared),
        ("rows", rows),
    ])
    if PARAMS["format"] == "json":
        print(json.dumps(payload))
        return

    tot_pkts = sum(r["pkts"] for r in rows)
    tot_bytes = sum(r["bytes"] for r in rows)
    print("")
    print("=== OVERALL (%s, snapshot %s) ===" % (PARAMS["source"], snapshot))
    print("Flows: %d" % len(rows))
    print("Total pkts: %d" % tot_pkts)
    print("Total bytes: %d" % tot_bytes)
    print("Avg B/packet: %.2f" % ((float(tot_bytes) / tot_pkts) if tot_pkts else 0.0))
    print("Flows with any AB traffic: %d / %d" % (sum(1 for r in rows if r["pkts_ab"] > 0), len(rows)))
    print("Flows with any BA traffic: %d / %d" % (sum(1 for r in rows if r["pkts_ba"] > 0), len(rows)))
    print("Flows with direction reference initialized: %d / %d"
          % (sum(1 for r in rows if r["dir_valid"]), len(rows)))
    print("Flows seen in more than one pipe: %d" % sum(1 for r in rows if r["multi_pipe"]))
    print("")
    print("=== TCP flags totals ===")
    print("SYN: %d" % sum(r["syn"] for r in rows))
    print("ACK: %d" % sum(r["ack"] for r in rows))
    print("RST: %d" % sum(r["rst"] for r in rows))
    if errors:
        print("")
        print("=== Read errors (%d) ===" % len(errors))
        for e in errors[:20]:
            print(e)

_read_registers_main()
'''


def build_inner_script(indexes, source: str, out_format: str, strict: bool, snapshot: str,
                       clear_if_unchanged=None) -> str:
    params = {"indexes": [int(i) for i in indexes], "source": source, "format": out_format,
              "strict": bool(strict), "snapshot": snapshot,
              "clear_if_unchanged": {str(int(k)): int(v) for k, v in (clear_if_unchanged or {}).items()}}
    return INNER_TEMPLATE.replace("__PARAMS__", repr(json.dumps(params)))


def parse_clear_arg(text: str) -> dict:
    out = {}
    for item in text.split(","):
        item = item.strip()
        if item:
            idx, pkts = item.split(":")
            out[int(idx)] = int(pkts)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--indexes", default="", help="comma-separated indexes, e.g. 1,2,3")
    ap.add_argument("--index-file", default=INDEX_FILE)
    ap.add_argument("--index-mode", choices=["cli", "file"], default="cli")
    ap.add_argument("--flow-buckets", type=int, default=FLOW_BUCKETS)
    ap.add_argument("--format", choices=["summary", "json"], default="summary")
    ap.add_argument("--bfshell", default=default_bfshell(),
                    help="local bfshell (default: $SDE_INSTALL/bin/bfshell)")
    ap.add_argument("--bf-port", type=int, default=BF_PORT)
    ap.add_argument("--ssh", help="run bfshell on this switch, e.g. root@172.168.1.2")
    ap.add_argument("--remote-sde-install", default=DEFAULT_REMOTE_SDE_INSTALL)
    ap.add_argument("--snapshot", choices=["sync", "hw"], default="sync")
    ap.add_argument("--clear-if-unchanged", default="",
                    help="IDX:PKTS,... clear these buckets after the read if pkts is still PKTS")
    ap.add_argument("--timeout", type=float, default=600)
    ap.add_argument(
        "--strict-core-registers",
        action="store_true",
        help="Fail if a required packet/byte register cannot be read or parsed",
    )
    args = ap.parse_args()

    if not args.ssh:
        if not Path(args.bfshell).exists():
            print(f"[ERROR] bfshell not found at: {args.bfshell}", file=sys.stderr)
            sys.exit(1)
        if not port_open("127.0.0.1", args.bf_port):
            print(f"[ERROR] Connection refused on 127.0.0.1:{args.bf_port}", file=sys.stderr)
            print("Start bf_switchd first, then re-run.", file=sys.stderr)
            print(f"Check: sudo ss -lntp | grep :{args.bf_port}", file=sys.stderr)
            sys.exit(1)

    if args.index_mode == "cli":
        raw = [int(x) for x in args.indexes.split(",") if x.strip()]
        source = "indices from CLI"
    else:
        raw = load_indices_from_file(args.index_file)
        source = "indices from file"
    idxs = []
    for i in raw:
        if not 0 <= i < args.flow_buckets:
            print(f"[ERROR] index {i} outside [0, {args.flow_buckets})", file=sys.stderr)
            sys.exit(1)
        if i not in idxs:
            idxs.append(i)

    clear = parse_clear_arg(args.clear_if_unchanged)
    unread = sorted(set(clear) - set(idxs))
    if unread:
        print(f"[ERROR] --clear-if-unchanged lists buckets that are not read: {unread}", file=sys.stderr)
        sys.exit(1)
    script = build_inner_script(idxs, source, args.format, args.strict_core_registers, args.snapshot,
                                clear_if_unchanged=clear)
    out = run_bfshell_script(script, bfshell=args.bfshell, port=args.bf_port, ssh_host=args.ssh,
                             remote_sde_install=args.remote_sde_install, timeout=args.timeout)
    if args.format != "json":
        print(out)
        return
    # bfshell's output also holds banners and the echoed commands: print only the payload.
    payload = extract_payload(out)
    if payload is None:
        print("[ERROR] no register payload in the bfshell output:", file=sys.stderr)
        print(out[-3000:], file=sys.stderr)
        sys.exit(1)
    print(payload)


def extract_payload(out: str):
    for line in reversed(out.splitlines()):
        line = line.strip()
        if line.startswith("{") and '"rows"' in line:
            try:
                json.loads(line)
                return line
            except ValueError:
                continue
    return None


if __name__ == "__main__":
    main()
