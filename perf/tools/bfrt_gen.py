#!/usr/bin/env python3
"""Generate bfrt_python scripts for the hardware runs (run on the switch with
`run_bfshell.sh -b SCRIPT`).

    bfrt_gen.py setup      --prog basic --ports 132,140 --fwd 132:140,140:132 \
                           [--mirror-sid 1 --mirror-port 192 --mirror-len 64]
    bfrt_gen.py clear-regs --prog basic [--check-idx 1,2] [--sample 200] [--seed 1]
    bfrt_gen.py read-regs  --prog basic --idx 123,456
    bfrt_gen.py port-stats --ports 132,140
    bfrt_gen.py snapshot   --ports 132,140 [--prog basic --idx 1,2 --registers reg_pkts,reg_bytes]

The script is written to stdout. Every result is also printed as one line
"HZJSON <json>" so that the PC1 side can parse it from the logged bfshell
output. The generated code avoids f-strings and handles bytes or str keys in
entry.data, because the bfrt_python dialect of SDE 9.6 is not known in
advance.

bfrt_python runs a script with separate globals and locals, so a top-level
function cannot see another top-level function (only names that bfrt_python's
own module happens to define, such as bfrt and json). All generated code
therefore lives inside one function, _hz_main(), whose helpers are closures.
"""
import argparse
import json
import textwrap

# The 14 registers of thesis-hybrid-ebpf-p4/ingress.p4.
REGISTERS = ["reg_pkts", "reg_bytes", "reg_pkts_ab", "reg_bytes_ab",
             "reg_ref_src_port", "reg_ref_dst_port", "reg_dir_valid",
             "reg_min_len", "reg_max_len", "reg_first_ts", "reg_last_ts",
             "reg_syn", "reg_ack", "reg_rst"]

PRELUDE = r'''
import json, random, time, traceback
PARAMS = json.loads(%(params)r)

def emit(kind, obj):
    obj = dict(obj)
    obj["kind"] = kind
    print("HZJSON " + json.dumps(obj, sort_keys=True))

def as_list(r):
    if r is None:
        return []
    if isinstance(r, (list, tuple)):
        return list(r)
    try:
        return list(r)
    except TypeError:
        return [r]

def data_of(entry):
    d = {}
    for k, v in entry.data.items():
        if isinstance(k, bytes):
            k = k.decode()
        d[str(k)] = v
    return d

def plain(v):
    if isinstance(v, bytes):
        return v.decode(errors="replace")
    if isinstance(v, (list, tuple)):
        return [plain(x) for x in v]
    return v

def resolve(obj, path):
    for part in path.split("."):
        obj = getattr(obj, part)
    return obj

def f1_values(entry):
    return as_list([v for k, v in data_of(entry).items() if k.endswith(".f1")][0])

def port_stats(out):
    for dp in PARAMS.get("stat_ports", []):
        try:
            d = data_of(get_one(bfrt.port.port_stat, DEV_PORT=dp))
            out.setdefault("stats", {})[str(dp)] = dict((k, plain(d.get(k))) for k in PARAMS["fields"])
        except Exception as e:
            out["errors"].append("port_stat %%d: %%s" %% (dp, e))

def get_one(table, **key):
    """table.get() for one key, tolerant of SDE variations."""
    try:
        r = table.get(print_ents=False, **key)
    except TypeError:
        r = table.get(**key)
    ents = as_list(r)
    return ents[0] if ents else None
'''

SETUP = r'''
prog = getattr(bfrt, PARAMS["prog"])
result = {"ports": {}, "forwarding": [], "mirror": None, "errors": []}

for dp in PARAMS["ports"]:
    try:
        bfrt.port.port.add(DEV_PORT=dp, SPEED="BF_SPEED_100G", FEC="BF_FEC_TYP_RS",
                           AUTO_NEGOTIATION="PM_AN_FORCE_DISABLE", PORT_ENABLE=True)
        print("[setup] added and enabled dev_port %%d (100G RS, AN off)" %% dp)
    except Exception as e:
        result["errors"].append("port add %%d: %%s" %% (dp, e))
        print("[setup] port add %%d failed: %%s" %% (dp, e))

def port_data(dp):
    try:
        e = get_one(bfrt.port.port, DEV_PORT=dp)
        return data_of(e) if e is not None else {}
    except Exception as ex:
        return {"error": str(ex)}

t_link = time.time()
deadline = t_link + PARAMS["link_timeout_s"]
while True:
    up = dict((dp, bool(port_data(dp).get("$PORT_UP"))) for dp in PARAMS["ports"])
    if all(up.values()) or time.time() > deadline:
        break
    time.sleep(1)
result["link_wait_s"] = round(time.time() - t_link, 1)
for dp in PARAMS["ports"]:
    d = port_data(dp)
    result["ports"][str(dp)] = dict((k, plain(d.get(k))) for k in
        ("$PORT_NAME", "$SPEED", "$FEC", "$AUTO_NEGOTIATION", "$PORT_ENABLE", "$PORT_UP",
         "$MEDIA_TYPE", "error"))
    print("[setup] dev_port %%d: %%s" %% (dp, result["ports"][str(dp)]))

fwd = resolve(prog, PARAMS["fwd_table"])
try:
    fwd.clear()
except Exception as e:
    result["errors"].append("forwarding clear: %%s" %% e)
for src, dst in PARAMS["fwd"]:
    try:
        fwd.add_with_send_using_port(src, port=dst)
        result["forwarding"].append([src, dst])
        print("[setup] forwarding %%d -> %%d" %% (src, dst))
    except Exception as e:
        result["errors"].append("forwarding %%d->%%d: %%s" %% (src, dst, e))
        print("[setup] forwarding %%d -> %%d failed: %%s" %% (src, dst, e))

m = PARAMS.get("mirror")
if m:
    cfg = bfrt.mirror.cfg
    try:
        cfg.delete(sid=m["sid"])
    except Exception:
        pass
    try:
        cfg.add_with_normal(sid=m["sid"], session_enable=True, direction="INGRESS",
                            ucast_egress_port=m["port"], ucast_egress_port_valid=True,
                            max_pkt_len=m["len"])
        result["mirror"] = m
        print("[setup] mirror sid %%d -> dev_port %%d, max_pkt_len %%d" %% (m["sid"], m["port"], m["len"]))
    except Exception as e:
        result["errors"].append("mirror: %%s" %% e)
        print("[setup] mirror failed: %%s" %% e)

if PARAMS.get("lat_ports"):
    lat_calc = resolve(prog, PARAMS["lat_path"] + ".lat_calc")
    result["lat_calc"] = []
    for dp in PARAMS["lat_ports"]:
        try:
            lat_calc.add_with_compute_lat(egress_port=dp)
            result["lat_calc"].append(dp)
            print("[setup] lat_calc: measure packets leaving on dev_port %%d" %% dp)
        except Exception as e:
            result["errors"].append("lat_calc %%d: %%s" %% (dp, e))
            print("[setup] lat_calc %%d failed: %%s" %% (dp, e))

try:
    bfrt.complete_operations()
except Exception as e:
    result["errors"].append("complete_operations: %%s" %% e)
try:
    result["forwarding_dump"] = len(as_list(fwd.get(regex=True, print_ents=False)))
except Exception as e:
    result["forwarding_dump"] = "n/a: %%s" %% e
emit("setup", result)
'''

CLEAR_REGS = r'''
prog = getattr(bfrt, PARAMS["prog"])
regs = prog.pipe.Ingress
out = {"cleared": [], "errors": [], "nonzero": []}
t0 = time.time()
for name in PARAMS["registers"]:
    try:
        getattr(regs, name).clear()
        out["cleared"].append(name)
    except Exception as e:
        out["errors"].append("%%s clear: %%s" %% (name, e))
try:
    bfrt.complete_operations()
except Exception as e:
    out["errors"].append("complete_operations: %%s" %% e)
out["clear_s"] = round(time.time() - t0, 3)
rng = random.Random(PARAMS["seed"])
idx = sorted(set(PARAMS["check_idx"] + [rng.randrange(PARAMS["buckets"])
                                         for _ in range(PARAMS["sample"])]))
t0 = time.time()
for name in PARAMS["registers"]:
    reg = getattr(regs, name)
    for i in idx:
        try:
            e = get_one(reg, REGISTER_INDEX=i, from_hw=True)
            vals = [v for k, v in data_of(e).items() if k.endswith(".f1")][0]
            if any(as_list(vals)):
                out["nonzero"].append([name, i, plain(vals)])
        except Exception as e:
            out["errors"].append("%%s[%%d] read: %%s" %% (name, i, e))
out["checked_indices"] = len(idx)
out["check_s"] = round(time.time() - t0, 3)
print("[clear] %%d registers cleared in %%.1f s; %%d indices x %%d registers read back in %%.1f s; nonzero: %%d"
      %% (len(out["cleared"]), out["clear_s"], len(idx), len(PARAMS["registers"]), out["check_s"],
         len(out["nonzero"])))
emit("clear_regs", out)
'''

READ_REGS = r'''
prog = getattr(bfrt, PARAMS["prog"])
regs = prog.pipe.Ingress
out = {"values": {}, "errors": []}
t0 = time.time()
for i in PARAMS["idx"]:
    row = {}
    for name in PARAMS["registers"]:
        try:
            e = get_one(getattr(regs, name), REGISTER_INDEX=i, from_hw=True)
            vals = [v for k, v in data_of(e).items() if k.endswith(".f1")][0]
            row[name] = plain(as_list(vals))
        except Exception as e:
            out["errors"].append("%%s[%%d]: %%s" %% (name, i, e))
    out["values"][str(i)] = row
    print("[read] index %%d: %%s" %% (i, json.dumps(row, sort_keys=True)))
out["read_s"] = round(time.time() - t0, 3)
emit("read_regs", out)
'''

PORT_STATS = r'''
out = {"stats": {}, "errors": [], "t_switch": time.time()}
for dp in PARAMS["ports"]:
    try:
        e = get_one(bfrt.port.port_stat, DEV_PORT=dp)
        d = data_of(e)
        out["stats"][str(dp)] = {k: plain(d.get(k)) for k in PARAMS["fields"]}
    except Exception as e:
        out["errors"].append("port_stat %%d: %%s" %% (dp, e))
    print("[stats] dev_port %%d: %%s" %% (dp, out["stats"].get(str(dp))))
emit("port_stats", out)
'''

SNAPSHOT = r'''
out = {"stats": {}, "regs": {}, "errors": [], "t_switch": time.time()}
for dp in PARAMS["ports"]:
    try:
        d = data_of(get_one(bfrt.port.port_stat, DEV_PORT=dp))
        out["stats"][str(dp)] = dict((k, plain(d.get(k))) for k in PARAMS["fields"])
    except Exception as e:
        out["errors"].append("port_stat %%d: %%s" %% (dp, e))
if PARAMS["registers"]:
    regs = getattr(bfrt, PARAMS["prog"]).pipe.Ingress
    for i in PARAMS["idx"]:
        row = {}
        for name in PARAMS["registers"]:
            try:
                e = get_one(getattr(regs, name), REGISTER_INDEX=i, from_hw=True)
                row[name] = plain(as_list([v for k, v in data_of(e).items() if k.endswith(".f1")][0]))
            except Exception as e:
                out["errors"].append("%%s[%%d]: %%s" %% (name, i, e))
        out["regs"][str(i)] = row
out["t_switch_end"] = time.time()
emit("snapshot", out)
'''

LAT_CLEAR = r'''
lat = resolve(getattr(bfrt, PARAMS["prog"]), PARAMS["lat_path"])
out = {"cleared": [], "errors": [], "t_switch": time.time()}
for name in PARAMS["scalars"] + PARAMS["hists"]:
    try:
        getattr(lat, name).clear()
        out["cleared"].append(name)
    except Exception as e:
        out["errors"].append("%%s clear: %%s" %% (name, e))
try:
    bfrt.complete_operations()
except Exception as e:
    out["errors"].append("complete_operations: %%s" %% e)
port_stats(out)
emit("lat_clear", out)
'''

LAT_READ = r'''
lat = resolve(getattr(bfrt, PARAMS["prog"]), PARAMS["lat_path"])
out = {"scalars": {}, "hists": {}, "errors": [], "t_switch": time.time()}
port_stats(out)
for name in PARAMS["scalars"]:
    try:
        out["scalars"][name] = plain(f1_values(get_one(getattr(lat, name), REGISTER_INDEX=0, from_hw=True)))
    except Exception as e:
        out["errors"].append("%%s: %%s" %% (name, e))
t0 = time.time()
for name in PARAMS["hists"]:
    reg = getattr(lat, name)
    nonzero = {}
    for i in range(PARAMS["bins"]):
        try:
            vals = plain(f1_values(get_one(reg, REGISTER_INDEX=i, from_hw=True)))
            for pipe, v in enumerate(vals):
                if v:
                    nonzero.setdefault(str(pipe), {})[str(i)] = v
        except Exception as e:
            out["errors"].append("%%s[%%d]: %%s" %% (name, i, e))
            break
    out["hists"][name] = nonzero
out["hist_read_s"] = round(time.time() - t0, 3)
print("[lat] scalars %%s; nonzero histogram bins: %%s" %% (json.dumps(out["scalars"], sort_keys=True),
      dict((k, dict((p, len(b)) for p, b in v.items())) for k, v in out["hists"].items())))
emit("lat_read", out)
'''

CPU_COUNTERS = r'''
out = {"stats": {}, "tm_eg_port": {}, "errors": [], "t_switch": time.time()}
port_stats(out)
for dp in PARAMS["tm_ports"]:
    try:
        d = data_of(get_one(bfrt.tf1.tm.counter.eg_port, dev_port=dp))
        out["tm_eg_port"][str(dp)] = dict((k, plain(v)) for k, v in d.items())
    except Exception as e:
        out["errors"].append("tm eg_port %%d: %%s" %% (dp, e))
emit("cpu_counters", out)
'''

NOOP = r'''
emit("noop", {"t_switch": time.time()})
'''

READOUT = r'''
import gzip
regs = resolve(getattr(bfrt, PARAMS["prog"]), PARAMS["regs_path"])
names = PARAMS["registers"]
nb = PARAMS["buckets"]
out = {"percell": [], "bulk": {}, "errors": [], "t_switch": time.time()}

def key_index(entry):
    for k, v in entry.key.items():
        k = k.decode() if isinstance(k, bytes) else k
        if k.endswith("REGISTER_INDEX"):
            return v
    raise KeyError("no REGISTER_INDEX in key")

# 1. Per-cell reads from hardware, the collector's method.
rng = random.Random(PARAMS["seed"])
for n in PARAMS["percell_n"]:
    idx = list(PARAMS["check_idx"][:n])
    pool = [i for i in rng.sample(range(nb), n + len(idx)) if i not in idx]
    idx += pool[:n - len(idx)]
    vals = {}
    t0 = time.time()
    for name in names:
        reg = getattr(regs, name)
        for i in idx:
            v = plain(f1_values(get_one(reg, REGISTER_INDEX=i, from_hw=True)))
            if i in PARAMS["check_idx"]:
                vals.setdefault(name, {})[str(i)] = v
    dt = time.time() - t0
    out["percell"].append({"n_indices": n, "cells": n * len(names), "s": round(dt, 4),
                           "us_per_cell": round(dt / (n * len(names)) * 1e6, 2), "check_values": vals})
    print("[readout] per-cell: %%d indices x %%d registers in %%.3f s (%%.1f us/cell)"
          %% (n, len(names), dt, dt / (n * len(names)) * 1e6))

# 1b. Sync all registers once, then per-cell reads from the driver's shadow copy.
if PARAMS["percell_sw_n"]:
    t0 = time.time()
    for name in names:
        done = []
        def cb(dev_id, pipe_id, direction, parser_id, done=done):
            done.append(time.time())
        t1 = time.time()
        getattr(regs, name).operation_register_sync(cb)
        while not done and time.time() - t1 < 120:
            time.sleep(0.0005)
    sync_all = time.time() - t0
    out["sync_all_s"] = round(sync_all, 4)
    print("[readout] sync of %%d registers: %%.3f s" %% (len(names), sync_all))
    rng = random.Random(PARAMS["seed"])
    out["percell_sw"] = []
    for n in PARAMS["percell_sw_n"]:
        idx = list(PARAMS["check_idx"][:n])
        pool = [i for i in rng.sample(range(nb), n + len(idx)) if i not in idx]
        idx += pool[:n - len(idx)]
        vals = {}
        t0 = time.time()
        for name in names:
            reg = getattr(regs, name)
            for i in idx:
                v = plain(f1_values(get_one(reg, REGISTER_INDEX=i, from_hw=False)))
                if i in PARAMS["check_idx"]:
                    vals.setdefault(name, {})[str(i)] = v
        dt = time.time() - t0
        out["percell_sw"].append({"n_indices": n, "cells": n * len(names), "s": round(dt, 4),
                                  "us_per_cell": round(dt / (n * len(names)) * 1e6, 2), "check_values": vals})
        print("[readout] per-cell from shadow: %%d indices x %%d registers in %%.3f s (%%.1f us/cell)"
              %% (n, len(names), dt, dt / (n * len(names)) * 1e6))

# 2./3. Whole-register dumps: straight from hardware, and after a register sync.
def dump_all(reg, from_hw):
    t0 = time.time()
    ents = as_list(reg.get(regex=True, from_hw=from_hw, print_ents=False, return_ents=True))
    t1 = time.time()
    pipes = None
    for e in ents:
        v = as_list(f1_values(e))
        if pipes is None:
            pipes = [[0] * nb for _ in v]
        i = key_index(e)
        for p, x in enumerate(v):
            pipes[p][i] = x
    t2 = time.time()
    return pipes or [], len(ents), t1 - t0, t2 - t1

for method in PARAMS["bulk_methods"]:
    res = {"registers": {}, "file": None}
    arrays = {}
    for name in names:
        reg = getattr(regs, name)
        r = {}
        try:
            if method == "sync":
                done = []
                def cb(dev_id, pipe_id, direction, parser_id, done=done):
                    done.append([time.time(), pipe_id])
                t0 = time.time()
                reg.operation_register_sync(cb)
                while not done and time.time() - t0 < 120:
                    time.sleep(0.0005)
                time.sleep(0.05)
                r["sync_s"] = round(done[0][0] - t0, 4) if done else None
                r["sync_callbacks"] = [[round(t - t0, 4), p] for t, p in done]
            pipes, n_ents, t_get, t_conv = dump_all(reg, method == "hw")
            r.update({"entries": n_ents, "get_s": round(t_get, 4), "convert_s": round(t_conv, 4),
                      "nonzero": [sum(1 for x in p if x) for p in pipes],
                      "sum": [sum(p) for p in pipes]})
            arrays[name] = pipes
        except Exception as e:
            out["errors"].append("%%s %%s: %%s" %% (method, name, e))
        res["registers"][name] = r
        print("[readout] %%s %%s: %%s" %% (method, name, json.dumps(r, sort_keys=True)))
    path = "%%s/readout_%%s_%%s.json.gz" %% (PARAMS["out_dir"], PARAMS["label"], method)
    with gzip.open(path, "wt") as f:
        json.dump(arrays, f)
    res["file"] = path
    tot = lambda k: round(sum(v.get(k) or 0 for v in res["registers"].values()), 3)
    res["total_s"] = {"sync": tot("sync_s"), "get": tot("get_s"), "convert": tot("convert_s")}
    out["bulk"][method] = res
    del arrays
emit("readout", out)
'''

LAT_SCALARS = ["lat_count", "lat_mac_min", "lat_mac_max", "lat_prsr_min", "lat_prsr_max",
               "lat_mac_ovf", "lat_prsr_ovf"]
LAT_HISTS = ["lat_mac_hist", "lat_prsr_hist"]

STAT_FIELDS = ["$FramesReceivedOK", "$FramesReceivedAll", "$FramesReceivedwithFCSError",
               "$FrameswithanyError", "$OctetsReceivedinGoodFrames", "$FramesDroppedBufferFull",
               "$FramesTransmittedOK", "$FramesTransmittedAll", "$FramesTransmittedwithError",
               "$OctetsTransmittedwithouterror", "$FramesTruncated"]


def ints(s):
    return [int(x) for x in s.split(",") if x] if s else []


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("setup")
    p.add_argument("--prog", required=True)
    p.add_argument("--ports", required=True)
    p.add_argument("--fwd", required=True, help="src:dst,src:dst")
    p.add_argument("--mirror-sid", type=int)
    p.add_argument("--mirror-port", type=int, default=192)
    p.add_argument("--mirror-len", type=int, default=64)
    p.add_argument("--link-timeout", type=int, default=45)
    p.add_argument("--fwd-table", default="pipe.Ingress.forwarding",
                   help="path below bfrt.<prog>; pipe.LatIngress.det.forwarding for *_lat")
    p.add_argument("--lat-ports", default="", help="egress ports to measure (lat_calc entries)")
    p.add_argument("--lat-path", default="pipe.LatEgress")
    p = sub.add_parser("clear-regs")
    p.add_argument("--prog", required=True)
    p.add_argument("--check-idx", default="")
    p.add_argument("--sample", type=int, default=200)
    p.add_argument("--seed", type=int, default=1)
    p.add_argument("--buckets", type=int, default=65536)
    p.add_argument("--extra-registers", default="",
                   help="registers beyond the 14, e.g. reg_fp,reg_shared (fingerprint variant)")
    p = sub.add_parser("read-regs")
    p.add_argument("--prog", required=True)
    p.add_argument("--idx", required=True)
    p.add_argument("--extra-registers", default="")
    p = sub.add_parser("port-stats")
    p.add_argument("--ports", required=True)
    p = sub.add_parser("snapshot", help="port stats plus selected register cells")
    p.add_argument("--ports", required=True)
    p.add_argument("--prog", default="basic")
    p.add_argument("--idx", default="", help="register indices; empty = no register reads")
    p.add_argument("--registers", default="reg_pkts,reg_bytes,reg_pkts_ab")
    sub.add_parser("noop", help="empty session (measures bfshell + bfrt_python start-up)")
    p = sub.add_parser("cpu-counters", help="port stats plus TM egress-port counters (e.g. CPU port 192)")
    p.add_argument("--ports", default="132,140")
    p.add_argument("--tm-ports", default="192")
    p = sub.add_parser("readout", help="time per-cell and whole-register reads (Phase 3.1-3.2)")
    p.add_argument("--prog", default="basic")
    p.add_argument("--regs-path", default="pipe.Ingress")
    p.add_argument("--percell-n", default="10,100,1000,5000")
    p.add_argument("--check-idx", default="", help="indices whose per-cell values are reported")
    p.add_argument("--bulk", default="hw,sync", help="whole-register methods: hw, sync")
    p.add_argument("--percell-sw-n", default="",
                   help="after syncing all registers, per-cell reads from the shadow copy")
    p.add_argument("--seed", type=int, default=1)
    p.add_argument("--out-dir", required=True, help="switch directory for the dump files")
    p.add_argument("--label", required=True)
    for name in ("lat-clear", "lat-read"):
        p = sub.add_parser(name, help="latency registers of a *_lat build, plus port stats")
        p.add_argument("--prog", required=True)
        p.add_argument("--lat-path", default="pipe.LatEgress")
        p.add_argument("--ports", default="132,140", help="port stats to include")
        p.add_argument("--bins", type=int, default=1024)
    a = ap.parse_args()

    if a.cmd == "setup":
        params = {"prog": a.prog, "ports": ints(a.ports), "link_timeout_s": a.link_timeout,
                  "fwd": [[int(x) for x in pair.split(":")] for pair in a.fwd.split(",")],
                  "fwd_table": a.fwd_table, "lat_ports": ints(a.lat_ports), "lat_path": a.lat_path}
        if a.mirror_sid is not None:
            params["mirror"] = {"sid": a.mirror_sid, "port": a.mirror_port, "len": a.mirror_len}
        body = SETUP
    elif a.cmd == "clear-regs":
        params = {"prog": a.prog, "registers": REGISTERS + [r for r in a.extra_registers.split(",") if r],
                  "check_idx": ints(a.check_idx), "sample": a.sample, "seed": a.seed, "buckets": a.buckets}
        body = CLEAR_REGS
    elif a.cmd == "read-regs":
        params = {"prog": a.prog, "registers": REGISTERS + [r for r in a.extra_registers.split(",") if r],
                  "idx": ints(a.idx)}
        body = READ_REGS
    elif a.cmd == "noop":
        params, body = {}, NOOP
    elif a.cmd == "cpu-counters":
        params = {"stat_ports": ints(a.ports), "fields": STAT_FIELDS, "tm_ports": ints(a.tm_ports)}
        body = CPU_COUNTERS
    elif a.cmd == "readout":
        params = {"prog": a.prog, "regs_path": a.regs_path, "registers": REGISTERS,
                  "buckets": 65536, "percell_n": ints(a.percell_n), "check_idx": ints(a.check_idx),
                  "bulk_methods": [m for m in a.bulk.split(",") if m], "seed": a.seed,
                  "percell_sw_n": ints(a.percell_sw_n),
                  "out_dir": a.out_dir, "label": a.label}
        body = READOUT
    elif a.cmd in ("lat-clear", "lat-read"):
        params = {"prog": a.prog, "lat_path": a.lat_path, "scalars": LAT_SCALARS, "hists": LAT_HISTS,
                  "bins": a.bins, "stat_ports": ints(a.ports), "fields": STAT_FIELDS}
        body = LAT_CLEAR if a.cmd == "lat-clear" else LAT_READ
    elif a.cmd == "snapshot":
        idx = ints(a.idx)
        params = {"ports": ints(a.ports), "fields": STAT_FIELDS, "prog": a.prog, "idx": idx,
                  "registers": [r for r in a.registers.split(",") if r] if idx else []}
        body = SNAPSHOT
    else:
        params = {"ports": ints(a.ports), "fields": STAT_FIELDS}
        body = PORT_STATS
    code = (PRELUDE + body) % {"params": json.dumps(params)}
    print("# generated by perf/tools/bfrt_gen.py %s" % a.cmd)
    print("def _hz_main():")
    print(textwrap.indent(code, "    "))
    print("_hz_main()")


if __name__ == "__main__":
    main()
