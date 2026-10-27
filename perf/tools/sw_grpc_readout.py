#!/usr/bin/env python2.7
"""Time whole-register reads over BF Runtime gRPC (Phase 3.2). Runs on the switch.

    python2.7 sw_grpc_readout.py OUT_JSON_GZ [--prog basic] [--from-hw 1] [--bind 0|1]
                                 [--keys-n 10,100,1000,5000] [--seed 1]

Uses the SDE 9.6 Python 2.7 client (bfrt_grpc.client) against 127.0.0.1:50052
("localhost" does not resolve on this switch). First, for each N in --keys-n,
N random indices of all 14 registers are read with one batched entry_get per
register (the collector's case: read the buckets named by CPU reports). Then,
for each register, one entry_get with an empty key list reads all 65,536
entries. The time of each call (gRPC request, server-side read, streaming,
client-side decoding) and of converting the entries into arrays are recorded. The client
first tries to read without binding; with --bind 1 it binds to the program
(a control-plane association only; the device is not reconfigured). Prints
one "HZJSON {...}" line; full arrays (pipe x bucket) go to OUT_JSON_GZ.
"""
import argparse
import gzip
import json
import sys
import time

sys.path.insert(0, "/root/bf-sde-9.6.0/install/lib/python2.7/site-packages/tofino")
sys.path.insert(0, "/root/bf-sde-9.6.0/install/lib/python2.7/site-packages")
import bfrt_grpc.client as gc  # noqa: E402

REGISTERS = ["reg_pkts", "reg_bytes", "reg_pkts_ab", "reg_bytes_ab", "reg_ref_src_port",
             "reg_ref_dst_port", "reg_dir_valid", "reg_min_len", "reg_max_len",
             "reg_first_ts", "reg_last_ts", "reg_syn", "reg_ack", "reg_rst"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("out")
    ap.add_argument("--prog", default="basic")
    ap.add_argument("--from-hw", type=int, default=1)
    ap.add_argument("--bind", type=int, default=0)
    ap.add_argument("--client-id", type=int, default=7)
    ap.add_argument("--keys-n", default="10,100,1000,5000")
    ap.add_argument("--seed", type=int, default=1)
    a = ap.parse_args()
    out = {"prog": a.prog, "from_hw": bool(a.from_hw), "bind": bool(a.bind), "registers": {},
           "keyed": [], "errors": []}
    t0 = time.time()
    c = gc.ClientInterface("127.0.0.1:50052", client_id=a.client_id, device_id=0,
                           perform_subscribe=bool(a.bind))
    info = c.bfrt_info_get(a.prog)
    if a.bind:
        c.bind_pipeline_config(a.prog)
    out["connect_s"] = round(time.time() - t0, 4)
    target = gc.Target(device_id=0, pipe_id=0xffff)

    # Batched reads of N given indices, one entry_get per register.
    import random
    rng = random.Random(a.seed)
    for n in [int(x) for x in a.keys_n.split(",") if x]:
        idx = rng.sample(range(65536), n)
        t1 = time.time()
        got = 0
        try:
            for name in REGISTERS:
                tbl = info.table_get("pipe.Ingress." + name)
                keys = [tbl.make_key([gc.KeyTuple("$REGISTER_INDEX", i)]) for i in idx]
                got += len(list(tbl.entry_get(target, keys, {"from_hw": bool(a.from_hw)})))
            dt = time.time() - t1
            out["keyed"].append({"n_indices": n, "cells": n * len(REGISTERS), "entries_returned": got,
                                 "s": round(dt, 4), "us_per_cell": round(dt / (n * len(REGISTERS)) * 1e6, 2)})
            sys.stderr.write("keyed: %d indices x 14 registers in %.3f s (%.1f us/cell)\n"
                             % (n, dt, dt / (n * len(REGISTERS)) * 1e6))
        except Exception as e:
            out["errors"].append("keyed %d: %s" % (n, str(e)[:300]))
            sys.stderr.write("keyed %d: ERROR %s\n" % (n, str(e)[:300]))
            break

    arrays = {}
    for name in REGISTERS:
        full = "pipe.Ingress." + name
        try:
            tbl = info.table_get(full)
            t1 = time.time()
            ents = list(tbl.entry_get(target, [], {"from_hw": bool(a.from_hw)}))
            t2 = time.time()
            nb = len(ents)
            pipes = None
            for data, key in ents:
                d = data.to_dict()
                v = d[full.replace("pipe.", "") + ".f1"]
                if pipes is None:
                    pipes = [[0] * 65536 for _ in v]
                i = key.to_dict()["$REGISTER_INDEX"]["value"]
                for p, x in enumerate(v):
                    pipes[p][i] = x
            t3 = time.time()
            arrays[name] = pipes
            out["registers"][name] = {"entries": nb, "read_s": round(t2 - t1, 4),
                                      "convert_s": round(t3 - t2, 4),
                                      "sum": [sum(p) for p in pipes or []]}
            sys.stderr.write("%s: %d entries, read %.2f s, convert %.2f s\n" % (name, nb, t2 - t1, t3 - t2))
        except Exception as e:
            out["errors"].append("%s: %s" % (name, str(e)[:300]))
            sys.stderr.write("%s: ERROR %s\n" % (name, str(e)[:300]))
            if not arrays:
                break
    out["total_read_s"] = round(sum(r["read_s"] for r in out["registers"].values()), 3)
    out["total_convert_s"] = round(sum(r["convert_s"] for r in out["registers"].values()), 3)
    with gzip.open(a.out, "wb") as f:
        f.write(json.dumps(arrays))
    out["file"] = a.out
    print("HZJSON " + json.dumps(out, sort_keys=True))
    try:
        c.tear_down_stream()
    except Exception:
        pass


if __name__ == "__main__":
    main()
