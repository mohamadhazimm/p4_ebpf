#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Reader of perf/variants/exact (the data-plane window features) over BF Runtime gRPC.

The program counts window e into bank e & 1 of its window registers (reg_w_*) and starts window e + 1
when a window marker (or a timer tick) passes: reg_epoch then holds e + 1, bank e & 1 holds window e
unchanged until window e + 2 starts. This reader follows reg_epoch and reads each finished window's
bank from the hardware, then clears the bank's extremes (reg_w_pa, reg_w_pb, reg_w_pd), which the
data plane only raises. The additive registers are never cleared; window_features.py takes the
difference of two reads of a bank. Values are combined over the pipes: summed, the extremes by max.

    window_reader.py --reset                  clear every register of the program, read back a few cells
    window_reader.py --frame-min DST/PREFIX   frame_len: count packets toward DST as at least 46 B of IPv4
                                              (60 B frames: the host's own capture sees them padded)
    window_reader.py --follow [--until-epoch N] [--poll-ms 1]
                                              one JSON line per finished window, from the window open at
                                              the start; stops when reg_epoch reaches N (or on SIGTERM)
    window_reader.py --once                   the current epoch and the bank of the window before it

A --follow line: {"epoch", "bank", "regs": {register: {index: value or [lo, hi]}}, "epoch_seen" (reg_epoch
when the window was found finished), "epoch_after" (after the read and the clear), "lost" (the bank may
hold packets of window e + 2: the read came too late), "t" (this host's clock), "read_ms", "clear_ms"}.

Runs under Python 2.7 (the SDE 9.6 client on the switch) and 3. Self-contained: it is copied to the
switch alone, as batched_reader.py is.
"""
from __future__ import print_function

import argparse
import glob
import json
import os
import signal
import socket
import struct
import sys
import time

TABLE_PREFIX = "pipe.Ingress."
DATA_PREFIX = "Ingress."
KEY = "$REGISTER_INDEX"
SDE_INSTALL_CANDIDATES = ["/root/bf-sde-9.6.0/install", "/home/ubuntu/open-p4studio/install"]
M32 = (1 << 32) - 1

# name, pair (lo/hi), combine over pipes, the indexes of bank b
WINDOW_REGS = [
    ("reg_w_tot",       True,  "sum", lambda b: [(b << 2) | i for i in range(4)]),
    ("reg_w_flags",     True,  "sum", lambda b: [b]),
    ("reg_w_rst",       False, "sum", lambda b: [b]),
    ("reg_w_cnt",       False, "sum", lambda b: [(b << 5) | i for i in range(32)]),
    ("reg_w_chg_len",   True,  "sum", lambda b: [b]),
    ("reg_w_chg_dur",   False, "sum", lambda b: [b]),
    ("reg_w_carry_len", True,  "sum", lambda b: [(b << 2) | c for c in range(4)]),
    ("reg_w_carry_dur", False, "sum", lambda b: [(b << 2) | c for c in range(4)]),
    ("reg_w_pa",        True,  "max", lambda b: [b]),
    ("reg_w_pb",        True,  "max", lambda b: [b]),
    ("reg_w_pd",        False, "max", lambda b: [b]),
]
EXTREMES = ["reg_w_pa", "reg_w_pb", "reg_w_pd"]
# every register of the program, for --reset (cells read back: 0, 1 and the last)
ALL_REGS = (["reg_epoch", "reg_way1", "reg_way2", "reg_way3", "reg_way4", "reg_ref", "reg_seen", "reg_ba",
             "reg_min", "reg_max", "reg_first", "reg_last"] + [r[0] for r in WINDOW_REGS])


def log(msg):
    sys.stderr.write("[window] %s\n" % msg)
    sys.stderr.flush()


def import_client(sde_install=None):
    roots = [r for r in [sde_install, os.environ.get("SDE_INSTALL")] + SDE_INSTALL_CANDIDATES if r]
    for root in roots:
        for sp in sorted(glob.glob(os.path.join(root, "lib", "python*", "site-packages"))):
            for p in (sp, os.path.join(sp, "tofino")):
                if os.path.isdir(p) and p not in sys.path:
                    sys.path.insert(0, p)
    import bfrt_grpc.client as gc
    return gc


class Program(object):
    def __init__(self, gc, grpc_addr, client_id, device_id, p4_name):
        self.gc = gc
        self.iface = gc.ClientInterface(grpc_addr, client_id=client_id, device_id=device_id,
                                        perform_subscribe=True)
        self.info = self.iface.bfrt_info_get(p4_name)
        self.bound = True
        try:
            self.iface.bind_pipeline_config(p4_name)
        except Exception as error:
            if "ALREADY_EXISTS" not in str(error) and "already owns" not in str(error):
                raise
            log("another client is bound to %s: continuing unbound" % p4_name)
            self.bound = False
        self.p4_name = p4_name
        self.target = gc.Target(device_id=device_id, pipe_id=0xFFFF)
        self.tables = {}

    def table(self, name):
        if name not in self.tables:
            self.tables[name] = self.info.table_get(TABLE_PREFIX + name)
        return self.tables[name]

    def kw(self, func):
        try:
            import inspect
            args = inspect.getargspec(func).args if hasattr(inspect, "getargspec") else \
                list(inspect.signature(func).parameters)
        except Exception:
            args = []
        return {"p4_name": self.p4_name} if (not self.bound and "p4_name" in args) else {}

    def get(self, name, indexes, pair):
        """index -> per-pipe values (pair: per-pipe [lo, hi])."""
        t = self.table(name)
        keys = [t.make_key([self.gc.KeyTuple(KEY, i)]) for i in indexes]
        out = {}
        for data, key in t.entry_get(self.target, keys, {"from_hw": True}, **self.kw(t.entry_get)):
            idx = key.to_dict()[KEY]["value"]
            d = data.to_dict()
            if pair:
                lo, hi = d[DATA_PREFIX + name + ".lo"], d[DATA_PREFIX + name + ".hi"]
                lo = lo if isinstance(lo, (list, tuple)) else [lo]
                hi = hi if isinstance(hi, (list, tuple)) else [hi]
                out[idx] = [[int(a), int(b)] for a, b in zip(lo, hi)]
            else:
                v = d[DATA_PREFIX + name + ".f1"]
                out[idx] = [int(x) for x in (v if isinstance(v, (list, tuple)) else [v])]
        return out

    def put_zero(self, name, indexes, pair):
        t = self.table(name)
        keys = [t.make_key([self.gc.KeyTuple(KEY, i)]) for i in indexes]
        fields = ([DATA_PREFIX + name + ".lo", DATA_PREFIX + name + ".hi"] if pair else [DATA_PREFIX + name + ".f1"])
        datas = [t.make_data([self.gc.DataTuple(f, 0) for f in fields]) for _ in indexes]
        t.entry_mod(self.target, keys, datas, **self.kw(t.entry_mod))

    def epoch(self):
        return max(self.get("reg_epoch", [0], False)[0])


def combine(per_pipe, how, pair):
    if pair:
        if how == "sum":
            return [sum(v[0] for v in per_pipe) & M32, sum(v[1] for v in per_pipe) & M32]
        return [max(v[0] for v in per_pipe), max(v[1] for v in per_pipe)]
    return (sum(per_pipe) & M32) if how == "sum" else max(per_pipe)


def read_bank(prog, bank):
    regs = {}
    for name, pair, how, idx in WINDOW_REGS:
        got = prog.get(name, idx(bank), pair)
        regs[name] = dict((str(i), combine(v, how, pair)) for i, v in sorted(got.items()))
    return regs


def clear_extremes(prog, bank):
    for name, pair, how, idx in WINDOW_REGS:
        if name in EXTREMES:
            prog.put_zero(name, idx(bank), pair)


def do_reset(prog):
    t0 = time.time()
    for name in ALL_REGS:
        t = prog.table(name)
        try:
            t.entry_del(prog.target, **prog.kw(t.entry_del))
        except Exception as error:
            raise RuntimeError("clearing %s failed: %s" % (name, error))
    size_of = {}
    bad = []
    for name in ALL_REGS:
        t = prog.table(name)
        try:
            size = t.info.size_get()
        except Exception:
            size = 1
        size_of[name] = size
        pair = name in [r[0] for r in WINDOW_REGS if r[1]]
        cells = sorted(set([0, min(1, size - 1), size - 1]))
        for idx, vals in prog.get(name, cells, pair).items():
            flat = [x for v in vals for x in (v if pair else [v])]
            if any(flat):
                bad.append("%s[%d]=%r" % (name, idx, vals))
    if bad:
        raise RuntimeError("registers not zero after the clear: " + ", ".join(bad))
    print(json.dumps({"reset": len(ALL_REGS), "ms": round((time.time() - t0) * 1e3, 1), "sizes": size_of}))


def ip_to_int(text):
    return struct.unpack("!I", socket.inet_aton(text))[0]


def do_frame_min(prog, spec):
    addr, _, plen = spec.partition("/")
    plen = int(plen or 32)
    mask = (M32 << (32 - plen)) & M32
    t = prog.table("frame_len")
    gc = prog.gc
    key = t.make_key([gc.KeyTuple("hdr.vlan$0.$valid", 0), gc.KeyTuple("hdr.vlan$1.$valid", 0),
                      gc.KeyTuple("hdr.ipv4.dstAddr", ip_to_int(addr), mask),
                      gc.KeyTuple("hdr.ipv4.totalLen", low=0, high=45),
                      gc.KeyTuple("$MATCH_PRIORITY", 1)])
    data = t.make_data([gc.DataTuple("len", 46)], "Ingress.len_set")
    try:
        t.entry_add(prog.target, [key], [data], **prog.kw(t.entry_add))
    except Exception as error:
        if "ALREADY_EXISTS" not in str(error):
            raise
        t.entry_mod(prog.target, [key], [data], **prog.kw(t.entry_mod))
    print(json.dumps({"frame_len": spec, "len": 46}))


STOP = [False]


def do_follow(prog, until_epoch, poll_s):
    def stop(*_):
        STOP[0] = True
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    nxt = prog.epoch()
    log("following reg_epoch from %d" % nxt)
    print(json.dumps({"start_epoch": nxt, "t": time.time()}))
    sys.stdout.flush()
    while not STOP[0]:
        cur = prog.epoch()
        while nxt < cur and not STOP[0]:
            e, b = nxt, nxt & 1
            t0 = time.time()
            regs = read_bank(prog, b)
            t1 = time.time()
            after_read = prog.epoch()
            clear_extremes(prog, b)
            t2 = time.time()
            after = prog.epoch()
            line = {"epoch": e, "bank": b, "regs": regs, "epoch_seen": cur, "epoch_after": after,
                    "lost": bool(after_read >= e + 2 or cur >= e + 2), "t": t0,
                    "read_ms": round((t1 - t0) * 1e3, 2), "clear_ms": round((t2 - t1) * 1e3, 2)}
            print(json.dumps(line, sort_keys=True))
            sys.stdout.flush()
            nxt += 1
        if until_epoch is not None and cur >= until_epoch:
            break
        time.sleep(poll_s)
    log("stopped at epoch %d" % nxt)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--grpc-addr", default="127.0.0.1:50052")
    ap.add_argument("--client-id", type=int, default=9)
    ap.add_argument("--device-id", type=int, default=0)
    ap.add_argument("--p4-name", default="basic")
    ap.add_argument("--sde-install")
    ap.add_argument("--reset", action="store_true")
    ap.add_argument("--frame-min", action="append", default=[])
    ap.add_argument("--follow", action="store_true")
    ap.add_argument("--until-epoch", type=int)
    ap.add_argument("--poll-ms", type=float, default=1.0)
    ap.add_argument("--once", action="store_true")
    args = ap.parse_args()
    gc = import_client(args.sde_install)
    prog = Program(gc, args.grpc_addr, args.client_id, args.device_id, args.p4_name)
    if args.reset:
        do_reset(prog)
    for spec in args.frame_min:
        do_frame_min(prog, spec)
    if args.once:
        e = prog.epoch()
        print(json.dumps({"epoch": e, "bank_of_previous": (e - 1) & 1, "regs": read_bank(prog, (e - 1) & 1)},
                         sort_keys=True))
    if args.follow:
        do_follow(prog, args.until_epoch, args.poll_ms / 1e3)
    try:
        prog.iface.tear_down_stream()
    except Exception:
        pass


if __name__ == "__main__":
    main()
