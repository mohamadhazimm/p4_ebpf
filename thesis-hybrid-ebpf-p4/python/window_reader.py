#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Reader of perf/variants/exact (the data-plane window features) over BF Runtime gRPC.

The program counts window e into bank e & 1 of its window registers (reg_w_*) and starts window e + 1 when
a window marker (from a port in the parser's marker_ports) or a timer tick passes: reg_epoch then holds
e + 1, and bank e & 1 holds window e unchanged until window e + 2 starts. This reader reads a finished
window's bank from the hardware, then clears the bank's extremes (reg_w_pa, reg_w_pb, reg_w_pd), which the
data plane only raises. The additive registers are never cleared; window_features.py takes the difference
of two reads of a bank.

Pipes. Every pipe has its own registers and its own clock (a marker or a tick moves only the clock of the
pipe it enters). A window's values are combined over the pipes whose clock has passed it (summed, the
extremes by max); the packets that a pipe whose clock lags counted meanwhile are reported as
"unclocked_pkts" (they belong to no window), and a window whose set of clocked pipes changed is "lost".

    window_reader.py --reset                  clear every register of the program, read back a few cells
    window_reader.py --frame-min DST/PREFIX   frame_len: count packets toward DST as at least 46 B of IPv4
                                              (60 B frames: the host's own capture sees them padded)
    window_reader.py --marker-ports 192,132   the ports whose window markers count (replaces the set)
    window_reader.py --follow [--until-epoch N] [--poll-ms 1]
                                              one JSON line per finished window, from the window open at the
                                              start; stops when the clock reaches N (or on SIGTERM)
    window_reader.py --serve                  JSON lines on stdin, one JSON reply line each (the collector):
        {"cmd": "setup", "reset": true, "frame_min": [...], "marker_ports": [...]}
        {"cmd": "mark", "epoch": E}            send a marker for epoch E from --cpu-iface (the switch's CPU
                                              port) and wait until the clock shows it
        {"cmd": "follow"}                      from now on read every window as soon as it ends (a thread on the
                                              switch), so that a slow requester cannot make a read late
        {"cmd": "read", "epoch": e, "timeout": s}   wait until window e has ended, read it, clear it (after
                                              "follow": the line it read, once it has)
        {"cmd": "epoch"} / {"cmd": "quit"}
    window_reader.py --once                   the current epoch and the bank of the window before it

A window line: {"epoch", "bank", "regs": {register: {index: value or [lo, hi]}}, "epoch_seen" (the clock when
the window was found finished), "epoch_after" (after the read and the clear), "lost" (the bank may hold
another window's packets: the read came after window e + 2 started, or a late clear may have wiped this
window's extremes, or the clocked pipes changed), "pipe_epochs", "clocked_pipes", "unclocked_pkts",
"rejected_markers" (cumulative), "t" (this host's clock at the read), "read_ms", "clear_ms"}.

Runs under Python 2.7 (the SDE 9.6 client on the switch) and 3. Self-contained: it is copied to the switch
alone, as batched_reader.py is.
"""
from __future__ import print_function

import argparse
import glob
import json
import os
import signal
import socket
import struct
import subprocess
import sys
import threading
import time

TABLE_PREFIX = "pipe.Ingress."
DATA_PREFIX = "Ingress."
KEY = "$REGISTER_INDEX"
SDE_INSTALL_CANDIDATES = ["/root/bf-sde-9.6.0/install", "/home/ubuntu/open-p4studio/install"]
M32 = (1 << 32) - 1
WINDOW_ETHERTYPE = 0x88B5
WINDOW_MAGIC = 0x5745

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
PAIRS = set(r[0] for r in WINDOW_REGS if r[1])


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


def combine(per_pipe, how, pair, pipes):
    """per_pipe: [value or [lo, hi]] by pipe; only the pipes in `pipes` count."""
    vals = [per_pipe[p] for p in pipes if p < len(per_pipe)]
    if not vals:
        return [0, 0] if pair else 0
    if pair:
        if how == "sum":
            return [sum(v[0] for v in vals) & M32, sum(v[1] for v in vals) & M32]
        return [max(v[0] for v in vals), max(v[1] for v in vals)]
    return (sum(vals) & M32) if how == "sum" else max(vals)


def marker_frame(src_mac, epoch):
    frame = b"\xff" * 6 + src_mac + struct.pack("!HHI", WINDOW_ETHERTYPE, WINDOW_MAGIC, epoch)
    return frame + b"\x00" * (60 - len(frame))


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

    def table(self, name, prefix=TABLE_PREFIX):
        if prefix + name not in self.tables:
            self.tables[prefix + name] = self.info.table_get(prefix + name)
        return self.tables[prefix + name]

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

    def pipe_epochs(self):
        return self.get("reg_epoch", [0], False)[0]

    def rejected_markers(self):
        t = self.table("rejected_markers")
        for data, _ in t.entry_get(self.target, [t.make_key([self.gc.KeyTuple("$COUNTER_INDEX", 0)])],
                                   {"from_hw": True}, **self.kw(t.entry_get)):
            v = data.to_dict().get("$COUNTER_SPEC_PKTS", 0)
            return int(sum(v) if isinstance(v, (list, tuple)) else v)
        return 0


class WindowReader(object):
    """Reads finished windows in order; keeps what the lost / unclocked checks need between reads."""

    def __init__(self, prog, cpu_iface="enp5s0"):
        self.prog = prog
        self.cpu_iface = cpu_iface
        self.tainted = set()          # windows whose extremes a late clear may have wiped
        self.clocked = None           # the pipes counted in the windows so far
        self.unclocked_prev = {}      # pipe -> packets of all its tot cells at the previous read
        self.sock = None

    def clock(self, epochs=None):
        """The clock: the most advanced pipe's epoch."""
        return max(epochs if epochs is not None else self.prog.pipe_epochs())

    def read_window(self, e, epochs):
        """Window e (finished: the clock is past it) from the pipes whose clock has passed it."""
        prog = self.prog
        b = e & 1
        lost = self.clock(epochs) >= e + 2 or e in self.tainted
        self.tainted.discard(e)
        clocked = [p for p, ep in enumerate(epochs) if ep >= e + 1]
        if self.clocked is not None and clocked != self.clocked:
            lost = True
            log("window %d: clocked pipes %s, before %s" % (e, clocked, self.clocked))
        self.clocked = clocked
        t0 = time.time()
        regs = {}
        unclocked = 0
        for name, pair, how, idx in WINDOW_REGS:
            got = prog.get(name, idx(b) if name != "reg_w_tot" else range(8), pair)
            if name == "reg_w_tot":
                # the packets of the pipes whose clock lags, over both banks: they count in no window
                for p in range(len(epochs)):
                    if p in clocked:
                        continue
                    now = sum(got[i][p][0] for i in range(8)) & M32
                    unclocked += (now - self.unclocked_prev.get(p, now)) & M32
                    self.unclocked_prev[p] = now
                got = dict((i, v) for i, v in got.items() if i in idx(b))
            regs[name] = dict((str(i), combine(v, how, pair, clocked)) for i, v in sorted(got.items()))
        t1 = time.time()
        after_read = self.clock()
        for name, pair, how, idx in WINDOW_REGS:
            if name in EXTREMES:
                prog.put_zero(name, idx(b), pair)
        t2 = time.time()
        after = self.clock()
        if after_read >= e + 2:
            lost = True
        if after >= e + 2:
            # the clear may have come after window e + 2 started in this bank: its extremes are suspect
            self.tainted.add(e + 2)
        return {"epoch": e, "bank": b, "regs": regs, "epoch_seen": self.clock(epochs), "epoch_after": after,
                "lost": bool(lost), "pipe_epochs": list(epochs), "clocked_pipes": clocked,
                "unclocked_pkts": unclocked, "rejected_markers": prog.rejected_markers(), "t": t0,
                "read_ms": round((t1 - t0) * 1e3, 2), "clear_ms": round((t2 - t1) * 1e3, 2)}

    def wait_and_read(self, e, timeout, poll_s=0.001):
        deadline = time.time() + timeout
        while True:
            epochs = self.prog.pipe_epochs()
            if self.clock(epochs) > e:
                return self.read_window(e, epochs)
            if time.time() > deadline:
                return {"epoch": e, "error": "the clock stayed at %d: window %d did not end within %.1f s"
                        % (self.clock(epochs), e, timeout), "pipe_epochs": list(epochs)}
            time.sleep(poll_s)

    def mark(self, epoch, timeout=1.0):
        """A window marker for `epoch` from the CPU port; returns when the clock shows it."""
        if self.sock is None:
            state = open("/sys/class/net/%s/operstate" % self.cpu_iface).read().strip()
            if state == "down":
                subprocess.call(["ip", "link", "set", self.cpu_iface, "up"])
                log("%s was down: set up" % self.cpu_iface)
            self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
            self.sock.bind((self.cpu_iface, 0))
            mac = open("/sys/class/net/%s/address" % self.cpu_iface).read().strip().replace(":", "")
            self.mac = bytes(bytearray(int(mac[i:i + 2], 16) for i in range(0, 12, 2)))
        t0 = time.time()
        self.sock.send(marker_frame(self.mac, epoch))
        while True:
            epochs = self.prog.pipe_epochs()
            if self.clock(epochs) >= epoch:
                return {"marked": epoch, "t_sent": t0, "t_seen": time.time(), "pipe_epochs": list(epochs)}
            if time.time() - t0 > timeout:
                return {"marked": epoch, "error": "the clock stayed at %d after the marker (is %s in marker_ports "
                        "and up?)" % (self.clock(epochs), self.cpu_iface), "t_sent": t0, "pipe_epochs": list(epochs)}
            time.sleep(0.0002)


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
        cells = sorted(set([0, min(1, size - 1), size - 1]))
        for idx, vals in prog.get(name, cells, name in PAIRS).items():
            flat = [x for v in vals for x in (v if name in PAIRS else [v])]
            if any(flat):
                bad.append("%s[%d]=%r" % (name, idx, vals))
    if bad:
        raise RuntimeError("registers not zero after the clear: " + ", ".join(bad))
    return {"reset": len(ALL_REGS), "ms": round((time.time() - t0) * 1e3, 1), "sizes": size_of}


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
    return {"frame_len": spec, "len": 46}


def do_marker_ports(prog, ports):
    """The parser's marker_ports value set: exactly these ports."""
    t = prog.table("marker_ports", prefix="pipe.IngressParser.")
    try:
        t.entry_del(prog.target, **prog.kw(t.entry_del))
    except Exception as error:
        log("clearing marker_ports: %s" % str(error).splitlines()[0][:200])
    for p in ports:
        t.entry_add(prog.target, [t.make_key([prog.gc.KeyTuple("f1", int(p), 0x1FF)])], **prog.kw(t.entry_add))
    return {"marker_ports": [int(p) for p in ports]}


def setup(prog, reset=False, frame_min=(), marker_ports=None):
    out = {}
    if reset:
        out.update(do_reset(prog))
    for spec in frame_min:
        out.setdefault("frame_min", []).append(do_frame_min(prog, spec)["frame_len"])
    if marker_ports is not None:
        out.update(do_marker_ports(prog, marker_ports))
    return out


STOP = [False]


def do_follow(prog, reader, until_epoch, poll_s):
    def stop(*_):
        STOP[0] = True
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    nxt = reader.clock()
    log("following the window clock from %d" % nxt)
    print(json.dumps({"start_epoch": nxt, "t": time.time()}))
    sys.stdout.flush()
    while not STOP[0]:
        epochs = prog.pipe_epochs()
        cur = reader.clock(epochs)
        while nxt < cur and not STOP[0]:
            print(json.dumps(reader.read_window(nxt, epochs), sort_keys=True))
            sys.stdout.flush()
            nxt += 1
            epochs = prog.pipe_epochs()
        if until_epoch is not None and cur >= until_epoch:
            break
        time.sleep(poll_s)
    log("stopped at epoch %d" % nxt)


class Follower(object):
    """Reads every window as soon as the clock passes it (--serve's "follow"), keeping the lines for "read"."""

    def __init__(self, prog, reader, poll_s=0.001):
        self.prog, self.reader, self.poll_s = prog, reader, poll_s
        self.lines, self.cond, self.error = {}, threading.Condition(), None
        self.nxt = reader.clock()
        self.thread = threading.Thread(target=self.run)
        self.thread.daemon = True
        self.thread.start()

    def run(self):
        try:
            while True:
                epochs = self.prog.pipe_epochs()
                while self.nxt < self.reader.clock(epochs):
                    line = self.reader.read_window(self.nxt, epochs)
                    with self.cond:
                        self.lines[self.nxt] = line
                        self.cond.notify_all()
                    self.nxt += 1
                    epochs = self.prog.pipe_epochs()
                time.sleep(self.poll_s)
        except Exception as error:
            with self.cond:
                self.error = "%s: %s" % (type(error).__name__, error)
                self.cond.notify_all()

    def get(self, e, timeout):
        deadline = time.time() + timeout
        with self.cond:
            while e not in self.lines and self.error is None:
                left = deadline - time.time()
                if left <= 0:
                    return {"epoch": e, "error": "window %d did not end within %.1f s (clock %d)"
                            % (e, timeout, self.nxt)}
                self.cond.wait(min(left, 0.5))
            if e in self.lines:
                return self.lines.pop(e)
            return {"epoch": e, "error": "the follower stopped: %s" % self.error}


def do_serve(prog, reader):
    print(json.dumps({"ready": True, "epoch": reader.clock(), "pipe_epochs": prog.pipe_epochs()}))
    sys.stdout.flush()
    follower = None
    for line in iter(sys.stdin.readline, ""):
        line = line.strip()
        if not line:
            continue
        t_recv = time.time()
        try:
            req = json.loads(line)
            cmd = req.get("cmd")
            if cmd == "setup":
                out = setup(prog, bool(req.get("reset")), req.get("frame_min") or (), req.get("marker_ports"))
            elif cmd == "mark":
                out = reader.mark(int(req["epoch"]), float(req.get("timeout", 1.0)))
            elif cmd == "follow":
                if follower is None:
                    follower = Follower(prog, reader)
                out = {"following_from": follower.nxt}
            elif cmd == "read":
                if follower is not None:
                    out = follower.get(int(req["epoch"]), float(req.get("timeout", 5.0)))
                else:
                    out = reader.wait_and_read(int(req["epoch"]), float(req.get("timeout", 5.0)))
            elif cmd == "epoch":
                out = {"pipe_epochs": prog.pipe_epochs()}
            elif cmd == "quit":
                print(json.dumps({"bye": True}))
                sys.stdout.flush()
                return
            else:
                out = {"error": "unknown command %r" % cmd}
        except Exception as error:
            out = {"error": "%s: %s" % (type(error).__name__, error)}
        out["reader_t_recv"], out["reader_t_send"] = t_recv, time.time()
        print(json.dumps(out, sort_keys=True))
        sys.stdout.flush()


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--grpc-addr", default="127.0.0.1:50052")
    ap.add_argument("--client-id", type=int, default=9)
    ap.add_argument("--device-id", type=int, default=0)
    ap.add_argument("--p4-name", default="basic")
    ap.add_argument("--sde-install")
    ap.add_argument("--cpu-iface", default="enp5s0", help="the switch's CPU-port netdev, for --serve's markers")
    ap.add_argument("--reset", action="store_true")
    ap.add_argument("--frame-min", action="append", default=[])
    ap.add_argument("--marker-ports", help="comma-separated dev_ports whose window markers count ('' for none)")
    ap.add_argument("--follow", action="store_true")
    ap.add_argument("--serve", action="store_true")
    ap.add_argument("--until-epoch", type=int)
    ap.add_argument("--poll-ms", type=float, default=1.0)
    ap.add_argument("--once", action="store_true")
    args = ap.parse_args()
    gc = import_client(args.sde_install)
    prog = Program(gc, args.grpc_addr, args.client_id, args.device_id, args.p4_name)
    reader = WindowReader(prog, args.cpu_iface)
    ports = None if args.marker_ports is None else [int(p) for p in args.marker_ports.split(",") if p.strip()]
    if args.reset or args.frame_min or ports is not None:
        print(json.dumps(setup(prog, args.reset, args.frame_min, ports)))
        sys.stdout.flush()
    if args.once:
        epochs = prog.pipe_epochs()
        e = reader.clock(epochs)
        print(json.dumps({"epoch": e, "pipe_epochs": epochs, "regs": reader.read_window(e - 1, epochs)["regs"]},
                         sort_keys=True))
    if args.follow:
        do_follow(prog, reader, args.until_epoch, args.poll_ms / 1e3)
    if args.serve:
        do_serve(prog, reader)
    try:
        prog.iface.tear_down_stream()
    except Exception:
        pass


if __name__ == "__main__":
    main()
