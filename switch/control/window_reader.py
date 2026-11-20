#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Reader of switch/variants/exact (the data-plane window features) over BF Runtime gRPC.

The program counts window e into bank e & 1 of its window registers (reg_w_*) and starts window e + 1 when
a window marker (from a port in the parser's marker_ports) or a timer tick passes: reg_epoch then holds
e + 1, and bank e & 1 holds window e unchanged until window e + 2 starts. This reader reads a finished
window's bank from the hardware, then clears the bank's extremes (reg_w_pa, reg_w_pb, reg_w_pd), which the
data plane only raises. The additive registers are never cleared; window_features.py takes the difference
of two reads of a bank.

Pipes. Every pipe has its own registers and its own clock (a marker or a tick moves only the clock of the
pipe it enters). A window's values are combined over the pipes whose clock has passed it (summed, the
extremes by max); the packets that a pipe whose clock lags counted meanwhile are reported as
"unclocked_pkts" (they belong to no window). Pipes ticked by their own generators (the timer build) do not
tick at the same instant (about 1 ms apart on the Wedge), so once the clock has passed window e the reader
waits up to --pipe-grace-ms for every pipe that has reached e to pass it too; a pipe further behind is not
waited for. A window's additive values are the difference of two reads of its bank, so the difference is
only right if both reads combined the same pipes: a window whose bank was last read with another set of
clocked pipes is "lost" (after a change of the set, the next window of each bank).

    window_reader.py --reset                  clear every register of the program, read back a few cells
    window_reader.py --frame-min DST/PREFIX   frame_len: count packets toward DST as at least 46 B of IPv4
                                              (60 B frames: the host's own capture sees them padded);
                                              repeatable, replaces the table's entries
    window_reader.py --marker-ports 192,132   the ports whose window markers count (replaces the set)
    window_reader.py --follow [--until-epoch N] [--poll-ms 1] [--timer-ns NS]
                                              one JSON line per finished window, from the window open at the
                                              start; stops when the clock reaches N (or on SIGTERM); with
                                              --timer-ns the generators' timers tick every NS (started
                                              first, stopped at the end)
    window_reader.py --serve                  JSON lines on stdin, one JSON reply line each (the collector):
        {"cmd": "setup", "reset": true, "frame_min": [...], "marker_ports": [...]}
        {"cmd": "mark", "epoch": E}            send a marker for epoch E from --cpu-iface (the switch's CPU
                                              port) and wait until the clock shows it
        {"cmd": "timer", "period_ns": NS}      start the window timer on every pipe's generator (a build with
                                              -DTIMER_LOCAL_PORT=68): a tick every NS, the first NS after this;
                                              "prepare": true only configures it (about 20 ms), then
                                              {"cmd": "timer", "enable": true} starts it (about 1 ms per pipe);
                                              {"cmd": "timer", "stop": true} stops it, as quit and exit do
        {"cmd": "follow"}                      from now on read every window as soon as it ends (a thread on the
                                              switch), so that a slow requester cannot make a read late
        {"cmd": "read", "epoch": e, "timeout": s}   wait until window e has ended, read it, clear it (after
                                              "follow": the line it read, once it has)
        {"cmd": "block", "op": "add", "entries": [ENTRY, ...]}   switch/variants/exact_block: drop packets that
                                              match (one write for the list); "del" removes these entries,
                                              "clear" all, "list" returns them with their dropped packets
        {"cmd": "epoch"} / {"cmd": "quit"}
    window_reader.py --block-add SPEC / --block-del SPEC / --block-clear / --block-list
                                              the block table by hand (exact_block): SPEC is comma-separated
                                              port=, src=, dst= (an address or ADDR/PREFIX), proto=, sport=,
                                              dport=; a field left out matches anything
    window_reader.py --once                   the current epoch and the bank of the window before it
                                              (reads and clears that window: not during a run)

A block ENTRY: {"port", "src", "dst", "proto", "sport", "dport"}, every field optional (missing or null:
any value); src and dst as "a.b.c.d" or "a.b.c.d/prefix". A "setup" with "reset" also clears the block table
(when the program has one) and its total counter.

A window line: {"epoch", "bank", "regs": {register: {index: value or [lo, hi]}}, "epoch_seen" (the clock when
the window was found finished), "epoch_after" (after the read and the clear), "lost" (the bank may hold
another window's packets: the read came after window e + 2 started, or a late clear may have wiped this
window's extremes, or the bank was last read with other clocked pipes), "pipe_epochs", "clocked_pipes",
"unclocked_pkts",
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
        self.device_id = device_id
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


TIMER_ETHERTYPE = 0x88B6
TIMER_APP = 0
# the generator's tables and periodic-timer action: SDE 9.6 names, then SDE 9.13 (open-p4studio)
PKTGEN_TABLES = [("$PKTGEN_PORT_CFG", "$PKTGEN_APPLICATION_CFG", "$PKTGEN_PKT_BUFFER", "$PKTGEN_TRIGGER_TIMER_PERIODIC"),
                 ("tf1.pktgen.port_cfg", "tf1.pktgen.app_cfg", "tf1.pktgen.pkt_buffer", "trigger_timer_periodic")]


class WindowTimer(object):
    """The window clock from the packet generators, for a build with -DTIMER_LOCAL_PORT=68: timer app 0 of every
    pipe's generator sends a 60-byte frame (EtherType 0x88B6, not counted) from that pipe's local port every
    period, and the program advances the pipe's reg_epoch on each. The apps are enabled one after the other, so
    the pipes tick about 1 ms apart (the reader waits for them: WindowReader.settle). Local port 68: on the Wedge
    another generator port sends only while 68 is a generator port too (PC1.md part 6d). Tofino 1: the local
    port of pipe p is dev_port 128 p + port."""

    def __init__(self, prog, local_port=68):
        self.prog, self.local_port = prog, local_port
        self.pipes, self.period_ns, self.enabled = [], None, False

    def _tables(self):
        """port_cfg, app_cfg, pkt_buffer under this SDE's names; sets self.trigger (the periodic-timer action)."""
        t = self.prog.table
        for port, app, buf, trigger in PKTGEN_TABLES:
            try:
                tables = t(port, prefix=""), t(app, prefix=""), t(buf, prefix="")
            except Exception:
                continue
            self.trigger = trigger
            return tables
        raise RuntimeError("no packet generator tables (%s)" % " or ".join(n[0] for n in PKTGEN_TABLES))

    def _pipe(self, p):
        return self.prog.gc.Target(device_id=self.prog.device_id, pipe_id=p)

    def start(self, period_ns, pipes=None):
        self.prepare(period_ns, pipes)
        return self.enable()

    def prepare(self, period_ns, pipes=None):
        """Configure the apps and ports (about 20 ms over gRPC), the apps still disabled; enable() starts them."""
        prog, gc = self.prog, self.prog.gc
        if pipes is None:
            pipes = list(range(len(prog.pipe_epochs())))
        self.stop(pipes)
        port_cfg, app_cfg, pkt_buf = self._tables()
        frame = b"\xff" * 6 + b"\x02\x00\x00\x00\x07\x01" + struct.pack("!H", TIMER_ETHERTYPE) + b"\x00" * 46
        k_app = app_cfg.make_key([gc.KeyTuple("app_id", TIMER_APP)])
        k_buf = pkt_buf.make_key([gc.KeyTuple("pkt_buffer_offset", 0), gc.KeyTuple("pkt_buffer_size", len(frame) - 6)])
        d_buf = pkt_buf.make_data([gc.DataTuple("buffer", frame[6:])])
        d_app = app_cfg.make_data([
            gc.DataTuple("timer_nanosec", int(period_ns)), gc.DataTuple("app_enable", bool_val=False),
            gc.DataTuple("pkt_len", len(frame) - 6), gc.DataTuple("pkt_buffer_offset", 0),
            gc.DataTuple("pipe_local_source_port", self.local_port),
            gc.DataTuple("increment_source_port", bool_val=False),
            gc.DataTuple("batch_count_cfg", 0), gc.DataTuple("packets_per_batch_cfg", 0),
            gc.DataTuple("ibg", 0), gc.DataTuple("ibg_jitter", 0), gc.DataTuple("ipg", 0), gc.DataTuple("ipg_jitter", 0),
            gc.DataTuple("batch_counter", 0), gc.DataTuple("pkt_counter", 0), gc.DataTuple("trigger_counter", 0)],
            self.trigger)
        for p in pipes:
            k_port = port_cfg.make_key([gc.KeyTuple("dev_port", 128 * p + self.local_port)])
            port_cfg.entry_mod(prog.target, [k_port], [port_cfg.make_data([gc.DataTuple("pktgen_enable", bool_val=True)])],
                               **prog.kw(port_cfg.entry_mod))
            for tbl, k, d in ((pkt_buf, k_buf, d_buf), (app_cfg, k_app, d_app)):
                try:
                    tbl.entry_add(self._pipe(p), [k], [d], **prog.kw(tbl.entry_add))
                except Exception:
                    tbl.entry_mod(self._pipe(p), [k], [d], **prog.kw(tbl.entry_mod))
        self.pipes, self.period_ns, self.enabled = list(pipes), int(period_ns), False
        return {"timer_ns": int(period_ns), "timer_pipes": list(pipes), "timer_local_port": self.local_port,
                "prepared": True}

    def enable(self):
        """Start the prepared apps, one pipe after the other (about 1 ms per gRPC write): the first ticks come
        one period later."""
        prog, gc = self.prog, self.prog.gc
        if not self.pipes:
            raise RuntimeError("the window timer is not prepared")
        _, app_cfg, _ = self._tables()
        k_app = app_cfg.make_key([gc.KeyTuple("app_id", TIMER_APP)])
        d_on = app_cfg.make_data([gc.DataTuple("app_enable", bool_val=True)], self.trigger)
        t0 = time.time()
        after = []
        for p in self.pipes:
            app_cfg.entry_mod(self._pipe(p), [k_app], [d_on], **prog.kw(app_cfg.entry_mod))
            after.append(round(time.time() - t0, 6))
        self.enabled = True
        log("window timer: a tick every %d ns on pipes %s (local port %d), enabled %s s after the first write"
            % (self.period_ns, self.pipes, self.local_port, after))
        return {"timer_ns": self.period_ns, "timer_pipes": list(self.pipes), "timer_local_port": self.local_port,
                "t_enabled": t0, "enabled_after_s": after}

    def stop(self, pipes=None):
        """Disable the timer apps and the generator ports (of `pipes`, default: those started). Errors are logged."""
        prog, gc = self.prog, self.prog.gc
        pipes = self.pipes if pipes is None else pipes
        if not pipes:
            return {"timer_stopped": []}
        try:
            port_cfg, app_cfg, _ = self._tables()
        except RuntimeError as error:
            log("window timer: %s: nothing to stop" % error)
            return {"timer_stopped": []}
        k_app = app_cfg.make_key([gc.KeyTuple("app_id", TIMER_APP)])
        for p in pipes:
            try:
                app_cfg.entry_mod(self._pipe(p), [k_app], [app_cfg.make_data(
                    [gc.DataTuple("app_enable", bool_val=False)], self.trigger)], **prog.kw(app_cfg.entry_mod))
            except Exception as error:
                if "not found" not in str(error).lower() and "not_found" not in str(error).lower():
                    log("window timer: disabling the app of pipe %d: %s" % (p, str(error).splitlines()[0][:200]))
            try:
                k_port = port_cfg.make_key([gc.KeyTuple("dev_port", 128 * p + self.local_port)])
                port_cfg.entry_mod(prog.target, [k_port], [port_cfg.make_data(
                    [gc.DataTuple("pktgen_enable", bool_val=False)])], **prog.kw(port_cfg.entry_mod))
            except Exception as error:
                log("window timer: disabling generator port of pipe %d: %s" % (p, str(error).splitlines()[0][:200]))
        stopped, self.pipes = list(pipes), [p for p in self.pipes if p not in pipes]
        self.enabled = self.enabled and bool(self.pipes)
        return {"timer_stopped": stopped}


class WindowReader(object):
    """Reads finished windows in order; keeps what the lost / unclocked checks need between reads."""

    def __init__(self, prog, cpu_iface="enp5s0", grace_s=0.05):
        self.prog = prog
        self.cpu_iface = cpu_iface
        self.grace_s = grace_s
        self.tainted = set()          # windows whose extremes a late clear may have wiped
        self.bank_pipes = {}          # bank -> the pipes combined at its previous read
        self.unclocked_prev = {}      # pipe -> packets of all its tot cells at the previous read
        self.sock = None

    def clock(self, epochs=None):
        """The clock: the most advanced pipe's epoch."""
        return max(epochs if epochs is not None else self.prog.pipe_epochs())

    def settle(self, e, epochs):
        """The clock has passed window e: wait (up to grace_s) for the pipes that have reached e to pass it too."""
        deadline = time.time() + self.grace_s
        while any(ep == e for ep in epochs) and time.time() < deadline:
            time.sleep(0.0002)
            epochs = self.prog.pipe_epochs()
        return epochs

    def read_window(self, e, epochs):
        """Window e (finished: the clock is past it) from the pipes whose clock has passed it."""
        prog = self.prog
        b = e & 1
        lost = self.clock(epochs) >= e + 2 or e in self.tainted
        self.tainted.discard(e)
        clocked = [p for p, ep in enumerate(epochs) if ep >= e + 1]
        before = self.bank_pipes.get(b)
        if before is not None and clocked != before:
            # the bank's previous read combined other pipes: the difference mixes them
            lost = True
            log("window %d: clocked pipes %s, at the bank's previous read %s" % (e, clocked, before))
        self.bank_pipes[b] = clocked
        for p in clocked:
            self.unclocked_prev.pop(p, None)
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
                return self.read_window(e, self.settle(e, epochs))
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


def clear_frame_len(prog):
    t = prog.table("frame_len")
    try:
        t.entry_del(prog.target, **prog.kw(t.entry_del))
    except Exception as error:
        log("clearing frame_len: %s" % str(error).splitlines()[0][:200])


# ---------------------------------------------------------------- block rules (switch/variants/exact_block)
BLOCK_TABLE = "block_rules"
BLOCK_ACTION = DATA_PREFIX + "block_drop"
BLOCK_PRIORITY = 1
# entry field -> (key field, width in bits)
BLOCK_FIELDS = [("port", "ig_intr_md.ingress_port", 9), ("src", "hdr.ipv4.srcAddr", 32),
                ("dst", "hdr.ipv4.dstAddr", 32), ("proto", "hdr.ipv4.protocol", 8),
                ("sport", "meta.l4_sport", 16), ("dport", "meta.l4_dport", 16)]


def block_key_spec(entry):
    """An entry (dict) -> [(key field, value, mask)] for every key of block_rules; a field left out (or null)
    matches anything (value 0, mask 0). Raises ValueError on an unknown field or a value out of range."""
    unknown = set(entry) - set(f for f, _, _ in BLOCK_FIELDS)
    if unknown:
        raise ValueError("unknown block field(s): %s" % ", ".join(sorted(unknown)))
    spec = []
    for name, key, bits in BLOCK_FIELDS:
        full = (1 << bits) - 1
        value = entry.get(name)
        if value is None or value == "":
            spec.append((key, 0, 0))
            continue
        if name in ("src", "dst"):
            addr, _, plen = str(value).partition("/")
            plen = int(plen) if plen else 32
            if not 0 <= plen <= 32:
                raise ValueError("bad prefix length in %s=%s" % (name, value))
            mask = (M32 << (32 - plen)) & M32
            spec.append((key, ip_to_int(addr) & mask, mask))
        else:
            v = int(value)
            if not 0 <= v <= full:
                raise ValueError("%s=%s is out of range (%d bits)" % (name, value, bits))
            spec.append((key, v, full))
    return spec


def parse_block_spec(text):
    """'src=10.0.0.10,dport=80' -> {"src": "10.0.0.10", "dport": 80}."""
    entry = {}
    for part in text.split(","):
        part = part.strip()
        if not part:
            continue
        name, sep, value = part.partition("=")
        if not sep:
            raise ValueError("block spec %r: expected NAME=VALUE" % part)
        entry[name.strip()] = value.strip() if name.strip() in ("src", "dst") else int(value.strip(), 0)
    block_key_spec(entry)
    return entry


def has_table(prog, name):
    try:
        prog.table(name)
        return True
    except Exception:
        return False


def _block_key(prog, t, entry):
    gc = prog.gc
    return t.make_key([gc.KeyTuple(k, v, m) for k, v, m in block_key_spec(entry)] +
                      [gc.KeyTuple("$MATCH_PRIORITY", BLOCK_PRIORITY)])


def blocked_total(prog):
    """The packets block_rules has dropped since the last reset (blocked_pkts)."""
    t = prog.table("blocked_pkts")
    for data, _ in t.entry_get(prog.target, [t.make_key([prog.gc.KeyTuple("$COUNTER_INDEX", 0)])],
                               {"from_hw": True}, **prog.kw(t.entry_get)):
        v = data.to_dict().get("$COUNTER_SPEC_PKTS", 0)
        return int(sum(v) if isinstance(v, (list, tuple)) else v)
    return 0


def _full_at(text):
    """The index of the first entry a batch add could not fit ("At index K: RESOURCE_EXHAUSTED"), or None."""
    for line in text.splitlines():
        if "RESOURCE_EXHAUSTED" in line and "At index" in line:
            try:
                return int(line.split("At index", 1)[1].split(":", 1)[0])
            except ValueError:
                return None
    return None


def block_add(prog, entries):
    """Install the entries in one write (one by one if some exist already). Returns what was added. A full table is
    reported (an "error" and "table_full"), not raised: on the Wedge the 1,024-entry build with the direct counter
    holds 1,023 entries (PC1.md part 11b), and BF Runtime keeps the entries of a batch before the first that did
    not fit."""
    t = prog.table(BLOCK_TABLE)
    keys = [_block_key(prog, t, e) for e in entries]
    t0 = time.time()
    added, existing, full = 0, 0, None
    if keys:
        datas = [t.make_data([], BLOCK_ACTION) for _ in keys]
        try:
            t.entry_add(prog.target, keys, datas, **prog.kw(t.entry_add))
            added = len(keys)
        except Exception as error:
            text = str(error)
            if "RESOURCE_EXHAUSTED" in text and "ALREADY_EXISTS" not in text:
                k = _full_at(text)
                added = k if k is not None else 0
                full = text.strip().splitlines()[-1][:200]
            elif "ALREADY_EXISTS" not in text:
                raise
            else:
                for key, data in zip(keys, datas):
                    try:
                        t.entry_add(prog.target, [key], [data], **prog.kw(t.entry_add))
                        added += 1
                    except Exception as error1:
                        if "RESOURCE_EXHAUSTED" in str(error1):
                            full = str(error1).strip().splitlines()[-1][:200]
                            break
                        if "ALREADY_EXISTS" not in str(error1):
                            raise
                        existing += 1
    out = {"block": "add", "added": added, "existing": existing, "t_written": time.time(),
           "write_ms": round((time.time() - t0) * 1e3, 3)}
    if full is not None:
        out["table_full"] = True
        out["error"] = "the block table is full: %d of %d entries added or there (%s)" % (added + existing, len(keys),
                                                                                          full.strip())
    return out


def block_del(prog, entries):
    t = prog.table(BLOCK_TABLE)
    keys = [_block_key(prog, t, e) for e in entries]
    t0 = time.time()
    if keys:
        t.entry_del(prog.target, keys, **prog.kw(t.entry_del))
    return {"block": "del", "deleted": len(keys), "write_ms": round((time.time() - t0) * 1e3, 3)}


def block_clear(prog, missing_ok=False, zero_total=False):
    """Delete every entry (and with zero_total, zero blocked_pkts). Without the table: an error, or with
    missing_ok nothing (the exact build has no block table)."""
    if not has_table(prog, BLOCK_TABLE):
        if missing_ok:
            return {}
        raise RuntimeError("the program has no %s table (a build of switch/variants/exact_block?)" % BLOCK_TABLE)
    t = prog.table(BLOCK_TABLE)
    t.entry_del(prog.target, **prog.kw(t.entry_del))
    out = {"block_cleared": True}
    if zero_total:
        c = prog.table("blocked_pkts")
        try:
            c.entry_mod(prog.target, [c.make_key([prog.gc.KeyTuple("$COUNTER_INDEX", 0)])],
                        [c.make_data([prog.gc.DataTuple("$COUNTER_SPEC_PKTS", 0)])], **prog.kw(c.entry_mod))
        except Exception as error:
            out["blocked_pkts_reset_error"] = str(error).splitlines()[0][:200]
    return out


def _key_field(kd, name):
    v = kd.get(name)
    if isinstance(v, dict):
        return int(v.get("value", 0)), int(v.get("mask", 0))
    return (int(v), None) if v is not None else (0, 0)


def block_list(prog):
    """Every entry, as an entry dict, with the packets it dropped (when the build has the direct counter). The
    table's direct counters are synced from the hardware once (the SyncCounters operation) and the entries read from
    software: read from the hardware entry by entry they cost about 51 ms each on the Wedge (5.1 s for 100 entries,
    PC1.md part 11b). Without the operation the entries are read from the hardware."""
    t = prog.table(BLOCK_TABLE)
    out = []
    flags = {"from_hw": True}
    if hasattr(t, "operations_execute"):
        try:
            t.operations_execute(prog.target, "SyncCounters", **prog.kw(t.operations_execute))
            flags = {"from_hw": False}
        except Exception as error:
            log("block list: no counter sync (%s): reading from the hardware" % str(error).splitlines()[0][:160])
    for data, key in t.entry_get(prog.target, None, flags, **prog.kw(t.entry_get)):
        kd, dd = key.to_dict(), data.to_dict()
        entry = {}
        for name, field, bits in BLOCK_FIELDS:
            value, mask = _key_field(kd, field)
            if mask == 0:
                continue
            if name in ("src", "dst"):
                plen = bin(mask if mask is not None else M32).count("1")
                text = socket.inet_ntoa(struct.pack("!I", value))
                entry[name] = text if plen == 32 else "%s/%d" % (text, plen)
            else:
                entry[name] = value
        pkts = dd.get("$COUNTER_SPEC_PKTS")
        if pkts is not None:
            entry["dropped_pkts"] = int(sum(pkts) if isinstance(pkts, (list, tuple)) else pkts)
        out.append(entry)
    return {"block": "list", "entries": out, "blocked_pkts": blocked_total(prog)}


def do_block(prog, req):
    op = req.get("op")
    if op == "add":
        return block_add(prog, req.get("entries") or [])
    if op == "del":
        return block_del(prog, req.get("entries") or [])
    if op == "clear":
        return block_clear(prog, zero_total=bool(req.get("zero_total")))
    if op == "list":
        return block_list(prog)
    return {"error": "unknown block op %r (add, del, clear, list)" % op}


def setup(prog, reset=False, frame_min=None, marker_ports=None, timer=None):
    """frame_min (a list, possibly empty) and marker_ports replace what the tables held. A reset first stops the
    window timer (`timer`, a WindowTimer; every pipe), so that no tick left from an earlier run moves the clock."""
    out = {}
    if reset:
        if timer is not None:
            timer.stop(list(range(len(prog.pipe_epochs()))))
        out.update(do_reset(prog))
        out.update(block_clear(prog, missing_ok=True, zero_total=True))
    if frame_min is not None:
        clear_frame_len(prog)
        out["frame_min"] = [do_frame_min(prog, spec)["frame_len"] for spec in frame_min]
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
            epochs = reader.settle(nxt, epochs)
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
                    epochs = self.reader.settle(self.nxt, epochs)
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


def do_serve(prog, reader, timer):
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
                out = setup(prog, bool(req.get("reset")), req.get("frame_min"), req.get("marker_ports"), timer)
            elif cmd == "timer":
                if req.get("stop"):
                    out = timer.stop()
                elif req.get("prepare"):
                    out = timer.prepare(int(req["period_ns"]), req.get("pipes"))
                elif req.get("enable"):
                    out = timer.enable()
                else:
                    out = timer.start(int(req["period_ns"]), req.get("pipes"))
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
            elif cmd == "block":
                out = do_block(prog, req)
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
    ap.add_argument("--pipe-grace-ms", type=float, default=50.0,
                    help="how long to wait for a pipe that has reached a finished window to pass it")
    ap.add_argument("--timer-ns", type=int, help="--follow: start the window timer (every pipe) with this period")
    ap.add_argument("--timer-local-port", type=int, default=68, help="the generator port of the timer build")
    ap.add_argument("--once", action="store_true")
    ap.add_argument("--block-add", action="append", default=[], metavar="SPEC",
                    help="exact_block: add a block entry (port=,src=,dst=,proto=,sport=,dport=); repeatable")
    ap.add_argument("--block-del", action="append", default=[], metavar="SPEC", help="exact_block: delete an entry")
    ap.add_argument("--block-clear", action="store_true", help="exact_block: delete every block entry")
    ap.add_argument("--block-list", action="store_true", help="exact_block: print the entries and their drops")
    args = ap.parse_args()
    gc = import_client(args.sde_install)
    prog = Program(gc, args.grpc_addr, args.client_id, args.device_id, args.p4_name)
    reader = WindowReader(prog, args.cpu_iface, args.pipe_grace_ms / 1e3)
    timer = WindowTimer(prog, args.timer_local_port)
    ports = None if args.marker_ports is None else [int(p) for p in args.marker_ports.split(",") if p.strip()]
    try:
        if args.block_clear:
            print(json.dumps(block_clear(prog)))
        if args.block_del:
            print(json.dumps(block_del(prog, [parse_block_spec(s) for s in args.block_del])))
        if args.block_add:
            print(json.dumps(block_add(prog, [parse_block_spec(s) for s in args.block_add])))
        if args.block_list:
            print(json.dumps(block_list(prog), sort_keys=True))
        sys.stdout.flush()
        if args.reset or args.frame_min or ports is not None:
            print(json.dumps(setup(prog, args.reset, args.frame_min or None, ports, timer)))
            sys.stdout.flush()
        if args.once:
            epochs = prog.pipe_epochs()
            e = reader.clock(epochs)
            print(json.dumps({"epoch": e, "pipe_epochs": epochs, "regs": reader.read_window(e - 1, epochs)["regs"]},
                             sort_keys=True))
        if args.follow:
            if args.timer_ns:
                start = timer.start(args.timer_ns)
                sys.stderr.write("[window] %s\n" % json.dumps(start))
            do_follow(prog, reader, args.until_epoch, args.poll_ms / 1e3)
        if args.serve:
            # terminated (the collector's stop when quit is not answered): leave through the finally below
            signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
            do_serve(prog, reader, timer)
    finally:
        if timer.pipes:
            timer.stop()
            log("window timer stopped")
    try:
        prog.iface.tear_down_stream()
    except Exception:
        pass


if __name__ == "__main__":
    main()
