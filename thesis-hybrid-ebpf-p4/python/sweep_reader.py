#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Control plane of perf/variants/sweep over BF Runtime gRPC (runs on the switch).

perf/variants/sweep reads its own registers: a probe (EtherType 0x88B6 from a port in the parser's sweep_ports)
names one bucket in the low 16 bits of its destination MAC, picks up that bucket's 14 registers (bucket 0 also the
seven totals and the sweep number) and leaves through the table sweep_export (headers.p4, ingress.p4). This tool
sets the program up and drives the packet generator that sends the probes; the records are turned into window
features off the switch (sweep_features.py).

    sweep_reader.py --setup [--reset] [--frame-min DST/PREFIX ...] [--sweep-ports P,P] [--export-port P]
        --reset        clear the 14 flow registers, the seven totals, reg_sweep_seq and the two probe counters,
                       then read a few cells back (they must be 0)
        --frame-min    frame_len: count packets toward DST as at least 46 B of IPv4 (the 60-byte frame minimum
                       the dataset's guest saw); repeatable, replaces the table's entries ('' clears it)
        --sweep-ports  the ports whose 0x88B6 frames are probes (replaces the value set; '' empties it)
        --export-port  sweep_export's default action: export_to(P); -1 restores export_drop
    sweep_reader.py --generator start --period-ns NS [--buckets 65536] [--ipg-ns NS] [--pipes 1] [--local-port 68]
                    [--app 0] [--buffer-offset 0]
        the generator of each pipe sends one batch of --buckets probes (packet ids 0..N-1, --ipg-ns apart) every
        NS: one sweep per window. The generator's ports (dev_port 128 pipe + local port) are added to
        sweep_ports. On the Wedge a local port other than 68 sends only while 68 of the same pipe is a generator
        port too (PC1.md part 6d)
    sweep_reader.py --generator stop [--pipes 1] [--local-port 68] [--app 0]
    sweep_reader.py --state
        reg_sweep_seq and the counters sweep_probes / sweep_exported per pipe, the export action, the sweep ports,
        the frame_len entries, and the generator apps' counters (with --pipes/--app/--local-port)

One JSON line per command on stdout, diagnostics on stderr. Every pipe has its own registers: the probes of the
generator in pipe p read pipe p's buckets (dev_ports 128 p .. 128 p + 127). On the Wedge the replay host's port 132
is in pipe 1.

Runs under Python 2.7 (the SDE 9.6 client on the switch) and 3. Self-contained: it is copied to the switch alone,
as window_reader.py is.
"""
from __future__ import print_function

import argparse
import glob
import json
import os
import socket
import struct
import sys
import time

TABLE_PREFIX = "pipe.Ingress."
DATA_PREFIX = "Ingress."
KEY = "$REGISTER_INDEX"
SDE_INSTALL_CANDIDATES = ["/root/bf-sde-9.6.0/install", "/home/ubuntu/open-p4studio/install"]
M32 = (1 << 32) - 1
ETHERTYPE_SWEEP = 0x88B6
SWEEP_MAGIC = 0x5357
RECORD_BYTES = 90

FLOW_REGS = ["reg_pkts", "reg_bytes", "reg_pkts_ab", "reg_bytes_ab", "reg_ref_src_port", "reg_ref_dst_port",
             "reg_dir_valid", "reg_min_len", "reg_max_len", "reg_first_ts", "reg_last_ts", "reg_syn", "reg_ack",
             "reg_rst"]
TOTAL_REGS = ["reg_g_pkts_ab", "reg_g_bytes_ab", "reg_g_pkts_ba", "reg_g_bytes_ba", "reg_g_syn", "reg_g_ack",
              "reg_g_rst"]
SEQ_REG = "reg_sweep_seq"
COUNTERS = ["sweep_probes", "sweep_exported"]
# the generator's tables and periodic-timer action: SDE 9.6 names, then SDE 9.13 (open-p4studio)
PKTGEN_TABLES = [("$PKTGEN_PORT_CFG", "$PKTGEN_APPLICATION_CFG", "$PKTGEN_PKT_BUFFER", "$PKTGEN_TRIGGER_TIMER_PERIODIC"),
                 ("tf1.pktgen.port_cfg", "tf1.pktgen.app_cfg", "tf1.pktgen.pkt_buffer", "trigger_timer_periodic")]


def log(msg):
    sys.stderr.write("[sweep] %s\n" % msg)
    sys.stderr.flush()


def first_line(error):
    return (str(error).splitlines() or [""])[0][:300]


def import_client(sde_install=None):
    roots = [r for r in [sde_install, os.environ.get("SDE_INSTALL")] + SDE_INSTALL_CANDIDATES if r]
    for root in roots:
        for sp in sorted(glob.glob(os.path.join(root, "lib", "python*", "site-packages"))):
            for p in (sp, os.path.join(sp, "tofino")):
                if os.path.isdir(p) and p not in sys.path:
                    sys.path.insert(0, p)
    import bfrt_grpc.client as gc
    return gc


def generator_frame(src_mac=b"\x02\x00\x00\x00\x88\xb6"):
    """The probe as the generator sends it: 6 bytes the generator overwrites with its header (pipe, app, batch id,
    packet id = the bucket), the source MAC, EtherType 0x88B6, a sweep_t with its magic and zeros (104 bytes)."""
    return b"\x00" * 6 + src_mac + struct.pack("!HH", ETHERTYPE_SWEEP, SWEEP_MAGIC) + b"\x00" * (RECORD_BYTES - 2)


def as_list(v):
    return list(v) if isinstance(v, (list, tuple)) else [v]


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

    def has(self, name, prefix=TABLE_PREFIX):
        try:
            self.table(name, prefix)
            return True
        except Exception:
            return False

    def kw(self, func):
        try:
            import inspect
            args = inspect.getargspec(func).args if hasattr(inspect, "getargspec") else \
                list(inspect.signature(func).parameters)
        except Exception:
            args = []
        return {"p4_name": self.p4_name} if (not self.bound and "p4_name" in args) else {}

    def pipe(self, p):
        return self.gc.Target(device_id=self.device_id, pipe_id=p)

    def get(self, name, indexes):
        """index -> per-pipe values of a register."""
        t = self.table(name)
        keys = [t.make_key([self.gc.KeyTuple(KEY, i)]) for i in indexes]
        out = {}
        for data, key in t.entry_get(self.target, keys, {"from_hw": True}, **self.kw(t.entry_get)):
            idx = key.to_dict()[KEY]["value"]
            out[idx] = [int(x) for x in as_list(data.to_dict()[DATA_PREFIX + name + ".f1"])]
        return out

    def counter(self, name):
        """A one-cell packet counter: its value per pipe as BF Runtime returns it (a list, or one number)."""
        t = self.table(name)
        for data, _ in t.entry_get(self.target, [t.make_key([self.gc.KeyTuple("$COUNTER_INDEX", 0)])],
                                   {"from_hw": True}, **self.kw(t.entry_get)):
            v = data.to_dict().get("$COUNTER_SPEC_PKTS", 0)
            return [int(x) for x in as_list(v)]
        return []


# ------------------------------------------------------------------------------------------------ setup
def do_reset(prog):
    t0 = time.time()
    names = [n for n in FLOW_REGS + TOTAL_REGS + [SEQ_REG] if prog.has(n)]
    missing = [n for n in FLOW_REGS + [SEQ_REG] if n not in names]
    if missing:
        raise RuntimeError("not the sweep build: no %s" % ", ".join(missing))
    for name in names:
        t = prog.table(name)
        try:
            t.entry_del(prog.target, **prog.kw(t.entry_del))
        except Exception as error:
            raise RuntimeError("clearing %s failed: %s" % (name, first_line(error)))
    counters = []
    for name in COUNTERS:
        if not prog.has(name):
            continue
        t = prog.table(name)
        key = t.make_key([prog.gc.KeyTuple("$COUNTER_INDEX", 0)])
        try:
            t.entry_mod(prog.target, [key], [t.make_data([prog.gc.DataTuple("$COUNTER_SPEC_PKTS", 0)])],
                        **prog.kw(t.entry_mod))
            counters.append(name)
        except Exception as error:
            log("resetting the counter %s: %s" % (name, first_line(error)))
    bad, sizes = [], {}
    for name in names:
        t = prog.table(name)
        try:
            size = t.info.size_get()
        except Exception:
            size = 1
        sizes[name] = size
        cells = sorted(set([0, min(1, size - 1), size - 1]))
        for idx, vals in prog.get(name, cells).items():
            if any(vals):
                bad.append("%s[%d]=%r" % (name, idx, vals))
    for name in counters:
        vals = prog.counter(name)
        if any(vals):
            bad.append("%s=%r" % (name, vals))
    if bad:
        raise RuntimeError("not zero after the clear: " + ", ".join(bad))
    return {"reset": names, "counters_reset": counters, "sizes": sizes, "ms": round((time.time() - t0) * 1e3, 1)}


def ip_to_int(text):
    return struct.unpack("!I", socket.inet_aton(text))[0]


def do_frame_min(prog, specs):
    """frame_len: exactly these entries (DST/PREFIX: packets toward DST with totalLen 0..45 count as 46)."""
    gc = prog.gc
    t = prog.table("frame_len")
    try:
        t.entry_del(prog.target, **prog.kw(t.entry_del))
    except Exception as error:
        log("clearing frame_len: %s" % first_line(error))
    out = []
    for prio, spec in enumerate(specs, 1):
        addr, _, plen = spec.partition("/")
        plen = int(plen or 32)
        mask = (M32 << (32 - plen)) & M32
        key = t.make_key([gc.KeyTuple("hdr.ipv4.dstAddr", ip_to_int(addr), mask),
                          gc.KeyTuple("hdr.ipv4.totalLen", low=0, high=45),
                          gc.KeyTuple("$MATCH_PRIORITY", prio)])
        data = t.make_data([gc.DataTuple("len", 46)], "Ingress.len_set")
        t.entry_add(prog.target, [key], [data], **prog.kw(t.entry_add))
        out.append(spec)
    return {"frame_min": out}


def get_frame_min(prog):
    t = prog.table("frame_len")
    out = []
    for data, key in t.entry_get(prog.target, None, {"from_hw": False}, **prog.kw(t.entry_get)):
        k = key.to_dict()
        dst = k.get("hdr.ipv4.dstAddr", {})
        ln = k.get("hdr.ipv4.totalLen", {})
        out.append({"dst": socket.inet_ntoa(struct.pack("!I", int(dst.get("value", 0)))),
                    "mask": "%08x" % int(dst.get("mask", 0)), "len": [ln.get("low"), ln.get("high")],
                    "action": data.action_name, "data": dict((a, b) for a, b in data.to_dict().items()
                                                              if not a.startswith("$") and a != "action_name")})
    return out


def value_set(prog):
    return prog.table("sweep_ports", prefix="pipe.IngressParser.")


def get_sweep_ports(prog):
    t = value_set(prog)
    out = []
    for _, key in t.entry_get(prog.target, None, {"from_hw": False}, **prog.kw(t.entry_get)):
        out.append(int(key.to_dict()["f1"]["value"]))
    return sorted(out)


def set_sweep_ports(prog, ports, replace=True):
    t = value_set(prog)
    if replace:
        try:
            t.entry_del(prog.target, **prog.kw(t.entry_del))
        except Exception as error:
            log("clearing sweep_ports: %s" % first_line(error))
        have = []
    else:
        have = get_sweep_ports(prog)
    for p in ports:
        if int(p) in have:
            continue
        t.entry_add(prog.target, [t.make_key([prog.gc.KeyTuple("f1", int(p), 0x1FF)])], **prog.kw(t.entry_add))
        have.append(int(p))
    return {"sweep_ports": get_sweep_ports(prog)}


def set_export_port(prog, port):
    t = prog.table("sweep_export")
    if port is None or int(port) < 0:
        t.default_entry_reset(prog.target, **prog.kw(t.default_entry_reset))
    else:
        data = t.make_data([prog.gc.DataTuple("port", int(port))], "Ingress.export_to")
        t.default_entry_set(prog.target, data, **prog.kw(t.default_entry_set))
    return {"export": get_export(prog)}


def get_export(prog):
    t = prog.table("sweep_export")
    for data, _ in t.default_entry_get(prog.target, {"from_hw": False}, **prog.kw(t.default_entry_get)):
        d = data.to_dict()
        return {"action": data.action_name, "port": d.get("port")}
    return {}


def setup(prog, reset=False, frame_min=None, sweep_ports=None, export_port=None):
    out = {}
    if reset:
        out.update(do_reset(prog))
    if frame_min is not None:
        out.update(do_frame_min(prog, frame_min))
    if sweep_ports is not None:
        out.update(set_sweep_ports(prog, sweep_ports))
    if export_port is not None:
        out.update(set_export_port(prog, export_port))
    return out


# ------------------------------------------------------------------------------------------------ generator
class SweepGenerator(object):
    """App `app` of the generator of each pipe in `pipes`: periodic timer, one batch of `buckets` probes every
    period (packet ids 0..buckets-1, `ipg_ns` apart), from pipe-local port `local_port` (dev_port 128 p + port)."""

    def __init__(self, prog, pipes, local_port=68, app=0, buffer_offset=0):
        self.prog, self.pipes = prog, list(pipes)
        self.local_port, self.app, self.buffer_offset = int(local_port), int(app), int(buffer_offset)
        if self.buffer_offset % 16:
            raise ValueError("--buffer-offset must be a multiple of 16")

    def tables(self):
        t = self.prog.table
        for port, app, buf, trigger in PKTGEN_TABLES:
            try:
                tables = t(port, prefix=""), t(app, prefix=""), t(buf, prefix="")
            except Exception:
                continue
            self.trigger = trigger
            return tables
        raise RuntimeError("no packet generator tables (%s)" % " or ".join(n[0] for n in PKTGEN_TABLES))

    def dev_ports(self):
        return [128 * p + self.local_port for p in self.pipes]

    def start(self, period_ns, buckets=65536, ipg_ns=0):
        prog, gc = self.prog, self.prog.gc
        buckets, period_ns, ipg_ns = int(buckets), int(period_ns), int(ipg_ns)
        if not 1 <= buckets <= 65536:
            raise ValueError("--buckets must be 1..65536")
        if buckets * max(ipg_ns, 1) >= period_ns:
            raise ValueError("a sweep (%d probes, %d ns apart) does not fit in the period (%d ns)"
                             % (buckets, ipg_ns, period_ns))
        self.stop()
        port_cfg, app_cfg, pkt_buf = self.tables()
        frame = generator_frame()
        k_app = app_cfg.make_key([gc.KeyTuple("app_id", self.app)])
        k_buf = pkt_buf.make_key([gc.KeyTuple("pkt_buffer_offset", self.buffer_offset),
                                  gc.KeyTuple("pkt_buffer_size", len(frame) - 6)])
        d_buf = pkt_buf.make_data([gc.DataTuple("buffer", frame[6:])])
        d_app = app_cfg.make_data([
            gc.DataTuple("timer_nanosec", period_ns), gc.DataTuple("app_enable", bool_val=False),
            gc.DataTuple("pkt_len", len(frame) - 6), gc.DataTuple("pkt_buffer_offset", self.buffer_offset),
            gc.DataTuple("pipe_local_source_port", self.local_port),
            gc.DataTuple("increment_source_port", bool_val=False),
            gc.DataTuple("batch_count_cfg", 0), gc.DataTuple("packets_per_batch_cfg", buckets - 1),
            gc.DataTuple("ibg", 0), gc.DataTuple("ibg_jitter", 0), gc.DataTuple("ipg", ipg_ns),
            gc.DataTuple("ipg_jitter", 0),
            gc.DataTuple("batch_counter", 0), gc.DataTuple("pkt_counter", 0), gc.DataTuple("trigger_counter", 0)],
            self.trigger)
        ports = set_sweep_ports(prog, self.dev_ports(), replace=False)["sweep_ports"]
        for p, dp in zip(self.pipes, self.dev_ports()):
            k_port = port_cfg.make_key([gc.KeyTuple("dev_port", dp)])
            port_cfg.entry_mod(prog.target, [k_port], [port_cfg.make_data([gc.DataTuple("pktgen_enable", bool_val=True)])],
                               **prog.kw(port_cfg.entry_mod))
            for tbl, k, d in ((pkt_buf, k_buf, d_buf), (app_cfg, k_app, d_app)):
                try:
                    tbl.entry_add(prog.pipe(p), [k], [d], **prog.kw(tbl.entry_add))
                except Exception:
                    tbl.entry_mod(prog.pipe(p), [k], [d], **prog.kw(tbl.entry_mod))
        d_on = app_cfg.make_data([gc.DataTuple("app_enable", bool_val=True)], self.trigger)
        t0 = time.time()
        after = []
        for p in self.pipes:
            app_cfg.entry_mod(prog.pipe(p), [k_app], [d_on], **prog.kw(app_cfg.entry_mod))
            after.append(round(time.time() - t0, 6))
        log("generator: %d probes every %d ns, %d ns apart, pipes %s, app %d, local port %d"
            % (buckets, period_ns, ipg_ns, self.pipes, self.app, self.local_port))
        return {"generator": "started", "period_ns": period_ns, "buckets": buckets, "ipg_ns": ipg_ns,
                "sweep_ns": buckets * ipg_ns, "pipes": self.pipes, "app": self.app, "local_port": self.local_port,
                "dev_ports": self.dev_ports(), "buffer_offset": self.buffer_offset, "frame_bytes": len(frame),
                "t_enabled": t0, "enabled_after_s": after, "sweep_ports": ports}

    def stop(self):
        prog, gc = self.prog, self.prog.gc
        try:
            port_cfg, app_cfg, _ = self.tables()
        except RuntimeError as error:
            log("generator: %s: nothing to stop" % error)
            return {"generator": "stopped", "pipes": []}
        k_app = app_cfg.make_key([gc.KeyTuple("app_id", self.app)])
        errors = []
        for p, dp in zip(self.pipes, self.dev_ports()):
            try:
                app_cfg.entry_mod(prog.pipe(p), [k_app], [app_cfg.make_data(
                    [gc.DataTuple("app_enable", bool_val=False)], self.trigger)], **prog.kw(app_cfg.entry_mod))
            except Exception as error:
                if "not found" not in str(error).lower() and "not_found" not in str(error).lower():
                    errors.append("app of pipe %d: %s" % (p, first_line(error)))
            try:
                port_cfg.entry_mod(prog.target, [port_cfg.make_key([gc.KeyTuple("dev_port", dp)])],
                                   [port_cfg.make_data([gc.DataTuple("pktgen_enable", bool_val=False)])],
                                   **prog.kw(port_cfg.entry_mod))
            except Exception as error:
                errors.append("port %d: %s" % (dp, first_line(error)))
        for e in errors:
            log("generator stop: %s" % e)
        return {"generator": "stopped", "pipes": self.pipes, "errors": errors}

    def counters(self):
        """pkt_counter, batch_counter, trigger_counter of the app in each pipe."""
        prog, gc = self.prog, self.prog.gc
        _, app_cfg, _ = self.tables()
        k_app = app_cfg.make_key([gc.KeyTuple("app_id", self.app)])
        d_get = app_cfg.make_data([gc.DataTuple("pkt_counter"), gc.DataTuple("batch_counter"),
                                   gc.DataTuple("trigger_counter")], self.trigger, get=True)
        out = {}
        for p in self.pipes:
            try:
                for data, _ in app_cfg.entry_get(prog.pipe(p), [k_app], {"from_hw": True}, d_get,
                                                 **prog.kw(app_cfg.entry_get)):
                    d = data.to_dict()
                    out[str(p)] = dict((k, d.get(k)) for k in ("pkt_counter", "batch_counter", "trigger_counter"))
            except Exception as error:
                out[str(p)] = {"error": first_line(error)}
        return out


def state(prog, gen=None):
    out = {"t": time.time()}
    for name, fn in (("sweep_seq", lambda: prog.get(SEQ_REG, [0])[0]),
                     ("sweep_probes", lambda: prog.counter("sweep_probes")),
                     ("sweep_exported", lambda: prog.counter("sweep_exported")),
                     ("export", lambda: get_export(prog)),
                     ("sweep_ports", lambda: get_sweep_ports(prog)),
                     ("frame_len", lambda: get_frame_min(prog)),
                     ("totals", lambda: dict((n, prog.get(n, [0])[0]) for n in TOTAL_REGS if prog.has(n)))):
        try:
            out[name] = fn()
        except Exception as error:
            out[name + "_error"] = first_line(error)
    if gen is not None:
        try:
            out["generator"] = gen.counters()
        except Exception as error:
            out["generator_error"] = first_line(error)
    return out


def ports_arg(text):
    if text is None:
        return None
    return [int(p) for p in text.split(",") if p.strip()]


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--grpc-addr", default="127.0.0.1:50052")
    ap.add_argument("--client-id", type=int, default=9)
    ap.add_argument("--device-id", type=int, default=0)
    ap.add_argument("--p4-name", default="basic")
    ap.add_argument("--sde-install")
    ap.add_argument("--setup", action="store_true")
    ap.add_argument("--reset", action="store_true")
    ap.add_argument("--frame-min", action="append", default=None)
    ap.add_argument("--sweep-ports", help="comma-separated dev_ports ('' for none)")
    ap.add_argument("--export-port", type=int)
    ap.add_argument("--generator", choices=("start", "stop"))
    ap.add_argument("--period-ns", type=int, default=500000000)
    ap.add_argument("--buckets", type=int, default=65536)
    ap.add_argument("--ipg-ns", type=int, default=2000,
                    help="between two probes of a sweep (default 2000: a full sweep in 131 ms, at most 500 kpps of "
                         "exports)")
    ap.add_argument("--pipes", default="1")
    ap.add_argument("--local-port", type=int, default=68)
    ap.add_argument("--app", type=int, default=0)
    ap.add_argument("--buffer-offset", type=int, default=0, help="a multiple of 16")
    ap.add_argument("--state", action="store_true")
    args = ap.parse_args()
    gc = import_client(args.sde_install)
    prog = Program(gc, args.grpc_addr, args.client_id, args.device_id, args.p4_name)
    gen = SweepGenerator(prog, ports_arg(args.pipes), args.local_port, args.app, args.buffer_offset)
    code = 0
    try:
        if args.setup or args.reset:
            frame_min = None
            if args.frame_min is not None:
                frame_min = [s for s in args.frame_min if s.strip()]
            out = setup(prog, args.reset, frame_min, ports_arg(args.sweep_ports), args.export_port)
            print(json.dumps(out, sort_keys=True))
            sys.stdout.flush()
        if args.generator == "start":
            print(json.dumps(gen.start(args.period_ns, args.buckets, args.ipg_ns), sort_keys=True))
            sys.stdout.flush()
        elif args.generator == "stop":
            print(json.dumps(gen.stop(), sort_keys=True))
            sys.stdout.flush()
        if args.state:
            print(json.dumps(state(prog, gen), sort_keys=True))
            sys.stdout.flush()
    except Exception as error:
        print(json.dumps({"error": "%s: %s" % (type(error).__name__, first_line(error))}))
        code = 1
    try:
        prog.iface.tear_down_stream()
    except Exception:
        pass
    sys.exit(code)


if __name__ == "__main__":
    main()
