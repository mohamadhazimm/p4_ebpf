#!/usr/bin/env python2.7
"""The window clock of perf/variants/exact from the packet generator (p4_perf.md section 5.7). Runs on the switch.

    python2.7 sw_window_timer.py OUT_JSON --period-ns 500000000 --seconds 20 [--pipes 1 | --pipes 0,1] [--local-port 68]

A build of perf/variants/exact with -DTIMER_LOCAL_PORT=68 ticks its window clock on timer packets from that local port of any
pipe (pipe 1: dev_port 196). Timer app 0 of
each pipe's generator (--pipes; the apps are enabled one after the other, as fast as the client allows) sends one
64-byte frame (not IPv4, EtherType 0x88B6) every PERIOD ns from that port; the program advances the pipe's
reg_epoch on each and drops it. This tool enables the apps, polls reg_epoch (every --poll-ms) for SECONDS, disables
the apps and the generator ports again, and reports per pipe the epochs seen with this host's time of the first
poll that saw each, the intervals between them, the generator's packet counter (one per tick), and reg_w_tot
before and after (the ticks must not count); with several pipes also how far each pipe's ticks lag the first
pipe's (the same epoch, as polled), and the enable times.
"""
from __future__ import print_function

import argparse
import json
import sys
import time

sys.path.insert(0, "/root/bf-sde-9.6.0/install/lib/python2.7/site-packages/tofino")
sys.path.insert(0, "/root/bf-sde-9.6.0/install/lib/python2.7/site-packages")
import bfrt_grpc.client as gc  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("out")
    ap.add_argument("--prog", default="basic")
    ap.add_argument("--period-ns", type=int, default=500000000)
    ap.add_argument("--seconds", type=float, default=20.0)
    ap.add_argument("--pipe", type=int, default=1)
    ap.add_argument("--pipes", help="comma-separated pipes (default: --pipe)")
    ap.add_argument("--local-port", type=int, default=68)
    ap.add_argument("--poll-ms", type=float, default=1.0)
    ap.add_argument("--client-id", type=int, default=9)
    a = ap.parse_args()
    pipes = [int(x) for x in a.pipes.split(",")] if a.pipes else [a.pipe]
    out = {"period_ns": a.period_ns, "pipes": pipes, "dev_ports": [128 * p + a.local_port for p in pipes],
           "errors": []}
    c = gc.ClientInterface("127.0.0.1:50052", client_id=a.client_id, device_id=0, perform_subscribe=True)
    info = c.bfrt_info_get(a.prog)
    KW = {}
    try:
        c.bind_pipeline_config(a.prog)
    except Exception as e:
        # another client (window_reader.py --follow) owns the program: work unbound, naming it in every request
        if "already owns" not in str(e) and "ALREADY_EXISTS" not in str(e):
            raise
        KW = {"p4_name": a.prog}
    t_all = gc.Target(device_id=0, pipe_id=0xffff)
    t_pipe = dict((p, gc.Target(device_id=0, pipe_id=p)) for p in pipes)
    port_cfg = info.table_get("$PKTGEN_PORT_CFG")
    app_cfg = info.table_get("$PKTGEN_APPLICATION_CFG")
    pkt_buf = info.table_get("$PKTGEN_PKT_BUFFER")
    epoch_t = info.table_get("pipe.Ingress.reg_epoch")
    tot_t = info.table_get("pipe.Ingress.reg_w_tot")
    k_gen = dict((p, port_cfg.make_key([gc.KeyTuple("dev_port", 128 * p + a.local_port)])) for p in pipes)
    k_app = app_cfg.make_key([gc.KeyTuple("app_id", 0)])

    def epoch():
        for data, _ in epoch_t.entry_get(t_all, [epoch_t.make_key([gc.KeyTuple("$REGISTER_INDEX", 0)])],
                                         {"from_hw": True}, **KW):
            return [int(x) for x in data.to_dict()["Ingress.reg_epoch.f1"]]

    def totals():
        s = None
        for i in range(8):
            for data, _ in tot_t.entry_get(t_all, [tot_t.make_key([gc.KeyTuple("$REGISTER_INDEX", i)])],
                                           {"from_hw": True}, **KW):
                v = [int(x) for x in data.to_dict()["Ingress.reg_w_tot.lo"]]
                s = v if s is None else [x + y for x, y in zip(s, v)]
        return s

    def app_counter(p):
        for data, _ in app_cfg.entry_get(t_pipe[p], [k_app], {"from_hw": True}, **KW):
            return data.to_dict().get("pkt_counter")

    frame = b"\xff" * 6 + b"\x02\x00\x00\x00\x07\x01" + b"\x88\xb6" + b"\x00" * 46
    k_buf = pkt_buf.make_key([gc.KeyTuple("pkt_buffer_offset", 0), gc.KeyTuple("pkt_buffer_size", len(frame) - 6)])
    d_buf = pkt_buf.make_data([gc.DataTuple("buffer", frame[6:])])
    d_app = app_cfg.make_data([
        gc.DataTuple("timer_nanosec", a.period_ns), gc.DataTuple("app_enable", bool_val=False),
        gc.DataTuple("pkt_len", len(frame) - 6), gc.DataTuple("pkt_buffer_offset", 0),
        gc.DataTuple("pipe_local_source_port", a.local_port), gc.DataTuple("increment_source_port", bool_val=False),
        gc.DataTuple("batch_count_cfg", 0), gc.DataTuple("packets_per_batch_cfg", 0),
        gc.DataTuple("ibg", 0), gc.DataTuple("ibg_jitter", 0), gc.DataTuple("ipg", 0), gc.DataTuple("ipg_jitter", 0),
        gc.DataTuple("batch_counter", 0), gc.DataTuple("pkt_counter", 0), gc.DataTuple("trigger_counter", 0)],
        "$PKTGEN_TRIGGER_TIMER_PERIODIC")
    for p in pipes:
        port_cfg.entry_mod(t_all, [k_gen[p]], [port_cfg.make_data([gc.DataTuple("pktgen_enable", bool_val=True)])], **KW)
        try:
            pkt_buf.entry_add(t_pipe[p], [k_buf], [d_buf], **KW)
        except Exception:
            pkt_buf.entry_mod(t_pipe[p], [k_buf], [d_buf], **KW)
        try:
            app_cfg.entry_add(t_pipe[p], [k_app], [d_app], **KW)
        except Exception:
            app_cfg.entry_mod(t_pipe[p], [k_app], [d_app], **KW)
    out["epoch_before"], out["tot_before"] = epoch(), totals()
    out["gen_before"] = [app_counter(p) for p in pipes]

    def app_set(p, enable):
        app_cfg.entry_mod(t_pipe[p], [k_app], [app_cfg.make_data([gc.DataTuple("app_enable", bool_val=enable)],
                                                                 "$PKTGEN_TRIGGER_TIMER_PERIODIC")], **KW)

    seen = dict((p, []) for p in pipes)
    t_on = time.time()
    enabled_at = []
    for p in pipes:
        app_set(p, True)
        enabled_at.append(round(time.time() - t_on, 6))
    out["enabled_at_s"] = enabled_at
    try:
        last = dict((p, None) for p in pipes)
        while time.time() - t_on < a.seconds:
            ep = epoch()
            now = round(time.time() - t_on, 6)
            for p in pipes:
                if ep[p] != last[p]:
                    seen[p].append([now, ep[p]])
                    last[p] = ep[p]
            time.sleep(a.poll_ms / 1e3)
    finally:
        for p in pipes:
            app_set(p, False)
        time.sleep(a.period_ns / 1e9 + 0.1)
        out["epoch_after"], out["tot_after"] = epoch(), totals()
        out["gen_after"] = [app_counter(p) for p in pipes]
        for p in pipes:
            port_cfg.entry_mod(t_all, [k_gen[p]], [port_cfg.make_data([gc.DataTuple("pktgen_enable", bool_val=False)])], **KW)
    out["seen"] = dict((str(p), seen[p]) for p in pipes)
    out["ticks"] = dict((str(p), out["epoch_after"][p] - out["epoch_before"][p]) for p in pipes)
    out["generated"] = dict((str(p), (g1 or 0) - (g0 or 0)) for p, g0, g1 in zip(pipes, out["gen_before"],
                                                                                  out["gen_after"]))
    out["counted_by_tot"] = [y - x for x, y in zip(out["tot_before"], out["tot_after"])]
    out["intervals"] = {}
    for p in pipes:
        iv = sorted(round(y[0] - x[0], 6) for x, y in zip(seen[p][1:], seen[p][2:]))
        if iv:
            out["intervals"][str(p)] = {"min": iv[0], "median": iv[len(iv) // 2], "max": iv[-1], "n": len(iv)}
    if len(pipes) > 1:
        # the lag of each pipe's ticks behind the first pipe's, per epoch both reached while polled
        first = dict((e, t) for t, e in seen[pipes[0]][1:])
        out["lag_behind_first_s"] = {}
        for p in pipes[1:]:
            lags = sorted(round(t - first[e], 6) for t, e in seen[p][1:] if e in first)
            if lags:
                out["lag_behind_first_s"][str(p)] = {"min": lags[0], "median": lags[len(lags) // 2],
                                                     "max": lags[-1], "n": len(lags)}
    print("HZJSON " + json.dumps(out, sort_keys=True))
    json.dump(out, open(a.out, "w"), indent=2, sort_keys=True)

if __name__ == "__main__":
    main()
