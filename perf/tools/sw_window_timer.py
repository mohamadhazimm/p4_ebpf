#!/usr/bin/env python2.7
"""The window clock of perf/variants/exact from the packet generator (p4_perf.md section 5.7). Runs on the switch.

    python2.7 sw_window_timer.py OUT_JSON --period-ns 500000000 --seconds 20 [--pipe 1] [--local-port 68]

For a build compiled with -DTIMER_PORT=<the generator port> (pipe 1, local port 68: dev_port 196): timer app 0 of
the pipe's generator sends one 64-byte frame (not IPv4, EtherType 0x88B6) every PERIOD ns from that port; the
program advances reg_epoch on each and drops it. This tool enables the app, polls reg_epoch (every --poll-ms) for
SECONDS, disables the app and the generator port again, and reports the epochs seen with this host's time of the
first poll that saw each, the intervals between them, the generator's packet counter (one per tick), and
reg_w_tot before and after (the ticks must not count).
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
    ap.add_argument("--local-port", type=int, default=68)
    ap.add_argument("--poll-ms", type=float, default=1.0)
    ap.add_argument("--client-id", type=int, default=9)
    a = ap.parse_args()
    out = {"period_ns": a.period_ns, "pipe": a.pipe, "dev_port": 128 * a.pipe + a.local_port, "errors": []}
    c = gc.ClientInterface("127.0.0.1:50052", client_id=a.client_id, device_id=0, perform_subscribe=True)
    info = c.bfrt_info_get(a.prog)
    c.bind_pipeline_config(a.prog)
    t_all = gc.Target(device_id=0, pipe_id=0xffff)
    t_pipe = gc.Target(device_id=0, pipe_id=a.pipe)
    port_cfg = info.table_get("$PKTGEN_PORT_CFG")
    app_cfg = info.table_get("$PKTGEN_APPLICATION_CFG")
    pkt_buf = info.table_get("$PKTGEN_PKT_BUFFER")
    epoch_t = info.table_get("pipe.Ingress.reg_epoch")
    tot_t = info.table_get("pipe.Ingress.reg_w_tot")
    k_gen = port_cfg.make_key([gc.KeyTuple("dev_port", 128 * a.pipe + a.local_port)])
    k_app = app_cfg.make_key([gc.KeyTuple("app_id", 0)])

    def epoch():
        for data, _ in epoch_t.entry_get(t_all, [epoch_t.make_key([gc.KeyTuple("$REGISTER_INDEX", 0)])],
                                         {"from_hw": True}):
            return [int(x) for x in data.to_dict()["Ingress.reg_epoch.f1"]]

    def totals():
        s = 0
        for i in range(8):
            for data, _ in tot_t.entry_get(t_all, [tot_t.make_key([gc.KeyTuple("$REGISTER_INDEX", i)])],
                                           {"from_hw": True}):
                s += sum(int(x) for x in data.to_dict()["Ingress.reg_w_tot.lo"])
        return s

    def app_counter():
        for data, _ in app_cfg.entry_get(t_pipe, [k_app], {"from_hw": True}):
            return data.to_dict().get("pkt_counter")

    frame = b"\xff" * 6 + b"\x02\x00\x00\x00\x07\x01" + b"\x88\xb6" + b"\x00" * 46
    port_cfg.entry_mod(t_all, [k_gen], [port_cfg.make_data([gc.DataTuple("pktgen_enable", bool_val=True)])])
    k_buf = pkt_buf.make_key([gc.KeyTuple("pkt_buffer_offset", 0), gc.KeyTuple("pkt_buffer_size", len(frame) - 6)])
    d_buf = pkt_buf.make_data([gc.DataTuple("buffer", frame[6:])])
    try:
        pkt_buf.entry_add(t_pipe, [k_buf], [d_buf])
    except Exception:
        pkt_buf.entry_mod(t_pipe, [k_buf], [d_buf])
    d_app = app_cfg.make_data([
        gc.DataTuple("timer_nanosec", a.period_ns), gc.DataTuple("app_enable", bool_val=False),
        gc.DataTuple("pkt_len", len(frame) - 6), gc.DataTuple("pkt_buffer_offset", 0),
        gc.DataTuple("pipe_local_source_port", a.local_port), gc.DataTuple("increment_source_port", bool_val=False),
        gc.DataTuple("batch_count_cfg", 0), gc.DataTuple("packets_per_batch_cfg", 0),
        gc.DataTuple("ibg", 0), gc.DataTuple("ibg_jitter", 0), gc.DataTuple("ipg", 0), gc.DataTuple("ipg_jitter", 0),
        gc.DataTuple("batch_counter", 0), gc.DataTuple("pkt_counter", 0), gc.DataTuple("trigger_counter", 0)],
        "$PKTGEN_TRIGGER_TIMER_PERIODIC")
    try:
        app_cfg.entry_add(t_pipe, [k_app], [d_app])
    except Exception:
        app_cfg.entry_mod(t_pipe, [k_app], [d_app])
    out["epoch_before"], out["tot_before"], out["gen_before"] = epoch(), totals(), app_counter()

    def app_set(enable):
        app_cfg.entry_mod(t_pipe, [k_app], [app_cfg.make_data([gc.DataTuple("app_enable", bool_val=enable)],
                                                              "$PKTGEN_TRIGGER_TIMER_PERIODIC")])

    seen = []
    app_set(True)
    t_on = time.time()
    try:
        last = None
        while time.time() - t_on < a.seconds:
            e = max(epoch())
            if e != last:
                seen.append([round(time.time() - t_on, 6), e])
                last = e
            time.sleep(a.poll_ms / 1e3)
    finally:
        app_set(False)
        time.sleep(a.period_ns / 1e9 + 0.1)
        out["epoch_after"], out["tot_after"], out["gen_after"] = epoch(), totals(), app_counter()
        port_cfg.entry_mod(t_all, [k_gen], [port_cfg.make_data([gc.DataTuple("pktgen_enable", bool_val=False)])])
    iv = [round(b[0] - a_[0], 6) for a_, b in zip(seen[1:], seen[2:])]
    out.update(seen=seen, intervals_s=iv, ticks=out["epoch_after"][a.pipe] - out["epoch_before"][a.pipe],
               generated=(out["gen_after"] or 0) - (out["gen_before"] or 0),
               counted_by_tot=out["tot_after"] - out["tot_before"])
    if iv:
        s = sorted(iv)
        out["interval_s"] = {"min": s[0], "median": s[len(s) // 2], "max": s[-1], "n": len(s)}
    print("HZJSON " + json.dumps(out, sort_keys=True))
    json.dump(out, open(a.out, "w"), indent=2, sort_keys=True)


if __name__ == "__main__":
    main()
