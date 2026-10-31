#!/usr/bin/env python2.7
"""Line-rate run with the Tofino packet generator (BF Runtime gRPC). Runs on the switch.

    python2.7 sw_pktgen_run.py OUT_JSON --prog basic --size 64 [--seconds 10] [--warmup 1]
                               [--flow-index N] [--sink-port 0] [--pipe 1]
    python2.7 sw_pktgen_run.py OUT_JSON --prog basic --cleanup

The generator of pipe PIPE sends, with --apps N timer apps in parallel (app ids
0, 2, ..., on pipe-local ports 68, 69, ..., dev_port 128*PIPE+68+i), one
UDP flow (10.99.7.1:7000 -> 10.99.7.2:7001) of SIZE-byte frames (FCS included)
back to back: timer app 0, periodic, 65,536 packets per trigger, no gaps. Its
6-byte header takes the place of the destination MAC, which the detector never
reads. The program under test is loaded unchanged; this tool only adds one
forwarding entry per generator port -> SINK_PORT. SINK_PORT
(default dev_port 0 = 16/0, pipe 0, no cable) is brought up at 100G in MAC
near-end loopback, so nothing leaves the switch: its TX counters give the rate,
and the looped-back copies enter pipe 0, find no forwarding entry and are dropped.

--rate-pct 0 (default) runs the generator at its own maximum, which exceeds one
100G port (150 Gbps at 1518 B): the sink transmits at line rate and the TM
drops the rest. --rate-pct P paces it to P% of the 100G line rate: each timer
tick (about 4 us) sends a burst of packets, split evenly over the apps, so the
total is P% of line rate. One app tops out at 135.5 Mpps (91% of line rate at
64 B); use --apps 2 for small frames.

Counted before and after each run: the generator's pkt_counter, the sink's MAC
counters, TM egress drops of the sink, and (detector only, --flow-index) the
flow's reg_pkts and reg_bytes in every pipe. Pipe PIPE must count exactly the
generated packets, pipe 0 the looped-back ones. The rate is taken between two
reads of the sink's TX counters while the generator runs (after --warmup).
Prints one "HZJSON {...}" line and writes it to OUT_JSON. --cleanup disables
the generator port and removes the forwarding entry and the sink port.

Uses the SDE 9.6 Python 2.7 client against 127.0.0.1:50052 and binds to the
program (a control-plane association; the device is not reconfigured).
"""
from __future__ import print_function

import argparse
import json
import socket
import struct
import sys
import time

sys.path.insert(0, "/root/bf-sde-9.6.0/install/lib/python2.7/site-packages/tofino")
sys.path.insert(0, "/root/bf-sde-9.6.0/install/lib/python2.7/site-packages")
import bfrt_grpc.client as gc  # noqa: E402

SRC_IP, DST_IP, SPORT, DPORT = "10.99.7.1", "10.99.7.2", 7000, 7001
SRC_MAC = b"\x02\x00\x00\x00\x07\x01"
PKTS_PER_TRIGGER = 65536
TIMER_NS = 1000
MASK32 = (1 << 32) - 1


def checksum(raw):
    if len(raw) % 2:
        raw += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(raw) // 2), raw))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def udp_frame(size):
    """The frame without its FCS (size - 4 bytes); the first 6 bytes are a placeholder."""
    ip_len = size - 4 - 14
    udp_len = ip_len - 20
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, ip_len, 0, 0, 64, 17, 0,
                     socket.inet_aton(SRC_IP), socket.inet_aton(DST_IP))
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    udp = struct.pack("!HHHH", SPORT, DPORT, udp_len, 0) + b"\x00" * (udp_len - 8)
    return b"\x00" * 6 + SRC_MAC + struct.pack("!H", 0x0800) + ip + udp


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("out")
    ap.add_argument("--prog", default="basic")
    ap.add_argument("--size", type=int, default=64)
    ap.add_argument("--seconds", type=float, default=10.0)
    ap.add_argument("--warmup", type=float, default=1.0)
    ap.add_argument("--pipe", type=int, default=1)
    ap.add_argument("--sink-port", type=int, default=0)
    ap.add_argument("--flow-index", type=int, default=-1)
    ap.add_argument("--rate-pct", type=float, default=0.0)
    ap.add_argument("--apps", type=int, default=1)
    ap.add_argument("--client-id", type=int, default=9)
    ap.add_argument("--cleanup", action="store_true")
    a = ap.parse_args()
    apps = [(2 * i, 68 + i, 128 * a.pipe + 68 + i) for i in range(a.apps)]   # (app_id, local port, dev_port)
    out = {"prog": a.prog, "size": a.size, "pipe": a.pipe, "apps": apps, "sink_port": a.sink_port,
           "flow": [SRC_IP, DST_IP, SPORT, DPORT, 17], "errors": [], "steps": []}

    c = gc.ClientInterface("127.0.0.1:50052", client_id=a.client_id, device_id=0, perform_subscribe=True)
    info = c.bfrt_info_get(a.prog)
    c.bind_pipeline_config(a.prog)
    t_all = gc.Target(device_id=0, pipe_id=0xffff)
    t_pipe = gc.Target(device_id=0, pipe_id=a.pipe)
    port_cfg = info.table_get("$PKTGEN_PORT_CFG")
    app_cfg = info.table_get("$PKTGEN_APPLICATION_CFG")
    pkt_buf = info.table_get("$PKTGEN_PKT_BUFFER")
    port_tbl = info.table_get("$PORT")
    port_stat = info.table_get("$PORT_STAT")
    fwd = info.table_get("pipe.Ingress.forwarding")
    tm_eg = info.table_get("tf1.tm.counter.eg_port")

    def step(name, fn):
        try:
            fn()
            out["steps"].append(name)
            return True
        except Exception as e:
            out["errors"].append("%s: %s" % (name, str(e)[:300]))
            return False

    def get_dict(tbl, target, key, from_hw=True):
        for data, _ in tbl.entry_get(target, [key], {"from_hw": from_hw}):
            return data.to_dict()
        return {}

    def get_if_present(tbl, target, key):
        try:
            return get_dict(tbl, target, key, from_hw=False)
        except gc.BfruntimeReadWriteRpcException:
            return {}

    k_gen = [port_cfg.make_key([gc.KeyTuple("dev_port", dp)]) for _, _, dp in apps]
    k_app = [app_cfg.make_key([gc.KeyTuple("app_id", aid)]) for aid, _, _ in apps]
    k_sink = port_tbl.make_key([gc.KeyTuple("$DEV_PORT", a.sink_port)])
    k_fwd = [fwd.make_key([gc.KeyTuple("ig_intr_md.ingress_port", dp)]) for _, _, dp in apps]

    def app_set(enable):
        for k in k_app:
            app_cfg.entry_mod(t_pipe, [k], [app_cfg.make_data(
                [gc.DataTuple("app_enable", bool_val=enable)], "$PKTGEN_TRIGGER_TIMER_PERIODIC")])

    if a.cleanup:
        step("app disable", lambda: app_set(False))
        for kg, kf in zip(k_gen, k_fwd):
            step("pktgen port disable", lambda: port_cfg.entry_mod(
                t_all, [kg], [port_cfg.make_data([gc.DataTuple("pktgen_enable", bool_val=False)])]))
            step("forwarding delete", lambda: fwd.entry_del(t_all, [kf]))
        step("sink port delete", lambda: port_tbl.entry_del(t_all, [k_sink]))
        print("HZJSON " + json.dumps(out, sort_keys=True))
        json.dump(out, open(a.out, "w"), indent=2, sort_keys=True)
        return

    # Sink port: 100G, MAC near-end loopback.
    if not get_if_present(port_tbl, t_all, k_sink):
        step("sink port add", lambda: port_tbl.entry_add(t_all, [k_sink], [port_tbl.make_data([
            gc.DataTuple("$SPEED", str_val="BF_SPEED_100G"), gc.DataTuple("$FEC", str_val="BF_FEC_TYP_RS"),
            gc.DataTuple("$AUTO_NEGOTIATION", str_val="PM_AN_FORCE_DISABLE"),
            gc.DataTuple("$LOOPBACK_MODE", str_val="BF_LPBK_MAC_NEAR"),
            gc.DataTuple("$PORT_ENABLE", bool_val=True)])]))
    t0 = time.time()
    while time.time() - t0 < 20:
        d = get_if_present(port_tbl, t_all, k_sink)
        if d.get("$PORT_UP"):
            break
        time.sleep(0.5)
    sink = get_if_present(port_tbl, t_all, k_sink)
    out["sink"] = dict((k, sink.get(k)) for k in ("$PORT_NAME", "$SPEED", "$FEC", "$LOOPBACK_MODE", "$PORT_UP"))
    if not sink.get("$PORT_UP"):
        out["errors"].append("sink port not up after %.0f s" % (time.time() - t0))

    # Forwarding entry: generator port -> sink.
    d_fwd = fwd.make_data([gc.DataTuple("port", a.sink_port)], "Ingress.send_using_port")
    for kf in k_fwd:
        if not step("forwarding add", lambda: fwd.entry_add(t_all, [kf], [d_fwd])):
            out["errors"].pop()
            step("forwarding mod", lambda: fwd.entry_mod(t_all, [kf], [d_fwd]))

    # Generator: port, packet buffer, timer app (disabled until the run starts).
    frame = udp_frame(a.size)
    line_pps = 100e9 / ((a.size + 20) * 8)
    if a.rate_pct > 0:
        rate = line_pps * a.rate_pct / 100.0 / a.apps
        n_pkts = max(1, int(round(rate * 4e-6)))
        timer_ns = int(round(n_pkts / rate * 1e9))
    else:
        n_pkts, timer_ns = PKTS_PER_TRIGGER, TIMER_NS
    out.update({"rate_pct_target": a.rate_pct, "packets_per_trigger": n_pkts, "timer_ns": timer_ns,
                "paced_rate_mpps": round(a.apps * n_pkts / (timer_ns * 1e-9) / 1e6, 4) if a.rate_pct > 0 else None})
    for kg in k_gen:
        step("pktgen port enable", lambda: port_cfg.entry_mod(
            t_all, [kg], [port_cfg.make_data([gc.DataTuple("pktgen_enable", bool_val=True)])]))
    k_buf = pkt_buf.make_key([gc.KeyTuple("pkt_buffer_offset", 0), gc.KeyTuple("pkt_buffer_size", len(frame) - 6)])
    d_buf = pkt_buf.make_data([gc.DataTuple("buffer", frame[6:])])
    if not step("pkt buffer add", lambda: pkt_buf.entry_add(t_pipe, [k_buf], [d_buf])):
        out["errors"].pop()
        step("pkt buffer mod", lambda: pkt_buf.entry_mod(t_pipe, [k_buf], [d_buf]))
    for (aid, local, dp), ka in zip(apps, k_app):
        d_app = app_cfg.make_data([
            gc.DataTuple("timer_nanosec", timer_ns), gc.DataTuple("app_enable", bool_val=False),
            gc.DataTuple("pkt_len", len(frame) - 6), gc.DataTuple("pkt_buffer_offset", 0),
            gc.DataTuple("pipe_local_source_port", local), gc.DataTuple("increment_source_port", bool_val=False),
            gc.DataTuple("batch_count_cfg", 0), gc.DataTuple("packets_per_batch_cfg", n_pkts - 1),
            gc.DataTuple("ibg", 0), gc.DataTuple("ibg_jitter", 0), gc.DataTuple("ipg", 0), gc.DataTuple("ipg_jitter", 0),
            gc.DataTuple("batch_counter", 0), gc.DataTuple("pkt_counter", 0), gc.DataTuple("trigger_counter", 0)],
            "$PKTGEN_TRIGGER_TIMER_PERIODIC")
        if not step("app %d add" % aid, lambda: app_cfg.entry_add(t_pipe, [ka], [d_app])):
            out["errors"].pop()
            step("app %d mod" % aid, lambda: app_cfg.entry_mod(t_pipe, [ka], [d_app]))

    def snapshot():
        s = {"t": time.time()}
        st = get_dict(port_stat, t_all, port_stat.make_key([gc.KeyTuple("$DEV_PORT", a.sink_port)]))
        for k in ("$FramesTransmittedOK", "$OctetsTransmittedwithouterror", "$FramesTransmittedwithError",
                  "$FramesReceivedOK", "$OctetsReceivedinGoodFrames", "$FrameswithanyError"):
            s[k] = st.get(k)
        # The counters are read with an action-specific data object, as in the SDE's tna_pktgen test.
        d_get = app_cfg.make_data([gc.DataTuple("pkt_counter"), gc.DataTuple("batch_counter"),
                                   gc.DataTuple("trigger_counter")], "$PKTGEN_TRIGGER_TIMER_PERIODIC", get=True)
        per_app = []
        for ka in k_app:
            ap_d = {}
            for data, _ in app_cfg.entry_get(t_pipe, [ka], {"from_hw": True}, d_get):
                ap_d = data.to_dict()
            per_app.append(dict((k, ap_d.get(k)) for k in ("pkt_counter", "batch_counter", "trigger_counter")))
        s["per_app"] = per_app
        for k in ("pkt_counter", "batch_counter", "trigger_counter"):
            vals = [x[k] for x in per_app]
            s[k] = sum(vals) if None not in vals else None
        try:
            tm = get_dict(tm_eg, t_all, tm_eg.make_key([gc.KeyTuple("dev_port", a.sink_port)]))
            s["tm_eg"] = dict((k, v) for k, v in tm.items() if isinstance(v, (int, long)))
        except Exception as e:
            s["tm_eg_error"] = str(e)[:200]
        if a.flow_index >= 0:
            for name in ("reg_pkts", "reg_bytes"):
                tbl = info.table_get("pipe.Ingress." + name)
                d = get_dict(tbl, t_all, tbl.make_key([gc.KeyTuple("$REGISTER_INDEX", a.flow_index)]))
                s[name] = [int(x) for x in d.get("Ingress.%s.f1" % name, [])]
        return s

    before = snapshot()
    step("app enable", lambda: app_set(True))
    t_on = time.time()
    time.sleep(a.warmup)
    s1 = snapshot()
    time.sleep(a.seconds)
    s2 = snapshot()
    step("app disable", lambda: app_set(False))
    t_off = time.time()
    time.sleep(1.0)
    after = snapshot()

    dt = s2["t"] - s1["t"]
    fr = (s2["$FramesTransmittedOK"] - s1["$FramesTransmittedOK"]) / dt
    by = (s2["$OctetsTransmittedwithouterror"] - s1["$OctetsTransmittedwithouterror"]) / dt
    delta = lambda k: (after[k] - before[k]) if None not in (after.get(k), before.get(k)) else None
    out.update({
        "frame_bytes": a.size, "buffer_bytes": len(frame) - 6,
        "on_s": round(t_off - t_on, 4), "measure_s": round(dt, 4),
        "gen_mpps": round((s2["pkt_counter"] - s1["pkt_counter"]) / dt / 1e6, 4),
        "tx_mpps": round(fr / 1e6, 4), "tx_gbps_l2": round(by * 8 / 1e9, 4),
        "tx_gbps_l1": round(fr * (a.size + 20) * 8 / 1e9, 4), "line_rate_mpps": round(line_pps / 1e6, 4),
        "pct_of_line_rate": round(100 * fr / line_pps, 3),
        "generated": delta("pkt_counter"), "sink_tx_frames": delta("$FramesTransmittedOK"),
        "sink_tx_octets": delta("$OctetsTransmittedwithouterror"), "sink_rx_frames": delta("$FramesReceivedOK"),
        "sink_tx_errors": delta("$FramesTransmittedwithError"), "sink_rx_errors": delta("$FrameswithanyError"),
        "triggers": delta("trigger_counter"), "batches": delta("batch_counter"),
        "before": before, "s1": s1, "s2": s2, "after": after,
    })
    if "tm_eg" in before and "tm_eg" in after:
        out["tm_eg_delta"] = dict((k, after["tm_eg"][k] - before["tm_eg"].get(k, 0)) for k in after["tm_eg"])
    if a.flow_index >= 0:
        out["reg_pkts_delta"] = [(x - y) & MASK32 for x, y in zip(after["reg_pkts"], before["reg_pkts"])]
        out["reg_bytes_delta"] = [(x - y) & MASK32 for x, y in zip(after["reg_bytes"], before["reg_bytes"])]
    print("HZJSON " + json.dumps(out, sort_keys=True))
    json.dump(out, open(a.out, "w"), indent=2, sort_keys=True)


if __name__ == "__main__":
    main()
