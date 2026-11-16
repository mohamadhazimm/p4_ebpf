"""Tests of perf/variants/exact's window features without a switch: exact_model.py (the program's registers and
per-packet logic) read as window_reader.py reads it and rebuilt by window_features.py must give, window by window,
the features of the dataset's model (features/switch_model.py, copied below for Python 3.8). Also the window
markers' order (live_test/replay_absolute.py) and the reader's register layout."""
import random
import socket
import struct
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parents[2] / "live_test"))
from exact_model import ExactModel  # noqa: E402
from window_features import FEATURES, WindowFeatures  # noqa: E402
from window_reader import WINDOW_REGS  # noqa: E402
import replay_absolute  # noqa: E402

WINDOW_NS = 500_000_000
TTL = 3
HOST = "10.0.0.10"
DUR = {"net_flow_duration_mean", "net_flow_duration_max"}


def reference_windows(packets, windows):
    """features/switch_model.py's FlowTable on (window, t_s, src, dst, proto, sport, dport, flags, frame_len)."""
    first_source, state, last_seen, out = {}, {}, {}, []
    by_window = {}
    for p in packets:
        by_window.setdefault(p[0], []).append(p)
    for w in range(windows):
        delta = {}
        for (_, ts, src, dst, proto, sp, dp, flags, length) in by_window.get(w, []):
            a, b = (src, sp), (dst, dp)
            key = (proto,) + tuple(sorted((a, b)))
            direction = "ab" if a == first_source.setdefault(key, a) else "ba"
            st = state.setdefault(key, dict(packets=0, bytes=0, ab_packets=0, ab_bytes=0, ba_packets=0, ba_bytes=0,
                                            syn=0, ack=0, rst=0, min_len=length, max_len=length, first=ts, last=ts))
            d = delta.setdefault(key, dict(packets=0, bytes=0, ab_packets=0, ab_bytes=0, ba_packets=0, ba_bytes=0,
                                           syn=0, ack=0, rst=0))
            for c in (st, d):
                c["packets"] += 1
                c["bytes"] += length
                c[direction + "_packets"] += 1
                c[direction + "_bytes"] += length
                c["syn"] += int(bool(flags & 2))
                c["ack"] += int(bool(flags & 16))
                c["rst"] += int(bool(flags & 4))
            st["min_len"], st["max_len"] = min(st["min_len"], length), max(st["max_len"], length)
            st["first"], st["last"] = min(st["first"], ts), max(st["last"], ts)
            last_seen[key] = w
        active = [k for k, s in last_seen.items() if 0 <= w - s <= TTL]
        f = dict.fromkeys(FEATURES, 0)
        mins, maxs, durs = [], [], []
        for k in active:
            for name, c in (("net_pkts_total_delta", "packets"), ("net_bytes_total_delta", "bytes"),
                            ("net_pkts_ab_delta", "ab_packets"), ("net_bytes_ab_delta", "ab_bytes"),
                            ("net_pkts_ba_delta", "ba_packets"), ("net_bytes_ba_delta", "ba_bytes"),
                            ("net_syn_delta", "syn"), ("net_ack_delta", "ack"), ("net_rst_delta", "rst")):
                f[name] += delta.get(k, {}).get(c, 0)
            mins.append(state[k]["min_len"])
            maxs.append(state[k]["max_len"])
            durs.append(max(state[k]["last"] - state[k]["first"], 0.0))
            f["net_flows_with_ab"] += int(state[k]["ab_packets"] > 0)
            f["net_flows_with_ba"] += int(state[k]["ba_packets"] > 0)
            f["net_dir_valid_count"] += 1
        n = len(active)
        P, S = f["net_pkts_total_delta"], f["net_bytes_total_delta"]
        f.update(net_flow_count_seen=n, net_min_len_mean=sum(mins) / n if n else 0.0,
                 net_max_len_mean=sum(maxs) / n if n else 0.0, net_min_len_min=min(mins, default=0),
                 net_max_len_max=max(maxs, default=0), net_flow_duration_mean=sum(durs) / n if n else 0.0,
                 net_flow_duration_max=max(durs, default=0.0))
        f["net_avg_pkt_size_delta"] = S / P if P else 0.0
        f["net_avg_pkt_size_ab_delta"] = f["net_bytes_ab_delta"] / f["net_pkts_ab_delta"] if f["net_pkts_ab_delta"] else 0.0
        f["net_avg_pkt_size_ba_delta"] = f["net_bytes_ba_delta"] / f["net_pkts_ba_delta"] if f["net_pkts_ba_delta"] else 0.0
        f["net_bytes_per_sec_delta"], f["net_pkts_per_sec_delta"] = S / 0.5, P / 0.5
        f["net_down_up_ratio_delta"] = f["net_bytes_ba_delta"] / f["net_bytes_ab_delta"] if f["net_bytes_ab_delta"] else 0.0
        f["net_ab_ratio_pkt_delta"] = f["net_pkts_ab_delta"] / P if P else 0.0
        f["net_ba_ratio_pkt_delta"] = f["net_pkts_ba_delta"] / P if P else 0.0
        f["net_ab_ratio_byte_delta"] = f["net_bytes_ab_delta"] / S if S else 0.0
        f["net_ba_ratio_byte_delta"] = f["net_bytes_ba_delta"] / S if S else 0.0
        out.append(f)
    return out


def switch_windows(packets, windows, **kw):
    """The model of the program fed the same packets, window markers between the windows."""
    m = ExactModel(frame_min={HOST}, **kw)
    wf = WindowFeatures()
    out, cur = [], 0
    m.marker(1)
    by_window = {}
    for p in packets:
        by_window.setdefault(p[0], []).append(p)
    for w in range(windows):
        for (_, ts, src, dst, proto, sp, dp, flags, length, total, t_ns) in by_window.get(w, []):
            m.packet(src, dst, proto, sp, dp, flags, total, t_ns)
        m.marker(w + 2)
        out.append(wf.add(m.read(w + 1)))
    return out, m


def make_traffic(seed, n_flows=60, windows=40):
    """Random flows: the guest (HOST) and peers, both directions, small packets toward the guest (padded in
    its capture), port pairings swapped between the same two addresses, flows with equal ports, a flow to
    itself, idle gaps longer than the TTL (returning flows), and TCP flags."""
    rnd = random.Random(seed)
    peers = ["10.0.0.1", "10.0.1.%d" % rnd.randint(2, 250), "192.168.5.7"]
    flows = []
    for i in range(n_flows):
        peer = rnd.choice(peers)
        proto = rnd.choice((6, 17))
        sp, dp = rnd.randint(1024, 65535), rnd.choice((80, 53, 443, 23, 123))
        if i % 15 == 3:
            sp = dp                                  # equal ports (e.g. NTP 123 <-> 123)
        flows.append((HOST, peer, proto, sp, dp))
        if i % 10 == 5:
            flows.append((HOST, peer, proto, dp, sp))   # the same addresses with the ports paired the other way
    flows.append((HOST, HOST, 17, 5000, 5000))           # to itself
    packets = []
    t0 = 1_792_932_220_000_000_000
    for f in flows:
        start = rnd.randint(0, windows * WINDOW_NS - 1)
        burst_windows = rnd.choice((1, 2, 6, 15))
        t = start
        first_from_host = rnd.random() < 0.7
        for k in range(rnd.randint(1, 30)):
            t += rnd.randint(1, burst_windows * WINDOW_NS // 6)
            if rnd.random() < 0.1:
                t += rnd.randint(4, 8) * WINDOW_NS       # idle longer than the TTL: the flow returns
            if t >= windows * WINDOW_NS:
                break
            forward = first_from_host if k == 0 else rnd.random() < 0.55
            src, dst, proto, sp, dp = f if forward else (f[1], f[0], f[2], f[4], f[3])
            hdr = 20 + (20 if proto == 6 else 8)
            total = hdr + rnd.choice((0, 0, 6, 12, 100, 512, 1400))
            flags = rnd.choice((0x002, 0x012, 0x010, 0x018, 0x004, 0x011)) if proto == 6 else 0
            frame = total + 14
            if dst == HOST:
                frame = max(frame, 60)                   # the guest's capture sees received frames padded
            t_ns = t0 + t
            packets.append((t // WINDOW_NS, t_ns / 1e9, src, dst, proto, sp, dp, flags, frame, total, t_ns))
    packets.sort(key=lambda p: p[10])
    return packets


def close(a, b, tol):
    return abs(float(a) - float(b)) <= tol


class ExactWindowsTest(unittest.TestCase):
    def check(self, seed, **kw):
        packets = make_traffic(seed, **kw)
        ref = reference_windows([p[:9] for p in packets], 40)
        got, model = switch_windows(packets, 40)
        self.assertEqual(model.untracked_flows, set())
        for w, (r, g) in enumerate(zip(ref, got)):
            for f in FEATURES:
                if f in DUR:
                    # the switch's times are in units of 65.536 us: a flow's duration is off by less than one
                    self.assertTrue(close(r[f], g[f], 2 * 65.536e-6), (seed, w, f, r[f], g[f]))
                else:
                    self.assertTrue(close(r[f], g[f], 1e-9 * max(1.0, abs(r[f]))), (seed, w, f, r[f], g[f]))
            self.assertEqual(g["net_untracked_pkts"], 0)

    def test_window_features_equal_the_models(self):
        for seed in range(12):
            self.check(seed)

    def test_many_flows(self):
        self.check(99, n_flows=600)

    def test_swapped_port_pairings_are_two_flows(self):
        t0 = 1_792_932_220_000_000_000
        pk = [(0, (t0 + i * 1000) / 1e9, HOST, "10.0.0.1", 6, sp, dp, 0x002, 60, 46, t0 + i * 1000)
              for i, (sp, dp) in enumerate(((1000, 80), (80, 1000)))]
        got, _ = switch_windows(pk, 2)
        self.assertEqual(got[0]["net_flow_count_seen"], 2)
        self.assertEqual(got[0]["net_flows_with_ba"], 0)
        self.assertEqual(got[0]["net_pkts_ab_delta"], 2)

    def test_a_full_table_is_reported_and_the_totals_stay_exact(self):
        packets = make_traffic(7, n_flows=80)
        ref = reference_windows([p[:9] for p in packets], 40)
        got, model = switch_windows(packets, 40, ways=1, way_bits=3)    # 8 slots
        self.assertTrue(model.untracked_flows)
        self.assertGreater(sum(g["net_untracked_pkts"] for g in got), 0)
        for r, g in zip(ref, got):
            for f in ("net_pkts_total_delta", "net_bytes_total_delta", "net_syn_delta", "net_ack_delta",
                      "net_rst_delta"):
                self.assertEqual(r[f], g[f])

    def test_reads_must_come_in_order(self):
        m = ExactModel()
        wf = WindowFeatures()
        m.marker(1)
        m.marker(2)
        m.marker(3)
        wf.add(m.read(1))
        with self.assertRaises(ValueError):
            wf.add(m.read(1))


class ReaderLayoutTest(unittest.TestCase):
    def test_the_two_banks_hold_disjoint_indexes_within_the_registers(self):
        sizes = {"reg_w_tot": 8, "reg_w_flags": 2, "reg_w_rst": 2, "reg_w_cnt": 64, "reg_w_chg_len": 2,
                 "reg_w_chg_dur": 2, "reg_w_carry_len": 8, "reg_w_carry_dur": 8, "reg_w_pa": 2, "reg_w_pb": 2,
                 "reg_w_pd": 2}
        for name, pair, how, idx in WINDOW_REGS:
            a, b = set(idx(0)), set(idx(1))
            self.assertFalse(a & b, name)
            self.assertEqual(a | b, set(range(sizes[name])), name)


class MarkerOrderTest(unittest.TestCase):
    def test_a_frame_at_a_boundary_follows_its_marker(self):
        anchor = 1_792_932_220_000_000
        times = [anchor + 10, anchor + 499_999, anchor + 500_000, anchor + 1_000_001]
        with tempfile.NamedTemporaryFile(suffix=".pcap") as f:
            f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
            for i, t in enumerate(times):
                frame = bytes([i]) * 60
                f.write(struct.pack("<IIII", t // 1_000_000, t % 1_000_000, len(frame), len(frame)) + frame)
            f.flush()
            ev = replay_absolute.with_markers(f.name, b"\x02" * 6, anchor, 500_000, 3, 1)
        kinds = [("M%d" % struct.unpack("!I", fr[16:20])[0]) if m else "F%d" % fr[0] for _, fr, m in ev]
        self.assertEqual(kinds, ["M1", "F0", "F1", "M2", "F2", "M3", "F3", "M4"])
        self.assertEqual(struct.unpack("!H", ev[0][1][12:14])[0], 0x88B5)
        self.assertEqual(len(ev[0][1]), 60)


if __name__ == "__main__":
    unittest.main()
