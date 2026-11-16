"""Tests of perf/variants/exact's window features without a switch: exact_model.py (the program's registers and
per-packet logic) read as window_reader.py reads it and rebuilt by window_features.py must give, window by window,
the features of the dataset's model (features/switch_model.py, copied below for Python 3.8); so must
hybrid_collector.py's exact loop, with the markers from the CPU port or in band. Also the window markers' order
(live_test/replay_absolute.py), the reader's register layout and its lost / unclocked checks, and
replay_capture.py's exact self-check."""
import random
import socket
import struct
import sys
import tempfile
import time
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parents[2] / "live_test"))
from exact_model import ExactModel  # noqa: E402
from window_features import FEATURES, WindowFeatures  # noqa: E402
from window_reader import WINDOW_REGS  # noqa: E402
import replay_absolute  # noqa: E402
import replay_capture  # noqa: E402
import window_features  # noqa: E402
import window_reader  # noqa: E402
sys.path.insert(0, str(HERE.parents[2]))
import hybrid_collector as hc  # noqa: E402

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


class FakeClock:
    """time() / sleep() for the collector; sleeping feeds the model the packets sent until then."""

    def __init__(self, t0, feed):
        self.now, self.feed = t0, feed

    def time(self):
        return self.now

    def sleep(self, d):
        self.now += d
        self.feed(self.now)


class FakeWindowReader:
    """window_reader.py --serve on exact_model.py: mark sets the clock, read returns the window's line."""

    def __init__(self, model, inband_marks=None):
        self.model, self.requests = model, []

    def request(self, req, timeout=None):
        self.requests.append(req)
        if req["cmd"] == "mark":
            self.model.marker(req["epoch"])
            return {"marked": req["epoch"]}
        if req["cmd"] == "follow":
            return {"following_from": self.model.epoch}
        if req["cmd"] == "read":
            if self.model.epoch <= req["epoch"]:
                return {"epoch": req["epoch"], "error": "window %d did not end" % req["epoch"]}
            return self.model.read(req["epoch"])
        return {"error": "unexpected %r" % req}


class DoneProc:
    def poll(self):
        return 0


class CollectorExactTest(unittest.TestCase):
    def run_collector(self, markers):
        packets = make_traffic(3)
        ref = reference_windows([p[:9] for p in packets], 40)
        t0 = 1_792_932_220.0                           # make_traffic's windows start at t0 = 1792932220 s
        model = ExactModel(frame_min={HOST})
        pending = list(packets)
        if markers == "inband":
            model.marker(1)

        def feed(now):
            # the packets sent until `now` reach the switch; in band, each window's marker comes first
            while pending and pending[0][10] / 1e9 < now:
                p = pending.pop(0)
                if markers == "inband" and p[0] + 1 > model.epoch:
                    model.marker(p[0] + 1)
                model.packet(p[2], p[3], p[4], p[5], p[6], p[7], p[9], p[10])
            if markers == "inband":
                model.marker(max(model.epoch, int((now - t0 + 1e-9) // 0.5) + 1))

        reader = FakeWindowReader(model)
        clock = FakeClock(t0, feed)
        rows = []
        hc.collect_windows_exact(reader, DoneProc(), 0.5, t0, markers=markers,
                                 on_window=lambda w: rows.append(w["exact_features"]), max_windows=40, clock=clock)
        self.assertEqual(len(rows), 40)
        for w, (r, g) in enumerate(zip(ref, rows)):
            for f in FEATURES:
                tol = 2 * 65.536e-6 if f in DUR else 1e-9 * max(1.0, abs(r[f]))
                self.assertTrue(close(r[f], g[f], tol), (markers, w, f, r[f], g[f]))
            self.assertEqual(g["net_untracked_pkts"], 0)
        return reader

    def test_cpu_markers_give_the_models_windows(self):
        reader = self.run_collector("cpu")
        marks = [r["epoch"] for r in reader.requests if r["cmd"] == "mark"]
        self.assertEqual(marks, list(range(1, 42)))            # epoch 1 at the start, w + 2 after window w
        reads = [r["epoch"] for r in reader.requests if r["cmd"] == "read"]
        self.assertEqual(reads, list(range(1, 41)))

    def test_inband_markers_give_the_models_windows(self):
        reader = self.run_collector("inband")
        self.assertFalse([r for r in reader.requests if r["cmd"] == "mark"])
        self.assertEqual(reader.requests[0], {"cmd": "follow"})      # the reader reads each window as it ends

    def test_a_window_that_does_not_end_stops_the_run(self):
        model = ExactModel()
        reader = FakeWindowReader(model)
        with self.assertRaises(hc.P4ReadError):
            hc.collect_windows_exact(reader, DoneProc(), 0.5, 0.0, markers="inband", max_windows=3,
                                     clock=FakeClock(0.0, lambda now: None))

    def test_exact_summary_keeps_the_collector_columns(self):
        feats = dict.fromkeys(FEATURES, 1)
        feats.update(net_flow_duration_mean=0.25, net_flow_duration_max=0.5, net_untracked_pkts=3)
        out = hc.exact_summary(feats, duration_unit="ns")
        self.assertEqual(set(hc.NET_ZERO) | set(hc.EXACT_EXTRA_KEYS), set(out))
        self.assertEqual(out["net_flow_duration_max"], 0.5e9)
        self.assertEqual(out["net_untracked_pkts"], 3)
        self.assertEqual(out["net_new_conn_dst_max"], 0)


class FakeProgram:
    """window_reader.Program for two pipes: per-pipe registers; reg_epoch per pipe."""

    def __init__(self):
        self.epochs = [0, 0]
        self.cells = {}               # (name, idx) -> per-pipe values
        self.after_clear = None
        self.on_epochs = None         # called before each read of the clocks (a pipe that ticks a moment later)

    def pipe_epochs(self):
        if self.on_epochs:
            self.on_epochs()
        return list(self.epochs)

    def get(self, name, indexes, pair):
        zero = [0, 0] if pair else 0
        return {i: [list(v) if pair else v for v in self.cells.get((name, i), [zero, zero])] for i in indexes}

    def put_zero(self, name, indexes, pair):
        for i in indexes:
            self.cells.pop((name, i), None)
        if self.after_clear:
            self.after_clear()

    def rejected_markers(self):
        return 0


class WindowReaderChecksTest(unittest.TestCase):
    def test_packets_of_a_pipe_whose_clock_lags_are_reported_not_counted(self):
        prog = FakeProgram()
        r = window_reader.WindowReader(prog)
        prog.epochs = [0, 2]                                   # pipe 1 is clocked, pipe 0 is not
        prog.cells[("reg_w_tot", 7)] = [[5, 500], [9, 900]]    # bank 1, found 1, A->B: pipe 0 has 5, pipe 1 has 9
        first = r.read_window(1, prog.pipe_epochs())
        self.assertEqual(first["regs"]["reg_w_tot"]["7"], [9, 900])
        self.assertEqual(first["clocked_pipes"], [1])
        prog.cells[("reg_w_tot", 7)] = [[12, 1200], [9, 900]]  # pipe 0 counted 7 more
        prog.epochs = [0, 3]
        second = r.read_window(2, prog.pipe_epochs())
        self.assertEqual(second["unclocked_pkts"], 7)
        self.assertFalse(second["lost"])

    def test_a_clear_after_the_next_window_started_taints_that_window(self):
        prog = FakeProgram()
        r = window_reader.WindowReader(prog)
        prog.epochs = [0, 2]

        def late():
            prog.epochs = [0, 4]                               # window 3 (bank 1) started before the clear
        prog.after_clear = late
        first = r.read_window(1, prog.pipe_epochs())
        self.assertFalse(first["lost"])
        prog.after_clear = None
        self.assertTrue(r.read_window(2, prog.pipe_epochs())["lost"])   # read once window 4 has started
        prog.epochs = [0, 4]
        self.assertTrue(r.read_window(3, prog.pipe_epochs())["lost"])   # its extremes may have been cleared

    def test_a_change_of_the_clocked_pipes_loses_the_next_window_of_each_bank(self):
        # a window is the difference of two reads of its bank: both must combine the same pipes
        prog = FakeProgram()
        r = window_reader.WindowReader(prog)
        for e in (1, 2):
            prog.epochs = [0, e + 1]
            self.assertFalse(r.read_window(e, prog.pipe_epochs())["lost"])
        prog.epochs = [4, 4]                                   # pipe 0 is clocked from window 3 on
        self.assertTrue(r.read_window(3, prog.pipe_epochs())["lost"])    # bank 1 last read with pipe 1 alone
        prog.epochs = [5, 5]
        self.assertTrue(r.read_window(4, prog.pipe_epochs())["lost"])    # bank 0 likewise
        prog.epochs = [6, 6]
        self.assertFalse(r.read_window(5, prog.pipe_epochs())["lost"])   # bank 1 read with both pipes twice
        prog.epochs = [6, 7]                                   # pipe 0 falls behind again
        self.assertTrue(r.read_window(6, prog.pipe_epochs())["lost"])
        prog.epochs = [6, 8]
        self.assertTrue(r.read_window(7, prog.pipe_epochs())["lost"])
        prog.epochs = [6, 9]
        self.assertFalse(r.read_window(8, prog.pipe_epochs())["lost"])

    def test_a_pipe_that_ticks_a_moment_later_is_waited_for(self):
        # the timer build: each pipe's generator ticks its own clock, about 1 ms apart
        prog = FakeProgram()
        r = window_reader.WindowReader(prog, grace_s=0.5)
        calls = []

        def tick_later():
            calls.append(1)
            if len(calls) == 3:
                prog.epochs = [prog.epochs[1], prog.epochs[1]]
        for e in range(4):
            calls.clear()
            prog.epochs = [e, e + 1]                           # pipe 1 has ticked, pipe 0 not yet
            prog.on_epochs = tick_later
            line = r.read_window(e, r.settle(e, prog.pipe_epochs()))
            prog.on_epochs = None
            self.assertEqual(line["clocked_pipes"], [0, 1])
            self.assertFalse(line["lost"])

    def test_a_pipe_far_behind_is_not_waited_for(self):
        prog = FakeProgram()
        r = window_reader.WindowReader(prog, grace_s=5.0)
        prog.epochs = [0, 4]                                   # pipe 0 never clocked (markers into pipe 1)
        t0 = time.time()
        epochs = r.settle(3, prog.pipe_epochs())
        self.assertLess(time.time() - t0, 0.5)
        self.assertEqual(r.read_window(3, epochs)["clocked_pipes"], [1])

    def test_a_pipe_that_stays_at_the_window_is_given_up_on_after_the_grace(self):
        prog = FakeProgram()
        r = window_reader.WindowReader(prog, grace_s=0.05)
        prog.epochs = [3, 4]                                   # pipe 0's timer stopped at window 3
        t0 = time.time()
        epochs = r.settle(3, prog.pipe_epochs())
        self.assertGreaterEqual(time.time() - t0, 0.05)
        self.assertEqual(r.read_window(3, epochs)["clocked_pipes"], [1])

    def test_a_pipe_counts_as_unclocked_only_while_it_lags(self):
        prog = FakeProgram()
        r = window_reader.WindowReader(prog)
        prog.cells[("reg_w_tot", 3)] = [[5, 500], [0, 0]]
        prog.epochs = [0, 1]
        self.assertEqual(r.read_window(0, prog.pipe_epochs())["unclocked_pkts"], 0)   # the baseline
        prog.cells[("reg_w_tot", 3)] = [[8, 800], [0, 0]]
        prog.epochs = [0, 2]
        self.assertEqual(r.read_window(1, prog.pipe_epochs())["unclocked_pkts"], 3)
        prog.epochs = [3, 3]                                   # pipe 0 clocked: its packets count in windows
        prog.cells[("reg_w_tot", 3)] = [[20, 2000], [0, 0]]
        self.assertEqual(r.read_window(2, prog.pipe_epochs())["unclocked_pkts"], 0)
        prog.cells[("reg_w_tot", 3)] = [[30, 3000], [0, 0]]
        prog.epochs = [3, 4]                                   # behind again: a new baseline, not the old one
        self.assertEqual(r.read_window(3, prog.pipe_epochs())["unclocked_pkts"], 0)
        prog.cells[("reg_w_tot", 3)] = [[31, 3100], [0, 0]]
        prog.epochs = [3, 5]
        self.assertEqual(r.read_window(4, prog.pipe_epochs())["unclocked_pkts"], 1)

    def test_a_lost_window_marks_the_windows_rebuilt_from_it(self):
        lines = []
        prog = FakeProgram()
        r = window_reader.WindowReader(prog)
        for e in range(9):
            prog.epochs = [0, e + 1]
            line = r.read_window(e, prog.pipe_epochs())
            line["lost"] = e == 2
            lines.append(line)
        rows = window_features.window_rows(lines)
        self.assertEqual([rows[e]["net_window_lost"] for e in range(9)], [0, 0, 1, 1, 1, 1, 0, 0, 0])


class FollowerTest(unittest.TestCase):
    def test_the_follower_reads_each_window_as_its_clock_passes(self):
        prog = FakeProgram()
        reader = window_reader.WindowReader(prog)
        f = window_reader.Follower(prog, reader, poll_s=0.0005)
        prog.cells[("reg_w_tot", 3)] = [[0, 0], [4, 400]]      # window 0 (bank 0) in pipe 1
        prog.epochs = [0, 1]
        line = f.get(0, 2.0)
        self.assertEqual(line["epoch"], 0)
        self.assertEqual(line["regs"]["reg_w_tot"]["3"], [4, 400])
        self.assertIn("error", f.get(1, 0.05))                 # window 1 has not ended


class ReplayExactCheckTest(unittest.TestCase):
    def frame(self, dst, total, proto=6):
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0, 0, 64, proto, 0, socket.inet_aton("10.0.0.1"),
                         socket.inet_aton(dst))
        return b"\x02" * 12 + b"\x08\x00" + ip + b"\x00" * 20

    def test_windows_are_split_at_the_markers_and_compared_exactly(self):
        mk = lambda e: replay_absolute.marker_frame(b"\x02" * 6, e)
        tx = [(0, mk(1)), (0, self.frame(HOST, 40)), (0, self.frame("10.0.0.1", 100)), (0, mk(2)),
              (0, self.frame(HOST, 52)), (0, mk(3))]
        rows = {0: {"net_pkts_total_delta": "2", "net_bytes_total_delta": str(46 + 14 + 100 + 14)},
                1: {"net_pkts_total_delta": "1", "net_bytes_total_delta": str(52 + 14 + 1)}}
        got = replay_capture.exact_check(tx, rows, header_bytes=14, frame_min=["10.0.0.10/32"])
        self.assertEqual([w["check"] for w in got["per_window"]], ["exact", "differs"])
        self.assertEqual(got["per_window"][0]["sent_bytes"], 46 + 14 + 100 + 14)


if __name__ == "__main__":
    unittest.main()
