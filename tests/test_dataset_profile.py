"""Tests of the dataset profile of hybrid_collector.py (RUNBOOK 19.9): frame bytes, durations in seconds with the
32-bit wrap resolved, dormant reads instead of clears, a fixed number of windows with the scenario stopped after the
last read, the dataset's launcher, and the timing log's extra fields. No switch, no BPF, no root."""
import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "switch" / "control"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "collector"))
import hybrid_collector as hc  # noqa: E402

WRAP = 1 << 32


def mkrow(idx, pkts, nbytes=None, pkts_ab=None, bytes_ab=None, min_len=40, max_len=300, first_ts=1, last_ts=2):
    nbytes = 100 * pkts if nbytes is None else nbytes
    pkts_ab = pkts if pkts_ab is None else pkts_ab
    bytes_ab = nbytes if bytes_ab is None else bytes_ab
    return {"idx": idx, "pkts": pkts, "bytes": nbytes, "pkts_ab": pkts_ab, "bytes_ab": bytes_ab, "min_len": min_len,
            "max_len": max_len, "first_ts": first_ts, "last_ts": last_ts, "syn": 0, "ack": 0, "rst": 0, "dir_valid": 1}


class FakeClock:
    def __init__(self, t=1000.0):
        self.t = t

    def time(self):
        return self.t

    def sleep(self, seconds):
        self.t += max(0.0, seconds)

    def advance(self, seconds):
        self.t += seconds


class FakeCollector:
    def __init__(self, reports_by_window, t0, window_sec, proto=17):
        self.reports, self.t0, self.window_sec, self.proto = reports_by_window, t0, window_sec, proto

    def take(self, start, end):
        w = round((start - self.t0) / self.window_sec)
        return [{"idx": i, "idx_source": "report", "idx_computed": i, "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
                 "sport": 1000 + i, "dport": 80, "proto": self.proto} for i in self.reports.get(w, [])]


class NeverEndingProc:
    def poll(self):
        return None


class Reader:
    """Register reader: pkts_fn(window, idx) gives a bucket's packet count; fixed sync 10 ms and 5 ms per bucket,
    taken from the clock when given. Every clear requested succeeds."""

    SYNC_MS, READ_MS, PROBE_MS = 10.0, 5.0, 0.5

    def __init__(self, pkts_fn, clock=None, read_ms=None, has_dst=True):
        self.pkts_fn, self.clock, self.calls, self.has_dst = pkts_fn, clock, [], has_dst
        if read_ms is not None:
            self.READ_MS = read_ms

    def __call__(self, indexes, w, snapshot="sync", clear_if_unchanged=None, dst_indexes=None, clear_indexes=None,
                 probe=None, probe_max_full=None):
        self.calls.append({"w": w, "indexes": list(indexes), "clear": dict(clear_if_unchanged or {}),
                           "clear_indexes": list(clear_indexes or []), "probe": dict(probe or {}),
                           "probe_max_full": probe_max_full, "dst": list(dst_indexes or [])})
        # batched_reader.read_window's probe: the buckets whose count differs are read in full as well, at most
        # probe_max_full of them; the others are deferred
        changed = sorted(i for i, last in (probe or {}).items() if self.pkts_fn(w, i) != last and i not in indexes)
        n = len(changed) if probe_max_full is None else probe_max_full
        resumed, deferred = changed[:n], changed[n:]
        read = sorted(set(indexes) | set(resumed))
        read_ms, probe_ms = self.READ_MS * len(read), self.PROBE_MS * len(probe or {})
        if self.clock is not None:
            self.clock.advance((self.SYNC_MS + read_ms + probe_ms) / 1000.0)
        cleared = sorted(set(clear_if_unchanged or {}) | set(clear_indexes or []))
        errors, dst_rows = [], []
        if dst_indexes:
            if self.has_dst:
                dst_rows = [{"idx": i, "new_conn": 1, "pipes": [0]} for i in dst_indexes]
            else:   # the deployed basic_fix: batched_reader's error, no rows, no time
                errors.append("Register is missing from pipeline: reg_newconn_dst")
        payload = {"rows": [mkrow(i, self.pkts_fn(w, i)) for i in read], "dst_rows": dst_rows, "cleared": cleared,
                   "snapshot": snapshot, "errors": errors,
                   "timing": {"sync_ms": self.SYNC_MS, "read_ms": read_ms, "clear_ms": 0.0, "probe_ms": probe_ms}}
        if probe:
            payload["resumed"], payload["deferred"] = resumed, deferred
        return payload


def run_live(reports, reader, n_windows, window_sec=0.5, clock=None, **kw):
    clock = clock if clock is not None else FakeClock()
    reader.clock = reader.clock if reader.clock is not None else None
    t0 = clock.time()
    stops = []
    windows = hc.collect_windows_live(FakeCollector(reports, t0, window_sec), NeverEndingProc(), window_sec, 0.0, t0,
                                      "reader.py", active_ttl_windows=3, clear_idle_windows=0, read_fn=reader,
                                      clock=clock, max_windows=n_windows,
                                      stop_fn=lambda: stops.append(len(reader.calls)), **kw)
    return windows, stops


class ProfileTests(unittest.TestCase):
    BASE = ["--mode", "command", "--scenario-name", "s", "--label", "benign", "--command", "true"]

    def test_the_dataset_profile_bundle(self):
        args = hc.build_arg_parser("dataset").parse_args(self.BASE + ["--profile", "dataset"])
        self.assertEqual((args.window_sec, args.windows, args.active_ttl_windows, args.clear_idle_windows),
                         (0.5, 40, 3, 0))
        self.assertEqual((args.reader, args.reader_raw_wire, args.reader_sync_batched, args.read_budget_frac),
                         ("batched", True, True, 0.7))
        self.assertEqual((args.clear_expired, args.dormant_reads, args.dormant_probe), (0, 1, 1))
        self.assertEqual((args.byte_layer, args.duration_unit, args.launcher), ("frame", "s", "dataset"))

    def test_the_new_options_default_to_the_old_behaviour(self):
        plain = hc.build_arg_parser().parse_args(self.BASE)
        self.assertEqual((plain.dormant_reads, plain.dormant_probe, plain.byte_layer, plain.duration_unit, plain.windows,
                          plain.launcher), (0, 0, "ipv4", "ns", 0, "shell"))


class FrameBytesTests(unittest.TestCase):
    def test_frame_bytes_add_14_per_packet_to_bytes_and_lengths(self):
        rows = [mkrow(1, 10, nbytes=1000, pkts_ab=6, bytes_ab=600, min_len=40, max_len=300)]
        frame = hc.build_net_summaries([{"rows": rows}], 0.5, byte_layer="frame")[0]
        self.assertEqual((frame["net_bytes_total_delta"], frame["net_bytes_ab_delta"], frame["net_bytes_ba_delta"]),
                         (1140, 684, 456))
        self.assertEqual((frame["net_min_len_mean"], frame["net_max_len_mean"], frame["net_min_len_min"],
                          frame["net_max_len_max"]), (54.0, 314.0, 54, 314))
        self.assertAlmostEqual(frame["net_avg_pkt_size_delta"], 114.0)
        self.assertAlmostEqual(frame["net_avg_pkt_size_ba_delta"], 114.0)
        self.assertAlmostEqual(frame["net_bytes_per_sec_delta"], 1140 / 0.5)
        self.assertAlmostEqual(frame["net_ab_ratio_byte_delta"], 684 / 1140)
        self.assertAlmostEqual(frame["net_down_up_ratio_delta"], 456 / 684)
        ipv4 = hc.build_net_summaries([{"rows": rows}], 0.5)[0]
        self.assertEqual((ipv4["net_bytes_total_delta"], ipv4["net_min_len_min"]), (1000, 40))

    def test_the_header_is_added_to_the_window_delta_only(self):
        windows = [{"rows": [mkrow(1, 10, nbytes=1000)]}, {"rows": [mkrow(1, 15, nbytes=1500)]}]
        s = hc.build_net_summaries(windows, 0.5, byte_layer="frame")
        self.assertEqual([w["net_bytes_total_delta"] for w in s], [1140, 570])

    def test_an_empty_bucket_keeps_zero_lengths(self):
        rows = [mkrow(1, 0, nbytes=0, min_len=0, max_len=0)]
        s = hc.build_net_summaries([{"rows": rows}], 0.5, byte_layer="frame")[0]
        self.assertEqual((s["net_min_len_min"], s["net_max_len_max"], s["net_bytes_total_delta"]), (0, 0, 0))


class DurationTests(unittest.TestCase):
    def windows_for(self, true_ns_by_window, first_ts=123456789, read_every_window=True):
        """One bucket, first seen in window 2; true_ns_by_window[w] is its duration when read in window w."""
        windows = []
        pkts = 0
        for w in range(max(true_ns_by_window) + 1):
            if w in true_ns_by_window:
                pkts += 1
                last = (first_ts + true_ns_by_window[w]) % WRAP
                windows.append({"rows": [mkrow(7, pkts, first_ts=first_ts, last_ts=last)]})
            elif read_every_window and w >= 2:
                last = (first_ts + true_ns_by_window[max(k for k in true_ns_by_window if k < w)]) % WRAP
                windows.append({"rows": [mkrow(7, pkts, first_ts=first_ts, last_ts=last)]})
            else:
                windows.append({"rows": []})
        return windows

    def test_seconds_resolve_the_wrap_when_the_bucket_is_read_every_window(self):
        # a flow that lasts 4.6 s: the register difference wraps to 0.305 s
        truth = {2: int(0.1e9)}
        for w in range(3, 12):
            truth[w] = int(0.1e9 + (w - 2) * 0.5e9)
        s = hc.build_net_summaries(self.windows_for(truth), 0.5, duration_unit="s")
        self.assertAlmostEqual(s[11]["net_flow_duration_max"], 4.6, places=6)
        self.assertAlmostEqual(s[5]["net_flow_duration_max"], 1.6, places=6)
        ns = hc.build_net_summaries(self.windows_for(truth), 0.5)
        self.assertAlmostEqual(ns[11]["net_flow_duration_max"], (4.6e9) % WRAP, places=0)

    def test_seconds_after_a_gap_in_the_reads(self):
        # first seen in window 2, not read in windows 3-8, read again with a change in window 9: 3.0 s
        truth = {2: 0, 9: int(3.0e9)}
        s = hc.build_net_summaries(self.windows_for(truth, read_every_window=False), 0.5, duration_unit="s")
        self.assertAlmostEqual(s[9]["net_flow_duration_max"], 3.0, places=6)

    def test_a_single_window_keeps_the_modular_value(self):
        s = hc.build_net_summaries([{"rows": [mkrow(1, 2, first_ts=WRAP - 10, last_ts=90)]}], 10.0, duration_unit="s")
        self.assertAlmostEqual(s[0]["net_flow_duration_max"], 100e-9)

    def test_a_cleared_bucket_restarts_its_timeline(self):
        windows = [{"rows": [mkrow(1, 2, first_ts=10, last_ts=int(2.0e9) + 10)], "cleared_indexes": [1]},
                   {"rows": [mkrow(1, 1, first_ts=50, last_ts=60)]}]
        s = hc.build_net_summaries(windows, 0.5, duration_unit="s")
        self.assertAlmostEqual(s[1]["net_flow_duration_max"], 10e-9)
        self.assertEqual(s[1]["net_pkts_total_delta"], 1)


class ActiveFilterTests(unittest.TestCase):
    def test_dormant_rows_only_update_the_bookkeeping(self):
        w0 = {"rows": [mkrow(1, 10), mkrow(2, 5)], "active_after_read_indexes": [1, 2]}
        w1 = {"rows": [mkrow(1, 12), mkrow(2, 5)], "active_after_read_indexes": [1]}      # 2 is dormant, unchanged
        w2 = {"rows": [mkrow(1, 12), mkrow(2, 9)], "active_after_read_indexes": [1, 2]}   # 2 resumed
        s = hc.build_net_summaries([w0, w1, w2], 0.5)
        self.assertEqual([w["net_flow_count_seen"] for w in s], [2, 1, 2])
        self.assertEqual([w["net_pkts_total_delta"] for w in s], [15, 2, 4])
        self.assertEqual(s[2]["net_bytes_total_delta"], 400, "the resumed flow's delta counts from its old registers")

    def test_a_torn_dormant_read_keeps_its_bytes_for_the_window_that_counts_its_packets(self):
        # PC1.md part 4 (bulk1600, bulk2000: 320 B short): a dormant bucket's reused 5-tuple sends five
        # packets (320 B) between the reg_pkts sync and the reg_bytes sync of window 1. Window 1 reads
        # pkts unchanged (the bucket stays dormant) but bytes +320; window 2 reads pkts +5, bytes +0.
        w0 = {"rows": [mkrow(2, 5, nbytes=500)], "active_after_read_indexes": [2]}
        w1 = {"rows": [mkrow(2, 5, nbytes=820, bytes_ab=820)], "active_after_read_indexes": []}
        w2 = {"rows": [mkrow(2, 10, nbytes=820, pkts_ab=10, bytes_ab=820)], "active_after_read_indexes": [2]}
        for layer, header in (("ipv4", 0), ("frame", 14)):
            s = hc.build_net_summaries([w0, w1, w2], 0.5, byte_layer=layer)
            self.assertEqual([w["net_pkts_total_delta"] for w in s], [5, 0, 5], layer)
            self.assertEqual(s[2]["net_bytes_total_delta"], 320 + 5 * header, layer)
            self.assertEqual(s[2]["net_bytes_ab_delta"], 320 + 5 * header, layer)
            self.assertEqual(sum(w["net_bytes_total_delta"] for w in s), 820 + 10 * header, layer)

    def test_without_the_key_every_row_read_counts(self):
        s = hc.build_net_summaries([{"rows": [mkrow(1, 10), mkrow(2, 5)]}], 0.5)
        self.assertEqual(s[0]["net_flow_count_seen"], 2)


class DormantReadTests(unittest.TestCase):
    def test_expired_buckets_are_re_read_and_a_resumed_flow_is_active_again(self):
        def pkts(w, idx):
            if idx == 1:
                return 10 if w == 0 else (20 if w < 7 else 30)
            return 5

        reader = Reader(pkts)
        windows, stops = run_live({0: [1, 2]}, reader, 9, dormant_reads=True)
        self.assertEqual(len(windows), 9)
        # idx 2 last changed in window 0 and expires at window 4; idx 1 changed in window 1 and expires at window 5
        self.assertEqual([w["dormant_read_indexes"] for w in windows[:8]], [[], [], [], [], [2], [1, 2], [1, 2], [1, 2]])
        self.assertEqual([w["active_indexes"] for w in windows[4:8]], [[1], [], [], []])
        self.assertEqual(windows[7]["active_after_read_indexes"], [1], "the change in window 7 makes idx 1 active")
        self.assertEqual(windows[7]["dormant_count"], 1)
        self.assertEqual(windows[8]["active_indexes"], [1])
        self.assertTrue(all(not c["clear_indexes"] and not c["clear"] for c in reader.calls[:9]),
                        "nothing is cleared during the run")
        self.assertEqual(reader.calls[-1]["clear_indexes"], [1, 2], "everything tracked is cleared at the end")
        self.assertEqual(windows[-1]["final_cleared_indexes"], [1, 2])
        self.assertTrue(all(w["overload"] is False for w in windows))
        summaries = hc.build_net_summaries(windows, 0.5)
        self.assertEqual([s["net_flow_count_seen"] for s in summaries], [2, 2, 2, 2, 1, 0, 0, 1, 1])
        self.assertEqual(summaries[7]["net_pkts_total_delta"], 10, "30 - 20: the registers were never reset")

    def test_the_scenario_is_stopped_after_the_last_read(self):
        reader = Reader(lambda w, idx: 10 * (w + 1))
        windows, stops = run_live({0: [1]}, reader, 5, dormant_reads=True)
        self.assertEqual(len(windows), 5)
        self.assertEqual(stops, [5], "stop_fn ran once, after the fifth read and before the end-of-run clear")
        self.assertEqual(len(reader.calls), 6)

    def test_dormant_reads_use_the_allowance_left_after_the_active_set_round_robin(self):
        # Exact, non-learning costs: 5 ms per read plus 5 ms per bucket, so the 70 ms allowance (70% of a
        # 100 ms window; 69.999 ms in floating point) fits 12 buckets. 12 buckets report in window 0; 4 keep
        # changing and 8 go quiet (dormant from window 4), when 4 new buckets report: 8 active, 4 dormant
        # reads per window.
        clock = FakeClock()
        reader = Reader(lambda w, idx: 10 * (w + 1) if idx < 4 or idx >= 20 else 7, clock=clock)
        cost = hc.ReadCostModel(fixed_ms=5.0, read_ms_per_bucket=5.0, clear_ms_per_bucket=1.0, alpha=0.0)
        windows, _ = run_live({0: list(range(12)), 4: [20, 21, 22, 23]}, reader, 8, window_sec=0.1, clock=clock,
                              dormant_reads=True, read_budget_frac=0.7, cost_model=cost)
        self.assertEqual([w["active_indexes"] for w in windows[4:7]], [[0, 1, 2, 3, 20, 21, 22, 23]] * 3)
        self.assertEqual([w["dormant_count"] for w in windows[4:7]], [8, 8, 8])
        self.assertEqual([w["dormant_read_indexes"] for w in windows[4:7]],
                         [[4, 5, 6, 7], [8, 9, 10, 11], [4, 5, 6, 7]], "round robin over the dormant buckets")
        self.assertEqual([len(c["indexes"]) for c in reader.calls[4:7]], [12, 12, 12])
        self.assertTrue(all(w["overload"] is False and w["p4_read_overrun"] is False for w in windows))
        self.assertEqual([w["dormant_read_indexes"] for w in windows[:4]], [[]] * 4)

    def resume_scenario(self, dormant_probe):
        # PC1.md part 4b. 30 buckets (100-129) report in window 0 and go quiet: dormant from window 4, when 8
        # new ones (20-27) report and keep changing. Exact costs: 5 ms per read, 2 ms per bucket, probes 0.3 ms
        # (DST_WEIGHT of a bucket), a 70 ms allowance: 32 bucket reads fit, so round robin reads 24 of the 30
        # dormant buckets per window; the probes (all 30) fit next to the 8 active and the 8-read reserve.
        # Bucket 120 resumes in window 5, where round robin does not reach it (it reads 124-129 and 100-117).
        def pkts(w, idx):
            if idx >= 100:
                return 9 if (idx == 120 and w >= 5) else 7
            return 10 * (w + 1)

        clock = FakeClock()
        reader = Reader(pkts, clock=clock, read_ms=2.0)
        cost = hc.ReadCostModel(fixed_ms=5.0, read_ms_per_bucket=2.0, clear_ms_per_bucket=1.0, alpha=0.0)
        windows, _ = run_live({0: list(range(100, 130)), 4: list(range(20, 28))}, reader, 8, window_sec=0.1,
                              clock=clock, dormant_reads=True, dormant_probe=dormant_probe, read_budget_frac=0.7,
                              cost_model=cost)
        return windows, reader, hc.build_net_summaries(windows, 0.1)

    def test_round_robin_counts_a_resumed_dormant_flow_late(self):
        windows, reader, s = self.resume_scenario(False)
        self.assertEqual([len(w["dormant_read_indexes"]) for w in windows[4:7]], [24, 24, 24])
        self.assertNotIn(120, windows[5]["dormant_read_indexes"])
        self.assertEqual([s[k]["net_pkts_total_delta"] for k in (5, 6)], [80, 82], "120's 2 packets come a window late")
        self.assertTrue(all(not c["probe"] for c in reader.calls))

    def test_the_dormant_probe_counts_it_in_its_own_window(self):
        windows, reader, s = self.resume_scenario(True)
        self.assertEqual([sorted(c["probe"]) for c in reader.calls[4:6]], [list(range(100, 130))] * 2,
                         "every dormant bucket is probed every window")
        self.assertEqual(sorted(reader.calls[6]["probe"]), [i for i in range(100, 130) if i != 120])
        self.assertEqual([c["probe"][100] for c in reader.calls[4:7]], [7, 7, 7], "with the count last read")
        self.assertEqual(windows[5]["dormant_resumed_indexes"], [120])
        self.assertIn(120, windows[5]["active_after_read_indexes"])
        self.assertNotIn(120, reader.calls[6]["probe"], "active again, so read, not probed")
        self.assertIn(120, reader.calls[6]["indexes"])
        self.assertEqual([s[k]["net_pkts_total_delta"] for k in (5, 6)], [82, 80])
        self.assertEqual([w["dormant_read_indexes"] for w in windows], [[]] * 8, "no round-robin full reads")
        self.assertEqual([w["dormant_probed_count"] for w in windows[4:7]], [30, 30, 29])
        self.assertTrue(all(w["overload"] is False and w["p4_read_overrun"] is False for w in windows))

    def test_the_probes_stop_where_the_allowance_ends_round_robin(self):
        # The allowance (70 ms) less 8 active reads, the 8-read reserve and the fixed part (5 + 16 x 2 = 37 ms)
        # leaves 33 ms: at 3.25 ms per probe, 10 of the 30 dormant buckets per window, oldest probed first.
        def pkts(w, idx):
            return 7 if idx >= 100 else 10 * (w + 1)

        clock = FakeClock()
        reader = Reader(pkts, clock=clock, read_ms=2.0)
        cost = hc.ReadCostModel(fixed_ms=5.0, read_ms_per_bucket=2.0, clear_ms_per_bucket=1.0, alpha=0.0,
                                probe_ms_per_bucket=3.25)
        self.assertEqual(hc.DORMANT_RESUME_RESERVE, 8)
        windows, _ = run_live({0: list(range(100, 130)), 4: list(range(20, 28))}, reader, 8, window_sec=0.1,
                              clock=clock, dormant_reads=True, dormant_probe=True, read_budget_frac=0.7,
                              cost_model=cost)
        self.assertEqual([sorted(c["probe"]) for c in reader.calls[4:8]],
                         [list(range(100, 110)), list(range(110, 120)), list(range(120, 130)), list(range(100, 110))])
        self.assertTrue(all(w["overload"] is False for w in windows), "probes are never counted as overload")

    def test_changed_dormant_buckets_beyond_the_allowance_are_deferred_not_read(self):
        # PC1.md part 4c: a fan-out flood changes thousands of occupied dormant buckets at once, and reading them
        # all in full overran the window. Here all 30 dormant buckets change in window 5; the allowance after the
        # 8 active reads and the 30 probes (69.999 - 21 - 9 ms: 70% of 100 ms in floating point) fits 19 full
        # reads at 2 ms.
        def pkts(w, idx):
            if idx >= 100:
                return 9 if w >= 5 else 7
            return 10 * (w + 1)

        clock = FakeClock()
        reader = Reader(pkts, clock=clock, read_ms=2.0)
        cost = hc.ReadCostModel(fixed_ms=5.0, read_ms_per_bucket=2.0, clear_ms_per_bucket=1.0, alpha=0.0)
        windows, _ = run_live({0: list(range(100, 130)), 4: list(range(20, 28))}, reader, 10, window_sec=0.1,
                              clock=clock, dormant_reads=True, dormant_probe=True, read_budget_frac=0.7,
                              cost_model=cost)
        self.assertEqual(reader.calls[5]["probe_max_full"], 19)
        resumed, deferred = windows[5]["dormant_resumed_indexes"], windows[5]["dormant_deferred_indexes"]
        self.assertEqual((len(resumed), len(deferred)), (19, 11))
        self.assertEqual(sorted(resumed + deferred), list(range(100, 130)))
        self.assertTrue(set(deferred) <= set(windows[5]["active_after_read_indexes"]), "deferred: active again")
        self.assertEqual(windows[6]["dormant_count"], 0)
        # read later with the active set (38 active, 32 fit: windows 6-8 are overloaded), or, for those the
        # budget's ranking left out until they expired, probed again and read in full in window 9
        later = set().union(*(set(c["indexes"]) for c in reader.calls[6:10]),
                            *(set(w["dormant_resumed_indexes"]) for w in windows[6:10]))
        self.assertTrue(set(deferred) <= later)
        self.assertEqual([w["overload"] for w in windows[5:10]], [False, True, True, True, False])
        self.assertTrue(all(w["p4_read_overrun"] is False for w in windows), "no read past the next boundary")
        s = hc.build_net_summaries(windows, 0.1)
        self.assertEqual(sum(x["net_pkts_total_delta"] for x in s), 30 * 9 + 8 * 100, "every packet counted once")
        self.assertTrue(all(c["probe_max_full"] is None or c["probe_max_full"] >= 0 for c in reader.calls))

    def test_the_cost_model_learns_the_probe_cost_apart(self):
        cost = hc.ReadCostModel(fixed_ms=5.0, read_ms_per_bucket=2.0, alpha=1.0, min_rate_units=20)
        self.assertAlmostEqual(cost.probe_ms_per_bucket, hc.ReadCostModel.DST_WEIGHT * 2.0)
        self.assertAlmostEqual(cost.predict_ms(10, n_probe=100), 5.0 + 20.0 + 30.0)
        timing = hc.payload_timing_ms({"timing": {"sync_ms": 4.0, "read_ms": 20.0, "clear_ms": 0.0,
                                                  "probe_ms": 8.0}}, wall_ms=33.0)
        self.assertEqual((timing["probe_ms"], timing["overhead_ms"]), (8.0, 1.0), "the probe is not overhead")
        cost.update(10, 0, timing, n_probe=100)
        self.assertAlmostEqual(cost.probe_ms_per_bucket, 0.08)
        self.assertAlmostEqual(cost.read_ms_per_bucket, 2.0)
        self.assertAlmostEqual(cost.fixed_ms, 5.0)
        cost.update(10, 0, dict(timing, probe_ms=1.0), n_probe=5)
        self.assertAlmostEqual(cost.probe_ms_per_bucket, 0.08, msg="too few probes to learn from")
        self.assertEqual(cost.probes_within(1.0), 12)
        self.assertEqual(cost.probes_within(0.0), 0)

    def test_the_timing_log_gets_the_dormant_fields(self):
        records = []
        reader = Reader(lambda w, idx: 7)

        def log(window, payload, read_start, read_end, n_active, n_dst, window_end=None, extra=None):
            records.append({"window": window, "n": n_active, **(extra or {})})

        clock = FakeClock()
        t0 = clock.time()
        hc.collect_windows_live(FakeCollector({0: [1, 2]}, t0, 0.5), NeverEndingProc(), 0.5, 0.0, t0, "reader.py",
                                active_ttl_windows=3, clear_idle_windows=0, read_fn=reader, clock=clock,
                                max_windows=6, timing_log=log, dormant_reads=True)
        self.assertEqual(records[5], {"window": 5, "n": 2, "active_read": 0, "dormant": 2, "dormant_read": 2})

    def test_timing_logger_records_extra_fields(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "t.jsonl")
            payload = {"rows": [], "timing": {"sync_ms": 1.0, "read_ms": 2.0, "clear_ms": 0.0}}
            hc.make_timing_logger("batched", path)(3, payload, 0.0, 0.01, 2, 0, extra={"dormant": 5})
            record = json.loads(Path(path).read_text().splitlines()[0])
            self.assertEqual((record["window"], record["dormant"]), (3, 5))


def totals(pkts, nbytes, pkts_ab=None, bytes_ab=None, syn=0, ack=0, rst=0):
    return {"pkts": pkts, "bytes": nbytes, "pkts_ab": pkts if pkts_ab is None else pkts_ab,
            "bytes_ab": nbytes if bytes_ab is None else bytes_ab, "syn": syn, "ack": ack, "rst": rst}


class GlobalTotalsSummaryTests(unittest.TestCase):
    """NetSummarizer(global_totals=True), PC1.md part 4d: the window totals from the gtot build's one-entry totals."""

    def test_in_a_window_the_buckets_cover_the_totals_change_nothing(self):
        w0 = {"rows": [mkrow(1, 10, nbytes=1000, pkts_ab=6, bytes_ab=600)], "totals": totals(10, 1000, 6, 600)}
        w1 = {"rows": [mkrow(1, 15, nbytes=1500, pkts_ab=9, bytes_ab=900)], "totals": totals(15, 1500, 9, 900)}
        for layer in ("ipv4", "frame"):
            plain = hc.build_net_summaries([w0, w1], 0.5, byte_layer=layer)
            gtot = hc.build_net_summaries([w0, w1], 0.5, byte_layer=layer, global_totals=True)
            for a, b in zip(plain, gtot):
                self.assertEqual(a, {k: v for k, v in b.items() if not k.startswith("net_gtot_")}, layer)
            self.assertEqual([s["net_gtot_used"] for s in gtot], [1, 1])
            self.assertEqual([s["net_gtot_bucket_pkts_delta"] for s in gtot], [10, 5])

    def test_an_overloaded_window_takes_its_totals_from_the_registers(self):
        # one bucket read of a flood that put 1,000 packets (60 B, 400 SYN) through the switch in the window
        w0 = {"rows": [mkrow(1, 2, nbytes=120)], "totals": totals(1000, 60000, 1000, 60000, syn=400)}
        s = hc.build_net_summaries([w0], 0.5, byte_layer="frame", global_totals=True)[0]
        self.assertEqual((s["net_pkts_total_delta"], s["net_bytes_total_delta"], s["net_syn_delta"]),
                         (1000, 60000 + 14 * 1000, 400))
        self.assertEqual((s["net_pkts_ba_delta"], s["net_bytes_ba_delta"]), (0, 0))
        self.assertAlmostEqual(s["net_pkts_per_sec_delta"], 2000.0)
        self.assertAlmostEqual(s["net_avg_pkt_size_delta"], 74.0)
        self.assertEqual((s["net_gtot_bucket_pkts_delta"], s["net_gtot_bucket_bytes_delta"]), (2, 120 + 28))
        self.assertEqual(s["net_flow_count_seen"], 1, "per-flow features still come from the buckets read")

    def test_differences_wrap_at_32_bits_and_a_lost_window_only_resets_the_baseline(self):
        wrap = (1 << 32) - 5
        ws = [{"rows": [mkrow(1, 1)], "totals": totals(wrap, wrap)},
              {"rows": [mkrow(1, 2)], "totals": totals(5, 5)},              # wrapped: +10 each
              {"rows": [mkrow(1, 3)], "totals": None},                       # read failed
              {"rows": [mkrow(1, 4)], "totals": totals(100, 100)},          # only the baseline
              {"rows": [mkrow(1, 5)], "totals": totals(130, 160)}]
        s = hc.build_net_summaries(ws, 0.5, global_totals=True)
        self.assertEqual([x["net_gtot_used"] for x in s], [1, 1, 0, 0, 1])
        self.assertEqual([x["net_pkts_total_delta"] for x in s], [wrap, 10, 1, 1, 30],
                         "windows without usable totals keep the bucket sums")
        self.assertEqual(s[4]["net_bytes_total_delta"], 60)

    def test_the_split_build_takes_b_to_a_as_counted(self):
        # basic_gtot_ba (PC1.md part 4f): no total registers; B->A counted. A flood window whose A->B was read after
        # the total gave B->A packets that were never sent on gtot; here B->A grows only with B->A packets.
        def split(pab, bab, pba, bba, syn=0):
            return {"pkts_ab": pab, "bytes_ab": bab, "pkts_ba": pba, "bytes_ba": bba, "syn": syn, "ack": 0, "rst": 0}
        self.assertEqual(hc.gtot_keys(split(1, 2, 3, 4)), hc.GTOT_KEYS_SPLIT)
        self.assertEqual(hc.gtot_keys(totals(1, 2)), hc.GTOT_KEYS)
        self.assertIsNone(hc.gtot_keys(dict(split(1, 2, 3, 4), pkts_ba=None)))
        wrap = (1 << 32) - 3
        ws = [{"rows": [mkrow(1, 2, nbytes=120)], "totals": split(1000, 60000, 0, 0, syn=1000)},
              {"rows": [mkrow(1, 3, nbytes=180)], "totals": split(33000, 1980000, 0, 0, syn=33000)},
              {"rows": [mkrow(1, 4, nbytes=240)], "totals": split(33010, 1980600, wrap, wrap)},
              {"rows": [mkrow(1, 5, nbytes=300)], "totals": split(33010, 1980600, 4, 5)}]
        s = hc.build_net_summaries(ws, 0.5, byte_layer="frame", global_totals=True)
        self.assertEqual([x["net_gtot_used"] for x in s], [1, 1, 1, 1])
        self.assertEqual([x["net_pkts_ba_delta"] for x in s], [0, 0, wrap, 7], "B->A wraps at 32 bits")
        self.assertEqual([x["net_pkts_total_delta"] for x in s], [1000, 32000, 10 + wrap, 7])
        self.assertEqual(s[1]["net_bytes_total_delta"], 1920000 + 14 * 32000)
        self.assertEqual((s[1]["net_bytes_ba_delta"], s[3]["net_bytes_ba_delta"]), (0, 8 + 14 * 7))
        self.assertEqual(s[1]["net_syn_delta"], 32000)

    def test_a_change_of_key_set_only_resets_the_baseline(self):
        ws = [{"rows": [mkrow(1, 1)], "totals": totals(10, 100)},
              {"rows": [mkrow(1, 2)], "totals": {"pkts_ab": 20, "bytes_ab": 200, "pkts_ba": 0, "bytes_ba": 0,
                                                 "syn": 0, "ack": 0, "rst": 0}},
              {"rows": [mkrow(1, 3)], "totals": {"pkts_ab": 25, "bytes_ab": 250, "pkts_ba": 1, "bytes_ba": 10,
                                                 "syn": 0, "ack": 0, "rst": 0}}]
        s = hc.build_net_summaries(ws, 0.5, global_totals=True)
        self.assertEqual([x["net_gtot_used"] for x in s], [1, 0, 1])
        self.assertEqual(s[2]["net_pkts_total_delta"], 6)

    def test_every_row_has_the_same_columns_and_the_socket_join_ignores_the_totals(self):
        ws = [{"rows": [], "totals": totals(0, 0)}, {"rows": [mkrow(1, 3)], "totals": totals(3, 300)},
              {"rows": [mkrow(1, 3)], "totals": totals(9, 900), "owned_indexes": [1]}]
        s = hc.build_net_summaries(ws, 0.5, global_totals=True)
        self.assertEqual(len({tuple(x) for x in s}), 1, "one CSV layout")
        self.assertEqual(s[2]["net_pkts_total_delta"], 0, "an execution's own flows: the totals are the switch's")
        self.assertEqual(s[2]["net_gtot_used"], 0)
        self.assertNotIn("net_gtot_used", hc.build_net_summaries(ws, 0.5)[1])

    def test_the_collector_asks_for_the_totals_and_keeps_them(self):
        clock = FakeClock()
        calls = []

        def reader(indexes, w, **kw):
            calls.append((list(indexes), kw))
            return {"rows": [mkrow(i, 10 * (w + 1)) for i in indexes], "dst_rows": [], "cleared": [], "errors": [],
                    "timing": {"sync_ms": 1.0, "read_ms": 1.0, "clear_ms": 0.0,
                               "reader_t_totals_start": 7.0 + w, "reader_t_totals_end": 7.5 + w},
                    "totals": totals(10 * (w + 1), 0) if kw.get("totals") else None}

        def run(n, **kw):
            calls[:] = []
            return hc.collect_windows_live(FakeCollector({0: [1]}, clock.time(), 0.5), NeverEndingProc(), 0.5, 0.0,
                                           clock.time(), "r.py", active_ttl_windows=3, clear_idle_windows=0,
                                           read_fn=reader, clock=clock, max_windows=n, global_totals=True, **kw)

        # default "boundary": a totals-only request first, then the window's read without them
        windows = run(3)
        self.assertEqual([(i, k.get("totals")) for i, k in calls],
                         [([], True), ([1], None), ([], True), ([1], None), ([], True), ([1], None)])
        self.assertEqual([w["totals"]["pkts"] for w in windows], [10, 20, 30])
        self.assertEqual({w["totals_cut"] for w in windows}, {"boundary"})
        windows = run(2, totals_cut="read")
        self.assertEqual([k.get("totals") for _i, k in calls], [True, True])
        self.assertEqual({w["totals_cut"] for w in windows}, {"read"})
        run(2, totals_cut="snapshot")
        self.assertEqual([k.get("totals") for _i, k in calls], ["snapshot", "snapshot"])
        with contextlib.redirect_stdout(io.StringIO()):
            plain = hc.collect_windows_live(FakeCollector({0: [1]}, clock.time(), 0.5), NeverEndingProc(), 0.5, 0.0,
                                            clock.time(), "r.py", active_ttl_windows=3, clear_idle_windows=0,
                                            read_fn=reader, clock=clock, max_windows=2)
        self.assertIsNone(plain[0]["totals"])
        self.assertIsNone(plain[0]["totals_cut"])

    def test_a_failed_boundary_read_leaves_the_totals_to_the_windows_read(self):
        clock = FakeClock()
        calls = []

        def reader(indexes, w, **kw):
            calls.append((list(indexes), kw.get("totals")))
            if not indexes and kw.get("totals"):
                raise RuntimeError("batched reader: no reply")
            return {"rows": [mkrow(i, 10 * (w + 1)) for i in indexes], "dst_rows": [], "cleared": [], "errors": [],
                    "timing": {"sync_ms": 1.0, "read_ms": 1.0, "clear_ms": 0.0}, "totals": totals(10 * (w + 1), 0)}

        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            windows = hc.collect_windows_live(FakeCollector({0: [1]}, clock.time(), 0.5), NeverEndingProc(), 0.5, 0.0,
                                              clock.time(), "r.py", active_ttl_windows=3, clear_idle_windows=0,
                                              read_fn=reader, clock=clock, max_windows=2, global_totals=True)
        self.assertEqual(calls, [([], True), ([1], True), ([], True), ([1], True)])
        self.assertEqual([w["totals"]["pkts"] for w in windows], [10, 20])
        self.assertEqual({w["totals_cut"] for w in windows}, {"read"})
        self.assertIn("the boundary totals read failed", out.getvalue())

    def test_the_option(self):
        args = hc.build_arg_parser("dataset").parse_args(ProfileTests.BASE + ["--profile", "dataset", "--global-totals", "1"])
        self.assertEqual((args.global_totals, args.totals_cut), (1, "boundary"))
        self.assertEqual(hc.build_arg_parser().parse_args(ProfileTests.BASE).global_totals, 0)
        self.assertEqual(hc.build_arg_parser().parse_args(ProfileTests.BASE + ["--totals-cut", "snapshot"]).totals_cut,
                         "snapshot")


class MissingDestinationRegisterTests(unittest.TestCase):
    """PC1.md part 4c: the deployed basic_fix has no reg_newconn_dst. Its reads return an error and no rows in no
    time, yet each counted DST_WEIGHT of a bucket in the cost model: in windows with destination buckets but few
    flow buckets the per-bucket estimate fell from 0.56 to 0.19 ms, and a later read of 955 buckets took 605 ms."""

    def run_tcp(self, has_dst):
        clock = FakeClock()
        reader = Reader(lambda w, idx: 10 * (w + 1), clock=clock, has_dst=has_dst)
        cost = hc.ReadCostModel(fixed_ms=5.0, read_ms_per_bucket=5.0, clear_ms_per_bucket=1.0, alpha=1.0)
        t0 = clock.time()
        windows = hc.collect_windows_live(FakeCollector({0: [1, 2], 2: [3]}, t0, 0.5, proto=6), NeverEndingProc(),
                                          0.5, 0.0, t0, "reader.py", active_ttl_windows=3, clear_idle_windows=0,
                                          read_fn=reader, clock=clock, max_windows=6, read_budget_frac=0.7,
                                          cost_model=cost)
        return windows, reader, cost

    def test_after_the_first_error_no_destination_bucket_is_requested_or_counted(self):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            windows, reader, cost = self.run_tcp(has_dst=False)
        self.assertTrue(reader.calls[0]["dst"], "window 0 asks for its destination buckets")
        self.assertEqual([c["dst"] for c in reader.calls[1:6]], [[]] * 5)
        self.assertIn("no reg_newconn_dst", out.getvalue())
        self.assertTrue(all(w["overload"] is False for w in windows), "an absent register is not an overload")
        self.assertTrue(all(w["report_aggregates"]["net_dst_buckets_skipped"] == 0 for w in windows))
        self.assertEqual(cost.read_ms_per_bucket, 5.0, "learned from the flow buckets read, not from absent rows")

    def test_a_program_with_the_register_keeps_reading_it(self):
        with contextlib.redirect_stdout(io.StringIO()):
            windows, reader, cost = self.run_tcp(has_dst=True)
        self.assertTrue(all(c["dst"] for c in reader.calls[:4]))


class LauncherTests(unittest.TestCase):
    def test_the_launcher_argv(self):
        self.assertEqual(hc.dataset_launch_command(["prog", "a b"]), hc.DATASET_LAUNCHER + ["prog", "a b"])
        argv = hc.dataset_launch_command(["prog", "a b"], "/sys/fs/cgroup/x")
        self.assertEqual(argv[:2], ["/bin/bash", "-c"])
        self.assertEqual(argv[3:], ["/sys/fs/cgroup/x", "prog", "a b"])
        self.assertIn("sample-launch", argv[2])
        with self.assertRaises(ValueError):
            hc.dataset_launch_command([])

    def test_the_program_runs_with_devnull_stdin_in_the_workspace_and_a_new_session(self):
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "out.json")
            program = ("import json, os, sys; json.dump({'stdin': sys.stdin.read(), 'cwd': os.getcwd(), "
                       "'argv': sys.argv[1:], 'sid': os.getsid(0), 'pid': os.getpid()}, open(sys.argv[1], 'w'))")
            cmd = f"{sys.executable} -c {json.dumps(program)} {out} 'two words'"
            proc = hc.run_scenario_command(cmd, launcher="dataset", workspace=d)
            self.assertEqual(proc.wait(timeout=20), 0)
            got = json.load(open(out))
            self.assertEqual(got["stdin"], "")
            self.assertEqual(Path(got["cwd"]).resolve(), Path(d).resolve())
            self.assertEqual(got["argv"], [out, "two words"])
            self.assertEqual(got["sid"], got["pid"], "the program leads its own session")
            self.assertEqual(got["pid"], proc.pid, "the launcher execs the program: same PID")

    def test_with_a_cgroup_the_moved_pid_is_the_programs(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "cgroup.procs").write_text("")
            out = os.path.join(d, "out.txt")
            proc = hc.run_scenario_command(f'/bin/sh -c "echo $$ > {out}"', cgroup=d, launcher="dataset", workspace=d)
            self.assertEqual(proc.wait(timeout=20), 0)
            moved = (Path(d) / "cgroup.procs").read_text().split()
            self.assertEqual(moved, [Path(out).read_text().strip()])
            self.assertEqual(int(moved[0]), proc.pid)

    def test_stop_scenario_terminates_then_kills(self):
        proc = hc.run_scenario_command("sleep 30", launcher="dataset")
        t = time.time()
        hc.stop_scenario(proc, grace=2.0, own_session=True)
        self.assertEqual(proc.returncode, -15)
        self.assertLess(time.time() - t, 2.0)
        stubborn = (f"{sys.executable} -c "
                    + json.dumps("import signal, time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(30)"))
        proc = hc.run_scenario_command(stubborn, launcher="dataset")
        time.sleep(0.5)   # let it install the handler
        hc.stop_scenario(proc, grace=0.5, own_session=True)
        self.assertEqual(proc.returncode, -9)

    def test_stop_scenario_leaves_a_finished_process_alone(self):
        proc = subprocess.Popen(["true"])
        proc.wait()
        hc.stop_scenario(proc)
        self.assertEqual(proc.returncode, 0)


if __name__ == "__main__":
    unittest.main()
