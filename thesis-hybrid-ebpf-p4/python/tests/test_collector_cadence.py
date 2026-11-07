"""Tests of the read cadence additions to hybrid_collector.py (2026-11-07): the read budget and overload mode,
the report-only aggregate columns, the option profiles, the CSV schema guard, and the in-kernel monitor's start
protocol. No switch, no BPF, no root: the register reader and the monitor are fakes."""
import os
import signal
import stat
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))  # repository root
import hybrid_collector as hc  # noqa: E402

FAKE_MONITOR = r"""#!/usr/bin/env python3
# Stand-in for ebpf_perf/hostmon_agg: READY, a future shared start on stdin, one window block, HEALTH on SIGINT.
import signal, sys, time
window = float(sys.argv[1]); cgroup = sys.argv[2]
print("HOSTMON_READY,4242", flush=True)
start = float(sys.stdin.readline())
if start <= time.monotonic():
    print("ERROR start not in the future", flush=True); sys.exit(1)
header = "COMM,PID,EXEC,OPEN,REN,DEL,CONN,UNIQIP,UNIQPRT,TOTAL_SYSCALLS,UNIQUE_SYSCALLS,ENTROPY,TOP_SYSCALL_FREQ,AVG_RUN_LENGTH,MAX_RUN_LENGTH,TRANSITION_COUNT,RARE_SYSCALL_RATIO,FIRST50_UNIQUE,FIRST100_UNIQUE"
def finish(*_):
    print("\n==== HOST WINDOW 0 START=%.6f END=%.6f DUR=%.6f ====" % (0.0, window, window))
    print(header)
    print("fake,1,0,0,0,0,0,0,0,106,9,2.5,0.3,1.5,4,70,0.1,9,9")
    print("HOSTMON_HEALTH,0,0,0,0", flush=True)
    sys.exit(0)
signal.signal(signal.SIGINT, finish); signal.signal(signal.SIGTERM, finish)
while True:
    time.sleep(0.05)
"""


def mkrow(idx, pkts):
    return {"idx": idx, "pkts": pkts, "bytes": 100 * pkts, "pkts_ab": pkts, "bytes_ab": 100 * pkts, "min_len": 60,
            "max_len": 1500, "first_ts": 1, "last_ts": 2, "syn": 1, "ack": pkts, "rst": 0, "dir_valid": 1}


class FakeCollector:
    def __init__(self, reports_by_window, t0, window_sec):
        self.reports, self.t0, self.window_sec = reports_by_window, t0, window_sec

    def take(self, start, end):
        w = round((start - self.t0) / self.window_sec)
        return list(self.reports.get(w, []))


class FakeProc:
    def __init__(self, windows):
        self.windows, self.calls = windows, 0

    def poll(self):
        self.calls += 1
        return 0 if self.calls >= self.windows else None


def report(idx, src="10.0.0.1", dst="10.0.0.2", dport=80, proto=6):
    return {"idx": idx, "idx_source": "report", "idx_computed": idx, "src_ip": src, "dst_ip": dst,
            "sport": 1000 + idx, "dport": dport, "proto": proto}


class FakeClock:
    """A clock for collect_windows_live: sleep() and advance() move it, nothing else does."""

    def __init__(self, t=1000.0):
        self.t = t

    def time(self):
        return self.t

    def sleep(self, seconds):
        self.t += max(0.0, seconds)

    def advance(self, seconds):
        self.t += seconds


class FakeReader:
    """Register reader whose payload carries a timing block: fixed sync 10 ms, 5 ms per bucket read, clear_ms per
    bucket cleared. A compare-and-clear succeeds when the caller's count equals the fake's current count; an
    unconditional clear (clear_indexes) always succeeds unless fail_clears. With a FakeClock the read also takes
    that long, or durations[w] seconds for the windows listed there (its timing block then reports the extra time
    as read time)."""

    SYNC_MS, READ_MS = 10.0, 5.0

    def __init__(self, clock=None, durations=None, fail_clears=False, clear_ms=1.0):
        self.calls, self.clock, self.durations, self.fail_clears, self.clear_ms = [], clock, durations or {}, fail_clears, clear_ms

    def __call__(self, indexes, w, snapshot="sync", clear_if_unchanged=None, dst_indexes=None, clear_indexes=None):
        pkts = 10 * (w + 1)
        cleared = [i for i, p in (clear_if_unchanged or {}).items() if p == pkts]
        if not self.fail_clears:
            cleared += [i for i in (clear_indexes or []) if i not in cleared]
        self.calls.append({"w": w, "indexes": list(indexes), "dst": list(dst_indexes or []),
                           "clear": dict(clear_if_unchanged or {}), "clear_indexes": list(clear_indexes or [])})
        read_ms, clear_ms = self.READ_MS * len(indexes), self.clear_ms * len(cleared)
        if self.clock is not None:
            duration = self.durations.get(w, (self.SYNC_MS + read_ms + clear_ms) / 1000.0)
            self.clock.advance(duration)
            read_ms = duration * 1000.0 - self.SYNC_MS - clear_ms
        return {"rows": [mkrow(i, pkts) for i in indexes],
                "dst_rows": [{"idx": i, "new_conn": 3} for i in (dst_indexes or [])], "cleared": sorted(cleared),
                "snapshot": snapshot, "timing": {"sync_ms": self.SYNC_MS, "read_ms": read_ms, "clear_ms": clear_ms}}


class ReadBudgetTests(unittest.TestCase):
    def run_live(self, reports, n_windows, window_sec=0.05, clock=None, reader=None, **kw):
        # A fake clock by default: the allowances asserted below are exact, and a real 50 ms window would make
        # them depend on scheduling jitter. The reads take no time unless the test gives the reader the clock.
        clock = clock if clock is not None else FakeClock()
        reader = reader if reader is not None else FakeReader()
        t0 = clock.time()
        windows = hc.collect_windows_live(FakeCollector(reports, t0, window_sec), FakeProc(n_windows), window_sec, 0.0,
                                          t0, "reader.py", active_ttl_windows=3, clear_idle_windows=0, read_fn=reader,
                                          clock=clock, **kw)
        return windows, reader

    def test_without_a_budget_every_active_bucket_is_read_and_aggregates_are_present(self):
        windows, reader = self.run_live({0: [report(i) for i in range(10)]}, 3)
        self.assertEqual(reader.calls[0]["indexes"], list(range(10)))
        self.assertEqual(windows[0]["skipped_count"], 0)
        self.assertFalse(windows[0]["overload"])
        agg = windows[0]["report_aggregates"]
        self.assertEqual(agg["rep_new_flows"], 10)
        self.assertAlmostEqual(agg["rep_new_flows_per_sec"], 10 / 0.05)
        self.assertEqual(agg["net_buckets_read"], 10)
        self.assertEqual(agg["net_overload"], 0)
        self.assertEqual((agg["net_buckets_cleared"], agg["net_clear_backlog"], agg["net_read_allow_ms"]), (0, 0, 0.0))
        self.assertEqual(set(hc.REPORT_ZERO), set(agg))
        self.assertEqual(reader.calls[0]["clear_indexes"], [])

    def test_the_budget_limits_the_read_to_the_most_recent_buckets(self):
        # 50 ms window, 80% budget = 40 ms; fixed 10 ms + 5 ms per bucket -> 6 buckets fit (UDP flows: no
        # reg_newconn_dst reads, which would take their share of the allowance too).
        cost = hc.ReadCostModel(fixed_ms=10.0, read_ms_per_bucket=5.0, clear_ms_per_bucket=1.0)
        reports = {0: [report(i, proto=17) for i in range(10)], 1: [report(10, proto=17), report(11, proto=17)]}
        windows, reader = self.run_live(reports, 3, read_budget_frac=0.8, cost_model=cost)
        self.assertEqual(reader.calls[0]["indexes"], [0, 1, 2, 3, 4, 5])          # ties by index
        self.assertEqual(windows[0]["skipped_count"], 4)
        self.assertTrue(windows[0]["overload"])
        self.assertEqual(windows[0]["report_aggregates"]["net_buckets_skipped"], 4)
        self.assertEqual(windows[0]["report_aggregates"]["net_buckets_active"], 10)
        # window 1: the two new buckets (last seen 1) come first, then the oldest indexes of window 0
        self.assertEqual(reader.calls[1]["indexes"], [0, 1, 2, 3, 10, 11])
        self.assertEqual(windows[1]["report_aggregates"]["net_read_budget_ms"], 40.0)
        self.assertEqual(windows[1]["report_aggregates"]["net_read_allow_ms"], 40.0)   # on time: the whole budget
        # the cost model followed the fake reader's 5 ms per bucket and its 10 ms sync (+ IPC overhead)
        self.assertAlmostEqual(cost.read_ms_per_bucket, 5.0, places=6)
        self.assertGreaterEqual(cost.fixed_ms, 10.0)

    def test_expired_buckets_are_cleared_unconditionally_in_one_request(self):
        # 20 flows reported in window 0; 6 fit the 40 ms allowance and are read every window (their counters
        # change, so they stay the most recent). The 14 skipped ones are never read, expire after the 3-window
        # TTL (window 4) and, with clear_expired, are all cleared there: (40 - 10) x 0.5 = 15 ms at 0.5 ms each.
        cost = hc.ReadCostModel(fixed_ms=10.0, read_ms_per_bucket=5.0, clear_ms_per_bucket=0.5)
        reports = {0: [report(i, proto=17) for i in range(20)]}
        windows, reader = self.run_live(reports, 7, reader=FakeReader(clear_ms=0.5), read_budget_frac=0.8,
                                        cost_model=cost, clear_expired=True)
        self.assertEqual([c["clear_indexes"] for c in reader.calls[:4]], [[], [], [], []])
        self.assertEqual(reader.calls[4]["clear_indexes"], list(range(6, 20)))
        self.assertEqual(windows[4]["expired_indexes"], list(range(6, 20)))
        self.assertEqual(windows[4]["expired_cleared_indexes"], list(range(6, 20)))
        self.assertEqual(windows[4]["cleared_indexes"], list(range(6, 20)))
        agg = windows[4]["report_aggregates"]
        self.assertEqual((agg["net_buckets_cleared"], agg["net_clear_backlog"]), (14, 0))
        # the 14 clears (7 ms) came out of the read allowance: (40 - 10 - 7) // 5 = 4 of the 6 active were read
        self.assertEqual((agg["net_buckets_read"], agg["net_buckets_skipped"], agg["net_overload"]), (4, 2, 1))
        self.assertTrue(all(c["clear_indexes"] == [] for c in reader.calls[5:7]))
        self.assertEqual(windows[6]["report_aggregates"]["net_buckets_read"], 6)      # back to the full set
        # End of the run: one more request clears the six live buckets without reading anything.
        self.assertEqual(len(reader.calls), len(windows) + 1)
        self.assertEqual((reader.calls[-1]["indexes"], reader.calls[-1]["dst"], reader.calls[-1]["clear_indexes"]),
                         ([], [], list(range(6))))
        self.assertEqual(windows[-1]["final_cleared_indexes"], list(range(6)))

    def test_the_end_of_run_clear_takes_the_backlog_too_and_only_with_clear_expired(self):
        # Clears cost 5 ms (3 per window), so the run ends with buckets still waiting in the queue.
        cost = hc.ReadCostModel(fixed_ms=10.0, read_ms_per_bucket=5.0, clear_ms_per_bucket=5.0)
        windows, reader = self.run_live({0: [report(i, proto=17) for i in range(20)]}, 6,
                                        reader=FakeReader(clear_ms=5.0), read_budget_frac=0.8, cost_model=cost,
                                        clear_expired=True)
        backlog = windows[-1]["report_aggregates"]["net_clear_backlog"]
        self.assertGreater(backlog, 0)
        final = reader.calls[-1]["clear_indexes"]
        self.assertEqual(len(final), len(windows[-1]["active_indexes"]) + backlog)
        self.assertEqual(windows[-1]["final_cleared_indexes"], sorted(final))
        # without --clear-expired: no end-of-run request
        windows, reader = self.run_live({0: [report(i, proto=17) for i in range(20)]}, 6,
                                        reader=FakeReader(clear_ms=5.0), read_budget_frac=0.8,
                                        cost_model=hc.ReadCostModel(fixed_ms=10.0, read_ms_per_bucket=5.0,
                                                                    clear_ms_per_bucket=5.0))
        self.assertEqual(len(reader.calls), len(windows))
        self.assertNotIn("final_cleared_indexes", windows[-1])

    def test_a_failed_end_of_run_clear_does_not_end_the_run_with_an_error(self):
        class FailingAtTheEnd(FakeReader):
            def __call__(self, indexes, w, **kw):
                if not indexes and kw.get("clear_indexes"):
                    raise hc.P4ReadError("switch gone")
                return super().__call__(indexes, w, **kw)

        cost = hc.ReadCostModel(fixed_ms=10.0, read_ms_per_bucket=5.0, clear_ms_per_bucket=0.5)
        windows, _ = self.run_live({0: [report(i, proto=17) for i in range(4)]}, 3, reader=FailingAtTheEnd(),
                                   read_budget_frac=0.8, cost_model=cost, clear_expired=True)
        self.assertEqual(windows[-1]["final_cleared_indexes"], [])

    def test_the_reported_destination_bucket_is_used_without_a_crc(self):
        saved = hc.compute_newconn_dst_index

        def no_crc(*_a, **_k):
            raise AssertionError("the collector computed a CRC for a report that carries dst_idx")

        hc.compute_newconn_dst_index = no_crc
        try:
            reports = {0: [dict(report(1), dst_idx=4242), dict(report(2), dst_idx=4242), dict(report(3), dst_idx=7)]}
            windows, reader = self.run_live(reports, 2)
        finally:
            hc.compute_newconn_dst_index = saved
        self.assertEqual(windows[0]["dst_indexes"], [7, 4242])
        self.assertEqual(reader.calls[0]["dst"], [7, 4242])
        # a report without dst_idx (an older capture path) still gets its bucket computed
        windows, _ = self.run_live({0: [report(1)]}, 2)
        self.assertEqual(windows[0]["dst_indexes"], [hc.compute_newconn_dst_index("10.0.0.1", "10.0.0.2", 80, 6)])

    def test_the_measured_selection_time_is_taken_off_the_allowance(self):
        cost = hc.ReadCostModel(fixed_ms=10.0, read_ms_per_bucket=5.0, clear_ms_per_bucket=1.0)
        cost.select_ms, cost.post_ms = 300.0, 100.0
        windows, _ = self.run_live({0: [report(i, proto=17) for i in range(400)]}, 3, window_sec=1.0,
                                   read_budget_frac=0.8, cost_model=cost)
        a0 = windows[0]["report_aggregates"]
        # decided on time: 1000 - 300 (selection) - 100 (post-read work) - 5 (margin) = 595 ms < the 800 ms budget
        self.assertEqual(a0["net_read_allow_ms"], 595.0)
        self.assertEqual(a0["net_buckets_read"], (595 - 10) // 5)
        # this fake clock takes no time for the selection, so the averages come down window by window
        self.assertGreater(windows[1]["report_aggregates"]["net_read_allow_ms"], 595.0)

    def test_reads_that_overrun_their_prediction_raise_the_margin(self):
        clock = FakeClock(1000.0)
        cost = hc.ReadCostModel(fixed_ms=10.0, read_ms_per_bucket=5.0, clear_ms_per_bucket=1.0)
        reader = FakeReader(clock=clock, durations={0: 0.9})      # predicted 10 + 158 x 5 = 800 ms, took 900
        windows, _ = self.run_live({0: [report(i, proto=17) for i in range(200)]}, 3, window_sec=1.0, clock=clock,
                                   reader=reader, read_budget_frac=0.8, cost_model=cost)
        self.assertEqual(windows[0]["report_aggregates"]["net_buckets_read"], 158)
        self.assertGreater(cost.margin_ms, 0.0)
        self.assertLess(windows[1]["report_aggregates"]["net_buckets_read"], 158)

    def test_a_one_bucket_first_window_does_not_overload_the_benign_windows_after_it(self):
        class RequestCostReader(FakeReader):
            """The raw route's measured shape: a read 23 ms plus 0.56 ms per unit, a clear 3 ms plus 0.105 per bucket."""

            def __call__(self, indexes, w, **kw):
                payload = super().__call__(indexes, w, **kw)
                units = len(indexes) + hc.ReadCostModel.DST_WEIGHT * len(kw.get("dst_indexes") or [])
                n_clear = len(payload["cleared"])
                payload["timing"]["read_ms"] = 23.0 + 0.56 * units if units else 0.0
                payload["timing"]["clear_ms"] = 3.0 + 0.105 * n_clear if n_clear else 0.0
                return payload

        reports = {0: [report(0, proto=17)]}                                         # the connection probe alone
        reports.update({w: [report(100 * w + i, proto=17) for i in range(100)] for w in range(1, 8)})
        windows, reader = self.run_live(reports, 8, window_sec=1.0, reader=RequestCostReader(),
                                        read_budget_frac=0.7, cost_model=hc.ReadCostModel.for_route("raw"))
        self.assertEqual([w["report_aggregates"]["net_overload"] for w in windows], [0] * len(windows))
        aggs = [w["report_aggregates"] for w in windows]
        self.assertEqual([a["net_buckets_read"] for a in aggs], [a["net_buckets_active"] for a in aggs])
        self.assertGreater(max(a["net_buckets_active"] for a in aggs), 400)

    def test_without_clear_expired_the_buckets_just_expire(self):
        cost = hc.ReadCostModel(fixed_ms=10.0, read_ms_per_bucket=5.0, clear_ms_per_bucket=0.5)
        windows, reader = self.run_live({0: [report(i, proto=17) for i in range(20)]}, 6,
                                        read_budget_frac=0.8, cost_model=cost)
        self.assertEqual(windows[4]["expired_indexes"], list(range(6, 20)))
        self.assertEqual(windows[4]["expired_cleared_indexes"], [])
        self.assertTrue(all(c["clear_indexes"] == [] for c in reader.calls))
        self.assertEqual(windows[4]["report_aggregates"]["net_clear_backlog"], 0)

    def test_the_clear_backlog_is_bounded_per_window_and_drains_oldest_first(self):
        # clears cost 5 ms (the fake reports the same, so the model keeps it): (40 - 10) x 0.5 = 15 ms -> 3 per window
        cost = hc.ReadCostModel(fixed_ms=10.0, read_ms_per_bucket=5.0, clear_ms_per_bucket=5.0)
        reader = FakeReader(clear_ms=5.0)
        windows, reader = self.run_live({0: [report(i, proto=17) for i in range(20)]}, 12, reader=reader,
                                        read_budget_frac=0.8, cost_model=cost, clear_expired=True)
        backlog = [w["report_aggregates"]["net_clear_backlog"] for w in windows]
        # The three clears (15 ms) leave (40 - 10 - 15) // 5 = 3 bucket reads, so only 3 of the 6 live buckets
        # are read from window 4 on ([0, 1, 2]: ties by index); [3, 4, 5] change but are never read again,
        # expire at window 7 and join the queue: the price of a blind clear under an overload is that a live
        # flow the budget could not read is split, not that it is lost.
        self.assertEqual(backlog[3:11], [0, 11, 8, 5, 5, 2, 0, 0])
        self.assertEqual([c["clear_indexes"] for c in reader.calls[4:10]], [[6, 7, 8], [9, 10, 11], [12, 13, 14],
                                                                            [15, 16, 17], [18, 19, 3], [4, 5]])
        self.assertEqual(windows[7]["expired_indexes"], [3, 4, 5])
        self.assertTrue(all(w["overload"] for w in windows[4:9]))      # a deferred clear is an overload
        self.assertEqual(windows[4]["report_aggregates"]["net_buckets_read"], 3)
        self.assertAlmostEqual(cost.clear_ms_per_bucket, 5.0, places=6)

    def test_a_bucket_that_reports_again_leaves_the_clear_queue(self):
        cost = hc.ReadCostModel(fixed_ms=10.0, read_ms_per_bucket=5.0, clear_ms_per_bucket=5.0)
        reader = FakeReader(clear_ms=5.0)
        reports = {0: [report(i, proto=17) for i in range(20)], 5: [report(19, proto=17)]}
        windows, reader = self.run_live(reports, 10, reader=reader, read_budget_frac=0.8, cost_model=cost,
                                        clear_expired=True)
        self.assertIn(19, windows[4]["expired_indexes"])
        self.assertIn(19, windows[5]["active_indexes"])
        self.assertTrue(all(19 not in c["clear_indexes"] for c in reader.calls[:len(windows)]))
        # window 5: 19 leaves the queue (10 left, 3 cleared); window 7: the 3 unread live buckets join it
        self.assertEqual([w["report_aggregates"]["net_clear_backlog"] for w in windows[4:8]], [11, 7, 4, 4])

    def test_a_failed_unconditional_clear_is_retried_then_given_up(self):
        cost = hc.ReadCostModel(fixed_ms=10.0, read_ms_per_bucket=5.0, clear_ms_per_bucket=0.5)
        reader = FakeReader(fail_clears=True)
        windows, reader = self.run_live({0: [report(i, proto=17) for i in range(20)]}, 10, reader=reader,
                                        read_budget_frac=0.8, cost_model=cost, clear_expired=True)
        asked = [c["clear_indexes"] for c in reader.calls]
        self.assertEqual(asked[4], list(range(6, 20)))
        self.assertEqual(asked[4], asked[5])
        self.assertEqual(asked[5], asked[6])
        # given up after three failed attempts; the two live buckets the 4-read budget never reaches ([4, 5])
        # expire at window 7 and go through the same three attempts
        self.assertEqual(asked[7:10], [[4, 5], [4, 5], [4, 5]])
        self.assertEqual([w["report_aggregates"]["net_clear_backlog"] for w in windows[4:10]], [14, 14, 0, 2, 2, 0])
        self.assertTrue(all(w["expired_cleared_indexes"] == [] for w in windows))

    def test_a_late_read_shrinks_the_next_allowance_and_the_schedule_recovers(self):
        clock = FakeClock(1000.0)
        cost = hc.ReadCostModel(fixed_ms=10.0, read_ms_per_bucket=5.0, clear_ms_per_bucket=1.0)
        reader = FakeReader(clock=clock, durations={0: 1.3})      # window 0's read takes 1.3 s of a 1 s window
        reports = {0: [report(i, proto=17) for i in range(200)]}
        windows, reader = self.run_live(reports, 4, window_sec=1.0, clock=clock, reader=reader,
                                        read_budget_frac=0.8, cost_model=cost)
        a0, a1, a2 = (w["report_aggregates"] for w in windows[:3])
        self.assertEqual((a0["net_read_allow_ms"], a0["net_buckets_read"], a0["net_read_late_ms"]), (800.0, 158, 0.0))
        self.assertTrue(windows[0]["p4_read_overrun"])
        # window 1 is decided 300 ms after its boundary: 700 ms are left, minus the 5 ms margin
        self.assertAlmostEqual(a1["net_read_late_ms"], 300.0, delta=0.1)
        self.assertAlmostEqual(a1["net_read_allow_ms"], 695.0, delta=0.1)
        self.assertLess(a1["net_buckets_read"], 158)
        self.assertFalse(windows[1]["p4_read_overrun"])          # it ended before the next boundary ...
        self.assertEqual((a2["net_read_late_ms"], a2["net_read_allow_ms"]), (0.0, 800.0))   # ... so window 2 is on time
        # window 0's slow read raised the per-bucket estimate; it is still coming back down in window 2
        self.assertGreater(a2["net_buckets_read"], a1["net_buckets_read"])
        self.assertLessEqual(a2["net_buckets_read"], 158)
        self.assertGreaterEqual(cost.windows_seen, 4)

    def test_a_hard_cap_applies_without_a_budget(self):
        windows, reader = self.run_live({0: [report(i) for i in range(10)]}, 2, max_read_buckets=3)
        self.assertEqual(reader.calls[0]["indexes"], [0, 1, 2])
        self.assertEqual(windows[0]["skipped_count"], 7)

    def test_destination_buckets_are_capped_by_report_count(self):
        # 3 TCP flows to 10.0.0.2:80, 1 to 10.0.0.3:443: one dst bucket each; cap 1 keeps the busier one.
        dst_a = hc.compute_newconn_dst_index("10.0.0.1", "10.0.0.2", 80, 6)
        dst_b = hc.compute_newconn_dst_index("10.0.0.1", "10.0.0.3", 443, 6)
        reports = {0: [report(1), report(2), report(3), report(4, dst="10.0.0.3", dport=443)]}
        windows, reader = self.run_live(reports, 2, max_dst_reads=1)
        self.assertEqual(reader.calls[0]["dst"], [dst_a])
        self.assertEqual(windows[0]["active_dst_indexes"], sorted([dst_a, dst_b]))
        self.assertEqual(windows[0]["report_aggregates"]["net_dst_buckets_skipped"], 1)
        self.assertTrue(windows[0]["overload"])


class HelperTests(unittest.TestCase):
    def test_report_aggregates(self):
        reports = [report(1), report(2), report(3, dst="10.0.0.3", dport=53, proto=17),
                   report(4, src="10.0.0.9", dst="10.0.0.3", dport=53, proto=17)]
        agg = hc.report_aggregates(reports, 2.0)
        self.assertEqual(agg["rep_new_flows"], 4)
        self.assertEqual(agg["rep_new_flows_per_sec"], 2.0)
        self.assertEqual(agg["rep_distinct_src_ips"], 2)
        self.assertEqual(agg["rep_distinct_dst_ips"], 2)
        self.assertEqual(agg["rep_distinct_dst_ports"], 2)
        self.assertEqual(agg["rep_tcp_share"], 0.5)
        self.assertEqual(agg["rep_max_flows_to_one_dst"], 2)
        self.assertEqual(agg["rep_max_flows_to_one_dst_port"], 2)
        self.assertEqual(hc.report_aggregates([], 1.0)["rep_new_flows"], 0)

    def test_select_within_budget(self):
        active, seen = [1, 2, 3, 4], {1: 0, 2: 5, 3: 5, 4: 2}
        self.assertEqual(hc.select_within_budget(active, seen, 10), ([1, 2, 3, 4], []))
        self.assertEqual(hc.select_within_budget(active, seen, 2), ([2, 3], [1, 4]))
        self.assertEqual(hc.select_within_budget(active, seen, 3), ([2, 3, 4], [1]))
        self.assertEqual(hc.select_within_budget(active, seen, 0), ([], [1, 2, 3, 4]))

    def test_cost_model_budget_and_learning(self):
        cost = hc.ReadCostModel(fixed_ms=70.0, read_ms_per_bucket=1.3, clear_ms_per_bucket=0.7)
        self.assertEqual(cost.buckets_within(800.0), int((800 - 70) // 1.3))          # 1 s window, 80%: 561 buckets
        self.assertEqual(cost.buckets_within(50.0), 0)                              # 50 ms: the syncs alone exceed it
        self.assertEqual(cost.buckets_within(8000.0, n_cleared=1000), int((8000 - 70 - 700) // 1.3))
        for _ in range(30):                                                          # a slow control plane: 50 ms per bucket
            cost.update(100, 10, {"sync_ms": 2000.0, "read_ms": 5000.0, "clear_ms": 300.0, "overhead_ms": 100.0})
        self.assertAlmostEqual(cost.read_ms_per_bucket, 50.0, delta=0.01)
        self.assertAlmostEqual(cost.clear_ms_per_bucket, 30.0, delta=0.01)
        self.assertAlmostEqual(cost.fixed_ms, 2100.0, delta=0.1)

    def test_cost_model_routes_dst_weight_and_clears(self):
        raw = hc.ReadCostModel.for_route("raw")
        self.assertEqual((raw.route, raw.fixed_ms, raw.read_fixed_ms, raw.read_ms_per_bucket, raw.clear_fixed_ms,
                          raw.clear_ms_per_bucket, raw.min_rate_units), ("raw", 65.0, 23.0, 0.56, 3.0, 0.105, 20.0))
        for route in hc.ROUTE_COSTS:
            self.assertEqual(hc.ReadCostModel.for_route(route).route, route)
        # 1 s window, 70%: the raw route fits (700 - 65 - 23) // 0.56 buckets; 200 clears (their Write and
        # 0.105 ms each) and 100 dst reads take their share
        self.assertEqual(raw.buckets_within(700.0), int((700 - 65 - 23) // 0.56))
        self.assertEqual(raw.buckets_within(700.0, n_cleared=200, n_dst=100),
                         int((700 - 65 - 23 - 3 - 200 * 0.105 - 100 * hc.ReadCostModel.DST_WEIGHT * 0.56) // 0.56))
        self.assertEqual(raw.clears_within(100.0), int(100 // 0.105))
        self.assertEqual(raw.clears_within(0.0), 0)
        self.assertAlmostEqual(raw.predict_ms(100, n_cleared=10, n_dst=20), 65 + 23 + 103 * 0.56 + 3 + 10 * 0.105)
        self.assertAlmostEqual(raw.predict_ms(0), 65.0)                              # nothing read or cleared
        # the per-bucket read cost is fitted per flow-bucket unit, a dst read counting DST_WEIGHT of one
        m = hc.ReadCostModel(fixed_ms=10.0, read_ms_per_bucket=1.0, clear_ms_per_bucket=1.0, alpha=1.0)
        m.update(100, 0, {"sync_ms": 10.0, "read_ms": 115.0, "clear_ms": 0.0, "overhead_ms": 0.0}, n_dst=100)
        self.assertAlmostEqual(m.read_ms_per_bucket, 1.0)
        m.update_processing(20.0, 40.0, select_ms=8.0)
        m.update_processing(0.0, 0.0)
        self.assertEqual((m.prep_ms, m.post_ms, m.select_ms), (5.0, 10.0, 2.0))
        self.assertEqual(m.as_dict()["route"], "fast")
        # margin: only overshoots of the prediction count, and buckets_within keeps the margin free
        m = hc.ReadCostModel(fixed_ms=10.0, read_ms_per_bucket=1.0, clear_ms_per_bucket=1.0, alpha=0.5)
        m.update(100, 0, {"sync_ms": 10.0, "read_ms": 80.0, "clear_ms": 0.0, "overhead_ms": 0.0})   # faster
        self.assertEqual(m.margin_ms, 0.0)
        m = hc.ReadCostModel(fixed_ms=10.0, read_ms_per_bucket=1.0, clear_ms_per_bucket=1.0, alpha=0.5)
        m.update(100, 0, {"sync_ms": 10.0, "read_ms": 140.0, "clear_ms": 0.0, "overhead_ms": 0.0})  # 40 ms over
        self.assertEqual(m.margin_ms, 20.0)
        self.assertEqual(m.buckets_within(200.0), int((200 - m.fixed_ms - 20.0) // m.read_ms_per_bucket))

    def test_small_reads_do_not_inflate_the_per_bucket_costs(self):
        # RUNBOOK 16 (bulk2000): the first read held one bucket, the collector's connection probe: 21 ms, all of it
        # request overhead. Learned per bucket, that was 18.6 ms, and five benign windows were then overloaded.
        raw = hc.ReadCostModel.for_route("raw")
        raw.update(1, 1, {"sync_ms": 33.0, "read_ms": 21.0, "clear_ms": 3.0, "overhead_ms": 2.0}, n_dst=1)
        self.assertEqual((raw.read_ms_per_bucket, raw.clear_ms_per_bucket), (0.56, 0.105))
        # a large read moves the per-bucket costs, with the per-request parts taken off first
        m = hc.ReadCostModel.for_route("raw", alpha=1.0)
        m.update(1016, 1600, {"sync_ms": 33.0, "read_ms": 612.0, "clear_ms": 144.0, "overhead_ms": 43.0}, n_dst=256)
        self.assertAlmostEqual(m.read_ms_per_bucket, (612.0 - 23.0) / (1016 + hc.ReadCostModel.DST_WEIGHT * 256))
        self.assertAlmostEqual(m.clear_ms_per_bucket, (144.0 - 3.0) / 1600)
        # a model built without per-request parts and minimum (the other tests) learns from every read as before
        m = hc.ReadCostModel(fixed_ms=10.0, read_ms_per_bucket=1.0, clear_ms_per_bucket=1.0, alpha=1.0)
        m.update(1, 1, {"sync_ms": 10.0, "read_ms": 21.0, "clear_ms": 3.0, "overhead_ms": 0.0})
        self.assertEqual((m.read_ms_per_bucket, m.clear_ms_per_bucket), (21.0, 3.0))

    def test_reports_that_arrive_after_the_last_window_are_cleared_at_the_end(self):
        class LateCollector(FakeCollector):
            def __init__(self, reports, t0, window_sec, late):
                super().__init__(reports, t0, window_sec)
                self.late, self.since = late, []

            def take_after(self, start):
                self.since.append(start)
                return list(self.late)

        clock = FakeClock()
        t0 = clock.time()
        late = [report(900, proto=17), report(901, proto=17), report(900, proto=17)]
        collector = LateCollector({0: [report(1, proto=17)]}, t0, 0.05, late)
        reader = FakeReader()
        windows = hc.collect_windows_live(collector, FakeProc(3), 0.05, 0.0, t0, "reader.py", active_ttl_windows=3,
                                          clear_idle_windows=0, read_fn=reader, clock=clock, clear_expired=True)
        self.assertEqual(reader.calls[-1]["indexes"], [])                            # the end-of-run clear reads nothing
        self.assertEqual(reader.calls[-1]["clear_indexes"], [1, 900, 901])
        self.assertEqual(windows[-1]["late_report_indexes"], [900, 901])
        self.assertAlmostEqual(collector.since[0], t0 + len(windows) * 0.05)       # the reports after the last window
        self.assertGreater(len(collector.since), 1)                                  # it waited until they stopped
        self.assertGreaterEqual(clock.time() - collector.since[0], hc.LATE_REPORT_QUIET_S)

    def test_late_reports_wait_until_quiet_or_the_maximum(self):
        clock = FakeClock()
        arrivals = iter(range(1, 1000))                                              # a report per poll: never quiet
        got = hc.wait_for_late_reports(lambda since: [{"idx": 0}] * next(arrivals), 0.0, clock)
        self.assertGreaterEqual(clock.time() - 1000.0, hc.LATE_REPORT_MAX_S)
        self.assertGreater(len(got), 1)
        clock = FakeClock()
        self.assertEqual(hc.wait_for_late_reports(lambda since: [], 0.0, clock), [])
        self.assertLess(clock.time() - 1000.0, hc.LATE_REPORT_QUIET_S + 0.1)

    def test_payload_timing_falls_back_to_the_legacy_fields(self):
        t = hc.payload_timing_ms({"sync_s": 0.04, "read_s": 0.14, "clear_s": 0.01}, 220.0)
        self.assertEqual((t["sync_ms"], t["read_ms"], t["clear_ms"]), (40.0, 100.0, 10.0))
        self.assertAlmostEqual(t["overhead_ms"], 70.0)


class ProfileTests(unittest.TestCase):
    BASE = ["--mode", "command", "--scenario-name", "s", "--label", "benign", "--command", "true"]

    def test_the_switch_profile_sets_the_recommended_bundle(self):
        args = hc.build_arg_parser("switch").parse_args(self.BASE + ["--profile", "switch"])
        self.assertEqual((args.window_sec, args.active_ttl_windows, args.clear_idle_windows), (1.0, 3, 3))
        self.assertEqual((args.reader, args.reader_raw_wire, args.reader_sync_batched), ("batched", True, True))
        self.assertEqual((args.read_budget_frac, args.max_dst_reads, args.forward_report_port), (0.7, 256, 192))
        self.assertEqual((args.clear_expired, args.clear_budget_frac), (1, 0.5))

    def test_explicit_options_override_the_profile(self):
        args = hc.build_arg_parser("switch").parse_args(self.BASE + ["--profile", "switch", "--window-sec", "2",
                                                                      "--reader", "legacy"])
        self.assertEqual((args.window_sec, args.reader, args.active_ttl_windows), (2.0, "legacy", 3))

    def test_the_model_profile_and_the_unchanged_defaults(self):
        args = hc.build_arg_parser("model").parse_args(self.BASE + ["--profile", "model"])
        self.assertEqual((args.window_sec, args.p4_snapshot, args.p4_read_timeout, args.clear_idle_windows,
                          args.read_budget_frac, args.clear_expired), (60.0, "sync", 600.0, 0, 0.0, 0))
        plain = hc.build_arg_parser().parse_args(self.BASE)
        self.assertEqual((plain.window_sec, plain.active_ttl_windows, plain.reader, plain.read_budget_frac,
                          plain.p4_snapshot, plain.p4_read_timeout, plain.clear_expired),
                         (10.0, 5, "legacy", 0.0, "sync", 120.0, 0))

    def test_every_profile_key_is_an_option(self):
        dests = {a.dest for a in hc.build_arg_parser()._actions}
        for name, bundle in hc.PROFILES.items():
            self.assertTrue(set(bundle) <= dests, (name, set(bundle) - dests))


class CsvGuardTests(unittest.TestCase):
    def test_a_different_column_set_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "out.csv")
            hc.append_csv_rows(path, [{"a": 1, "b": 2}])
            hc.append_csv_rows(path, [{"a": 3, "b": 4}])
            with self.assertRaises(ValueError):
                hc.append_csv_rows(path, [{"a": 1, "b": 2, "c": 3}])
            self.assertEqual(Path(path).read_text().count("\n"), 3)   # header + 2 rows, nothing half-written


class InKernelMonitorProtocolTests(unittest.TestCase):
    def test_ready_start_time_window_and_health(self):
        with tempfile.TemporaryDirectory() as d:
            mon = Path(d) / "fake_hostmon_agg.py"
            mon.write_text(FAKE_MONITOR)
            mon.chmod(mon.stat().st_mode | stat.S_IXUSR)
            log = os.path.join(d, "monitor.txt")
            proc = hc.start_hostmon_agg(str(mon), log, 0.5, Path(d), use_sudo=False)
            try:
                self.assertTrue(hc.wait_for_line(log, "HOSTMON_READY", 10.0, proc).startswith("HOSTMON_READY,4242"))
                hc.send_hostmon_start(proc, time.monotonic() + 0.3)
                time.sleep(0.5)
                self.assertIsNone(proc.poll(), "the monitor must still run after a valid start time")
            finally:
                hc.stop_hostmon(proc)
            windows = hc.read_host_windows(log)
            self.assertEqual(len(windows), 1)
            self.assertEqual(hc.summarize_host_window(windows[0]["rows"])["host_total_syscalls_total"], 106)
            self.assertEqual(hc.hostmon_health(log), {"lost": 0, "capacity_errors": 0, "late_events": 0, "failed": 0})

    def test_a_start_in_the_past_is_rejected_by_the_monitor(self):
        with tempfile.TemporaryDirectory() as d:
            mon = Path(d) / "fake_hostmon_agg.py"
            mon.write_text(FAKE_MONITOR)
            mon.chmod(mon.stat().st_mode | stat.S_IXUSR)
            log = os.path.join(d, "monitor.txt")
            proc = hc.start_hostmon_agg(str(mon), log, 0.5, Path(d), use_sudo=False)
            hc.wait_for_line(log, "HOSTMON_READY", 10.0, proc)
            hc.send_hostmon_start(proc, time.monotonic() - 1.0)
            self.assertEqual(proc.wait(timeout=5), 1)
            with self.assertRaises(RuntimeError):
                hc.wait_for_line(log, "NEVER", 0.2, proc)

    def test_the_cgroup_wrapper_moves_the_shell_before_the_command(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "cgroup.procs").write_text("")
            out = os.path.join(d, "out.txt")
            argv = hc.cgroup_wrapped_command(f"echo $$ > {out}; echo done >> {out}", d)
            rc = hc.subprocess.run(argv).returncode
            self.assertEqual(rc, 0)
            moved = (Path(d) / "cgroup.procs").read_text().split()
            lines = Path(out).read_text().split()
            self.assertEqual(len(moved), 1)
            self.assertEqual(lines[-1], "done")
            self.assertEqual(moved[0], lines[0], "exec keeps the PID: the command runs as the process that was moved")

    def test_ensure_cgroup_checks_for_a_cgroup_v2_directory(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(RuntimeError):
                hc.ensure_cgroup(d)
            (Path(d) / "cgroup.procs").write_text("")
            path, created = hc.ensure_cgroup(d)
            self.assertEqual((path, created), (Path(d), False))


if __name__ == "__main__":
    unittest.main()
