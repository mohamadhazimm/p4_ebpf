from __future__ import annotations

import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))  # repository root

import hybrid_collector  # noqa: E402
from flow_index import compute_newconn_dst_index  # noqa: E402
from hybrid_collector import build_net_summaries, collect_windows_live  # noqa: E402


def row(idx, pkts, pkts_ab, nbytes, bytes_ab, first_ts=0, last_ts=0):
    return {"idx": idx, "pkts": pkts, "pkts_ab": pkts_ab, "bytes": nbytes, "bytes_ab": bytes_ab,
            "syn": 0, "ack": 0, "rst": 0, "min_len": 40, "max_len": 1500,
            "first_ts": first_ts, "last_ts": last_ts, "dir_valid": 1}


class BuildNetSummariesTests(unittest.TestCase):
    def test_each_window_gets_the_traffic_of_that_window(self):
        windows = [
            {"rows": [row(3, 10, 6, 1000, 600)]},
            {"rows": [row(3, 25, 15, 2500, 1500)]},
            {"rows": []},
        ]
        s = build_net_summaries(windows, window_sec=10.0)
        self.assertEqual((s[0]["net_pkts_total_delta"], s[0]["net_pkts_ab_delta"], s[0]["net_pkts_ba_delta"]),
                         (10, 6, 4))
        self.assertEqual((s[1]["net_pkts_total_delta"], s[1]["net_pkts_ab_delta"], s[1]["net_pkts_ba_delta"]),
                         (15, 9, 6))
        self.assertEqual(s[1]["net_bytes_total_delta"], 1500)
        self.assertEqual(s[2]["net_pkts_total_delta"], 0)

    def test_duration_survives_the_32_bit_timestamp_wrap(self):
        s = build_net_summaries([{"rows": [row(1, 2, 2, 100, 100, first_ts=(1 << 32) - 10, last_ts=90)]}], 10.0)
        self.assertEqual(s[0]["net_flow_duration_max"], 100.0)

    def test_a_cleared_bucket_counts_its_new_flow_from_zero(self):
        windows = [
            {"rows": [row(5, 10, 10, 1000, 1000)], "cleared_indexes": [5]},
            {"rows": [row(5, 3, 3, 300, 300)]},
        ]
        s = build_net_summaries(windows, 10.0)
        self.assertEqual([w["net_pkts_total_delta"] for w in s], [10, 3])

    def test_new_conn_dst_max_is_the_largest_bucket_increase(self):
        windows = [
            {"rows": [row(3, 1, 1, 60, 60)], "dst_rows": [{"idx": 11, "new_conn": 700}, {"idx": 12, "new_conn": 20}]},
            {"rows": [row(3, 2, 2, 120, 120)], "dst_rows": [{"idx": 11, "new_conn": 1400}, {"idx": 12, "new_conn": 90}]},
            {"rows": [], "dst_rows": [{"idx": 12, "new_conn": 100}]},
            {"rows": [row(3, 2, 2, 120, 120)], "dst_rows": [{"idx": 11, "new_conn": 1400}]},
        ]
        s = build_net_summaries(windows, 0.5)
        self.assertEqual([w["net_new_conn_dst_max"] for w in s], [700, 700, 10, 0])


class FakeCollector:
    # Reports of flows 10.0.0.1:(1000 + idx) -> 10.0.0.2:80 with protocol proto.
    def __init__(self, reports_by_window, t0, window_sec, proto=17):
        self.reports, self.t0, self.window_sec, self.proto = reports_by_window, t0, window_sec, proto

    def take(self, start, end):
        w = round((start - self.t0) / self.window_sec)
        return [{"idx": i, "idx_source": "report", "idx_computed": i, "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
                 "sport": 1000 + i, "dport": 80, "proto": self.proto} for i in self.reports.get(w, [])]


class FakeProc:
    def __init__(self, windows):
        self.windows, self.calls = windows, 0

    def poll(self):
        self.calls += 1
        return 0 if self.calls >= self.windows else None


class CollectWindowsLiveTests(unittest.TestCase):
    def run_windows(self, reports, pkts_by_window, n_windows, ttl, clear_idle, proto=17, new_conn_by_window=None):
        calls = []

        def fake_reader(reader_path, indexes, switch_ssh=None, snapshot="sync", clear_if_unchanged=None,
                        dst_indexes=None):
            w = len(calls)
            calls.append({"indexes": list(indexes), "clear": dict(clear_if_unchanged or {}),
                          "dst_indexes": list(dst_indexes or [])})
            rows = [row(i, pkts_by_window.get(w, {}).get(i, 0), 0, 0, 0) for i in indexes]
            cleared = [i for i, p in (clear_if_unchanged or {}).items()
                       if pkts_by_window.get(w, {}).get(i, 0) == p]
            dst_rows = [{"idx": i, "new_conn": (new_conn_by_window or {}).get(w, 0)} for i in dst_indexes or []]
            return {"rows": rows, "dst_rows": dst_rows, "cleared": cleared, "snapshot": snapshot}

        saved = hybrid_collector.run_p4_reader_json
        hybrid_collector.run_p4_reader_json = fake_reader
        try:
            window_sec, t0 = 0.02, time.time()
            windows = collect_windows_live(FakeCollector(reports, t0, window_sec, proto), FakeProc(n_windows),
                                           window_sec, 0.0, t0, "reader.py", ttl, clear_idle_windows=clear_idle)
        finally:
            hybrid_collector.run_p4_reader_json = saved
        return windows, calls

    def test_a_flow_that_keeps_sending_stays_active_beyond_the_ttl(self):
        # One report in window 0, then the counter grows every window (TTL is 2).
        pkts = {w: {7: 10 * (w + 1)} for w in range(20)}
        windows, calls = self.run_windows({0: [7]}, pkts, 8, ttl=2, clear_idle=0)
        self.assertGreaterEqual(len(windows), 8)  # one more window drains after the workload ends
        self.assertTrue(all(c["indexes"] == [7] for c in calls))

    def test_an_idle_bucket_is_cleared_and_dropped(self):
        # Bucket 5: report in window 0 (10 packets), then no new packets.
        pkts = {w: {5: 10} for w in range(8)}
        windows, calls = self.run_windows({0: [5]}, pkts, 8, ttl=10, clear_idle=3)
        self.assertEqual([c["clear"] for c in calls[:4]], [{}, {}, {}, {5: 10}])
        self.assertEqual(windows[3]["cleared_indexes"], [5])
        self.assertTrue(all(c["indexes"] == [] for c in calls[4:]))  # no longer read
        self.assertTrue(all(c["dst_indexes"] == [] for c in calls))  # UDP reports name no destination bucket

    def test_tcp_reports_name_their_destination_bucket(self):
        # Three flows of one client to one service in window 0: one destination
        # bucket. Its count grows until window 3; with TTL 1 it is read through
        # window 4 and then dropped.
        dst = compute_newconn_dst_index("10.0.0.1", "10.0.0.2", 80, 6)
        new_conn = {0: 3, 1: 50, 2: 90, 3: 120}
        new_conn.update({w: 120 for w in range(4, 12)})
        windows, calls = self.run_windows({0: [4, 5, 6]}, {}, 9, ttl=1, clear_idle=0, proto=6,
                                          new_conn_by_window=new_conn)
        self.assertEqual(windows[0]["dst_indexes"], [dst])
        self.assertEqual([c["dst_indexes"] for c in calls[:7]], [[dst]] * 5 + [[], []])
        s = build_net_summaries(windows, 0.02)
        self.assertEqual([w["net_new_conn_dst_max"] for w in s[:6]], [3, 47, 40, 30, 0, 0])


if __name__ == "__main__":
    unittest.main()
