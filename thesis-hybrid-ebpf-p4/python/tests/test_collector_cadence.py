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


class FakeReader:
    """Register reader whose payload carries a timing block: fixed sync 10 ms, 5 ms per bucket read."""

    def __init__(self):
        self.calls = []

    def __call__(self, indexes, w, snapshot="sync", clear_if_unchanged=None, dst_indexes=None):
        self.calls.append({"w": w, "indexes": list(indexes), "dst": list(dst_indexes or []),
                           "clear": dict(clear_if_unchanged or {})})
        return {"rows": [mkrow(i, 10 * (w + 1)) for i in indexes],
                "dst_rows": [{"idx": i, "new_conn": 3} for i in (dst_indexes or [])], "cleared": [],
                "snapshot": snapshot, "timing": {"sync_ms": 10.0, "read_ms": 5.0 * len(indexes), "clear_ms": 0.0}}


class ReadBudgetTests(unittest.TestCase):
    def run_live(self, reports, n_windows, **kw):
        reader = FakeReader()
        window_sec, t0 = 0.05, time.time()
        windows = hc.collect_windows_live(FakeCollector(reports, t0, window_sec), FakeProc(n_windows), window_sec, 0.0,
                                          t0, "reader.py", active_ttl_windows=3, clear_idle_windows=0, read_fn=reader,
                                          **kw)
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
        self.assertEqual(set(hc.REPORT_ZERO), set(agg))

    def test_the_budget_limits_the_read_to_the_most_recent_buckets(self):
        # 50 ms window, 80% budget = 40 ms; fixed 10 ms + 5 ms per bucket -> 6 buckets fit.
        cost = hc.ReadCostModel(fixed_ms=10.0, read_ms_per_bucket=5.0, clear_ms_per_bucket=1.0)
        reports = {0: [report(i) for i in range(10)], 1: [report(10), report(11)]}
        windows, reader = self.run_live(reports, 3, read_budget_frac=0.8, cost_model=cost)
        self.assertEqual(reader.calls[0]["indexes"], [0, 1, 2, 3, 4, 5])          # ties by index
        self.assertEqual(windows[0]["skipped_count"], 4)
        self.assertTrue(windows[0]["overload"])
        self.assertEqual(windows[0]["report_aggregates"]["net_buckets_skipped"], 4)
        self.assertEqual(windows[0]["report_aggregates"]["net_buckets_active"], 10)
        # window 1: the two new buckets (last seen 1) come first, then the oldest indexes of window 0
        self.assertEqual(reader.calls[1]["indexes"], [0, 1, 2, 3, 10, 11])
        self.assertEqual(windows[1]["report_aggregates"]["net_read_budget_ms"], 40.0)
        # the cost model followed the fake reader's 5 ms per bucket and its 10 ms sync (+ IPC overhead)
        self.assertAlmostEqual(cost.read_ms_per_bucket, 5.0, places=6)
        self.assertGreaterEqual(cost.fixed_ms, 10.0)

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
        self.assertEqual((args.read_budget_frac, args.max_dst_reads, args.forward_report_port), (0.8, 256, 192))

    def test_explicit_options_override_the_profile(self):
        args = hc.build_arg_parser("switch").parse_args(self.BASE + ["--profile", "switch", "--window-sec", "2",
                                                                      "--reader", "legacy"])
        self.assertEqual((args.window_sec, args.reader, args.active_ttl_windows), (2.0, "legacy", 3))

    def test_the_model_profile_and_the_unchanged_defaults(self):
        args = hc.build_arg_parser("model").parse_args(self.BASE + ["--profile", "model"])
        self.assertEqual((args.window_sec, args.p4_snapshot, args.p4_read_timeout, args.clear_idle_windows,
                          args.read_budget_frac), (60.0, "sync", 600.0, 0, 0.0))
        plain = hc.build_arg_parser().parse_args(self.BASE)
        self.assertEqual((plain.window_sec, plain.active_ttl_windows, plain.reader, plain.read_budget_frac,
                          plain.p4_snapshot, plain.p4_read_timeout), (10.0, 5, "legacy", 0.0, "sync", 120.0))

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
