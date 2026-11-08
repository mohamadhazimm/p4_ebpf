"""Tests of the dataset profile of hybrid_collector.py (RUNBOOK 19.9): frame bytes, durations in seconds with the
32-bit wrap resolved, dormant reads instead of clears, a fixed number of windows with the scenario stopped after the
last read, the dataset's launcher, and the timing log's extra fields. No switch, no BPF, no root."""
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))  # repository root
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
    def __init__(self, reports_by_window, t0, window_sec):
        self.reports, self.t0, self.window_sec = reports_by_window, t0, window_sec

    def take(self, start, end):
        w = round((start - self.t0) / self.window_sec)
        return [{"idx": i, "idx_source": "report", "idx_computed": i, "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
                 "sport": 1000 + i, "dport": 80, "proto": 17} for i in self.reports.get(w, [])]


class NeverEndingProc:
    def poll(self):
        return None


class Reader:
    """Register reader: pkts_fn(window, idx) gives a bucket's packet count; fixed sync 10 ms and 5 ms per bucket,
    taken from the clock when given. Every clear requested succeeds."""

    SYNC_MS, READ_MS = 10.0, 5.0

    def __init__(self, pkts_fn, clock=None):
        self.pkts_fn, self.clock, self.calls = pkts_fn, clock, []

    def __call__(self, indexes, w, snapshot="sync", clear_if_unchanged=None, dst_indexes=None, clear_indexes=None):
        self.calls.append({"w": w, "indexes": list(indexes), "clear": dict(clear_if_unchanged or {}),
                           "clear_indexes": list(clear_indexes or [])})
        read_ms = self.READ_MS * len(indexes)
        if self.clock is not None:
            self.clock.advance((self.SYNC_MS + read_ms) / 1000.0)
        cleared = sorted(set(clear_if_unchanged or {}) | set(clear_indexes or []))
        return {"rows": [mkrow(i, self.pkts_fn(w, i)) for i in indexes], "dst_rows": [], "cleared": cleared,
                "snapshot": snapshot, "timing": {"sync_ms": self.SYNC_MS, "read_ms": read_ms, "clear_ms": 0.0}}


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
        self.assertEqual((args.clear_expired, args.dormant_reads), (0, 1))
        self.assertEqual((args.byte_layer, args.duration_unit, args.launcher), ("frame", "s", "dataset"))

    def test_the_new_options_default_to_the_old_behaviour(self):
        plain = hc.build_arg_parser().parse_args(self.BASE)
        self.assertEqual((plain.dormant_reads, plain.byte_layer, plain.duration_unit, plain.windows, plain.launcher),
                         (0, "ipv4", "ns", 0, "shell"))


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
