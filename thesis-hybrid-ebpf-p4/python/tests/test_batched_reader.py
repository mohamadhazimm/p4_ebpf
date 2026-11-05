"""Acceptance tests of the batched gRPC register reader against the legacy
bfrt_python reader, on bfrt_mock (identical per-pipe register state for both).

  * equivalence: >= 100 windows of hybrid_collector.collect_windows_live with a
    changing active set (new flows, bursty flows, flows on two pipes, idle
    flows that are cleared and report again, counters that wrap mod 2^32,
    reg_newconn_dst buckets); windows and CSV rows must be identical
  * known answer: the 100-packet test connection of bucket 6886
  * idle clearing: cleared at the third unchanged read, re-reports from zero
  * RPC counts per window, chunking, fast/safe response parsing, sync
    operation names, missing registers, the serve protocol and the collector's
    BatchedReaderProcess (including a hung request that is retried)
"""
from __future__ import annotations

import ast
import contextlib
import copy
import csv
import inspect
import io
import json
import os
import random
import subprocess
import sys
import tempfile
import textwrap
import unittest
from argparse import Namespace
from pathlib import Path

HERE = Path(__file__).resolve().parent
PYDIR = HERE.parent
sys.path.insert(0, str(PYDIR))
sys.path.insert(0, str(PYDIR.parents[1]))  # repository root: hybrid_collector

import batched_reader  # noqa: E402
import bfrt_mock  # noqa: E402
import hybrid_collector as hc  # noqa: E402
from flow_index import compute_newconn_dst_index  # noqa: E402
from read_registers_with_index import INNER_TEMPLATE, build_inner_script  # noqa: E402

COMPARE_KEYS = ("flow_count", "snapshot", "errors", "dst_rows", "cleared", "rows")
M32 = 1 << 32


def run_legacy(switch, indexes, dst_indexes=(), clear_if_unchanged=None, snapshot="sync", strict=True):
    """The legacy reader's bfrt_python script on the mock, as bfshell would run it."""
    script = build_inner_script(indexes, "indices from CLI", "json", strict, snapshot,
                                clear_if_unchanged=clear_if_unchanged or {}, dst_indexes=list(dst_indexes))
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        exec(compile(script, "inner.py", "exec"),
             {"bfrt": bfrt_mock.legacy_view(switch), "__builtins__": __builtins__}, {})
    lines = [l for l in out.getvalue().splitlines() if l.startswith("{")]
    return json.loads(lines[-1])


def make_batched(switch, fast=True, chunk=4096, strict=True, addr="mock:1", sync_batched=False, client_id=7):
    bfrt_mock.serve(switch, addr)
    iface, info, bound = batched_reader.connect(bfrt_mock, addr, client_id, 0, "basic", bind=True)
    return batched_reader.BatchedRegisterReader(bfrt_mock, iface, info, p4_name="basic", strict=strict,
                                                chunk=chunk, fast=fast, sync_batched=sync_batched,
                                                p4_name_in_requests=not bound)


def run_batched(reader, indexes, dst_indexes=(), clear_if_unchanged=None, snapshot="sync"):
    payload = reader.read_window(indexes, list(dst_indexes), clear_if_unchanged or {}, snapshot)
    return json.loads(json.dumps(payload))  # as the collector receives it


def comparable(payload):
    return {k: payload[k] for k in COMPARE_KEYS}


# ---------------------------------------------------------------- traffic

def ip(k, host):
    return "10.%d.%d.%d" % ((k >> 8) & 0xFF, k & 0xFF, host)


class Scenario:
    """Deterministic traffic on a MockSwitch, window by window; window(w)
    applies the packets of window w and returns the CPU reports they cause."""

    KINDS = ["steady", "bursty", "multi_pipe", "idle_resume", "wrap", "replaced", "udp"]

    def __init__(self, switch, seed=1, n_windows=120):
        self.sw = switch
        self.rng = random.Random(seed)
        self.n_windows = n_windows
        idxs = self.rng.sample(range(1, 65536), 70)
        self.flows = []
        for k, idx in enumerate(idxs):
            kind = self.KINDS[k % len(self.KINDS)]
            start = 0 if k < 7 else self.rng.randrange(0, n_windows - 25)
            f = {"idx": idx, "kind": kind, "start": start, "len": self.rng.randrange(3, 12),
                 "src": ip(k, 1), "dst": ip(k, 2), "sport": 40000 + k, "dport": [80, 443, 22, 5001][k % 4],
                 "proto": 17 if kind == "udp" else 6, "ab_pipe": k % 2, "ba_pipe": (k + 1) % 2 if kind == "multi_pipe" else k % 2,
                 "sent": 0, "ba_sent": 0, "ts": 1000 + 97 * k}
            if kind == "wrap":
                p = f["ab_pipe"]
                switch.seed("reg_pkts", idx, p, M32 - 9)
                switch.seed("reg_bytes", idx, p, M32 - 3000)
                switch.seed("reg_pkts_ab", idx, p, M32 - 5)
                switch.seed("reg_bytes_ab", idx, p, M32 - 2000)
                switch.seed("reg_first_ts", idx, p, M32 - 50)   # the duration wraps too
            self.flows.append(f)

    def active(self, f, w):
        s, n = f["start"], f["len"]
        if f["kind"] in ("steady", "multi_pipe", "wrap", "udp"):
            return s <= w < s + n
        if f["kind"] == "bursty":
            return s <= w < s + 4 * n and (w - s) % 4 == 0
        if f["kind"] in ("idle_resume", "replaced"):
            # 3 windows of traffic, >= 6 idle windows (cleared at the third unchanged
            # read), then traffic again: the same 5-tuple, or a new one in the bucket.
            return s <= w < s + 3 or s + 9 <= w < s + 12
        raise AssertionError(f["kind"])

    def send(self, f, pipe, length, sport, dport, flags, reports):
        f["ts"] += 1250
        dst_idx = compute_newconn_dst_index(f["src"], f["dst"], dport, 6) if f["proto"] == 6 else None
        ab = (sport, dport) == (f["sport"], f["dport"])
        src, dst = (f["src"], f["dst"]) if ab else (f["dst"], f["src"])
        if self.sw.packet(f["idx"], pipe, length, sport, dport, f["proto"], flags, f["ts"],
                          dst_idx=compute_newconn_dst_index(src, dst, dport, 6) if f["proto"] == 6 else None):
            reports.append({"src_ip": src, "dst_ip": dst, "sport": sport, "dport": dport, "proto": f["proto"],
                            "reason": 1, "idx": f["idx"], "idx_source": "report", "idx_computed": f["idx"]})

    def window(self, w):
        reports = []
        for f in self.flows:
            if not self.active(f, w):
                continue
            if f["kind"] == "replaced" and w == f["start"] + 9:
                f["sport"] += 1000   # another connection lands in the same bucket
            n_ab = self.rng.randrange(1, 5)
            n_ba = self.rng.randrange(0, 4)
            for i in range(n_ab):
                flags = 0x02 if (f["sent"] == 0 and f["proto"] == 6) else 0x10
                if f["proto"] == 6 and self.rng.random() < 0.05:
                    flags |= 0x04
                self.send(f, f["ab_pipe"], self.rng.randrange(40, 1501), f["sport"], f["dport"], flags, reports)
                f["sent"] += 1
            for i in range(n_ba):
                flags = 0x12 if (f["ba_sent"] == 0 and f["proto"] == 6) else 0x10
                self.send(f, f["ba_pipe"], self.rng.randrange(40, 1501), f["dport"], f["sport"], flags, reports)
                f["ba_sent"] += 1
        return reports


class FakeTime:
    def __init__(self, now=1700000000.0):
        self.now = now

    def time(self):
        return self.now

    def sleep(self, dt):
        self.now += max(0.0, dt)


class FakeReports:
    def __init__(self, scenario):
        self.scenario = scenario
        self.w = 0

    def take(self, start, end):
        reports = self.scenario.window(self.w)
        self.w += 1
        return reports


class FakeProc:
    def __init__(self, reports, last_window):
        self.reports = reports
        self.last_window = last_window
        self.returncode = None

    def poll(self):
        if self.reports.w > self.last_window:
            self.returncode = 0
        return self.returncode


def run_pass(read_fn_factory, scenario_factory, n_windows, clear_idle_windows=3, ttl=5, window_sec=0.5):
    """collect_windows_live + NetSummarizer + build_rows on a fresh mock switch."""
    switch = bfrt_mock.MockSwitch(pipes=2)
    scenario = scenario_factory(switch)
    read_fn = read_fn_factory(switch)
    reports = FakeReports(scenario)
    proc = FakeProc(reports, n_windows - 1)
    fake = FakeTime()
    saved = hc.time
    hc.time = fake
    try:
        with contextlib.redirect_stdout(io.StringIO()) as out:
            windows = hc.collect_windows_live(
                collector=reports, proc=proc, window_sec=window_sec, drain_seconds=0.0, global_t0=fake.now,
                reader_path="unused", active_ttl_windows=ttl, switch_ssh=None, snapshot="sync",
                clear_idle_windows=clear_idle_windows, read_timeout=None, read_retries=0, on_window=None,
                read_fn=read_fn)
            summarizer = hc.NetSummarizer(window_sec)
            summaries = [summarizer.add(w) for w in windows]
            args = Namespace(scenario_name="equivalence", label="benign", mode="command", window_sec=window_sec)
            rows = hc.build_rows(args, "run_1", [], windows, summaries)
    finally:
        hc.time = saved
    text = io.StringIO()
    writer = csv.DictWriter(text, fieldnames=list(rows[0].keys()))
    writer.writeheader()
    writer.writerows(rows)
    return switch, windows, summaries, text.getvalue(), out.getvalue()


def legacy_factory(switch):
    return lambda idxs, w, **kw: run_legacy(switch, idxs, kw["dst_indexes"], kw["clear_if_unchanged"],
                                            kw["snapshot"])


def batched_factory(**opts):
    def factory(switch):
        reader = make_batched(switch, **opts)
        return lambda idxs, w, **kw: run_batched(reader, idxs, kw["dst_indexes"], kw["clear_if_unchanged"],
                                                 kw["snapshot"])
    return factory


# ---------------------------------------------------------------- known answer

def known_answer_packets():
    """perf/tools/make_test_pcaps.py sanity_packets(): the 100-packet test
    connection (51 A->B / 49 B->A, 32,440 bytes of IPv4 total length) that
    landed in bucket 6886 on the switch. (direction, flags, payload)."""
    sizes = [0, 1, 100, 500, 1000, 1460]
    seq = [("AB", 0x02, 0), ("BA", 0x12, 0), ("AB", 0x10, 0)]
    for i in range(92):
        if i % 2 == 0:
            seq.append(("AB", 0x18, sizes[(i // 2) % len(sizes)]))
        else:
            seq.append(("BA", 0x10, (i * 7) % 300))
    seq += [("AB", 0x11, 0), ("BA", 0x11, 0), ("AB", 0x10, 0), ("BA", 0x14, 0), ("AB", 0x04, 0)]
    assert len(seq) == 100
    return seq


KNOWN_IDX = 6886
KNOWN_ROW = {"idx": 6886, "pkts": 100, "bytes": 32440, "bpp": 324.4, "pkts_ab": 51, "pkts_ba": 49,
             "bytes_ab": 24068, "bytes_ba": 8372, "ref_src_port": 40001, "ref_dst_port": 5001, "dir_valid": 1,
             "min_len": 40, "max_len": 1500, "syn": 2, "ack": 98, "rst": 2, "duration_ns": 990000000,
             "pipes": [1], "multi_pipe": False}


def play_known_answer(switch, pipe=1):
    ts = M32 - 500000000  # the 32-bit timestamp wraps during the connection
    for d, flags, plen in known_answer_packets():
        sp, dp = (40001, 5001) if d == "AB" else (5001, 40001)
        switch.packet(KNOWN_IDX, pipe, 40 + plen, sp, dp, 6, flags, ts & 0xFFFFFFFF)
        ts += 10000000
    return switch


# ================================================================ tests

class SourceIdentityTests(unittest.TestCase):
    def test_combine_is_the_legacy_closure(self):
        start = INNER_TEMPLATE.index("    def combine(per_pipe):")
        end = INNER_TEMPLATE.index("        return row, pipes\n", start) + len("        return row, pipes\n")
        legacy = textwrap.dedent(INNER_TEMPLATE[start:end])
        self.assertEqual(inspect.getsource(batched_reader.combine), legacy)

    def test_row_fields_are_the_legacy_row(self):
        start = INNER_TEMPLATE.index("        pkts, byt = r[")
        end = INNER_TEMPLATE.index("        })\n", start)
        legacy = [l.strip() for l in INNER_TEMPLATE[start:end].splitlines() if l.strip()]
        legacy = [l for l in legacy if l != "rows.append({"]
        src = inspect.getsource(batched_reader.make_row)
        start = src.index("    pkts, byt = r[")
        end = src.index("    }\n", start)
        mine = [l.strip() for l in src[start:end].splitlines() if l.strip()]
        mine = [l for l in mine if l != "return {"]
        self.assertEqual(mine, legacy)

    def test_reader_and_mock_are_python2_compatible(self):
        for name in ("batched_reader.py", "bfrt_mock.py"):
            tree = ast.parse((PYDIR / name).read_text())
            for node in ast.walk(tree):
                self.assertNotIsInstance(node, (ast.JoinedStr, ast.AnnAssign, ast.AsyncFunctionDef, ast.Nonlocal,
                                                ast.YieldFrom, ast.Await), name)
                if hasattr(ast, "NamedExpr"):
                    self.assertNotIsInstance(node, ast.NamedExpr, name)
                if isinstance(node, ast.FunctionDef):
                    self.assertIsNone(node.returns, name)
                    self.assertFalse(node.args.kwonlyargs, "%s: keyword-only args in %s" % (name, node.name))
                    for a in node.args.args:
                        self.assertIsNone(a.annotation, name)

    def test_payload_keys_match_the_legacy_payload_and_rows_come_last(self):
        sw = bfrt_mock.MockSwitch()
        play_known_answer(sw)
        legacy = run_legacy(sw, [KNOWN_IDX])
        batched = make_batched(sw).read_window([KNOWN_IDX])
        self.assertEqual([k for k in batched if k != "timing"], list(legacy))
        self.assertEqual(list(batched)[-1], "rows")  # hybrid_collector's fallback parser needs this


class KnownAnswerTests(unittest.TestCase):
    def check_row(self, row):
        for key, value in KNOWN_ROW.items():
            self.assertEqual(row[key], value, key)
        self.assertEqual(row["pkts"] - row["pkts_ab"], 49)
        self.assertEqual(row["bytes"] - row["bytes_ab"], 8372)

    def test_bucket_6886_batched_fast_safe_and_legacy(self):
        sw = bfrt_mock.MockSwitch()
        play_known_answer(sw)
        fast = run_batched(make_batched(sw, fast=True), [KNOWN_IDX])
        safe = run_batched(make_batched(sw, fast=False), [KNOWN_IDX])
        legacy = run_legacy(sw, [KNOWN_IDX])
        self.check_row(fast["rows"][0])
        self.assertEqual(comparable(fast), comparable(safe))
        self.assertEqual(comparable(fast), comparable(legacy))
        self.assertTrue(fast["rows"][0]["first_ts"] > fast["rows"][0]["last_ts"])  # the timestamp wrapped

    def test_known_answer_from_seeded_registers(self):
        # The values as read on the switch, without the traffic model.
        sw = bfrt_mock.MockSwitch()
        values = {"reg_pkts": 100, "reg_bytes": 32440, "reg_pkts_ab": 51, "reg_bytes_ab": 24068,
                  "reg_min_len": 40, "reg_max_len": 1500, "reg_first_ts": M32 - 100000000,
                  "reg_last_ts": 890000000, "reg_syn": 2, "reg_ack": 98, "reg_rst": 2,
                  "reg_ref_src_port": 40001, "reg_ref_dst_port": 5001, "reg_dir_valid": 1}
        for name, v in values.items():
            sw.seed(name, KNOWN_IDX, 1, v)
        row = run_batched(make_batched(sw), [KNOWN_IDX])["rows"][0]
        self.check_row(row)
        self.assertEqual(row, run_legacy(sw, [KNOWN_IDX])["rows"][0])


class EquivalenceTests(unittest.TestCase):
    N_WINDOWS = 120

    def run_both(self, **batched_opts):
        n = self.N_WINDOWS
        legacy = run_pass(legacy_factory, lambda sw: Scenario(sw, 1, n), n)
        batched = run_pass(batched_factory(**batched_opts), lambda sw: Scenario(sw, 1, n), n)
        return legacy, batched

    @staticmethod
    def strip(windows):
        return [{k: v for k, v in w.items() if k not in ("p4_read_start_sec", "p4_read_sec")} for w in windows]

    def test_windows_and_csv_rows_are_identical_over_120_windows(self):
        (sw_l, win_l, sum_l, csv_l, out_l), (sw_b, win_b, sum_b, csv_b, out_b) = self.run_both()
        self.assertGreaterEqual(len(win_l), 100)
        self.assertEqual(len(win_l), len(win_b))
        for a, b in zip(self.strip(win_l), self.strip(win_b)):
            self.assertEqual(a, b)
        self.assertEqual(sum_l, sum_b)
        self.assertEqual(csv_l, csv_b)
        self.assertEqual(csv_l.count("\n"), len(win_l) + 1)
        # Both readers left the switch in the same state (same clears).
        self.assertEqual(sw_l.hw, sw_b.hw)
        self.assertEqual(sw_l.shadow, sw_b.shadow)
        self.assertNotIn("[WARN]", out_l + out_b)

        # The scenario covered what it should.
        cleared = [idx for w in win_b for idx in w["cleared_indexes"]]
        self.assertGreaterEqual(len(cleared), 8, "idle buckets cleared")
        reported_again = {idx for i, w in enumerate(win_b) for idx in w["indexes"]
                          if any(idx in prev["cleared_indexes"] for prev in win_b[:i])}
        self.assertGreaterEqual(len(reported_again), 4, "buckets that reported again after a clear")
        self.assertTrue(any(r["multi_pipe"] for w in win_b for r in w["rows"]), "flows on two pipes")
        self.assertTrue(any(w["dst_rows"] for w in win_b), "reg_newconn_dst rows")
        wrapped = 0
        last = {}
        for w in win_b:
            for r in w["rows"]:
                if last.get(r["idx"], 0) > (1 << 31) and r["pkts"] < (1 << 31):
                    wrapped += 1
                last[r["idx"]] = r["pkts"]
        self.assertGreaterEqual(wrapped, 2, "counters that wrapped mod 2^32")
        self.assertTrue(all(w["p4_snapshot"] == "sync" for w in win_b))
        busiest = max(len(w["active_indexes"]) for w in win_b)
        self.assertGreaterEqual(busiest, 10)
        self.assertTrue(any(s["net_pkts_total_delta"] > 0 for s in sum_b))

    def test_rpc_counts_per_window(self):
        (sw_l, win_l, _, _, _), (sw_b, win_b, _, _, _) = self.run_both()
        active_cells = sum(len(w["active_indexes"]) for w in win_l)
        dst_cells = sum(len(w["active_dst_indexes"]) for w in win_l)
        # Legacy: one get() per register per bucket (+ one per destination bucket), 14 (+1) syncs per window.
        self.assertEqual(sw_l.stats["legacy_gets"], 14 * active_cells + dst_cells)
        windows_with_dst = sum(1 for w in win_l if w["active_dst_indexes"])
        self.assertEqual(sw_l.stats["legacy_syncs"], 14 * len(win_l) + windows_with_dst)
        self.assertEqual(sw_l.stats["legacy_mods"], 14 * sum(len(w["cleared_indexes"]) for w in win_l))
        # Batched: one Sync write per table, 14 (+1) Reads, one clear write per window.
        windows_with_active = sum(1 for w in win_b if w["active_indexes"])
        windows_with_clears = sum(1 for w in win_b if w["cleared_indexes"])
        self.assertEqual(sw_b.stats["read_rpcs"], 14 * windows_with_active + windows_with_dst + 2)  # +2: self-check
        first_active = next(len(w["active_indexes"]) for w in win_b if w["active_indexes"])
        self.assertEqual(sw_b.stats["read_entities"], 14 * active_cells + dst_cells + 2 * min(4, first_active))
        self.assertEqual(sw_b.stats["sync_ops"], 14 * len(win_b) + windows_with_dst)
        self.assertEqual(sw_b.stats["write_rpcs"], 14 * len(win_b) + windows_with_dst + windows_with_clears)
        self.assertEqual(sw_b.stats["write_updates"], 14 * sum(len(w["cleared_indexes"]) for w in win_b))
        self.assertEqual(sw_b.stats["read_from_hw"], 0)
        # --sync-batched: the 14 (+1) Syncs of a window in one Write.
        sw_s, win_s, _, csv_s, _ = run_pass(batched_factory(sync_batched=True),
                                            lambda sw: Scenario(sw, 1, self.N_WINDOWS), self.N_WINDOWS)
        self.assertEqual(self.strip(win_s), self.strip(win_b))
        self.assertEqual(sw_s.stats["sync_ops"], sw_b.stats["sync_ops"])
        self.assertEqual(sw_s.stats["write_rpcs"], len(win_s) + windows_with_clears)

    def test_safe_parse_and_chunking_give_the_same_windows(self):
        (_, win_fast, _, csv_fast, _), (_, win_safe, _, csv_safe, _) = (
            run_pass(batched_factory(fast=True), lambda sw: Scenario(sw, 1, self.N_WINDOWS), self.N_WINDOWS),
            run_pass(batched_factory(fast=False), lambda sw: Scenario(sw, 1, self.N_WINDOWS), self.N_WINDOWS))
        self.assertEqual(self.strip(win_fast), self.strip(win_safe))
        self.assertEqual(csv_fast, csv_safe)
        sw_c, win_c, _, csv_c, _ = run_pass(batched_factory(chunk=7), lambda sw: Scenario(sw, 1, self.N_WINDOWS),
                                            self.N_WINDOWS)
        self.assertEqual(self.strip(win_fast), self.strip(win_c))
        expected_rpcs = sum(14 * -(-len(w["active_indexes"]) // 7) + -(-len(w["active_dst_indexes"]) // 7)
                            for w in win_c)
        self.assertEqual(sw_c.stats["read_rpcs"], expected_rpcs + 2)  # +2: the fast path's one-time self-check


class IdleClearingTests(unittest.TestCase):
    IDX = 777

    class Flow:
        def __init__(self, sw):
            self.sw = sw

        def window(self, w):
            reports = []
            if w in (0, 1, 2, 8):
                for i in range(3):
                    if self.sw.packet(IdleClearingTests.IDX, 1, 100, 40001, 80, 6, 0x10, 1000 * w + i):
                        reports.append({"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "sport": 40001, "dport": 80,
                                        "proto": 6, "reason": 1, "idx": IdleClearingTests.IDX,
                                        "idx_source": "report", "idx_computed": IdleClearingTests.IDX})
            return reports

    def check(self, factory):
        sw, windows, summaries, _, _ = run_pass(factory, self.Flow, 10)
        idx = self.IDX
        self.assertEqual(windows[0]["indexes"], [idx])
        self.assertEqual([w["cleared_indexes"] for w in windows[:6]], [[], [], [], [], [], [idx]])
        self.assertEqual([r["pkts"] for w in windows[:6] for r in w["rows"]], [3, 6, 9, 9, 9, 9])
        self.assertEqual(windows[6]["active_indexes"], [])
        self.assertEqual(sw.hw["reg_pkts"][idx], [0, 3], "cleared at window 5, three packets in window 8")
        self.assertEqual(windows[8]["indexes"], [idx], "the next packet reports again")
        self.assertEqual(windows[8]["rows"][0]["pkts"], 3)
        self.assertEqual([s["net_pkts_total_delta"] for s in summaries],
                         [3, 3, 3, 0, 0, 0, 0, 0, 3, 0])
        return windows

    def test_batched_reader_clears_at_the_third_unchanged_read_and_the_flow_reports_again(self):
        win_b = self.check(batched_factory())
        win_l = self.check(legacy_factory)
        self.assertEqual(EquivalenceTests.strip(win_b), EquivalenceTests.strip(win_l))

    def test_a_bucket_that_changed_since_the_decision_is_not_cleared(self):
        sw = bfrt_mock.MockSwitch()
        play_known_answer(sw)
        reader = make_batched(sw)
        payload = run_batched(reader, [KNOWN_IDX], clear_if_unchanged={KNOWN_IDX: 99})
        self.assertEqual(payload["cleared"], [])
        self.assertEqual(sw.hw["reg_pkts"][KNOWN_IDX][1], 100)
        payload = run_batched(reader, [KNOWN_IDX], clear_if_unchanged={KNOWN_IDX: 100})
        self.assertEqual(payload["cleared"], [KNOWN_IDX])
        self.assertEqual(payload["rows"][0]["pkts"], 100, "the row holds the values before the clear")
        self.assertTrue(all(sw.hw[n][KNOWN_IDX] == [0, 0] for n in bfrt_mock.REG_NAMES))
        self.assertNotIn(KNOWN_IDX, sw.hw["reg_newconn_dst"], "reg_newconn_dst is never cleared")


class VariantTests(unittest.TestCase):
    def test_sync_operation_name_variants_and_hardware_fallback(self):
        sw = bfrt_mock.MockSwitch(sync_ops=["SyncRegisters"])
        play_known_answer(sw)
        reader = make_batched(sw)
        self.assertEqual({t.sync_op for t in reader.flow_tables}, {"SyncRegisters"})
        payload = run_batched(reader, [KNOWN_IDX])
        self.assertEqual(payload["snapshot"], "sync")
        self.assertEqual(payload["rows"][0]["pkts"], 100)

        sw = bfrt_mock.MockSwitch(sync_ops=[])
        play_known_answer(sw)
        with contextlib.redirect_stderr(io.StringIO()):
            payload = run_batched(make_batched(sw), [KNOWN_IDX])
        legacy = run_legacy(sw, [KNOWN_IDX])
        self.assertEqual(payload["snapshot"], "hw")
        self.assertEqual(legacy["snapshot"], "hw")
        self.assertEqual(comparable(payload), comparable(legacy))
        self.assertGreater(sw.stats["read_from_hw"], 0)

    def test_reads_come_from_the_synced_snapshot(self):
        sw = bfrt_mock.MockSwitch()
        play_known_answer(sw)
        reader = make_batched(sw)
        self.assertEqual(run_batched(reader, [KNOWN_IDX])["rows"][0]["pkts"], 100)
        sw.packet(KNOWN_IDX, 1, 100, 40001, 5001, 6, 0x10, 5)
        self.assertEqual(run_batched(reader, [KNOWN_IDX], snapshot="hw")["rows"][0]["pkts"], 101)
        # Without a sync the shadow still holds the previous snapshot, as on the switch.
        tbl = reader.tables["reg_pkts"]
        self.assertEqual(reader._read_fast(tbl, [KNOWN_IDX], False, dict(read_rpcs=0, read_entities=0)),
                         {KNOWN_IDX: [0, 100]})
        self.assertEqual(run_batched(reader, [KNOWN_IDX])["rows"][0]["pkts"], 101)

    def test_missing_destination_register_is_reported_like_legacy(self):
        sw = bfrt_mock.MockSwitch(registers=bfrt_mock.REG_NAMES)
        play_known_answer(sw)
        batched = run_batched(make_batched(sw), [KNOWN_IDX], dst_indexes=[3])
        legacy = run_legacy(sw, [KNOWN_IDX], dst_indexes=[3])
        self.assertEqual(batched["errors"], ["Register is missing from pipeline: reg_newconn_dst"])
        self.assertEqual(comparable(batched), comparable(legacy))

    def test_missing_required_register_is_fatal_only_when_strict(self):
        sw = bfrt_mock.MockSwitch(registers=[n for n in bfrt_mock.REG_NAMES if n != "reg_bytes"])
        with self.assertRaises(RuntimeError):
            make_batched(sw, strict=True)
        payload = run_batched(make_batched(sw, strict=False), [5])
        legacy = run_legacy(sw, [5], strict=False)
        self.assertEqual(comparable(payload), comparable(legacy))

    def test_a_second_client_continues_unbound_while_another_holds_the_program(self):
        sw = bfrt_mock.MockSwitch()
        play_known_answer(sw)
        first = make_batched(sw, client_id=7)
        self.assertFalse(first.p4_name_in_requests)
        with contextlib.redirect_stderr(io.StringIO()) as err:
            second = make_batched(sw, client_id=8)
        self.assertIn("another client is bound", err.getvalue())
        self.assertTrue(second.p4_name_in_requests)
        self.assertEqual(comparable(run_batched(second, [KNOWN_IDX])), comparable(run_batched(first, [KNOWN_IDX])))
        first.close()
        third = make_batched(sw, client_id=9)   # the binding is free again
        self.assertFalse(third.p4_name_in_requests)

    def test_row_order_follows_the_requested_order(self):
        sw = bfrt_mock.MockSwitch()
        payload = run_batched(make_batched(sw), [9, 2, 65535, 0])
        self.assertEqual([r["idx"] for r in payload["rows"]], [9, 2, 65535, 0])
        self.assertEqual(payload["flow_count"], 4)

    def test_timing_logger_record(self):
        sw = bfrt_mock.MockSwitch()
        play_known_answer(sw)
        payload = run_batched(make_batched(sw), [KNOWN_IDX], clear_if_unchanged={KNOWN_IDX: 100})
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "timing.jsonl")
            log = hc.make_timing_logger("batched", path)
            with contextlib.redirect_stdout(io.StringIO()) as out:
                log(3, payload, 10.0, 10.25, 1, 0)
            record = json.loads(Path(path).read_text().splitlines()[-1])
        self.assertEqual((record["window"], record["reader"], record["active"], record["cleared"]), (3, "batched", 1, 1))
        self.assertAlmostEqual(record["wall_ms"], 250.0)
        self.assertEqual(record["rpcs"]["read_rpcs"], 14)
        self.assertIn("[TIMING] window 3: reader=batched active=1", out.getvalue())
        # The legacy payload has no "timing": its sync_s/read_s/clear_s are used.
        legacy = run_legacy(sw, [KNOWN_IDX])
        with contextlib.redirect_stdout(io.StringIO()) as out:
            hc.make_timing_logger("legacy")(0, legacy, 0.0, 1.5, 1, 0)
        self.assertIn("wall=1500.0 ms", out.getvalue())


class ServeProtocolTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        sw = bfrt_mock.MockSwitch()
        play_known_answer(sw)
        spec = {"pipes": 2, "cells": {name: {str(i): v for i, v in cells.items()} for name, cells in sw.hw.items()}}
        self.cells = os.path.join(self.dir.name, "cells.json")
        Path(self.cells).write_text(json.dumps(spec))
        self.script = str(PYDIR / "batched_reader.py")

    def test_collector_process_reads_through_the_serve_protocol(self):
        proc = hc.BatchedReaderProcess(self.script, grpc_addr="mock:serve", echo=False,
                                       extra_args=["--mock-cells", self.cells])
        try:
            ready = proc.start()
            self.assertTrue(ready["ready"])
            self.assertEqual(len(ready["tables"]), 14)
            payload = proc.read([KNOWN_IDX], dst_indexes=[1], clear_if_unchanged={KNOWN_IDX: 1}, timeout=30)
            self.assertEqual(payload["rows"][0]["pkts"], 100)
            self.assertEqual(payload["cleared"], [])
            self.assertEqual(payload["dst_rows"], [{"idx": 1, "new_conn": 0, "pipes": []}])
            payload = proc.read_with_retries([KNOWN_IDX], 1, retries=0, timeout=30,
                                             clear_if_unchanged={KNOWN_IDX: 100}, dst_indexes=[], snapshot="sync")
            self.assertEqual(payload["cleared"], [KNOWN_IDX])
            self.assertEqual(proc.read([KNOWN_IDX], timeout=30)["rows"][0]["pkts"], 0)
            self.assertEqual(proc.starts, 1)
        finally:
            proc.stop()

    def test_a_hung_request_is_retried_on_a_new_process(self):
        marker = os.path.join(self.dir.name, "hung.once")
        proc = hc.BatchedReaderProcess(self.script, grpc_addr="mock:hang", echo=False,
                                       extra_args=["--mock-cells", self.cells, "--mock-hang-on", "2",
                                                   "--mock-hang-marker", marker])
        saved_sleep = hc.time.sleep
        hc.time.sleep = lambda s: None
        try:
            with contextlib.redirect_stdout(io.StringIO()) as out:
                payload = proc.read_with_retries([KNOWN_IDX], 4, retries=1, timeout=2.0, dst_indexes=[],
                                                 clear_if_unchanged={}, snapshot="sync")
            self.assertEqual(payload["rows"][0]["pkts"], 100)
            self.assertEqual(proc.starts, 2)
            self.assertIn("window 4: register read attempt 1 failed (no answer within 2 s)", out.getvalue())
            with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(hc.P4ReadError):
                hc.BatchedReaderProcess(self.script, grpc_addr="mock:none", echo=False,
                                        extra_args=["--mock-cells", "/nonexistent.json"],
                                        start_timeout=20).read_with_retries([1], 5, retries=0, timeout=5)
        finally:
            hc.time.sleep = saved_sleep
            proc.stop()

    def test_one_shot_probe_and_bench_modes(self):
        env = dict(os.environ, PYTHONPATH=str(PYDIR))
        one = subprocess.run([sys.executable, self.script, "--mock-cells", self.cells, "--indexes", str(KNOWN_IDX),
                              "--format", "json"], capture_output=True, text=True, env=env, timeout=60)
        self.assertEqual(one.returncode, 0, one.stderr)
        payload = json.loads(one.stdout.strip().splitlines()[-1])
        self.assertEqual(payload["rows"][0]["bytes"], 32440)
        probe = subprocess.run([sys.executable, self.script, "--mock-cells", self.cells, "--probe"],
                               capture_output=True, text=True, env=env, timeout=60)
        self.assertEqual(probe.returncode, 0, probe.stderr)
        result = json.loads(probe.stdout.strip().splitlines()[-1])
        self.assertTrue(result["fast_equals_safe"])
        self.assertEqual(result["pipes"], 2)
        out = os.path.join(self.dir.name, "bench.json")
        bench = subprocess.run([sys.executable, self.script, "--mock-cells", self.cells, "--bench", "10,50",
                                "--bench-windows", "2", "--out", out], capture_output=True, text=True, env=env,
                               timeout=120)
        self.assertEqual(bench.returncode, 0, bench.stderr)
        table = json.loads(Path(out).read_text())["results"]
        self.assertEqual([r["active"] for r in table], [10, 50])
        self.assertEqual(table[1]["read_rpcs"], 14)
        self.assertIn("| 50 |", bench.stdout)


if __name__ == "__main__":
    unittest.main()
