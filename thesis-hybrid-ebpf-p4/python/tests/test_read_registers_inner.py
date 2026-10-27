from __future__ import annotations

import ast
import contextlib
import io
import json
import unittest

from read_registers_with_index import build_inner_script

REGS = ["reg_pkts", "reg_bytes", "reg_pkts_ab", "reg_bytes_ab", "reg_ref_src_port",
        "reg_ref_dst_port", "reg_dir_valid", "reg_min_len", "reg_max_len",
        "reg_first_ts", "reg_last_ts", "reg_syn", "reg_ack", "reg_rst"]


class Entry:
    def __init__(self, name, values):
        self.data = {("Ingress.%s.f1" % name).encode(): values}


class FakeRegister:
    def __init__(self, name, cells, sync=True):
        self.name, self.cells, self.reads, self.synced = name, cells, [], False
        if not sync:
            self.operation_register_sync = None

    def get(self, REGISTER_INDEX, from_hw, print_ents):
        self.reads.append(from_hw)
        return Entry(self.name, list(self.cells.get(REGISTER_INDEX, [0, 0])))

    def operation_register_sync(self, cb):  # replaced by None when sync is unsupported
        self.synced = True
        cb(0, 0xFFFF, 0, 0)

    def mod(self, REGISTER_INDEX, f1):
        self.cells[REGISTER_INDEX] = [f1, f1]
        self.mods = getattr(self, "mods", []) + [(REGISTER_INDEX, f1)]


class FakeBfrt:
    def __init__(self, cells, sync=True):
        names = REGS + [n for n in cells if n not in REGS]
        regs = {n: FakeRegister(n, {i: list(v) for i, v in cells.get(n, {}).items()}, sync) for n in names}
        self.regs = regs
        ingress = type("Ingress", (), dict(regs))
        pipe = type("Pipe", (), {"Ingress": ingress})
        self.basic = type("Prog", (), {"pipe": pipe})

    def complete_operations(self):
        pass


CELLS = {  # index -> per-pipe values [pipe0, pipe1]
    "reg_pkts": {5: [0, 10], 7: [3, 4]},
    "reg_bytes": {5: [0, 1000], 7: [300, 400]},
    "reg_pkts_ab": {5: [0, 6], 7: [3, 4]},
    "reg_bytes_ab": {5: [0, 600], 7: [300, 400]},
    "reg_ref_src_port": {5: [0, 1234], 7: [11, 22]},
    "reg_ref_dst_port": {5: [0, 80], 7: [33, 44]},
    "reg_dir_valid": {5: [0, 1], 7: [1, 1]},
    "reg_min_len": {5: [0, 40], 7: [60, 40]},
    "reg_max_len": {5: [0, 1500], 7: [100, 200]},
    "reg_first_ts": {5: [0, 100], 7: [500, 300]},
    "reg_last_ts": {5: [0, 50], 7: [900, 800]},
    "reg_syn": {5: [0, 1]},
    "reg_ack": {5: [0, 9]},
}


def run_inner(script, bfrt):
    # bfrt_python (SDE 9.6) runs a script with separate globals and locals.
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        exec(compile(script, "inner.py", "exec"), {"bfrt": bfrt, "__builtins__": __builtins__}, {})
    lines = [l for l in out.getvalue().splitlines() if l.startswith("{")]
    return json.loads(lines[-1])


class InnerScriptTests(unittest.TestCase):
    def test_no_fstrings_for_python_3_4(self):
        tree = ast.parse(build_inner_script([1], "t", "json", False, "sync"))
        self.assertFalse(any(isinstance(n, ast.JoinedStr) for n in ast.walk(tree)))

    def test_rows_combine_pipes_and_derive_reverse_direction(self):
        bfrt = FakeBfrt(CELLS)
        payload = run_inner(build_inner_script([5, 7, 9], "t", "json", True, "sync"), bfrt)
        rows = {r["idx"]: r for r in payload["rows"]}
        self.assertEqual(payload["snapshot"], "sync")
        self.assertEqual(list(payload)[-1], "rows")  # hybrid_collector's fallback parser needs this

        r = rows[5]
        self.assertEqual((r["pkts"], r["pkts_ab"], r["pkts_ba"]), (10, 6, 4))
        self.assertEqual((r["bytes"], r["bytes_ab"], r["bytes_ba"]), (1000, 600, 400))
        self.assertEqual((r["min_len"], r["max_len"], r["syn"], r["ack"], r["rst"]), (40, 1500, 1, 9, 0))
        self.assertEqual((r["ref_src_port"], r["ref_dst_port"], r["dir_valid"]), (1234, 80, 1))
        self.assertEqual(r["duration_ns"], (1 << 32) - 50)  # last_ts wrapped past first_ts
        self.assertEqual((r["pipes"], r["multi_pipe"]), ([1], False))

        r = rows[7]
        self.assertEqual((r["pkts"], r["bytes"], r["min_len"], r["max_len"]), (7, 700, 40, 200))
        self.assertEqual((r["first_ts"], r["last_ts"], r["ref_src_port"]), (300, 900, 11))
        self.assertEqual((r["pipes"], r["multi_pipe"]), ([0, 1], True))

        r = rows[9]
        self.assertEqual((r["pkts"], r["dir_valid"], r["pipes"], r["duration_ns"]), (0, 0, [], 0))

        self.assertTrue(all(reg.synced for reg in bfrt.regs.values()))
        self.assertTrue(all(not from_hw for reg in bfrt.regs.values() for from_hw in reg.reads))

    def test_hw_snapshot_reads_hardware(self):
        bfrt = FakeBfrt(CELLS)
        payload = run_inner(build_inner_script([5], "t", "json", True, "hw"), bfrt)
        self.assertEqual(payload["snapshot"], "hw")
        self.assertTrue(all(from_hw for reg in bfrt.regs.values() for from_hw in reg.reads))

    def test_sync_falls_back_to_hardware_reads_when_unsupported(self):
        bfrt = FakeBfrt(CELLS, sync=False)
        payload = run_inner(build_inner_script([5], "t", "json", True, "sync"), bfrt)
        self.assertEqual(payload["snapshot"], "hw")
        self.assertEqual(payload["rows"][0]["pkts"], 10)

    def test_unchanged_buckets_are_cleared_after_the_read(self):
        bfrt = FakeBfrt(CELLS)
        # Bucket 5 still holds 10 packets (idle): cleared. Bucket 7 changed (7 != 5): kept.
        payload = run_inner(build_inner_script([5, 7], "t", "json", True, "sync",
                                               clear_if_unchanged={5: 10, 7: 5}), bfrt)
        self.assertEqual(payload["cleared"], [5])
        self.assertEqual({r["idx"]: r["pkts"] for r in payload["rows"]}, {5: 10, 7: 7})  # values before the clear
        for reg in bfrt.regs.values():
            self.assertEqual(reg.mods, [(5, 0)])
            self.assertEqual(reg.cells[5], [0, 0])
        self.assertEqual(list(payload)[-2:], ["cleared", "rows"])

    def test_destination_buckets_are_read_and_never_cleared(self):
        bfrt = FakeBfrt(dict(CELLS, reg_newconn_dst={3: [0, 700], 4: [2, 5]}))
        payload = run_inner(build_inner_script([5], "t", "json", True, "sync", clear_if_unchanged={5: 10},
                                               dst_indexes=[3, 4, 8]), bfrt)
        self.assertEqual([(r["idx"], r["new_conn"], r["pipes"]) for r in payload["dst_rows"]],
                         [(3, 700, [1]), (4, 7, [0, 1]), (8, 0, [])])
        dst = bfrt.regs["reg_newconn_dst"]
        self.assertTrue(dst.synced and all(not from_hw for from_hw in dst.reads))
        self.assertEqual(payload["cleared"], [5])
        self.assertFalse(hasattr(dst, "mods"))  # clearing flow bucket 5 leaves it alone
        self.assertEqual(list(payload)[-2:], ["cleared", "rows"])

    def test_missing_destination_register_is_reported_not_fatal(self):
        payload = run_inner(build_inner_script([5], "t", "json", True, "sync", dst_indexes=[3]), FakeBfrt(CELLS))
        self.assertEqual(payload["dst_rows"], [])
        self.assertEqual(payload["errors"], ["Register is missing from pipeline: reg_newconn_dst"])
        self.assertEqual(payload["rows"][0]["pkts"], 10)

    def test_summary_format_runs(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            exec(compile(build_inner_script([5, 7], "t", "summary", False, "hw"), "inner.py", "exec"),
                 {"bfrt": FakeBfrt(CELLS), "__builtins__": __builtins__}, {})
        self.assertIn("Flows: 2", out.getvalue())
        self.assertIn("Flows seen in more than one pipe: 1", out.getvalue())


if __name__ == "__main__":
    unittest.main()
