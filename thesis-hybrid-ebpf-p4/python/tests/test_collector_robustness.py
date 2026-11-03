from __future__ import annotations

import ast
import contextlib
import csv
import io
import os
import stat
import subprocess
import sys
import tempfile
import time
import types
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))  # repository root

import hybrid_collector  # noqa: E402
import reset_registers  # noqa: E402
from hybrid_collector import (NetSummarizer, P4ReadError, RunWriter, build_net_summaries,  # noqa: E402
                              read_p4_with_retries, start_hostmon, stop_hostmon)


# ---------------------------------------------------------------- reset script

class Entry:
    def __init__(self, name, values):
        self.data = {("Ingress.%s.f1" % name).encode(): values}


class FakeRegister:
    def __init__(self, name, broken=False):
        self.name, self.broken, self.cleared = name, broken, False
        self.cells = {i: [7, 7] for i in reset_registers.CHECK_INDEXES}

    def clear(self):
        self.cleared = True
        if not self.broken:
            self.cells = {}

    def get(self, REGISTER_INDEX, from_hw, print_ents):
        assert from_hw is True
        return [Entry(self.name, list(self.cells.get(REGISTER_INDEX, [0, 0])))]


def fake_bfrt(names, broken=()):
    regs = {n: FakeRegister(n, n in broken) for n in names}
    ingress = type("Ingress", (), dict(regs))
    pipe = type("Pipe", (), {"Ingress": ingress})
    bfrt = types.SimpleNamespace(basic=type("Prog", (), {"pipe": pipe}), complete_operations=lambda: None)
    return bfrt, regs


def run_reset_inner(bfrt):
    # bfrt_python (SDE 9.6) runs a script with separate globals and locals.
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        exec(compile(reset_registers.build_inner_script(), "reset.py", "exec"),
             {"bfrt": bfrt, "__builtins__": __builtins__}, {})
    return out.getvalue().splitlines()


class ResetScriptTests(unittest.TestCase):
    def test_no_fstrings_for_python_3_4(self):
        tree = ast.parse(reset_registers.build_inner_script())
        self.assertFalse([n for n in ast.walk(tree) if isinstance(n, ast.JoinedStr)])

    def test_clears_and_checks_every_register(self):
        bfrt, regs = fake_bfrt(reset_registers.REGISTERS)
        lines = run_reset_inner(bfrt)
        self.assertTrue(all(r.cleared for r in regs.values()))
        self.assertEqual(len(regs), 15)
        self.assertTrue(lines[-1].startswith("[RESET-OK] 15 registers cleared"))

    def test_a_build_without_a_register_skips_it(self):
        bfrt, regs = fake_bfrt([n for n in reset_registers.REGISTERS if n != "reg_newconn_dst"])
        lines = run_reset_inner(bfrt)
        self.assertIn("[RESET-SKIP] reg_newconn_dst is not in this build", lines)
        self.assertTrue(lines[-1].startswith("[RESET-OK] 14 registers cleared"))

    def test_a_register_that_is_not_zero_after_clear_fails(self):
        bfrt, _ = fake_bfrt(reset_registers.REGISTERS, broken={"reg_dir_valid"})
        lines = run_reset_inner(bfrt)
        self.assertTrue(any(l.startswith("[RESET-FAIL] reg_dir_valid") for l in lines))
        self.assertFalse(any(l.startswith("[RESET-OK]") for l in lines))

    def test_reset_is_retried_until_it_completes(self):
        outputs = iter(["bfshell> exit\n", "[RESET] reg_pkts 0.1 s\n[RESET-OK] 15 registers cleared in 1.0 s\n"])
        saved = reset_registers.run_bfshell_script
        reset_registers.run_bfshell_script = lambda *a, **k: next(outputs)
        try:
            with contextlib.redirect_stderr(io.StringIO()):
                lines = reset_registers.reset_registers(attempts=3, retry_delay=0)
        finally:
            reset_registers.run_bfshell_script = saved
        self.assertEqual(lines[-1], "[RESET-OK] 15 registers cleared in 1.0 s")

    def test_reset_fails_after_its_attempts(self):
        saved = reset_registers.run_bfshell_script
        reset_registers.run_bfshell_script = lambda *a, **k: "[RESET-FAIL] reg_pkts is not zero at [0]\n"
        try:
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(RuntimeError):
                reset_registers.reset_registers(attempts=2, retry_delay=0)
        finally:
            reset_registers.run_bfshell_script = saved


# ---------------------------------------------------------------- read retries

class ReadRetryTests(unittest.TestCase):
    def with_reader(self, fake):
        saved = hybrid_collector.run_p4_reader_json
        hybrid_collector.run_p4_reader_json = fake
        self.addCleanup(setattr, hybrid_collector, "run_p4_reader_json", saved)

    def test_a_failed_read_is_retried(self):
        calls = []

        def fake(reader_path, indexes, **kwargs):
            calls.append(kwargs)
            if len(calls) == 1:
                raise subprocess.CalledProcessError(1, ["reader"], stderr="BfshellError: bfshell did not finish")
            return {"rows": [], "dst_rows": [], "cleared": []}

        self.with_reader(fake)
        with contextlib.redirect_stdout(io.StringIO()) as out:
            payload = read_p4_with_retries("reader.py", [3], window=4, retries=2, timeout=30, snapshot="hw")
        self.assertEqual(payload["rows"], [])
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0], {"snapshot": "hw", "timeout": 30})
        self.assertIn("window 4: register read attempt 1 failed", out.getvalue())
        self.assertIn("bfshell did not finish", out.getvalue())

    def test_a_busy_python_shell_waits_longer_and_is_named(self):
        # A client killed on timeout leaves its script running on the switch;
        # bf_switchd then refuses the next Python shell.
        busy = ("[ERROR] no register payload in the bfshell output:\n"
                "Only one Python shell instance allowed at a time. bfrt python and debug python share "
                "the python shell resource.\n\nbfshell> exit\n")
        calls, waits = [], []

        def fake(reader_path, indexes, **kwargs):
            calls.append(1)
            if len(calls) == 1:
                raise subprocess.CalledProcessError(1, ["reader"], stderr=busy)
            return {"rows": []}

        self.with_reader(fake)
        saved_sleep = hybrid_collector.time.sleep
        hybrid_collector.time.sleep = waits.append
        try:
            with contextlib.redirect_stdout(io.StringIO()) as out:
                read_p4_with_retries("reader.py", [1], window=2, retries=1)
        finally:
            hybrid_collector.time.sleep = saved_sleep
        self.assertEqual(waits, [15.0])
        self.assertIn("Only one Python shell instance allowed", out.getvalue())

    def test_no_timeout_argument_unless_one_is_set(self):
        seen = []
        self.with_reader(lambda reader_path, indexes, **kw: seen.append(kw) or {"rows": []})
        read_p4_with_retries("reader.py", [], window=0, snapshot="sync")
        self.assertEqual(seen, [{"snapshot": "sync"}])

    def test_the_last_failure_names_the_window_and_the_reader_error(self):
        def fake(reader_path, indexes, **kwargs):
            raise subprocess.TimeoutExpired(["reader"], 150)

        self.with_reader(fake)
        with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(P4ReadError) as caught:
            read_p4_with_retries("reader.py", [1], window=7, retries=1, timeout=120)
        self.assertIn("window 7 failed after 2 attempt(s)", str(caught.exception))
        self.assertIn("no answer within 150 s", str(caught.exception))


def read_csv(path):
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


def temp_dir(test):
    d = tempfile.TemporaryDirectory()
    test.addCleanup(d.cleanup)
    return Path(d.name)


# ---------------------------------------------------------------- HostMon stop

FAKE_HOSTMON = """\
#!{python}
import signal, subprocess, sys, time
mode = "{mode}"
print("started", flush=True)
if mode == "obedient":
    def stop(signum, frame):
        print("final window", flush=True)
        sys.exit(0)
    signal.signal(signal.SIGINT, stop)
else:
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    print("child", child.pid, flush=True)
while True:
    time.sleep(0.05)
"""


def alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    with open(f"/proc/{pid}/stat") as f:   # a zombie is not running
        return f.read().split()[2] != "Z"


class HostmonStopTests(unittest.TestCase):
    def start_fake(self, mode):
        d = temp_dir(self)
        exe = d / "hostmon"
        exe.write_text(FAKE_HOSTMON.format(python=sys.executable, mode=mode))
        exe.chmod(exe.stat().st_mode | stat.S_IXUSR)
        log = d / "hostmon.log"
        proc = start_hostmon(str(exe), str(log), 1.0, use_sudo=False)
        for _ in range(100):
            if "started" in log.read_text() and (mode == "obedient" or "child" in log.read_text()):
                break
            time.sleep(0.05)
        return proc, log

    def test_hostmon_runs_in_its_own_process_group(self):
        proc, _ = self.start_fake("obedient")
        try:
            self.assertEqual(os.getpgid(proc.pid), proc.pid)
            self.assertNotEqual(os.getpgid(proc.pid), os.getpgrp())
        finally:
            stop_hostmon(proc, grace=2)

    def test_sigint_lets_hostmon_print_its_last_window(self):
        proc, log = self.start_fake("obedient")
        stop_hostmon(proc, grace=2)
        self.assertIsNotNone(proc.poll())
        self.assertIn("final window", log.read_text())

    def test_a_hostmon_that_ignores_signals_is_killed_with_its_group(self):
        proc, log = self.start_fake("stubborn")
        child = int(next(l.split()[1] for l in log.read_text().splitlines() if l.startswith("child")))
        stop_hostmon(proc, grace=0.5)
        self.assertIsNotNone(proc.poll())
        for _ in range(40):
            if not alive(child):
                break
            time.sleep(0.05)
        self.assertFalse(alive(child), "a process of HostMon's group outlived stop_hostmon")


# ---------------------------------------------------------------- rows of a run

class RunWriterTests(unittest.TestCase):
    def setUp(self):
        self.dir = temp_dir(self)
        self.out = self.dir / "hybrid_windows.csv"

    def test_rows_are_on_disk_while_the_run_lasts_and_move_on_commit(self):
        w = RunWriter(str(self.out), "scenario/x_17")
        w.write({"window_id": 0, "v": 1})
        w.write({"window_id": 1, "v": 2})
        self.assertEqual(w.partial.name, "hybrid_windows.scenario_x_17.partial.csv")
        self.assertEqual(len(read_csv(w.partial)), 2)
        self.assertFalse(self.out.exists())
        w.commit()
        self.assertFalse(w.partial.exists())
        self.assertEqual([r["v"] for r in read_csv(self.out)], ["1", "2"])

    def test_a_failed_run_keeps_its_rows_out_of_the_output(self):
        w = RunWriter(str(self.out), "run_1")
        w.write({"window_id": 0, "v": 1})
        kept = w.abandon()
        self.assertEqual(kept.name, "hybrid_windows.run_1.incomplete.csv")
        self.assertEqual(len(read_csv(kept)), 1)
        self.assertFalse(self.out.exists())

    def test_a_run_without_rows_leaves_no_file(self):
        self.assertIsNone(RunWriter(str(self.out), "run_2").abandon())
        self.assertEqual(list(self.dir.iterdir()), [])


class NetSummarizerTests(unittest.TestCase):
    def test_incremental_summaries_equal_the_batch(self):
        def r(idx, pkts, ab):
            return {"idx": idx, "pkts": pkts, "pkts_ab": ab, "bytes": 60 * pkts, "bytes_ab": 60 * ab,
                    "syn": 1, "ack": pkts - 1, "rst": 0, "min_len": 60, "max_len": 60,
                    "first_ts": 5, "last_ts": 5 + pkts, "dir_valid": 1}
        windows = [{"rows": [r(1, 4, 2)], "dst_rows": [{"idx": 9, "new_conn": 3}]},
                   {"rows": [r(1, 9, 5), r(2, 3, 3)], "cleared_indexes": [2], "dst_rows": [{"idx": 9, "new_conn": 8}]},
                   {"rows": []},
                   {"rows": [r(2, 1, 1)]}]
        s = NetSummarizer(10.0)
        self.assertEqual([s.add(w) for w in windows], build_net_summaries(windows, 10.0))


if __name__ == "__main__":
    unittest.main()
