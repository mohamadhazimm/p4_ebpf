"""window_reader.py's WindowTimer finds the packet generator's tables under the names of SDE 9.6 ($PKTGEN_*, the
Wedge) and of SDE 9.13 (tf1.pktgen.*, open-p4studio), and a reset's timer stop does not fail where there is no
generator. On SDE 9.13.4 every --reset failed with KeyError '$PKTGEN_PORT_CFG' before the second set of names.

The fakes stand in for the BF Runtime client: looking up a fixed table this SDE does not have raises KeyError, as
bfrt_info.table_get does; the program's registers read back zero."""
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import window_reader  # noqa: E402

# (port_cfg, app_cfg, pkt_buffer) and the periodic-timer action, as each SDE's bf-rt.json names them
SDE96 = ("$PKTGEN_PORT_CFG", "$PKTGEN_APPLICATION_CFG", "$PKTGEN_PKT_BUFFER")
SDE913 = ("tf1.pktgen.port_cfg", "tf1.pktgen.app_cfg", "tf1.pktgen.pkt_buffer")
TRIGGER96 = "$PKTGEN_TRIGGER_TIMER_PERIODIC"
TRIGGER913 = "trigger_timer_periodic"


class FakeGc(object):
    @staticmethod
    def KeyTuple(name, value=None, **kw):
        return (name, value)

    @staticmethod
    def DataTuple(name, val=None, **kw):
        return (name, kw.get("bool_val") if val is None else val)

    @staticmethod
    def Target(device_id=0, pipe_id=0xFFFF):
        return ("pipe", pipe_id)


class FakeTable(object):
    """Records each write as (operation, table, the data's action)."""

    def __init__(self, name, calls):
        self.name, self.calls = name, calls
        self.info = self

    def size_get(self):
        return 1

    def make_key(self, fields):
        return fields

    def make_data(self, fields, action=None):
        return action

    def entry_add(self, target, keys, datas, **kw):
        self.calls.append(("add", self.name, datas[0]))

    def entry_mod(self, target, keys, datas, **kw):
        self.calls.append(("mod", self.name, datas[0]))

    def entry_del(self, target, **kw):
        self.calls.append(("del", self.name, None))


class FakeProgram(object):
    """window_reader.Program as WindowTimer and setup() use it, with one SDE's fixed tables (or none)."""

    def __init__(self, fixed_tables, pipes=2):
        self.calls = []
        self.fixed = dict((n, FakeTable(n, self.calls)) for n in fixed_tables)
        self.pipes = pipes
        self.gc = FakeGc
        self.device_id, self.target = 0, ("pipe", 0xFFFF)

    def table(self, name, prefix=window_reader.TABLE_PREFIX):
        if prefix == "":
            return self.fixed[name]
        return FakeTable(prefix + name, self.calls)

    def kw(self, func):
        return {}

    def pipe_epochs(self):
        return [0] * self.pipes

    def get(self, name, indexes, pair):
        return dict((i, [[0, 0]] * self.pipes if pair else [0] * self.pipes) for i in indexes)


class WindowTimerNamesTest(unittest.TestCase):
    def check_timer(self, names, trigger):
        prog = FakeProgram(names)
        timer = window_reader.WindowTimer(prog)
        timer.prepare(500000000)
        timer.enable()
        self.assertEqual(timer.stop(), {"timer_stopped": [0, 1]})
        port_cfg, app_cfg, pkt_buffer = names
        self.assertEqual(set(c[1] for c in prog.calls), set(names))
        self.assertEqual(set(c[2] for c in prog.calls if c[1] == app_cfg), {trigger})
        self.assertEqual(prog.calls.count(("add", app_cfg, trigger)), 2)      # the timer app of both pipes
        self.assertEqual(prog.calls.count(("add", pkt_buffer, None)), 2)      # and its frame

    def test_sde96_names(self):
        self.check_timer(SDE96, TRIGGER96)

    def test_sde913_names(self):
        self.check_timer(SDE913, TRIGGER913)

    def test_a_reset_stops_the_timer_under_sde913_names(self):
        prog = FakeProgram(SDE913)
        out = window_reader.setup(prog, reset=True, timer=window_reader.WindowTimer(prog))
        self.assertEqual(out["reset"], len(window_reader.ALL_REGS))
        disabled = [c for c in prog.calls if c[1] == "tf1.pktgen.app_cfg"]
        self.assertEqual(disabled, [("mod", "tf1.pktgen.app_cfg", TRIGGER913)] * 2)

    def test_without_a_generator_a_reset_still_works_and_a_timer_cannot_start(self):
        prog = FakeProgram(())
        timer = window_reader.WindowTimer(prog)
        self.assertEqual(timer.stop([0, 1]), {"timer_stopped": []})
        self.assertEqual(prog.calls, [])
        out = window_reader.setup(prog, reset=True, timer=timer)
        self.assertEqual(out["reset"], len(window_reader.ALL_REGS))
        with self.assertRaises(RuntimeError) as cm:
            timer.prepare(500000000, [0])
        self.assertIn("no packet generator tables", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
