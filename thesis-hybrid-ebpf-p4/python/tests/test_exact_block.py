"""Tests of perf/variants/exact_block and the verdict-to-block loop, without a switch (PC1.md part 11):

- the program: exact_block is perf/variants/exact plus inserted lines only (7 files byte for byte, every line of
  ingress.p4 kept in order), and the latency build's patch still applies;
- window_reader.py's "block" command on a fake BF Runtime client: the key of each entry, one write for a list, the
  fallback when an entry exists, list, clear, and a reset that clears the table;
- block_policy.py: sockowner's log read as it grows, what an alarm blocks (the program's flows in both directions,
  the flows it opens later, its host on a flood or without flow identities), a failing reader, the end;
- the whole loop: hybrid_collector.py's exact loop on exact_model.py with a Blocker. After the alarm the switch
  drops the program's packets and keeps counting them in the windows; other programs' flows pass;
- hybrid_collector.py's checks of the --block options."""
import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(REPO))
import block_policy  # noqa: E402
import window_reader  # noqa: E402
from exact_model import ExactModel  # noqa: E402
import hybrid_collector as hc  # noqa: E402

VARIANTS = REPO / "perf" / "variants"
PROGRAM, OTHER = 7, 8               # the monitored cgroup and another one


# ------------------------------------------------------------------ the program
class ProgramTest(unittest.TestCase):
    def test_exact_block_is_exact_plus_inserted_lines(self):
        import difflib
        names = sorted(p.name for p in (VARIANTS / "exact").glob("*.p4"))
        self.assertEqual(names, sorted(p.name for p in (VARIANTS / "exact_block").glob("*.p4")))
        for name in names:
            a = (VARIANTS / "exact" / name).read_text()
            b = (VARIANTS / "exact_block" / name).read_text()
            if name != "ingress.p4":
                self.assertEqual(a, b, name)
                continue
            ops = difflib.SequenceMatcher(None, a.split("\n"), b.split("\n"), autojunk=False).get_opcodes()
            self.assertEqual(sorted(set(op for op, *_ in ops)), ["equal", "insert"])
            inserted = "\n".join(line for op, _, _, j1, j2 in ops if op == "insert"
                                 for line in b.split("\n")[j1:j2])
            for needed in ("table block_rules", "block_rules.apply();", "ig_dprsr_md.drop_ctl = 3w1;",
                           "ig_intr_md.ingress_port : ternary;", "hdr.ipv4.srcAddr        : ternary;",
                           "meta.l4_dport           : ternary;", "blocked_pkts.count(0);"):
                self.assertIn(needed, inserted)

    def test_the_lookup_comes_after_forwarding_and_only_for_ipv4(self):
        text = (VARIANTS / "exact_block" / "ingress.p4").read_text()
        i = text.index("            forwarding.apply();")
        self.assertEqual(text[i:].split("\n")[1:4], ["            if (hdr.ipv4.isValid()) {",
                                                     "                block_rules.apply();", "            }"])
        # the marker and timer branches come before, and never look the table up
        self.assertLess(text.index("epoch_tick.execute(0);"), i)

    def test_the_latency_patch_still_applies(self):
        with tempfile.TemporaryDirectory() as out:
            r = subprocess.run(["bash", str(VARIANTS / "hwl" / "make_hwl_exact.sh"), str(VARIANTS / "exact_block"),
                                out], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            text = (Path(out) / "basic_hwl_exact" / "ingress.p4").read_text()
            self.assertIn("hdr.hw_bridge.setValid();", text)
            self.assertIn("block_rules.apply();", text)


# ------------------------------------------------------------------ window_reader.py's block command
class KeyTuple:
    def __init__(self, name, value=None, mask=None, prefix_len=None, low=None, high=None):
        self.name, self.value, self.mask = name, value, mask


class DataTuple:
    def __init__(self, name, val=None, bool_val=None):
        self.name, self.val = name, val


class Key:
    def __init__(self, fields):
        self.fields = tuple((f.name, f.value, f.mask) for f in fields)

    def to_dict(self):
        return {n: ({"value": v, "mask": m} if m is not None else v) for n, v, m in self.fields}


class Data:
    def __init__(self, fields, action=None):
        self.fields, self.action = {f.name: f.val for f in fields}, action

    def to_dict(self):
        return dict(self.fields)


class FakeGC:
    KeyTuple, DataTuple = KeyTuple, DataTuple


class FakeTable:
    def __init__(self, name):
        self.name, self.entries, self.writes = name, {}, []

    def make_key(self, fields):
        return Key(fields)

    def make_data(self, fields, action=None):
        return Data(fields, action)

    def entry_add(self, target, keys, datas):
        self.writes.append(("add", len(keys)))
        if any(k.fields in self.entries for k in keys):
            raise RuntimeError("Error: table_entry_add failed: ALREADY_EXISTS")
        for k, d in zip(keys, datas):
            self.entries[k.fields] = (d, 0)

    def entry_del(self, target, keys=None):
        self.writes.append(("del", None if keys is None else len(keys)))
        if keys is None:
            self.entries.clear()
        for k in keys or []:
            self.entries.pop(k.fields, None)

    def entry_get(self, target, keys, flags):
        if self.name == "blocked_pkts":
            yield Data([DataTuple("$COUNTER_SPEC_PKTS", [5, 6])]), None
            return
        for fields, (d, n) in self.entries.items():
            k = Key([KeyTuple(name, v, m) for name, v, m in fields])
            yield Data([DataTuple("$COUNTER_SPEC_PKTS", n)]), k

    def entry_mod(self, target, keys, datas):
        self.writes.append(("mod", len(keys)))


class FakeProg:
    def __init__(self, with_block=True):
        self.gc, self.target = FakeGC, object()
        self.tabs = {"block_rules": FakeTable("block_rules"), "blocked_pkts": FakeTable("blocked_pkts")} \
            if with_block else {}

    def table(self, name, prefix=None):
        return self.tabs[name]

    def kw(self, func):
        return {}


class ReaderBlockTest(unittest.TestCase):
    def test_key_spec(self):
        spec = dict((k, (v, m)) for k, v, m in window_reader.block_key_spec(
            {"src": "10.0.0.10", "dst": "203.0.113.0/24", "proto": 6, "dport": 443}))
        self.assertEqual(spec["hdr.ipv4.srcAddr"], (0x0A00000A, 0xFFFFFFFF))
        self.assertEqual(spec["hdr.ipv4.dstAddr"], (0xCB007100, 0xFFFFFF00))
        self.assertEqual(spec["hdr.ipv4.protocol"], (6, 0xFF))
        self.assertEqual(spec["meta.l4_dport"], (443, 0xFFFF))
        self.assertEqual(spec["meta.l4_sport"], (0, 0))              # left out: any value
        self.assertEqual(spec["ig_intr_md.ingress_port"], (0, 0))
        self.assertEqual(window_reader.block_key_spec({"port": 132})[0], ("ig_intr_md.ingress_port", 132, 0x1FF))
        for bad in ({"sport": 70000}, {"port": 600}, {"src": "10.0.0.1/33"}, {"addr": "1.2.3.4"}):
            with self.assertRaises(ValueError):
                window_reader.block_key_spec(bad)

    def test_parse_spec(self):
        self.assertEqual(window_reader.parse_block_spec("src=10.0.0.10, dport=80,proto=0x11"),
                         {"src": "10.0.0.10", "dport": 80, "proto": 17})
        with self.assertRaises(ValueError):
            window_reader.parse_block_spec("src")

    def test_add_list_del_clear(self):
        prog = FakeProg()
        e1 = {"src": "10.0.0.10", "sport": 4000, "dst": "203.0.113.5", "dport": 443, "proto": 6}
        e2 = {"src": "203.0.113.5", "sport": 443, "dst": "10.0.0.10", "dport": 4000, "proto": 6}
        r = window_reader.block_add(prog, [e1, e2])
        self.assertEqual((r["added"], r["existing"]), (2, 0))
        self.assertEqual(prog.tabs["block_rules"].writes, [("add", 2)])            # one write for the list
        fields = dict((n, (v, m)) for n, v, m in next(iter(prog.tabs["block_rules"].entries)))
        self.assertEqual(fields["$MATCH_PRIORITY"][0], window_reader.BLOCK_PRIORITY)
        # an entry that exists: the list goes in one by one, the new one is added
        e3 = {"src": "10.0.0.10"}
        r = window_reader.block_add(prog, [e1, e3])
        self.assertEqual((r["added"], r["existing"]), (1, 1))
        listed = window_reader.block_list(prog)
        self.assertEqual(listed["blocked_pkts"], 11)                               # summed over the pipes
        self.assertIn({"src": "10.0.0.10", "dropped_pkts": 0}, listed["entries"])
        self.assertIn(dict(e1, dropped_pkts=0), listed["entries"])
        window_reader.block_del(prog, [e3])
        self.assertEqual(len(prog.tabs["block_rules"].entries), 2)
        self.assertEqual(window_reader.block_clear(prog), {"block_cleared": True})
        self.assertEqual(prog.tabs["block_rules"].entries, {})

    def test_a_program_without_the_table(self):
        prog = FakeProg(with_block=False)
        self.assertEqual(window_reader.block_clear(prog, missing_ok=True), {})
        with self.assertRaises(RuntimeError):
            window_reader.block_clear(prog)
        self.assertIn("error", window_reader.do_block(prog, {"op": "flush"}))

    def test_a_reset_clears_the_block_table(self):
        prog = FakeProg()
        window_reader.block_add(prog, [{"src": "10.0.0.10"}])
        saved = window_reader.do_reset
        window_reader.do_reset = lambda p: {"reset": 0}
        try:
            out = window_reader.setup(prog, reset=True)
        finally:
            window_reader.do_reset = saved
        self.assertTrue(out["block_cleared"])
        self.assertEqual(prog.tabs["block_rules"].entries, {})
        self.assertIn(("mod", 1), prog.tabs["blocked_pkts"].writes)               # the total counter zeroed


# ------------------------------------------------------------------ block_policy.py
def flow_line(cgroup, direction, proto, saddr, sport, daddr, dport, ts=1):
    return "FLOW,%d,99,%d,%s,%s,%s,%d,%s,%d\n" % (ts, cgroup, direction, proto, saddr, sport, daddr, dport)


class FakeReader:
    """window_reader.py --serve's block command on exact_model.py (and the window commands for the loop test)."""

    def __init__(self, model=None, fail=False):
        self.model, self.fail, self.requests = model or ExactModel(), fail, []

    def request(self, req, timeout=None):
        self.requests.append(req)
        if req["cmd"] == "block":
            if self.fail:
                return {"error": "RuntimeError: no reply"}
            m = self.model
            op = req["op"]
            return (m.block_add(req["entries"]) if op == "add" else m.block_del(req["entries"]) if op == "del"
                    else m.block_clear() if op == "clear" else m.block_list())
        if req["cmd"] == "mark":
            self.model.marker(req["epoch"])
            return {"marked": req["epoch"]}
        if req["cmd"] == "read":
            if self.model.epoch <= req["epoch"]:
                return {"epoch": req["epoch"], "error": "window %d did not end" % req["epoch"]}
            return self.model.read(req["epoch"])
        return {"error": "unexpected %r" % req}

    def adds(self):
        return [r for r in self.requests if r["cmd"] == "block" and r["op"] == "add"]


class PolicyTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.log = os.path.join(self.dir.name, "sockowner.log")
        open(self.log, "w").close()

    def tearDown(self):
        self.dir.cleanup()

    def append(self, text):
        with open(self.log, "a") as f:
            f.write(text)

    def test_the_tail_reads_whole_lines_as_the_log_grows(self):
        tail = block_policy.FlowTail(self.log)
        line = flow_line(PROGRAM, "egress", "tcp", "10.0.0.10", 40000, "203.0.113.5", 443)
        self.append("SOCK,1,99,123,123,%d,2,1,6,odd\x0bname\n" % PROGRAM + line[:20])
        self.assertEqual(tail.poll(), 0)                                  # half a line: not yet
        self.append(line[20:] + flow_line(PROGRAM, "egress", "tcp", "10.0.0.10", 40000, "203.0.113.5", 443))
        self.assertEqual(tail.poll(), 1)                                  # the second sighting is the same flow
        self.append(flow_line(PROGRAM, "ingress", "udp", "198.51.100.9", 53, "10.0.0.11", 5353)
                    + flow_line(OTHER, "egress", "udp", "10.0.0.10", 50000, "198.51.100.9", 53) + "FLOW,bad\n")
        self.assertEqual(tail.poll(), 2)
        self.assertEqual(tail.malformed, 1)
        self.assertEqual(len(tail.flows_of([PROGRAM])), 2)
        self.assertEqual(tail.local_addresses([PROGRAM]), {"10.0.0.10", "10.0.0.11"})

    def test_flow_entries_are_both_directions(self):
        key = block_policy.sockjoin.flow_key(6, "10.0.0.10", 40000, "203.0.113.5", 443)
        a, b = block_policy.flow_entries(key)
        self.assertEqual({a["src"], b["src"]}, {"10.0.0.10", "203.0.113.5"})
        self.assertEqual((a["sport"], a["dport"]), (b["dport"], b["sport"]))
        for e in (a, b):
            window_reader.block_key_spec(e)                               # valid entries

    def blocker(self, reader, scores, **kw):
        it = iter(scores)
        kw.setdefault("cgroup_ids", [PROGRAM])
        kw.setdefault("tail", block_policy.FlowTail(self.log))
        blk = block_policy.Blocker(reader.request, lambda rows: next(it), echo=False,
                                   log_path=os.path.join(self.dir.name, "block.jsonl"), **kw)
        self.addCleanup(blk.close)
        return blk

    def test_no_alarm_blocks_nothing(self):
        reader = FakeReader()
        b = self.blocker(reader, [0.1, 0.2, 0.3])
        for w in range(3):
            b.on_net_window(w, {"net_flow_count_seen": 2})
            b.on_row(w, {})
        s = b.finish()
        self.assertIsNone(s["alarm"])
        self.assertEqual(reader.requests, [])                              # not even a list or a clear

    def test_an_alarm_blocks_the_programs_flows_then_its_new_ones(self):
        reader = FakeReader()
        self.append(flow_line(PROGRAM, "egress", "tcp", "10.0.0.10", 40000, "203.0.113.5", 443)
                    + flow_line(OTHER, "egress", "udp", "10.0.0.10", 50000, "198.51.100.9", 53))
        b = self.blocker(reader, [0.2, 0.7, 0.9, 0.1])
        b.on_row(0, {})
        b.on_row(1, {})                                                    # p 0.7: the alarm
        self.assertEqual(b.alarm["window"], 1)
        first = reader.adds()
        self.assertEqual(len(first), 1)
        self.assertEqual(len(first[0]["entries"]), 2)                      # one flow, both directions
        self.assertNotIn("198.51.100.9", json.dumps(first))                # the other cgroup's flow is not touched
        self.append(flow_line(PROGRAM, "egress", "tcp", "10.0.0.10", 40001, "203.0.113.6", 80))
        b.on_net_window(2, {"net_flow_count_seen": 3})
        self.assertEqual(len(reader.adds()), 2)
        self.assertIn("203.0.113.6", json.dumps(reader.adds()[1]))
        b.on_net_window(3, {"net_flow_count_seen": 3})                    # nothing new: no request
        self.assertEqual(len(reader.adds()), 2)
        b.on_row(2, {})                                                    # after the alarm: scored, nothing else
        s = b.finish()
        self.assertEqual(s["flows_blocked"], 2)
        self.assertFalse(s["host_blocked"])
        self.assertEqual([r["op"] for r in reader.requests if r["cmd"] == "block"][-2:], ["list", "clear"])
        self.assertEqual(reader.model.block, {})
        with open(os.path.join(self.dir.name, "block.jsonl")) as f:
            records = [json.loads(x) for x in f]
        self.assertEqual([r["event"] for r in records].count("score"), 3)
        self.assertEqual([r["reason"] for r in records if r["event"] == "block"], ["flows", "new_flows"])

    def test_a_flood_blocks_the_host(self):
        reader = FakeReader()
        self.append(flow_line(PROGRAM, "egress", "udp", "10.0.0.10", 40000, "203.0.113.5", 53))
        b = self.blocker(reader, [0.9], flood_flows=500, host_port=132)
        b.on_row(0, {"net_flow_count_seen": 3})                            # the alarm: flows first
        b.on_net_window(1, {"net_flow_count_seen": 4000})                  # then a flood: the host
        host = reader.adds()[-1]["entries"]
        self.assertEqual(host, [{"src": "10.0.0.10"}, {"port": 132}])
        self.append(flow_line(PROGRAM, "egress", "udp", "10.0.0.10", 40001, "203.0.113.7", 53))
        b.on_net_window(2, {"net_flow_count_seen": 4000})                  # the host is blocked: no flow entries
        self.assertEqual(len(reader.adds()), 2)
        self.assertTrue(b.finish()["host_blocked"])

    def test_a_flood_before_the_alarm_blocks_the_host_at_the_alarm(self):
        reader = FakeReader()
        self.append(flow_line(PROGRAM, "egress", "tcp", "10.0.0.10", 40000, "203.0.113.5", 23))
        b = self.blocker(reader, [0.2, 0.95])
        b.on_net_window(0, {"net_flow_count_seen": 30000})
        b.on_row(0, {"net_flow_count_seen": 30000})
        self.assertEqual(reader.adds(), [])
        b.on_row(1, {"net_flow_count_seen": 2})
        self.assertEqual(reader.adds()[0]["entries"], [{"src": "10.0.0.10"}])
        self.assertTrue(b.host_blocked)
        self.assertEqual(len(reader.adds()), 1)                            # no flow entries under a host block

    def test_without_flow_identities_the_alarm_blocks_the_host(self):
        reader = FakeReader()
        b = self.blocker(reader, [0.9], tail=None, cgroup_ids=[], host_addresses=["10.0.0.10"])
        b.on_row(0, {})
        self.assertEqual(reader.adds()[0]["entries"], [{"src": "10.0.0.10"}])
        b2 = self.blocker(FakeReader(), [0.9], tail=None, cgroup_ids=[])
        b2.on_row(0, {})
        self.assertEqual(b2.events[-1]["event"], "block_skipped")

    def test_a_forced_alarm_and_a_failing_reader(self):
        reader = FakeReader(fail=True)
        self.append(flow_line(PROGRAM, "egress", "tcp", "10.0.0.10", 40000, "203.0.113.5", 443))
        b = self.blocker(reader, [0.0, 0.0], force_window=1)
        b.on_row(0, {})
        self.assertIsNone(b.alarm)
        b.on_row(1, {})
        self.assertTrue(b.alarm["forced"])
        self.assertEqual(b.errors, 1)                                      # logged, the collection goes on
        self.assertEqual(b.blocked_flows, set())                           # not marked blocked: tried again
        reader.fail = False
        b.on_net_window(2, {"net_flow_count_seen": 1})
        self.assertEqual(len(b.blocked_flows), 1)

    def test_rows_after_the_end_are_only_scored(self):
        reader = FakeReader()
        b = self.blocker(reader, [0.1, 0.99])
        b.on_row(0, {})
        b.finish()
        b.on_row(1, {})
        b.on_net_window(1, {"net_flow_count_seen": 9999})
        self.assertIsNone(b.alarm)
        self.assertTrue(b.events[-1]["after_finish"])
        b.close()

    def test_more_flows_than_the_table_holds_block_the_host(self):
        reader = FakeReader()
        self.append("".join(flow_line(PROGRAM, "egress", "tcp", "10.0.0.10", 40000 + i, "203.0.113.5", 443)
                            for i in range(3)))
        b = self.blocker(reader, [0.9], max_entries=8)
        b.on_row(0, {})
        self.assertEqual(len(reader.adds()[0]["entries"]), 6)              # 3 flows, both directions
        self.append("".join(flow_line(PROGRAM, "egress", "tcp", "10.0.0.10", 41000 + i, "203.0.113.5", 443)
                            for i in range(2)))
        b.on_net_window(1, {"net_flow_count_seen": 5})                    # 4 more entries would not fit
        self.assertEqual(reader.adds()[-1]["entries"], [{"src": "10.0.0.10"}])
        self.assertEqual(b.events[-1]["reason"], "table_full")

    def test_the_flood_threshold_follows_the_window(self):
        self.assertEqual(block_policy.flood_threshold(0.5), 500)
        self.assertEqual(block_policy.flood_threshold(1.0), 1000)


# ------------------------------------------------------------------ the whole loop
class FakeClock:
    def __init__(self, t0, feed):
        self.now, self.feed = t0, feed

    def time(self):
        return self.now

    def sleep(self, d):
        self.now += d
        self.feed(self.now)


class DoneProc:
    def poll(self):
        return 0


class LoopTest(unittest.TestCase):
    def test_after_the_alarm_the_switch_drops_the_programs_packets_and_still_counts_them(self):
        t0 = 1_792_932_220.0
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        log = os.path.join(d.name, "sockowner.log")
        open(log, "w").close()
        # (owner, flow name, src, sport, dst, dport, proto, first window): the program's TCP flow with replies, a
        # flow it opens in window 5, and another program's UDP flow
        flows = [(PROGRAM, "a_out", "10.0.0.10", 40000, "203.0.113.5", 443, 6, 0),
                 (PROGRAM, "a_in", "203.0.113.5", 443, "10.0.0.10", 40000, 6, 0),
                 (PROGRAM, "b_out", "10.0.0.10", 40001, "203.0.113.6", 80, 6, 5),
                 (OTHER, "c_out", "10.0.0.10", 50000, "198.51.100.9", 53, 17, 0)]
        packets = []
        for w in range(10):
            for k in range(5):
                t = t0 + w * 0.5 + 0.02 + k * 0.09
                for f in flows:
                    if w >= f[7]:
                        packets.append((t, w) + f)
        packets.sort()
        sent = {}
        model = ExactModel()
        started = set()

        def feed(now):
            while packets and packets[0][0] < now:
                t, w, owner, name, src, sport, dst, dport, proto, _ = packets.pop(0)
                if name.endswith("_out") and name not in started:
                    started.add(name)                                      # sockowner sees the first packet
                    with open(log, "a") as f:
                        f.write(flow_line(owner, "egress", "tcp" if proto == 6 else "udp", src, sport, dst, dport))
                ok = model.packet(src, dst, proto, sport, dport, 0x10 if proto == 6 else 0, 100, int(t * 1e9))
                sent.setdefault((name, w), []).append(ok)

        clock = FakeClock(t0, feed)
        reader = FakeReader(model)
        blocker = block_policy.Blocker(reader.request, lambda rows: 0.9 if len(rows) >= 3 else 0.1,
                                       cgroup_ids=[PROGRAM], tail=block_policy.FlowTail(log), echo=False,
                                       clock=clock)
        rows = []

        def on_window(win):
            w = len(rows)
            feats = win["exact_features"]
            rows.append(feats)
            blocker.on_net_window(w, feats)
            blocker.on_row(w, feats)

        hc.collect_windows_exact(reader, DoneProc(), 0.5, t0, markers="cpu", on_window=on_window, max_windows=10,
                                 clock=clock)
        self.assertEqual(blocker.alarm["window"], 2)
        for (name, w), oks in sent.items():
            if name == "c_out":
                self.assertTrue(all(oks), (name, w))                        # another program's flow passes
            elif name in ("a_out", "a_in"):
                self.assertEqual(all(oks), w <= 2, (name, w))               # blocked from the window after the alarm
                self.assertEqual(any(oks), w <= 2, (name, w))
            else:
                self.assertEqual(all(oks), w <= 5, (name, w))               # its new flow: from the window after
        for w, feats in enumerate(rows):                                    # every packet is still counted
            self.assertEqual(feats["net_pkts_total_delta"], sum(len(v) for (n, ww), v in sent.items() if ww == w))
        dropped = sum(v.count(False) for v in sent.values())
        summary = blocker.finish()
        self.assertEqual(summary["blocked_pkts"], dropped)
        self.assertEqual(summary["flows_blocked"], 2)
        self.assertEqual(model.block, {})                                   # deleted at the end
        kinds = [r["cmd"] for r in reader.requests]
        self.assertEqual(kinds.count("mark"), 11)                           # the window clock is undisturbed


# ------------------------------------------------------------------ the collector's options
BASE = ["--mode", "command", "--command", "true", "--scenario-name", "t", "--label", "0"]


class CollectorOptionsTest(unittest.TestCase):
    def error_of(self, *argv):
        saved = sys.argv
        sys.argv = ["hybrid_collector.py"] + BASE + list(argv)
        err = io.StringIO()
        try:
            with contextlib.redirect_stderr(err), self.assertRaises(SystemExit) as cm:
                hc.main()
        finally:
            sys.argv = saved
        self.assertEqual(cm.exception.code, 2)
        return err.getvalue()

    def test_block_needs_the_exact_build(self):
        self.assertIn("--block-on-alarm needs --switch-program exact", self.error_of("--block-on-alarm"))

    def test_block_without_sockowner_needs_a_host(self):
        self.assertIn("can only block a host", self.error_of("--switch-program", "exact", "--block-on-alarm"))

    def test_sockowner_with_exact_only_for_blocking(self):
        self.assertIn("--sockowner needs the per-bucket registers",
                      self.error_of("--switch-program", "exact", "--sockowner", "x"))
        self.assertIn("--socket-join-csv and --socket-join-also need",
                      self.error_of("--switch-program", "exact", "--block-on-alarm", "--sockowner", "x",
                                    "--socket-join-csv", "y.csv"))

    def test_host_detectors_need_the_host_monitor(self):
        self.assertIn("needs the host monitor's windows",
                      self.error_of("--switch-program", "exact", "--block-on-alarm", "--block-host", "10.0.0.10",
                                    "--block-detector", "stacked"))

    def test_the_exact_profile(self):
        args = hc.build_arg_parser("exact").parse_args(BASE)
        self.assertEqual((args.switch_program, args.window_sec, args.window_markers, args.byte_layer, args.launcher),
                         ("exact", 0.5, "cpu", "frame", "dataset"))
        self.assertFalse(args.block_on_alarm)                               # blocking stays a choice


if __name__ == "__main__":
    unittest.main()
