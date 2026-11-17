"""perf/variants/sweep's host side: sweep_features.py (records, the program's model, window features) and
sweep_reader.py (the switch's setup and generator), against independent references and a fake BF Runtime client.

The program itself (perf/variants/sweep/*.p4) is not compiled here: what is checked is that the model the offline
check and the replay drivers rely on counts a packet as the bucket table of basic_gtot_ba does (written out again
below, from ingress.p4, without sweep_features' code), and that the window features of its probes' records are the
dataset's where the bucket table can be."""
import csv
import random
import struct
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
PYDIR = HERE.parent
REPO = PYDIR.parents[1]
sys.path.insert(0, str(PYDIR))
sys.path.insert(0, str(REPO / "live_test"))
import sweep_features as sf  # noqa: E402
import sweep_reader  # noqa: E402
from flow_index import compute_flow_index  # noqa: E402

RELEASE = REPO.parent / "p4-ebpf-malware-detection"
M32 = (1 << 32) - 1


def reference_bucket_table(frames, pad_dst=None):
    """The data path of basic_gtot_ba's ingress.p4 (plus frame_len toward pad_dst), written out independently."""
    b, g = {}, dict(pkts_ab=0, bytes_ab=0, pkts_ba=0, bytes_ba=0, syn=0, ack=0, rst=0)
    for ts, fr in frames:
        if len(fr) < 34 or fr[12:14] != b"\x08\x00" or fr[23] not in (6, 17):
            continue
        proto = fr[23]
        if len(fr) < 34 + (20 if proto == 6 else 8):
            continue
        sip, dip = struct.unpack("!II", fr[26:34])
        sp, dp = struct.unpack("!HH", fr[34:38])
        total = struct.unpack("!H", fr[16:18])[0]
        length = 46 if (pad_dst is not None and dip == pad_dst and total <= 45) else total
        idx = compute_flow_index(sip, dip, sp, dp, proto)
        r = b.setdefault(idx, dict(pkts=0, bytes=0, pkts_ab=0, bytes_ab=0, sp=0, dp=0, valid=0, min=0, max=0,
                                   syn=0, ack=0, rst=0, first=0, last=0))
        if not r["valid"]:
            r["valid"], r["sp"], r["dp"], ab = 1, sp, dp, True
        else:
            ab = not (sp == r["dp"] and dp == r["sp"] and not (sp == r["sp"] and dp == r["dp"]))
        r["pkts"] += 1
        r["bytes"] += length
        key = "ab" if ab else "ba"
        g["pkts_" + key] += 1
        g["bytes_" + key] += length
        if ab:
            r["pkts_ab"] += 1
            r["bytes_ab"] += length
        r["min"] = length if (r["min"] == 0 or length < r["min"]) else r["min"]
        r["max"] = max(r["max"], length)
        r["first"] = r["first"] or (ts & M32)
        r["last"] = ts & M32
        if proto == 6:
            flags = ((fr[46] & 1) << 8) | fr[47]
            for bit, name in ((0x002, "syn"), (0x004, "rst"), (0x010, "ack")):
                if flags & bit:
                    r[name] += 1
                    g[name] += 1
    return b, g


def random_frames(n, seed):
    """Frames with colliding and reversed 5-tuples, other protocols and short frames among them."""
    rnd = random.Random(seed)
    hosts = [sf.ip_to_int("10.0.0.%d" % i) for i in (1, 10, 53, 77)]
    out, t = [], 1000
    for _ in range(n):
        t += rnd.randint(1, 5000)
        s, d = rnd.sample(hosts, 2)
        proto = rnd.choice((6, 6, 17, 1))
        sp, dp = rnd.choice((80, 53, 443)), rnd.randint(1024, 1100)
        if rnd.random() < 0.5:
            s, d, sp, dp = d, s, dp, sp
        if proto == 1:
            fr = sf.ipv4_frame(s, d, 17, sp, dp, payload=4)
            fr = fr[:23] + b"\x01" + fr[24:]
        else:
            fr = sf.ipv4_frame(s, d, proto, sp, dp, rnd.randint(0, 0x1FF), rnd.choice((0, 0, 3, 200, 1400)))
        if rnd.random() < 0.02:
            fr = fr[:30]                    # truncated: not counted
        out.append((t * 1000, fr))
    return out


class ModelTest(unittest.TestCase):
    def check(self, frames, pad):
        model = sf.SweepModel(frame_min=(("10.0.0.10/32",) if pad else ()))
        for ts, fr in frames:
            model.packet(fr, ts)
        ref, g = reference_bucket_table(frames, sf.ip_to_int("10.0.0.10") if pad else None)
        self.assertEqual(set(model.b), set(ref))
        names = dict(pkts="pkts", bytes="bytes", pkts_ab="pkts_ab", bytes_ab="bytes_ab", ref_sp="sp", ref_dp="dp",
                     dir_valid="valid", min_len="min", max_len="max", syn="syn", ack="ack", rst="rst",
                     first_ts="first", last_ts="last")
        for idx, r in ref.items():
            for mine, theirs in names.items():
                self.assertEqual(model.b[idx][mine], r[theirs], (idx, mine))
        self.assertEqual(model.g, dict(("g_" + k, v) for k, v in g.items()))

    def test_model_is_the_bucket_table(self):
        for seed in range(5):
            frames = random_frames(3000, seed)
            self.check(frames, pad=False)
            self.check(frames, pad=True)

    def test_known_traffic(self):
        frames = [(int(t * 1e9), fr) for t, fr in sf.test_traffic(300, seed=3)]
        self.check(frames, pad=True)
        short = [fr for _, fr in frames if struct.unpack("!H", fr[16:18])[0] <= 45 and fr[30:34] == bytes([10, 0, 0, 10])]
        self.assertTrue(short, "the test traffic should hold short frames toward 10.0.0.10")

    def test_probe_of_an_empty_bucket_is_dropped_except_bucket_0(self):
        model = sf.SweepModel()
        self.assertIsNone(model.probe(5))
        rec = model.probe(0)
        self.assertEqual((rec["idx"], rec["seq"], rec["dir_valid"]), (0, 1, 0))
        fr = sf.ipv4_frame(sf.ip_to_int("10.0.0.10"), sf.ip_to_int("10.0.0.1"), 6, 1234, 80, 0x002, 10)
        idx = model.packet(fr, 7)
        rec = model.probe(idx)
        self.assertEqual((rec["seq"], rec["pkts"], rec["syn"], rec["dir_valid"]), (1, 1, 1, 1))
        self.assertEqual(model.probe(0)["seq"], 2)
        self.assertEqual((model.probes, model.exported), (4, 3))


class WireTest(unittest.TestCase):
    def test_record_round_trip(self):
        vals = dict((f, i + 1) for i, f in enumerate(sf.FIELDS))
        vals["magic"] = sf.SWEEP_MAGIC
        vals["dir_valid"], vals["reserved"] = 1, 0
        frame = sf.probe_frame("02:00:00:00:00:01", 0x1234)[:14] + sf.pack_record(**vals)
        rec = sf.parse_export(frame)
        self.assertEqual(rec, vals)
        self.assertIsNone(sf.parse_export(frame[:-1]))
        self.assertIsNone(sf.parse_export(frame[:12] + b"\x08\x00" + frame[14:]))

    def test_probe_frame(self):
        fr = sf.probe_frame(b"\x02\x11\x22\x33\x44\x55", 0xBEEF)
        self.assertEqual(len(fr), sf.FRAME_BYTES)
        self.assertEqual(fr[4:6], b"\xbe\xef")
        self.assertEqual(fr[6:12], b"\x02\x11\x22\x33\x44\x55")
        self.assertEqual(fr[12:14], b"\x88\xb6")
        rec = sf.parse_export(fr)
        self.assertEqual((rec["magic"], rec["idx"]), (sf.SWEEP_MAGIC, 0))   # idx is filled in by the switch

    def test_generator_frames_agree(self):
        """sweep_reader.py (on the switch) and sweep_features.py (here) build the same generator frame."""
        a, b = sweep_reader.generator_frame(), sf.generator_template()
        self.assertEqual(a, b)
        self.assertEqual(len(a), 104)
        self.assertEqual((sweep_reader.ETHERTYPE_SWEEP, sweep_reader.SWEEP_MAGIC, sweep_reader.RECORD_BYTES),
                         (sf.ETHERTYPE_SWEEP, sf.SWEEP_MAGIC, sf.RECORD.size))

    def test_pipe_from_the_generator_header(self):
        for pipe in range(4):
            for app in range(8):
                gen = (pipe << 11) | (app << 8)
                self.assertEqual(sf.pipe_of(dict(gen=gen)), pipe)

    def test_pcap_round_trip(self):
        model = sf.SweepModel()
        recs = [model.probe(0), model.probe(0)]
        frames = [(1.0 + i * 0.5, b"\x02\x00\x00\x00\x00\x00" * 2 + b"\x88\xb6" + sf.pack_record(**r))
                  for i, r in enumerate(recs)]
        frames.insert(1, (1.2, sf.ipv4_frame(1, 2, 17, 3, 4)))
        with tempfile.TemporaryDirectory() as d:
            sf.write_pcap(Path(d) / "x.pcap", frames)
            got = sf.read_exports(Path(d) / "x.pcap")
        self.assertEqual([r for _, r in got], recs)
        self.assertAlmostEqual(got[1][0], 1.5, places=6)


class PlanTest(unittest.TestCase):
    def frames_us(self, seed=5):
        return [(int(round(t * 1e6)), fr) for t, fr in sf.test_traffic(400, seed=seed, start=1000.0, spread_s=10.0)]

    def test_changed_and_all_give_the_same_windows(self):
        frames = self.frames_us()
        anchor = frames[0][0] + 250000
        rows = {}
        for mode in ("changed", "all"):
            exports, model = sf.simulate_inband(frames, anchor, 500000, 20, mode)
            sweeps = sf.group_sweeps(exports)
            self.assertEqual(len(sweeps), 21)
            self.assertEqual([s["seq"] for s in sweeps], list(range(1, 22)))
            windows = sf.windows_from_sweeps(sweeps)
            self.assertTrue(all(w["net_sweep_totals_mismatch"] == 0 for w in windows))
            rows[mode] = windows
        self.assertEqual(rows["changed"], [dict(w, net_sweep_buckets=rows["changed"][i]["net_sweep_buckets"])
                                           for i, w in enumerate(rows["all"])])

    def test_a_missed_bucket_shows_in_the_totals(self):
        frames = self.frames_us()
        exports, _ = sf.simulate_inband(frames, frames[0][0] + 250000, 500000, 20)
        sweeps = sf.group_sweeps(exports)
        k = next(i for i, s in enumerate(sweeps) if i > 0 and len(s["buckets"]) > 2)
        victim = next(i for i in sweeps[k]["buckets"] if i != 0)
        del sweeps[k]["buckets"][victim]
        windows = sf.windows_from_sweeps(sweeps)
        self.assertEqual(windows[k - 1]["net_sweep_totals_mismatch"], 1)

    def test_probes_go_where_the_markers_go(self):
        import replay_absolute as ra
        cap = REPO / "live_test" / "captures" / "cohort"
        with open(cap / "manifest.csv") as fh:
            man = list(csv.DictReader(fh))[:5]
        for r in man:
            mac = b"\x02\x00\x00\x00\x00\x01"
            anchor = int(r["anchor_us"])
            ev = ra.with_probes(str(cap / r["capture"]), mac, anchor, 500000, 40)
            mk = ra.with_markers(str(cap / r["capture"]), mac, anchor, 500000, 40, 1)
            self.assertEqual([e[1] for e in ev if not e[2]], [e[1] for e in mk if not e[2]])
            first = [i for i, e in enumerate(ev) if e[2] and e[1][4:6] == b"\x00\x00"]
            marks = [i for i, e in enumerate(mk) if e[2]]
            self.assertEqual([sum(1 for e in ev[:i] if not e[2]) for i in first],
                             [sum(1 for e in mk[:i] if not e[2]) for i in marks])

    def test_two_generators_stay_apart(self):
        model = sf.SweepModel()
        a = dict(model.probe(0), gen=(0 << 11), seq=1)
        b = dict(model.probe(0), gen=(1 << 11), seq=1)
        sweeps = sf.group_sweeps([(0.0, a), (0.0, b), (0.1, dict(a, seq=2))])
        self.assertEqual([(s["pipe"], s["seq"]) for s in sweeps], [(0, 1), (1, 1), (0, 2)])


@unittest.skipUnless((RELEASE / "dataset" / "features.csv").exists(), "needs the release repository beside this one")
class PublishedRowsTest(unittest.TestCase):
    def test_cohort_captures_through_the_model(self):
        """The calm cohort captures, through the program's model with in-band probes: the published row in all
        135 non-duration columns (p4_perf.md 5.7's prediction for the bucket table read in full)."""
        with open(RELEASE / "dataset" / "features.csv") as fh:
            published = dict((r["execution_id"], r) for r in csv.DictReader(fh))
        cap = REPO / "live_test" / "captures" / "cohort"
        with open(cap / "manifest.csv") as fh:
            rows = [r for r in csv.DictReader(fh) if r["expect_overload"] == "0"][:15]
        self.assertTrue(rows)
        for r in rows:
            frames = sf.read_pcap_us(cap / r["capture"])
            exports, _ = sf.simulate_inband(frames, int(r["anchor_us"]))
            windows = sf.windows_from_sweeps(sf.group_sweeps(exports))
            self.assertEqual(len(windows), 40)
            _, bad = sf.compare_row(sf.summarize(windows), published[r["execution_id"]])
            self.assertEqual(bad, [], r["execution_id"])


def export_frame(rec):
    return b"\x02\x00\x00\x00" + struct.pack("!H", rec["idx"]) + b"\x02\x00\x00\x00\x00\x01\x88\xb6" + \
        sf.pack_record(**rec)


@unittest.skipUnless((RELEASE / "dataset" / "features.csv").exists(), "needs the release repository beside this one")
class ReplayAnalysisTest(unittest.TestCase):
    """sweep_replay.py's analysis on what the switch would export (the model's records), without a switch."""

    def run_case(self, drop=None):
        import json
        import sweep_replay
        cap = REPO / "live_test" / "captures" / "cohort"
        with open(cap / "manifest.csv") as fh:
            r = next(x for x in csv.DictReader(fh) if x["expect_overload"] == "0" and int(x["tcpudp_packets"]) > 50)
        frames = sf.read_pcap_us(cap / r["capture"])
        exports, model = sf.simulate_inband(frames, int(r["anchor_us"]))
        if drop is not None:
            del exports[drop]
        with tempfile.TemporaryDirectory() as d:
            sf.write_pcap(Path(d) / "exports.pcap", [(t / 1e6, export_frame(rec)) for t, rec in exports])
            summary = dict(frame_min=["10.0.0.10/32"], pipe=1, probes_sent=model.probes, frames_failed=0,
                           tcpdump={"dropped_by_kernel": 0},
                           state_after={"sweep_probes": [0, model.probes], "sweep_exported": [0, model.exported],
                                        "sweep_seq": [0, 41]})
            (Path(d) / "summary.json").write_text(json.dumps(summary))
            import contextlib
            import io
            with contextlib.redirect_stdout(io.StringIO()):
                return sweep_replay.main([str(cap / r["capture"]), "--anchor-us", r["anchor_us"], "--out", d,
                                          "--execution-id", r["execution_id"], "--analyse-only"])

    def test_the_model_s_exports_pass_every_check(self):
        out = self.run_case()
        self.assertTrue(out["checks_ok"], out["checks"])
        self.assertEqual((out["exact_nodur"], out["equal_model_nodur"], out["sweeps"]), (135, 135, 41))

    def test_a_lost_export_fails(self):
        out = self.run_case(drop=-2)
        self.assertFalse(out["checks"]["exports"])
        self.assertFalse(out["checks_ok"])


class GeneratorAnalysisTest(unittest.TestCase):
    """sweep_generator_check.py's analysis on a simulated generator run: 65,536 probes every 0.5 s, 2 us apart, the
    known traffic in the middle; each bucket read when its probe passes."""

    def simulate(self, cut_last_at=None, ipg_ns=2000, period_s=0.5, traffic_start=2.2, sweeps=12):
        import sweep_generator_check as gcheck
        args = gcheck.parse_args(["--out", "x", "--analyse-only"])
        traffic = sf.test_traffic(args.flows, start=traffic_start)
        used = set(sf.SweepModel().bucket_of(fr) for _, fr in traffic)
        model = sf.SweepModel(frame_min=(args.frame_min,))
        gen = (1 << 11) | (0 << 8)
        exports, i, probes = [], 0, 0
        for k in range(sweeps):
            order = sorted(used | {0})
            last = 65535 if (cut_last_at is None or k < sweeps - 1) else cut_last_at
            for j in (x for x in order if x <= last):
                t = k * period_s + j * ipg_ns * 1e-9
                while i < len(traffic) and traffic[i][0] < t:
                    model.packet(traffic[i][1], int(traffic[i][0] * 1e9))
                    i += 1
                rec = model.probe(j, int(t * 1e9), gen=gen)
                if rec is not None:
                    exports.append((t, rec))
            probes += last + 1
        t1 = traffic[-1][0] + 0.001
        summary = dict(pipe=1, traffic_host_s=[traffic_start, t1], tcpdump={"dropped_by_kernel": 0},
                       state_after={"sweep_seq": [0, sweeps], "sweep_probes": [0, probes],
                                    "sweep_exported": [0, len(exports)], "generator": {"1": {"pkt_counter": probes}}})
        return args, exports, summary

    def analyse(self, args, exports, summary):
        import contextlib
        import io
        import json
        import sweep_generator_check as gcheck
        with tempfile.TemporaryDirectory() as d:
            sf.write_pcap(Path(d) / "exports.pcap", [(t, export_frame(rec)) for t, rec in exports])
            (Path(d) / "summary.json").write_text(json.dumps(summary))
            argv = ["--out", d, "--analyse-only"]
            with contextlib.redirect_stdout(io.StringIO()):
                return gcheck.main(argv)

    def test_whole_sweeps(self):
        out = self.analyse(*self.simulate())
        self.assertTrue(out["checks_ok"], out["checks"])
        self.assertEqual(out["records_before"], [1])
        self.assertFalse(out["last_sweep_partial"])
        self.assertGreater(out["windows_totals_equal"], 0)

    def test_a_cut_last_sweep_is_left_out(self):
        out = self.analyse(*self.simulate(cut_last_at=30000))
        self.assertTrue(out["last_sweep_partial"])
        self.assertTrue(out["checks_ok"], out["checks"])

    def test_a_sweep_that_misses_a_bucket_fails(self):
        args, exports, summary = self.simulate()
        victim = next(n for n in range(len(exports) - 1, 0, -1) if exports[n][1]["idx"] != 0)
        del exports[victim]
        summary["state_after"]["sweep_exported"][1] -= 1
        out = self.analyse(args, exports, summary)
        self.assertFalse(out["checks"]["sweeps_after"])


class FakeGc(object):
    @staticmethod
    def KeyTuple(name, value=None, mask=None, low=None, high=None, **kw):
        return dict(name=name, value=value, mask=mask, low=low, high=high)

    @staticmethod
    def DataTuple(name, val=None, **kw):
        return (name, kw.get("bool_val") if val is None else val)

    @staticmethod
    def Target(device_id=0, pipe_id=0xFFFF):
        return ("pipe", pipe_id)


class FakeKey(object):
    def __init__(self, fields):
        self.fields = fields

    def to_dict(self):
        return dict((f["name"], dict(value=f["value"], mask=f["mask"], low=f["low"], high=f["high"]))
                    for f in self.fields)


class FakeData(object):
    def __init__(self, fields, action=None):
        self.fields, self.action_name = dict(fields), action

    def to_dict(self):
        return dict(self.fields)


class FakeTable(object):
    """Keeps entries (key fields -> data) and the default entry; registers read back zero, counters zero."""

    def __init__(self, name, log, size=65536):
        self.name, self.log, self.size = name, log, size
        self.info = self
        self.entries = {}
        self.default = None

    def size_get(self):
        return self.size

    def make_key(self, fields):
        return FakeKey(fields)

    def make_data(self, fields=(), action=None, get=False):
        return FakeData(fields, action)

    @staticmethod
    def k(key):
        return tuple(sorted((f["name"], f["value"], f["mask"], f["low"], f["high"]) for f in key.fields))

    def entry_add(self, target, keys, datas=None, **kw):
        for i, key in enumerate(keys):
            if self.k(key) in self.entries:
                raise RuntimeError("ALREADY_EXISTS")
            self.entries[self.k(key)] = (key, datas[i] if datas else FakeData(()))
            self.log.append(("add", self.name, target, datas[i].action_name if datas else None,
                             dict(datas[i].fields) if datas else {}))

    def entry_mod(self, target, keys, datas, **kw):
        for key, data in zip(keys, datas):
            self.entries[self.k(key)] = (key, data)
            self.log.append(("mod", self.name, target, data.action_name, dict(data.fields)))

    def entry_del(self, target, key_list=None, **kw):
        self.entries = {}
        self.log.append(("del", self.name, target))

    def entry_get(self, target, keys=None, flags=None, required=None, **kw):
        if self.name.startswith("pipe.Ingress.reg_"):
            for key in keys:
                f = dict((x["name"], x["value"]) for x in key.fields)
                yield FakeData([("Ingress.%s.f1" % self.name.split(".")[-1], [0, 0])]), \
                    FakeKey([dict(name="$REGISTER_INDEX", value=f["$REGISTER_INDEX"], mask=None, low=None, high=None)])
            return
        if self.name.startswith("pipe.Ingress.sweep_"):
            yield FakeData([("$COUNTER_SPEC_PKTS", [0, 0])]), None
            return
        for key, data in list(self.entries.values()):
            yield data, key

    def default_entry_set(self, target, data, **kw):
        self.default = data
        self.log.append(("default", self.name, data.action_name, dict(data.fields)))

    def default_entry_reset(self, target, **kw):
        self.default = None
        self.log.append(("default_reset", self.name))

    def default_entry_get(self, target, flags=None, **kw):
        d = self.default or FakeData((), "Ingress.export_drop")
        yield d, None


class FakeProgram(sweep_reader.Program):
    def __init__(self, sde913=False):
        self.gc, self.log, self.tables = FakeGc, [], {}
        self.p4_name, self.device_id, self.bound = "basic", 0, True
        self.target = ("pipe", 0xFFFF)
        names = sweep_reader.PKTGEN_TABLES[1 if sde913 else 0][:3]
        regs = sweep_reader.FLOW_REGS + sweep_reader.TOTAL_REGS + [sweep_reader.SEQ_REG]
        known = (["pipe.Ingress." + n for n in regs + sweep_reader.COUNTERS + ["frame_len", "sweep_export"]] +
                 ["pipe.IngressParser.sweep_ports"] + list(names))
        self.known = set(known)

    def table(self, name, prefix=sweep_reader.TABLE_PREFIX):
        full = prefix + name
        if full not in self.known:
            raise KeyError(full)
        if full not in self.tables:
            size = 1 if (name.startswith("reg_g_") or name == sweep_reader.SEQ_REG) else 65536
            self.tables[full] = FakeTable(full, self.log, size)
        return self.tables[full]

    def kw(self, func):
        return {}


class ReaderTest(unittest.TestCase):
    def test_setup(self):
        prog = FakeProgram()
        out = sweep_reader.setup(prog, reset=True, frame_min=["10.0.0.10/32"], sweep_ports=[132], export_port=132)
        self.assertEqual(len(out["reset"]), 22)
        self.assertEqual(out["counters_reset"], sweep_reader.COUNTERS)
        self.assertEqual(out["sweep_ports"], [132])
        self.assertEqual(out["export"], {"action": "Ingress.export_to", "port": 132})
        fl = prog.tables["pipe.Ingress.frame_len"]
        (key, data), = fl.entries.values()
        kd = key.to_dict()
        self.assertEqual((kd["hdr.ipv4.dstAddr"]["value"], kd["hdr.ipv4.dstAddr"]["mask"]),
                         (sf.ip_to_int("10.0.0.10"), 0xFFFFFFFF))
        self.assertEqual((kd["hdr.ipv4.totalLen"]["low"], kd["hdr.ipv4.totalLen"]["high"]), (0, 45))
        self.assertEqual((data.action_name, data.fields), ("Ingress.len_set", {"len": 46}))
        out = sweep_reader.setup(prog, sweep_ports=[132, 140], export_port=-1)
        self.assertEqual(out["sweep_ports"], [132, 140])
        self.assertEqual(out["export"]["action"], "Ingress.export_drop")

    def test_reset_refuses_another_program(self):
        prog = FakeProgram()
        prog.known.discard("pipe.Ingress.reg_sweep_seq")
        with self.assertRaises(RuntimeError):
            sweep_reader.do_reset(prog)

    def check_generator(self, sde913):
        prog = FakeProgram(sde913)
        names = sweep_reader.PKTGEN_TABLES[1 if sde913 else 0]
        gen = sweep_reader.SweepGenerator(prog, [1], local_port=68, app=0, buffer_offset=0)
        out = gen.start(500000000, 65536, 2000)
        self.assertEqual(out["dev_ports"], [196])
        self.assertEqual(out["sweep_ports"], [196])
        self.assertEqual(out["sweep_ns"], 65536 * 2000)
        cfg = [x[4] for x in prog.log if x[0] in ("add", "mod") and x[1] == names[1] and
               "packets_per_batch_cfg" in x[4]]
        self.assertEqual(len(cfg), 1)                       # the app of pipe 1, configured once
        c = cfg[0]
        self.assertEqual((c["packets_per_batch_cfg"], c["batch_count_cfg"], c["ipg"], c["timer_nanosec"],
                          c["pipe_local_source_port"], c["pkt_len"]), (65535, 0, 2000, 500000000, 68, 98))
        buf = [e[1].fields["buffer"] for e in prog.tables[names[2]].entries.values()]
        self.assertEqual(buf, [sf.generator_template()[6:]])
        self.assertTrue(any(x[0] == "mod" and x[1] == names[1] and x[4] == {"app_enable": True} for x in prog.log))
        self.assertTrue(any(x[0] == "mod" and x[1] == names[0] and x[4] == {"pktgen_enable": True} for x in prog.log))
        stop = gen.stop()
        self.assertEqual(stop["errors"], [])
        self.assertEqual([x for x in prog.log if x[0] == "mod" and x[1] == names[0]][-1][4], {"pktgen_enable": False})

    def test_generator_sde96(self):
        self.check_generator(False)

    def test_generator_sde913(self):
        self.check_generator(True)

    def test_a_sweep_must_fit_its_period(self):
        gen = sweep_reader.SweepGenerator(FakeProgram(), [1])
        with self.assertRaises(ValueError):
            gen.start(100000000, 65536, 2000)
        with self.assertRaises(ValueError):
            sweep_reader.SweepGenerator(FakeProgram(), [1], buffer_offset=8)

    def test_state(self):
        prog = FakeProgram()
        sweep_reader.setup(prog, reset=True, frame_min=["10.0.0.10/32"], sweep_ports=[132], export_port=132)
        st = sweep_reader.state(prog)
        self.assertEqual(st["sweep_seq"], [0, 0])
        self.assertEqual(st["sweep_probes"], [0, 0])
        self.assertEqual(st["sweep_ports"], [132])
        self.assertEqual(st["export"]["port"], 132)
        self.assertEqual(st["frame_len"][0]["dst"], "10.0.0.10")
        self.assertEqual(sorted(st["totals"]), sorted(sweep_reader.TOTAL_REGS))


if __name__ == "__main__":
    unittest.main()
