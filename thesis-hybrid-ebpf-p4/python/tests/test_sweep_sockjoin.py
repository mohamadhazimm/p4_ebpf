"""The socket-level join on perf/variants/sweep (hybrid_collector.sweep_socket_join, sockjoin.BucketOwners), on the
program's model: no switch, no root, no BPF.

The sweep build sends no CPU report, so the collector names a bucket's flow from this host's sockets: the local
5-tuple that the switch hashes to the bucket and that has the bucket's reference ports. The checks:
- two programs through one switch: each program's socket-joined windows equal the windows of that program's traffic
  alone, and a selector that owns every flow gives the window-level windows;
- a second flow hashed into a program's bucket stays with the bucket's first flow (and is reported);
- a loopback 5-tuple hashed onto a used bucket owns nothing;
- a 5-tuple reused by another program's socket changes owner when the bucket next changes;
- with the generator, a bucket's owner is taken at the bucket's own cut, not at the window boundary;
- the command line accepts --sockowner with --switch-program sweep.
"""
import contextlib
import io
import os
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

HERE = Path(__file__).resolve().parent
PYDIR = HERE.parent
REPO = PYDIR.parents[1]
sys.path.insert(0, str(PYDIR))
sys.path.insert(0, str(REPO))
import sweep_features as sf  # noqa: E402
import sockjoin as sj  # noqa: E402
from flow_index import compute_flow_index  # noqa: E402

T0 = 2000.0                                # the collector's window 0 starts here (wall clock)
OFFSET = -int((T0 - 10.0) * 1e9)           # sockowner's monotonic clock = wall + OFFSET (window 0 at 10 s)
WINDOW_US = 500000
CG_A, CG_B, CG_X = 7001, 7002, 7003


def ip(text):
    return sf.ip_to_int(text)


def frames_of(flows):
    """[(time_us, frame)] in time order. flows: [(5-tuple (proto, src, sport, dst, dport), [(t_s, from_src, payload)])];
    TCP packets carry ACK (and SYN on the first)."""
    out = []
    for (proto, src, sport, dst, dport), packets in flows:
        for n, (t, forward, payload) in enumerate(packets):
            a, pa, b, pb = (src, sport, dst, dport) if forward else (dst, dport, src, sport)
            flags = (0x002 if n == 0 else 0x010) if proto == 6 else 0
            out.append((int(round(t * 1e6)), sf.ipv4_frame(ip(a), ip(b), proto, pa, pb, flags, payload)))
    out.sort(key=lambda x: x[0])
    return out


def bucket(t):
    proto, src, sport, dst, dport = t
    return compute_flow_index(src, dst, sport, dport, proto)


def port_into(target, proto, src, dst, dport):
    """The source port that puts (proto, src, sport, dst, dport) into bucket `target` (the hash is linear in the
    port field, so exactly one port XOR gives each bucket)."""
    for sport in range(65536):
        if compute_flow_index(src, dst, sport, dport, proto) == target:
            return sport
    raise AssertionError("no port")


class Log:
    """A sockowner log: SOCK for each socket, FLOW for the first packet of each 5-tuple on it."""

    def __init__(self):
        self.lines = ["SOCKOWNER_READY,1"]
        self.cookie = 100

    def socket(self, cgroup, tgid, t_wall, comm="prog"):
        self.cookie += 1
        self.lines.append("SOCK,%d,%d,%d,%d,%d,2,1,6,%s" % (self.ns(t_wall), self.cookie, tgid, tgid, cgroup, comm))
        return self.cookie

    def flow(self, cookie, cgroup, t_wall, five, direction="egress"):
        proto, src, sport, dst, dport = five
        self.lines.append("FLOW,%d,%d,%d,%s,%s,%s,%d,%s,%d" % (self.ns(t_wall), cookie, cgroup, direction,
                                                              "tcp" if proto == 6 else "udp", src, sport, dst, dport))

    @staticmethod
    def ns(t_wall):
        return int(round(t_wall * 1e9)) + OFFSET

    def table(self):
        return sj.OwnerTable(sj.parse_lines(self.lines + ["SOCKOWNER_HEALTH,0,0,0"]))


class FakeCapture:
    """The collector's ExportCapture fed by the test clock."""

    def __init__(self, hc, exports_us):
        self.cap = hc.ExportCapture("lo")
        self.pending = [(us / 1e6 + 1e-4, rec) for us, rec in exports_us]

    def feed(self, now):
        while self.pending and self.pending[0][0] < now:
            t, rec = self.pending.pop(0)
            self.cap.add(t, b"\x02\x00\x00\x00" + struct.pack("!H", rec["idx"]) + b"\x02\x00\x00\x00\x00\x01\x88\xb6"
                         + sf.pack_record(**rec))


class Clock:
    def __init__(self, t0, feed):
        self.now, self.feed = t0, feed

    def time(self):
        return self.now

    def sleep(self, d):
        self.now += d
        self.feed(self.now)


class Done:
    def poll(self):
        return 0


class SweepSocketJoinTest(unittest.TestCase):
    windows = 8

    @classmethod
    def setUpClass(cls):
        import hybrid_collector
        cls.hc = hybrid_collector

    def collect(self, frames_us):
        """The collector's windows (in-band probes at every boundary, keep_records) for these frames."""
        exports, _ = sf.simulate_inband(frames_us, int(T0 * 1e6), WINDOW_US, self.windows, frame_min=())
        fc = FakeCapture(self.hc, exports)
        wins = self.hc.collect_windows_sweep(fc.cap, Done(), WINDOW_US / 1e6, T0, probes="inband",
                                             max_windows=self.windows - 1, clock=Clock(T0, fc.feed),
                                             keep_records=True)
        self.assertEqual(len(wins), self.windows - 1)
        return wins

    def alone(self, frames_us):
        """The windows of these frames alone (the reference)."""
        exports, _ = sf.simulate_inband(frames_us, int(T0 * 1e6), WINDOW_US, self.windows, frame_min=())
        return sf.windows_from_sweeps(sf.group_sweeps(exports))[:self.windows - 1]

    def join(self, wins, table, cgroups):
        return self.hc.sweep_socket_join(wins, table, sj.Selector(cgroup_ids=set(cgroups)), OFFSET, WINDOW_US / 1e6,
                                         header=sf.ETHERNET_HEADER_BYTES, duration_unit="s")

    def assert_same(self, got, ref, msg=""):
        self.assertEqual(len(got), len(ref))
        for w, (g, r) in enumerate(zip(got, ref)):
            for f in sf.FEATURES:
                self.assertAlmostEqual(float(g[f]), float(r[f]), places=9, msg="%s window %d %s" % (msg, w, f))

    # ------------------------------------------------------------------------------------------------ two programs
    def two_programs(self):
        """Program A (cgroup 7001): a TCP connection and a DNS query; program B (cgroup 7002): a UDP stream to
        another server and a TCP connection. All in distinct buckets."""
        a_tcp = (6, "10.0.0.10", 40001, "10.0.0.1", 80)
        a_dns = (17, "10.0.0.10", 50001, "10.0.0.1", 53)
        b_udp = (17, "10.0.0.10", 50002, "10.0.0.2", 9000)
        b_tcp = (6, "10.0.0.10", 40002, "10.0.0.2", 443)
        flows_a = [(a_tcp, [(T0 + 0.10 + i * 0.07, i % 3 != 1, 40 + 30 * i) for i in range(30)]),
                   (a_dns, [(T0 + 1.30, True, 30), (T0 + 1.31, False, 120)])]
        flows_b = [(b_udp, [(T0 + 0.20 + i * 0.05, True, 200) for i in range(50)]),
                   (b_tcp, [(T0 + 0.60 + i * 0.11, i % 2 == 0, 10 + i) for i in range(20)])]
        self.assertEqual(len({bucket(t) for t, _ in flows_a + flows_b}), 4)
        log = Log()
        ca = log.socket(CG_A, 500, T0 + 0.05)
        cd = log.socket(CG_A, 500, T0 + 1.2)
        cb = log.socket(CG_B, 600, T0 + 0.15)
        ct = log.socket(CG_B, 600, T0 + 0.55)
        for cookie, cg, (five, packets) in ((ca, CG_A, flows_a[0]), (cd, CG_A, flows_a[1]), (cb, CG_B, flows_b[0]),
                                            (ct, CG_B, flows_b[1])):
            log.flow(cookie, cg, packets[0][0], five)
            back = [p for p in packets if not p[1]]
            if back:
                proto, src, sport, dst, dport = five
                log.flow(cookie, cg, back[0][0], (proto, dst, dport, src, sport), "ingress")
        return flows_a, flows_b, log

    def test_each_program_alone(self):
        flows_a, flows_b, log = self.two_programs()
        fa, fb = frames_of(flows_a), frames_of(flows_b)
        wins = self.collect(sorted(fa + fb))
        table = log.table()
        ja, jb = self.join(wins, table, [CG_A]), self.join(wins, table, [CG_B])
        self.assert_same(ja, self.alone(fa), "A")
        self.assert_same(jb, self.alone(fb), "B")
        whole = [w["exact_features"] for w in wins]
        for w in range(len(wins)):
            for k in ("net_pkts_total_delta", "net_bytes_total_delta", "net_flow_count_seen", "net_syn_delta",
                      "net_ack_delta"):
                self.assertEqual(ja[w][k] + jb[w][k], whole[w][k], (w, k))
        self.assertEqual([x["net_sock_owned_buckets"] for x in ja][-1], 2)
        self.assertEqual(sum(x["net_sock_shared_active"] + x["net_sock_hidden_flows"] for x in ja + jb), 0)
        # the sweep's own checks are the window's
        for k in self.hc.SWEEP_WINDOW_KEYS:
            self.assertEqual([x[k] for x in ja], [w["exact_features"][k] for w in wins], k)
        self.assertTrue(all(w["exact_features"]["net_sweep_totals_mismatch"] == 0 for w in wins))

    def test_everything_and_nothing(self):
        flows_a, flows_b, log = self.two_programs()
        wins = self.collect(sorted(frames_of(flows_a) + frames_of(flows_b)))
        table = log.table()
        both = self.join(wins, table, [CG_A, CG_B])
        self.assert_same(both, [w["exact_features"] for w in wins], "both")
        for k in ("net_sweep_coll_pkts", "net_sweep_merged_active", "net_sweep_merged_buckets"):
            self.assertEqual([x[k] for x in both], [w["exact_features"][k] for w in wins], k)
        none = self.join(wins, table, [CG_X])
        self.assertTrue(all(float(x[f]) == 0.0 for x in none for f in sf.FEATURES))
        self.assertEqual([x["net_sock_owned_buckets"] for x in none], [0] * len(wins))

    def test_features_from_the_kept_records_equal_whole_sweeps(self):
        """A sweep of the changed buckets gives the window's features: the collector keeps only those."""
        flows_a, flows_b, _ = self.two_programs()
        frames = sorted(frames_of(flows_a) + frames_of(flows_b))
        exports, _ = sf.simulate_inband(frames, int(T0 * 1e6), WINDOW_US, self.windows, mode="all", frame_min=())
        full = sf.SweepWindows()
        kept = sf.SweepWindows()
        for n, sweep in enumerate(sf.group_sweeps(exports)):
            f = full.add(sweep)
            recs = {i: sf.expand(sf.compact(sweep["buckets"][i])) for i in full.last_changed}
            g = kept.add({"buckets": recs, "totals": None}, select=set(sweep["buckets"]) | set(kept.state))
            if n == 0:
                self.assertIsNone(f)
                continue
            for k in sf.FEATURES + ["net_sweep_coll_pkts", "net_sweep_merged_active", "net_sweep_merged_buckets"]:
                self.assertAlmostEqual(float(f[k]), float(g[k]), places=9, msg=(n, k))

    # ------------------------------------------------------------------------------------------------ collisions
    def test_a_merged_flow_stays_with_the_buckets_first_flow(self):
        """B's flow hashes into A's bucket after A's flow started: the switch counts it in A's bucket (reg_coll),
        so the join gives the bucket to A, says the bucket is shared, and counts B's flow as hidden."""
        a_tcp = (6, "10.0.0.10", 40001, "10.0.0.1", 80)
        b_sp = port_into(bucket(a_tcp), 6, "10.0.0.10", "10.0.0.2", 80)
        b_tcp = (6, "10.0.0.10", b_sp, "10.0.0.2", 80)
        b_udp = (17, "10.0.0.10", 50002, "10.0.0.2", 9000)
        self.assertEqual(bucket(a_tcp), bucket(b_tcp))
        self.assertNotEqual(bucket(a_tcp), bucket(b_udp))
        flows_a = [(a_tcp, [(T0 + 0.1 + 0.1 * i, i % 2 == 0, 100) for i in range(20)])]
        flows_b = [(b_tcp, [(T0 + 0.6 + 0.1 * i, i % 2 == 0, 300) for i in range(10)]),
                   (b_udp, [(T0 + 0.3 + 0.2 * i, True, 50) for i in range(10)])]
        log = Log()
        ca, cb, cu = log.socket(CG_A, 500, T0), log.socket(CG_B, 600, T0 + 0.5), log.socket(CG_B, 600, T0 + 0.2)
        log.flow(ca, CG_A, T0 + 0.1, a_tcp)
        log.flow(cb, CG_B, T0 + 0.6, b_tcp)
        log.flow(cu, CG_B, T0 + 0.3, b_udp)
        fa, fb = frames_of(flows_a), frames_of(flows_b)
        wins = self.collect(sorted(fa + fb))
        table = log.table()
        ja, jb = self.join(wins, table, [CG_A]), self.join(wins, table, [CG_B])
        merged = self.alone(sorted(fa + frames_of(flows_b[:1])))        # A's bucket with B's merged packets
        self.assert_same(ja, merged, "A with B's merged flow")
        self.assert_same(jb, self.alone(frames_of(flows_b[1:])), "B without its merged flow")
        self.assertGreater(sum(x["net_sweep_merged_active"] for x in ja), 0)
        self.assertGreater(sum(x["net_sock_shared_active"] for x in ja), 0)
        self.assertEqual(jb[-1]["net_sock_hidden_flows"], 1)
        self.assertEqual(ja[-1]["net_sock_hidden_flows"], 0)
        self.assertEqual(sum(x["net_sweep_merged_active"] for x in jb), 0)

    def test_a_loopback_tuple_on_a_used_bucket_owns_nothing(self):
        """A loopback 5-tuple of B hashes onto A's bucket: it never crossed the switch, its ports are not the
        bucket's, so the bucket stays A's and B is not charged with it."""
        a_tcp = (6, "10.0.0.10", 40001, "10.0.0.1", 80)
        lo_sp = port_into(bucket(a_tcp), 17, "127.0.0.1", "127.0.0.53", 53)
        lo = (17, "127.0.0.1", lo_sp, "127.0.0.53", 53)
        self.assertEqual(bucket(lo), bucket(a_tcp))
        flows_a = [(a_tcp, [(T0 + 0.1 + 0.1 * i, True, 100) for i in range(20)])]
        log = Log()
        ca, cl = log.socket(CG_A, 500, T0), log.socket(CG_B, 600, T0 + 0.25)
        log.flow(ca, CG_A, T0 + 0.1, a_tcp)
        log.flow(cl, CG_B, T0 + 0.3, lo)                         # B's loopback query, during A's flow
        fa = frames_of(flows_a)
        wins = self.collect(fa)
        table = log.table()
        self.assert_same(self.join(wins, table, [CG_A]), self.alone(fa), "A")
        jb = self.join(wins, table, [CG_B])
        self.assertTrue(all(float(x[f]) == 0.0 for x in jb for f in sf.FEATURES))
        self.assertEqual(sum(x["net_sock_shared_active"] + x["net_sock_hidden_flows"] for x in jb), 0)

    # ------------------------------------------------------------------------------------------------ time
    def test_a_reused_tuple_changes_owner(self):
        """A's socket uses a 5-tuple until 1.0 s; B's socket uses the same 5-tuple from 2.2 s. One flow for the
        switch (and for the dataset's model); its windows go to A up to the reuse and to B after it."""
        five = (17, "10.0.0.10", 50010, "10.0.0.1", 9999)
        early = [(T0 + 0.1 + 0.1 * i, True, 100) for i in range(9)]           # windows 0 and 1
        late = [(T0 + 2.2 + 0.1 * i, True, 200) for i in range(10)]           # windows 4 to 6
        log = Log()
        ca, cb = log.socket(CG_A, 500, T0), log.socket(CG_B, 600, T0 + 2.1)
        log.flow(ca, CG_A, early[0][0], five)
        log.flow(cb, CG_B, late[0][0], five)
        frames = frames_of([(five, early + late)])
        wins = self.collect(frames)
        whole = [w["exact_features"] for w in wins]
        table = log.table()
        ja, jb = self.join(wins, table, [CG_A]), self.join(wins, table, [CG_B])
        pk = lambda rows: [r["net_pkts_total_delta"] for r in rows]           # noqa: E731
        self.assertEqual(pk(whole), [4, 5, 0, 0, 3, 5, 2])
        self.assertEqual(pk(ja), [4, 5, 0, 0, 0, 0, 0])
        self.assertEqual(pk(jb), [0, 0, 0, 0, 3, 5, 2])
        # the flow stays active for TTL windows after its last packet, with its owner of the time
        self.assertEqual([r["net_flow_count_seen"] for r in ja], [1, 1, 1, 1, 0, 0, 0])
        self.assertEqual([r["net_flow_count_seen"] for r in jb], [0, 0, 0, 0, 1, 1, 1])

    def test_a_flow_counted_before_its_sighting_keeps_its_owner(self):
        """The two clocks disagree by more than the slack: the first packets are counted in the window before the
        sighting. The bucket's only matching 5-tuple still gives it its owner."""
        five = (6, "10.0.0.10", 40001, "10.0.0.1", 80)
        packets = [(T0 + 0.40 + 0.03 * i, i % 2 == 0, 100) for i in range(10)]
        log = Log()
        c = log.socket(CG_A, 500, T0)
        log.flow(c, CG_A, packets[0][0] + 0.3, five)                          # 300 ms late
        frames = frames_of([(five, packets)])
        wins = self.collect(frames)
        self.assert_same(self.join(wins, log.table(), [CG_A]), self.alone(frames), "skewed")

    def test_generator_cut_times(self):
        """With the generator a bucket is cut when its probe passes, up to buckets x ipg after the boundary (here
        100 ms after it). B reuses A's 5-tuple 60 ms after the boundary at T0 + 1 s, before the bucket's probe: the
        switch counted B's first packets in the window that ends at that sweep, and the join gives that window's
        packets to B (taken at the boundary plus the slack, it would give them to A). Reused 160 ms after the
        boundary (past the probe and the 50 ms slack), the window's packets are A's."""
        hc = self.hc
        five = (17, "10.0.0.10", 50010, "10.0.0.1", 9999)
        idx = bucket(five)
        first = 5_000_000          # the switch time (ns) of each sweep's first record

        def rec(pkts):
            return sf.compact(dict(idx=idx, t=first + 100_000_000, pkts=pkts, bytes=100 * pkts, pkts_ab=pkts,
                                   bytes_ab=100 * pkts, first_ts=1000, last_ts=1000 + pkts, ref_sp=50010, ref_dp=9999,
                                   min_len=100, max_len=100, dir_valid=1))

        def owned_packets(reuse_after_s):
            log = Log()
            ca, cb = log.socket(CG_A, 500, T0), log.socket(CG_B, 600, T0 + 0.9)
            log.flow(ca, CG_A, T0 + 0.1, five)
            log.flow(cb, CG_B, T0 + 1.0 + reuse_after_s, five)
            wins = []
            for w, pkts in enumerate((3, 7)):
                wins.append({"net_window_id": w, "net_window_start_sec": w * 0.5, "net_window_end_sec": (w + 1) * 0.5,
                             "exact_features": {}, "sweep_records": [rec(pkts)],
                             "sweep_clock": [T0 + (w + 1) * 0.5 + 1e-5, first]})
            wins[0]["sweep_base"], wins[0]["sweep_base_clock"] = [], [T0 + 1e-5, first]
            table = log.table()
            return tuple([r["net_pkts_total_delta"] for r in
                          hc.sweep_socket_join(wins, table, sj.Selector(cgroup_ids={cg}), OFFSET, 0.5,
                                               duration_unit="s")] for cg in (CG_A, CG_B))

        self.assertEqual(owned_packets(0.060), ([3, 0], [0, 4]))
        self.assertEqual(owned_packets(0.160), ([3, 4], [0, 0]))

    # ------------------------------------------------------------------------------------------------ plumbing
    def test_socket_join_rows_end_to_end(self):
        """socket_join_rows() with a log file and a cgroup directory (its inode is the cgroup id): the sweep path."""
        flows_a, flows_b, _ = self.two_programs()
        fa, fb = frames_of(flows_a), frames_of(flows_b)
        wins = self.collect(sorted(fa + fb))
        with tempfile.TemporaryDirectory() as d:
            cg = Path(d) / "cg"
            cg.mkdir()
            ino = os.stat(cg).st_ino
            _, _, log = self.two_programs()
            text = "\n".join(log.lines).replace(",%d," % CG_A, ",%d," % ino) + "\nSOCKOWNER_HEALTH,0,0,0\n"
            path = Path(d) / "sockowner.log"
            path.write_text(text)
            args = SimpleNamespace(sockowner_log=str(path), window_sec=0.5, byte_layer="frame", duration_unit="s",
                                   scenario_name="t", label="benign", mode="command")
            rows = self.hc.socket_join_rows(args, "run", cg, T0, [], wins, OFFSET)
        self.assertEqual(len(rows), len(wins))
        self.assertTrue(all(r["join"] == "socket" for r in rows))
        ref = self.alone(fa)
        for w in range(len(wins)):
            self.assertEqual(rows[w]["net_pkts_total_delta"], ref[w]["net_pkts_total_delta"])
        for k in self.hc.SWEEP_SOCK_KEYS:
            self.assertIn(k, rows[0])

    def write_log(self, log, cgroups, d):
        """The log with the test's cgroup ids replaced by the inodes of real directories (the collector's ids)."""
        text = "\n".join(log.lines)
        for cg, path in cgroups.items():
            path.mkdir()
            (path / "cgroup.procs").write_text("")
            text = text.replace(",%d," % cg, ",%d," % os.stat(path).st_ino)
        out = Path(d) / "sockowner.log"
        out.write_text(text + "\nSOCKOWNER_HEALTH,0,0,0\n")
        return out

    def test_the_joins_partition_the_window_rows(self):
        """--socket-join-also and live_test/check_sweep_sockjoin.py: the monitored cgroup's rows and a background
        cgroup's rows add up to the window-level rows in every window; with the program alone, the socket rows
        are the window rows."""
        sys.path.insert(0, str(REPO / "live_test"))
        import check_sweep_sockjoin as chk
        hc = self.hc
        flows_a, flows_b, log = self.two_programs()
        with tempfile.TemporaryDirectory() as d:
            ca, cb = Path(d) / "cg_a", Path(d) / "cg_b"
            path = self.write_log(log, {CG_A: ca, CG_B: cb}, d)
            args = SimpleNamespace(sockowner_log=str(path), window_sec=0.5, byte_layer="frame", duration_unit="s",
                                   scenario_name="t", label="benign", mode="command", socket_join_csv=None,
                                   out_csv=str(Path(d) / "w.csv"))
            for case, frames, also in (("both", sorted(frames_of(flows_a) + frames_of(flows_b)), True),
                                       ("alone", frames_of(flows_a), False)):
                wins = self.collect(frames)
                window_rows = hc.build_rows(args, case, [], wins, [w["exact_features"] for w in wins])
                hc.append_csv_rows(str(Path(d) / ("%s.csv" % case)), window_rows)
                sock = hc.socket_csv_path(SimpleNamespace(socket_join_csv=None, out_csv=str(Path(d) / ("%s.csv" % case))))
                hc.append_csv_rows(str(sock), hc.socket_join_rows(args, case, ca, T0, [], wins, OFFSET))
                argv = ["--window", str(Path(d) / ("%s.csv" % case)), "--socket", str(sock)]
                if also:
                    extra = hc.extra_socket_csv_path(sock, cb.name)
                    self.assertEqual(extra.name, "both.socket.cg_b.csv")
                    hc.append_csv_rows(str(extra), hc.socket_join_rows(args, case, cb, T0, [], wins, OFFSET))
                    argv += ["--also", str(extra)]
                out = io.StringIO()
                with contextlib.redirect_stdout(out):
                    rc = chk.main(argv + ["--json", str(Path(d) / ("%s.json" % case))])
                self.assertEqual(rc, 0, out.getvalue())
                import json
                summary = json.loads(Path(d, "%s.json" % case).read_text())["summary"]
                self.assertEqual(summary["windows_with_a_remainder"], 0)
                if not also:
                    self.assertEqual(summary["windows_with_equal_features"], summary["windows"])
                else:
                    self.assertGreater(summary["packets"]["also"][0], 0)
            # a cgroup that owns nothing leaves the whole window as the remainder
            wins = self.collect(sorted(frames_of(flows_a) + frames_of(flows_b)))
            window_rows = hc.build_rows(args, "only_a", [], wins, [w["exact_features"] for w in wins])
            per, summary = chk.check({int(r["window_id"]): {k: str(v) for k, v in r.items()} for r in window_rows},
                                     {int(r["window_id"]): {k: str(v) for k, v in r.items()}
                                      for r in hc.socket_join_rows(args, "only_a", ca, T0, [], wins, OFFSET)}, [])
            self.assertGreater(summary["windows_with_a_remainder"], 0)

    def test_command_line(self):
        hc = self.hc
        base = ["hybrid_collector.py", "--mode", "command", "--scenario-name", "t", "--label", "benign", "--command",
                "true", "--switch-program", "sweep"]
        # --sockowner passes the option checks (and stops at the first missing file)
        argv = base + ["--sockowner", "/nonexistent/sockowner", "--hostmon-cgroup", "hazim_test",
                       "--hostmon", "/nonexistent/hostmon_agg"]
        with mock.patch.object(sys, "argv", argv), contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(FileNotFoundError):
                hc.main()
        for extra, words in ((["--scope-ip", "10.0.0.10"], "--scope-ip needs the CPU reports"),
                             (["--global-totals", "1"], "--global-totals is for the gtot test build"),
                             (["--socket-join-also", "/tmp"], "--socket-join-also needs --sockowner")):
            with mock.patch.object(sys, "argv", base + extra), contextlib.redirect_stderr(io.StringIO()) as err:
                with self.assertRaises(SystemExit):
                    hc.main()
            self.assertIn(words, err.getvalue())


if __name__ == "__main__":
    unittest.main()
