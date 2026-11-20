"""Tests of sockjoin.py, the socket-level join of switch flows to processes (no root, no BPF, no switch)."""
import os
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "switch" / "control"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "collector"))
import sockjoin as sj  # noqa: E402

LOG = """SOCKOWNER_READY,1
SOCK,1000,11,500,500,7001,2,1,6,client-a
SOCK,1100,12,600,601,7002,2,2,17,client-b
FLOW,2000,11,7001,egress,tcp,10.0.0.10,40001,10.0.0.1,80
FLOW,2100,11,7001,ingress,tcp,10.0.0.1,80,10.0.0.10,40001
FLOW,2200,12,7002,egress,udp,10.0.0.10,50001,10.0.0.1,53
FLOW,2300,0,0,egress,udp,10.0.0.10,123,10.0.0.1,123
REL,9000,11,500,500,7001,client-a
FLOW,9500,13,7002,egress,tcp,10.0.0.10,40001,10.0.0.1,80
garbage,line
SOCKOWNER_HEALTH,0,0,0
"""


class ParseTests(unittest.TestCase):
    def test_parse_and_owner(self):
        log = sj.parse_lines(LOG.splitlines())
        self.assertEqual(log.ready_cgroup, 1)
        self.assertEqual(log.health, {"ringbuf_drops": 0, "flow_map_errors": 0, "failed": 0})
        self.assertEqual(log.malformed, 1)
        self.assertEqual(log.sockets[11].tgid, 500)
        self.assertEqual(log.sockets[11].released_ns, 9000)
        self.assertEqual(log.sockets[12].comm, "client-b")
        table = sj.OwnerTable(log)
        key = sj.flow_key(6, "10.0.0.1", 80, "10.0.0.10", 40001)
        # both directions of the connection give the same key
        self.assertEqual(key, sj.flow_key(6, "10.0.0.10", 40001, "10.0.0.1", 80))
        self.assertEqual(table.owner(key).cookie, 11)
        # the 5-tuple was reused by another socket at 9500: time decides
        self.assertEqual(table.owner(key, at_ns=3000).cookie, 11)
        self.assertEqual(table.owner(key, at_ns=9600).cookie, 13)
        self.assertEqual(table.owner(key, at_ns=500).cookie, 11)  # before the first sighting: the first
        self.assertIsNone(table.owner(sj.flow_key(6, "10.0.0.10", 1, "10.0.0.1", 2)))
        self.assertEqual(table.process(table.owner(key, at_ns=3000)).comm, "client-a")
        self.assertIsNone(table.process(table.owner(key, at_ns=9600)))  # cookie 13: no SOCK event

    def test_selector(self):
        table = sj.OwnerTable(sj.parse_lines(LOG.splitlines()))
        key_tcp = sj.flow_key(6, "10.0.0.10", 40001, "10.0.0.1", 80)
        key_udp = sj.flow_key(17, "10.0.0.10", 50001, "10.0.0.1", 53)
        key_ntp = sj.flow_key(17, "10.0.0.10", 123, "10.0.0.1", 123)
        by_cgroup = sj.Selector(cgroup_ids={7001})
        self.assertTrue(by_cgroup.owns(table, table.owner(key_tcp, 3000)))
        self.assertFalse(by_cgroup.owns(table, table.owner(key_tcp, 9600)))  # reused by cgroup 7002
        self.assertFalse(by_cgroup.owns(table, table.owner(key_udp)))
        by_pid = sj.Selector(tgids={600})
        self.assertTrue(by_pid.owns(table, table.owner(key_udp)))
        self.assertFalse(by_pid.owns(table, table.owner(key_ntp)))  # socketless packet: nobody's
        self.assertFalse(by_pid.owns(table, None))

    def test_owned_bucket_indexes(self):
        table = sj.OwnerTable(sj.parse_lines(LOG.splitlines()))
        reports = [{"src_ip": "10.0.0.10", "dst_ip": "10.0.0.1", "sport": 40001, "dport": 80, "proto": 6, "idx": 7},
                   {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.10", "sport": 53, "dport": 50001, "proto": 17, "idx": 9},
                   {"src_ip": "10.0.0.10", "dst_ip": "10.0.0.1", "sport": 123, "dport": 123, "proto": 17, "idx": 11},
                   {"broken": True}]
        self.assertEqual(sj.owned_bucket_indexes(reports, table, sj.Selector(cgroup_ids={7001})), {7})
        self.assertEqual(sj.owned_bucket_indexes(reports, table, sj.Selector(cgroup_ids={7001, 7002})), {7, 9})
        late = sj.owned_bucket_indexes(reports, table, sj.Selector(cgroup_ids={7001}),
                                       to_monotonic_ns=lambda r: 9600)
        self.assertEqual(late, set())


def write_pcap(path, packets):
    """Classic pcap with Ethernet frames: packets = [(time_us, src, sport, dst, dport, proto, flags, payload)]."""
    def ip(a):
        return bytes(int(x) for x in a.split("."))
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for t, src, sport, dst, dport, proto, flags, payload in packets:
            if proto == 6:
                l4 = struct.pack("!HHIIBBHHH", sport, dport, 0, 0, 0x50, flags, 1024, 0, 0)
            else:
                l4 = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0)
            total = 20 + len(l4) + len(payload)
            iph = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0, 0, 64, proto, 0, ip(src), ip(dst))
            frame = b"\x00" * 12 + b"\x08\x00" + iph + l4 + payload
            f.write(struct.pack("<IIII", t // 1_000_000, t % 1_000_000, len(frame), len(frame)))
            f.write(frame)


class WindowJoinTests(unittest.TestCase):
    def setUp(self):
        release = Path(os.environ.get("SWITCH_MODEL_DIR") or
                       Path(__file__).resolve().parents[2] / "p4-ebpf-malware-detection" / "features")
        if not (release / "switch_model.py").exists():
            self.skipTest("release repository not next to p4_ebpf")
        sys.path.insert(0, str(release))
        import switch_model  # noqa: E402
        self.sm = switch_model

    def test_socket_join_recovers_each_program_alone(self):
        start = 1_700_000_000_000_000
        a = [(start + 100_000 + i * 20_000, "10.0.0.10", 40001, "10.0.0.1", 80, 6, 0x10, b"x" * 30) for i in range(10)]
        a += [(start + 120_000 + i * 20_000, "10.0.0.1", 80, "10.0.0.10", 40001, 6, 0x10, b"y" * 300) for i in range(10)]
        b = [(start + 700_000 + i * 50_000, "10.0.0.10", 50001, "10.0.0.1", 53, 17, 0, b"q" * 40) for i in range(8)]
        mixed = sorted(a + b)
        log = sj.parse_lines(LOG.splitlines())
        table = sj.OwnerTable(log)
        with tempfile.TemporaryDirectory() as tmp:
            both, only_a, only_b = (os.path.join(tmp, n) for n in ("both.pcap", "a.pcap", "b.pcap"))
            write_pcap(both, mixed)
            write_pcap(only_a, sorted(a))
            write_pcap(only_b, sorted(b))
            window_join = self.sm.window_features(both, start, windows=4)
            keep_a = sj.packet_filter(table, sj.Selector(cgroup_ids={7001}))
            keep_b = sj.packet_filter(table, sj.Selector(cgroup_ids={7002}))
            socket_a = sj.window_features_selected(self.sm, both, start, keep_a, windows=4)
            socket_b = sj.window_features_selected(self.sm, both, start, keep_b, windows=4)
            self.assertEqual(socket_a, self.sm.window_features(only_a, start, windows=4))
            self.assertEqual(socket_b, self.sm.window_features(only_b, start, windows=4))
            self.assertNotEqual(window_join, socket_a)  # the window join mixes both programs
            keep_all = lambda key, t: True  # noqa: E731
            self.assertEqual(sj.window_features_selected(self.sm, both, start, keep_all, windows=4), window_join)


if __name__ == "__main__":
    unittest.main()


class CollectorJoinTests(unittest.TestCase):
    """The collector side: socket_join_windows marks the owned buckets, NetSummarizer counts only them."""

    def setUp(self):
        import hybrid_collector as hc  # noqa: E402
        self.hc = hc

    def windows(self):
        row = lambda idx, pkts, by: {"idx": idx, "pkts": pkts, "bytes": by, "pkts_ab": pkts, "bytes_ab": by,  # noqa: E731
                                     "syn": 1, "ack": pkts, "rst": 0, "min_len": 60, "max_len": 100,
                                     "first_ts": 1000, "last_ts": 2000, "dir_valid": 1}
        return [
            {"net_window_id": 0, "net_window_start_sec": 0.0, "net_window_end_sec": 0.5,
             "report_keys": [[7, 6, "10.0.0.10", 40001, "10.0.0.1", 80], [9, 17, "10.0.0.10", 50001, "10.0.0.1", 53]],
             "rows": [row(7, 10, 1000), row(9, 4, 400)], "cleared_indexes": []},
            {"net_window_id": 1, "net_window_start_sec": 0.5, "net_window_end_sec": 1.0, "report_keys": [],
             "rows": [row(7, 15, 1500), row(9, 6, 600)], "cleared_indexes": [9]},
            {"net_window_id": 2, "net_window_start_sec": 1.0, "net_window_end_sec": 1.5,
             "report_keys": [], "rows": [row(7, 15, 1500)], "cleared_indexes": []},
        ]

    def test_owned_indexes_and_features(self):
        table = sj.OwnerTable(sj.parse_lines(LOG.splitlines()))
        # sockowner clock = wall + offset; windows end at t0 + 0.5 s ... so pick the offset that puts them at ~3000 ns
        t0 = 100.0
        offset = 3000 - int((t0 + 0.5) * 1e9)
        joined = sj.socket_join_windows(self.windows(), table, sj.Selector(cgroup_ids={7001}), t0, offset)
        self.assertEqual([w["owned_indexes"] for w in joined], [[7], [7], [7]])
        joined_b = sj.socket_join_windows(self.windows(), table, sj.Selector(cgroup_ids={7002}), t0, offset)
        # bucket 9 is cleared after window 1, so it has no owner in window 2
        self.assertEqual([w["owned_indexes"] for w in joined_b], [[9], [9], []])
        all_rows = self.hc.build_net_summaries(self.windows(), 0.5)
        only_a = self.hc.build_net_summaries(joined, 0.5)
        only_b = self.hc.build_net_summaries(joined_b, 0.5)
        self.assertEqual([s["net_pkts_total_delta"] for s in all_rows], [14, 7, 0])
        self.assertEqual([s["net_pkts_total_delta"] for s in only_a], [10, 5, 0])
        self.assertEqual([s["net_pkts_total_delta"] for s in only_b], [4, 2, 0])
        self.assertEqual([s["net_flow_count_seen"] for s in only_a], [1, 1, 1])
        self.assertEqual([s["net_flow_count_seen"] for s in all_rows], [2, 2, 1])
        # without the key the summarizer behaves as before
        self.assertEqual(self.hc.build_net_summaries([dict(w) for w in self.windows()], 0.5), all_rows)

    def test_health_parser_and_cli_guard(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "s.log")
            with open(path, "w") as f:
                f.write("SOCKOWNER_READY,1\nFLOW,1,2,3,egress,tcp,1.1.1.1,1,2.2.2.2,2\nSOCKOWNER_HEALTH,0,1,0\n")
            self.assertEqual(self.hc.sockowner_health(path), {"ringbuf_drops": 0, "flow_map_errors": 1, "failed": 0})
            self.assertIsNone(self.hc.sockowner_health(os.path.join(tmp, "missing.log")))
        parser = self.hc.build_arg_parser()
        args = parser.parse_args(["--mode", "command", "--scenario-name", "t", "--label", "benign",
                                  "--command", "true", "--sockowner", "/x"])
        self.assertEqual(args.sockowner_attach, "/sys/fs/cgroup")
        self.assertIsNone(args.hostmon_cgroup)


class IpScopeTests(unittest.TestCase):
    """The host-level join (--scope-ip): one host's network features are those of its own flows."""

    def setUp(self):
        import hybrid_collector as hc  # noqa: E402
        self.hc = hc

    def windows(self):
        row = lambda idx, pkts, by: {"idx": idx, "pkts": pkts, "bytes": by, "pkts_ab": pkts, "bytes_ab": by,  # noqa: E731
                                     "syn": 1, "ack": pkts, "rst": 0, "min_len": 60, "max_len": 100,
                                     "first_ts": 1000, "last_ts": 2000, "dir_valid": 1}
        # bucket 7: host 10.0.0.10's connection; bucket 9: host 10.0.0.11's, cleared after window 1, reported again
        return [
            {"net_window_id": 0, "net_window_start_sec": 0.0, "net_window_end_sec": 0.5,
             "report_keys": [[7, 6, "10.0.0.10", 40001, "10.0.0.2", 80], [9, 17, "10.0.0.11", 50001, "10.0.0.2", 53]],
             "rows": [row(7, 10, 1000), row(9, 4, 400)], "cleared_indexes": []},
            {"net_window_id": 1, "net_window_start_sec": 0.5, "net_window_end_sec": 1.0, "report_keys": [],
             "rows": [row(7, 15, 1500), row(9, 6, 600)], "cleared_indexes": [9]},
            {"net_window_id": 2, "net_window_start_sec": 1.0, "net_window_end_sec": 1.5,
             "report_keys": [[9, 17, "10.0.0.11", 50002, "10.0.0.2", 53]],
             "rows": [row(7, 15, 1500), row(9, 3, 300)], "cleared_indexes": []},
        ]

    def test_two_hosts_partition_the_window(self):
        a = sj.ip_scope_windows(self.windows(), ["10.0.0.10"])
        b = sj.ip_scope_windows(self.windows(), ["10.0.0.11"])
        server = sj.ip_scope_windows(self.windows(), ["10.0.0.2"])
        self.assertEqual([w["owned_indexes"] for w in a], [[7], [7], [7]])
        self.assertEqual([w["owned_indexes"] for w in b], [[9], [9], [9]])
        self.assertEqual([w["owned_indexes"] for w in server], [[7, 9], [7, 9], [7, 9]])
        self.assertEqual([w["owned_indexes"] for w in sj.ip_scope_windows(self.windows(), ["192.0.2.1"])], [[], [], []])
        whole = self.hc.build_net_summaries(self.windows(), 0.5)
        sa, sb = self.hc.build_net_summaries(a, 0.5), self.hc.build_net_summaries(b, 0.5)
        for k in range(3):
            self.assertEqual(sa[k]["net_pkts_total_delta"] + sb[k]["net_pkts_total_delta"], whole[k]["net_pkts_total_delta"])
            self.assertEqual(sa[k]["net_bytes_total_delta"] + sb[k]["net_bytes_total_delta"], whole[k]["net_bytes_total_delta"])
        self.assertEqual([s["net_flow_count_seen"] for s in sa], [1, 1, 1])
        # the server's address takes every flow: the window-level join
        self.assertEqual(self.hc.build_net_summaries(server, 0.5), whole)

    def test_cli(self):
        args = self.hc.build_arg_parser().parse_args(["--mode", "command", "--scenario-name", "t", "--label", "benign",
                                                      "--command", "true", "--scope-ip", "10.0.0.10",
                                                      "--scope-ip", "10.0.0.11"])
        self.assertEqual(args.scope_ip, ["10.0.0.10", "10.0.0.11"])
        self.assertEqual(self.hc.scoped_csv_path("runs/w.csv", "10.0.0.11"), Path("runs/w.scoped-10.0.0.11.csv"))

    def test_cli_refuses_the_exact_build(self):
        # switch/variants/exact sends no CPU reports, so no bucket has an owner to split the rows by
        import contextlib
        import io
        from unittest import mock
        argv = ["hybrid_collector.py", "--mode", "command", "--scenario-name", "t", "--label", "benign",
                "--command", "true", "--switch-program", "exact", "--scope-ip", "10.0.0.10"]
        err = io.StringIO()
        with mock.patch.object(sys, "argv", argv), contextlib.redirect_stderr(err):
            with self.assertRaises(SystemExit):
                self.hc.main()
        self.assertIn("--scope-ip needs the CPU reports", err.getvalue())
