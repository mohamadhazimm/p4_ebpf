from __future__ import annotations

import io
import socket
import struct
import unittest

from flow_index import compute_flow_index
from listen_cpu_reports import LEGACY_MAGIC, MAGIC, iter_pcap_stream, parse_cpu_report

PACKET_TAIL = bytes(range(46))  # mirrored copies carry the start of the packet after the report


def report(magic, src, dst, sport, dport, proto, idx=None):
    raw = struct.pack("!HIIHHBB", magic, struct.unpack("!I", socket.inet_aton(src))[0],
                      struct.unpack("!I", socket.inet_aton(dst))[0], sport, dport, proto, 1)
    if idx is not None:
        raw += struct.pack("!H", idx)
    return raw + PACKET_TAIL


class ParseCpuReportTests(unittest.TestCase):
    def test_current_report_carries_the_index(self):
        expected = compute_flow_index("10.0.0.1", "10.0.0.2", 1234, 80, 6)
        parsed = parse_cpu_report(report(MAGIC, "10.0.0.1", "10.0.0.2", 1234, 80, 6, idx=expected))
        self.assertEqual(parsed["idx"], expected)
        self.assertEqual(parsed["idx_source"], "report")
        self.assertEqual(parsed["idx_computed"], expected)
        self.assertEqual((parsed["src_ip"], parsed["sport"], parsed["dst_ip"], parsed["dport"]),
                         ("10.0.0.1", 1234, "10.0.0.2", 80))

    def test_reported_index_wins_over_the_computed_one(self):
        parsed = parse_cpu_report(report(MAGIC, "10.0.0.1", "10.0.0.2", 1234, 80, 6, idx=7))
        self.assertEqual(parsed["idx"], 7)
        self.assertNotEqual(parsed["idx_computed"], 7)

    def test_legacy_report_index_is_computed(self):
        parsed = parse_cpu_report(report(LEGACY_MAGIC, "10.0.0.1", "10.0.0.2", 1234, 80, 17))
        self.assertEqual(parsed["idx_source"], "computed")
        self.assertEqual(parsed["idx"], compute_flow_index("10.0.0.1", "10.0.0.2", 1234, 80, 17))

    def test_other_frames_are_ignored(self):
        self.assertIsNone(parse_cpu_report(b"\x01\x02" + bytes(60)))
        self.assertIsNone(parse_cpu_report(struct.pack("!H", MAGIC) + bytes(10)))


class PcapStreamTests(unittest.TestCase):
    def test_records_are_split_from_a_tcpdump_stream(self):
        frames = [b"\xbe\xf1" + bytes(20), b"\xbe\xef" + bytes(30)]
        stream = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 128, 1)
        for i, f in enumerate(frames):
            stream += struct.pack("<IIII", 100 + i, 500000, len(f), len(f)) + f
        out = list(iter_pcap_stream(io.BytesIO(stream)))
        self.assertEqual([f for _, f in out], frames)
        self.assertAlmostEqual(out[1][0], 101.5)


if __name__ == "__main__":
    unittest.main()
