from __future__ import annotations

import io
import os
import socket
import struct
import sys
import tempfile
import textwrap
import time
import unittest
from pathlib import Path

from flow_index import compute_flow_index, compute_newconn_dst_index
from listen_cpu_reports import LEGACY_MAGIC, MAGIC, ReportCollector, iter_pcap_stream, parse_cpu_report

PACKET_TAIL = bytes(range(46))  # mirrored copies carry the start of the packet after the report


def report(magic, src, dst, sport, dport, proto, idx=None):
    raw = struct.pack("!HIIHHBB", magic, struct.unpack("!I", socket.inet_aton(src))[0],
                      struct.unpack("!I", socket.inet_aton(dst))[0], sport, dport, proto, 1)
    if idx is not None:
        raw += struct.pack("!H", idx)
    return raw + PACKET_TAIL


class TakeTests(unittest.TestCase):
    def test_take_and_take_after(self):
        rc = ReportCollector("veth5")
        rc._reports.extend([(1.0, {"idx": 1}), (2.0, {"idx": 2}), (3.0, {"idx": 3})])
        self.assertEqual([r["idx"] for r in rc.take(1.0, 2.0)], [1])
        self.assertEqual([r["idx"] for r in rc.take_after(2.0)], [2, 3])
        self.assertEqual(rc.take_after(4.0), [])


class ParseCpuReportTests(unittest.TestCase):
    def test_current_report_carries_the_index(self):
        expected = compute_flow_index("10.0.0.1", "10.0.0.2", 1234, 80, 6)
        parsed = parse_cpu_report(report(MAGIC, "10.0.0.1", "10.0.0.2", 1234, 80, 6, idx=expected))
        self.assertEqual(parsed["idx"], expected)
        self.assertEqual(parsed["idx_source"], "report")
        self.assertEqual(parsed["idx_computed"], expected)
        self.assertEqual((parsed["src_ip"], parsed["sport"], parsed["dst_ip"], parsed["dport"]),
                         ("10.0.0.1", 1234, "10.0.0.2", 80))

    def test_a_tcp_report_carries_its_destination_bucket(self):
        parsed = parse_cpu_report(report(MAGIC, "10.99.6.1", "10.99.6.2", 40000, 80, 6, idx=1))
        self.assertEqual(parsed["dst_idx"], compute_newconn_dst_index("10.99.6.1", "10.99.6.2", 80, 6))
        self.assertEqual(parsed["dst_idx"], 11438)   # the compiled hash's known answer (test_flow_index)
        udp = parse_cpu_report(report(MAGIC, "10.99.6.1", "10.99.6.2", 40000, 80, 17, idx=1))
        self.assertIsNone(udp["dst_idx"])

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


class RemoteCaptureTests(unittest.TestCase):
    """ReportCollector(ssh_host=...) through a stand-in `ssh` on PATH that runs
    the remote command locally, with tcpdump replaced by a script that writes a
    pcap stream with one report and then waits to be killed: stop() must end
    that process through a second ssh, not only the local ssh."""

    def test_stop_kills_the_capture_on_the_remote_host(self):
        d = Path(tempfile.mkdtemp())
        frame = report(MAGIC, "10.0.0.1", "10.0.0.2", 1234, 80, 6, idx=7)
        pidfile = d / "tcpdump.pid"
        fake_tcpdump = d / "fake_tcpdump.py"
        fake_tcpdump.write_text(textwrap.dedent('''\
            import os, struct, sys, time
            frame = bytes.fromhex(%r)
            out = sys.stdout.buffer
            out.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1))
            out.write(struct.pack("<IIII", 1, 0, len(frame), len(frame)) + frame)
            out.flush()
            open(%r, "w").write(str(os.getpid()))
            os.rename(%r, %r)
            time.sleep(600)
            ''') % (frame.hex(), str(pidfile) + ".tmp", str(pidfile) + ".tmp", str(pidfile)))
        ssh = d / "ssh"
        ssh.write_text(textwrap.dedent('''\
            #!/bin/sh
            # stand-in for ssh: drop the options and the host, log the command, run it locally
            while [ "$#" -gt 0 ]; do case "$1" in -o) shift 2;; -*) shift;; *) break;; esac; done
            shift
            echo "$*" >> %r
            cmd=$(printf '%%s' "$*" | sed "s|exec tcpdump .*|exec %s %s|")
            exec sh -c "$cmd"
            ''') % (str(d / "ssh.log"), sys.executable, str(fake_tcpdump)))
        ssh.chmod(0o755)
        saved_path = os.environ["PATH"]
        os.environ["PATH"] = str(d) + os.pathsep + saved_path
        try:
            rc = ReportCollector("enp5s0", ssh_host="root@switch").start()
            deadline = time.time() + 10
            while time.time() < deadline and not pidfile.exists():
                time.sleep(0.05)
            pid = int(pidfile.read_text())
            while time.time() < deadline and not rc.take(0, float("inf")):
                time.sleep(0.05)
            self.assertEqual([r["idx"] for r in rc.take(0, float("inf"))], [7])
            rc.stop()
        finally:
            os.environ["PATH"] = saved_path
        self.assertEqual(rc.remote_pid, pid)
        self.assertIn("kill %d" % pid, (d / "ssh.log").read_text())
        with self.assertRaises(ProcessLookupError):   # ended and reaped, not left running
            os.kill(pid, 0)


if __name__ == "__main__":
    unittest.main()
