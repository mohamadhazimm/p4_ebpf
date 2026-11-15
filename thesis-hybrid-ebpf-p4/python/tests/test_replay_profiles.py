"""live_test/replay_capture.py --profile and live_test/dataset_row.py --skip-windows (PC1.md Part 4)."""
import csv
import importlib.util
import json
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
RELEASE = REPO.parent / "p4-ebpf-malware-detection"


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ReplayProfiles(unittest.TestCase):
    def setUp(self):
        self.rc = load("replay_capture", REPO / "live_test" / "replay_capture.py")

    def test_switch_profile_is_unchanged(self):
        window, extra = self.rc.profile_settings("switch", 2)
        self.assertEqual(window, 1.0)
        self.assertEqual(extra, ["--profile", "switch"])

    def test_dataset_profile_runs_k_plus_40_windows_of_half_a_second(self):
        window, extra = self.rc.profile_settings("dataset", 4)
        self.assertEqual(window, 0.5)
        self.assertEqual(extra, ["--profile", "dataset", "--launcher", "shell", "--windows", "44"])

    def test_unknown_profile(self):
        with self.assertRaises(ValueError):
            self.rc.profile_settings("model", 2)

    def test_collector_accepts_the_dataset_replay_options(self):
        hc = load("hybrid_collector_for_test", REPO / "hybrid_collector.py")
        _, extra = self.rc.profile_settings("dataset", 4)
        argv = extra + ["--mode", "command", "--scenario-name", "x", "--label", "replay", "--command", "true",
                        "--out-csv", "w.csv"]
        pre, _ = hc.profile_parser().parse_known_args(argv)
        args = hc.build_arg_parser(pre.profile).parse_args(argv)
        self.assertEqual(args.window_sec, 0.5)
        self.assertEqual(args.windows, 44)
        self.assertEqual(args.launcher, "shell")
        self.assertEqual(args.byte_layer, "frame")
        self.assertEqual(args.duration_unit, "s")


def write_pcap(path, frames):
    """A classic little-endian microsecond pcap of (time, frame) records."""
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for t, frame in frames:
            sec = int(t)
            f.write(struct.pack("<IIII", sec, int(round((t - sec) * 1e6)), len(frame), len(frame)))
            f.write(frame)


def tcp_frame(sport):
    """An Ethernet + IPv4 + TCP frame without payload (IPv4 total length 40), padded to 60 B."""
    eth = b"\x02\x00\x00\x00\x00\x01" + b"\x02\x00\x00\x00\x00\x02" + b"\x08\x00"
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 1, 0, 64, 6, 0, bytes([10, 0, 0, 10]), bytes([10, 0, 0, 1]))
    tcp = struct.pack("!HHIIBBHHH", sport, 80, 1, 0, 0x50, 0x02, 1024, 0, 0)
    return (eth + ip + tcp).ljust(60, b"\x00")


class SelfCheckByteLayer(unittest.TestCase):
    """PC1.md part 4: under --profile dataset the collector reports frame bytes (+14 B per packet), so
    the self-check has to count the sent bytes the same way, or every window with traffic is 'outside'."""

    def setUp(self):
        self.rc = load("replay_capture", REPO / "live_test" / "replay_capture.py")

    def test_the_header_matches_the_collectors_profiles(self):
        sys.path.insert(0, str(REPO))
        import hybrid_collector as hc
        self.assertEqual(hc.PROFILES["dataset"]["byte_layer"], "frame")
        self.assertEqual(self.rc.self_check_header_bytes("dataset"), hc.ETHERNET_HEADER_BYTES)
        self.assertNotEqual(hc.PROFILES["switch"].get("byte_layer", "ipv4"), "frame")
        self.assertEqual(self.rc.self_check_header_bytes("switch"), 0)
        with self.assertRaises(ValueError):
            self.rc.self_check_header_bytes("model")

    def test_frame_bytes_of_the_collector_fall_inside_the_bounds(self):
        t0, window = 1000.0, 0.5
        sent = [(1000.10, tcp_frame(1001)), (1000.20, tcp_frame(1002)), (1000.70, tcp_frame(1003))]
        with tempfile.TemporaryDirectory() as d:
            out = Path(d)
            write_pcap(out / "cap.pcap", [(t - 990.0, f) for t, f in sent])
            write_pcap(out / "tx.pcap", sent)
            with open(out / "timing.jsonl", "w") as f:
                for k in (0, 1):
                    end = t0 + (k + 1) * window
                    clock = {"collector_t_sent": end + 0.001, "reader_t_recv": end + 0.0015,
                             "reader_t_send": end + 0.0025, "collector_t_reply": end + 0.003,
                             "reader_t_sync_start": end + 0.0016, "reader_t_sync_end": end + 0.0020}
                    f.write(json.dumps({"window": k, "t_window_end": end, "clock": clock}) + "\n")
            with open(out / "windows.csv", "w", newline="") as f:
                w = csv.DictWriter(f, fieldnames=["net_window_id", "net_pkts_total_delta", "net_bytes_total_delta",
                                                  "net_overload"])
                w.writeheader()
                w.writerow({"net_window_id": 0, "net_pkts_total_delta": 2, "net_bytes_total_delta": 2 * 54,
                            "net_overload": 0})
                w.writerow({"net_window_id": 1, "net_pkts_total_delta": 1, "net_bytes_total_delta": 54,
                            "net_overload": 0})
            frame = self.rc.analyse(out, out / "cap.pcap", 0.0, 0, None, 0.02, window,
                                    header_bytes=self.rc.self_check_header_bytes("dataset"))
            ipv4 = self.rc.analyse(out, out / "cap.pcap", 0.0, 0, None, 0.02, window)
        sc = frame["self_check"]
        self.assertEqual((sc["windows_checked"], sc["windows_inside_bounds"]), (2, 2))
        self.assertEqual((sc["sent_bytes_total"], sc["switch_bytes_total"], sc["byte_layer"]), (162, 162, "frame"))
        self.assertEqual(ipv4["self_check"]["windows_inside_bounds"], 0, "IPv4 bytes against frame bytes: the old miss")
        self.assertEqual(ipv4["self_check"]["sent_bytes_total"], 120)


class SelfCheckTotalsCut(unittest.TestCase):
    """PC1.md part 4e: with --global-totals a window's totals are cut where the global totals were read, not at the
    flow registers' snapshot, and an overloaded window's totals do not depend on the buckets read."""

    def setUp(self):
        self.rc = load("replay_capture", REPO / "live_test" / "replay_capture.py")

    def test_the_totals_read_is_the_cut_and_overloaded_windows_are_checked(self):
        t0, window = 1000.0, 0.5
        # one packet 3 ms after the boundary of windows 0/1: after the totals' read (1.5-2.5 ms after it), so in
        # window 1, though before the end of the flow registers' snapshot (40 ms)
        sent = [(1000.10, tcp_frame(1001)), (1000.503, tcp_frame(1002)), (1000.70, tcp_frame(1003))]
        with tempfile.TemporaryDirectory() as d:
            out = Path(d)
            write_pcap(out / "cap.pcap", [(t - 990.0, f) for t, f in sent])
            write_pcap(out / "tx.pcap", sent)
            with open(out / "timing.jsonl", "w") as f:
                for k in (0, 1):
                    end = t0 + (k + 1) * window
                    clock = {"collector_t_sent": end + 0.001, "reader_t_recv": end + 0.0012,
                             "reader_t_send": end + 0.0418, "collector_t_reply": end + 0.042,
                             "reader_t_totals_start": end + 0.0015, "reader_t_totals_end": end + 0.0025,
                             "reader_t_sync_start": end + 0.010, "reader_t_sync_end": end + 0.040}
                    f.write(json.dumps({"window": k, "t_window_end": end, "clock": clock}) + "\n")

            def windows(pkts, gtot):
                with open(out / "windows.csv", "w", newline="") as f:
                    w = csv.DictWriter(f, fieldnames=["net_window_id", "net_pkts_total_delta", "net_bytes_total_delta",
                                                      "net_overload", "net_gtot_used"])
                    w.writeheader()
                    for k, n in enumerate(pkts):
                        w.writerow({"net_window_id": k, "net_pkts_total_delta": n, "net_bytes_total_delta": 54 * n,
                                    "net_overload": 1, "net_gtot_used": gtot})
                return self.rc.analyse(out, out / "cap.pcap", 0.0, 0, None, 0.0, window, header_bytes=14)

            totals = windows([1, 2], 1)["self_check"]
            spilled = windows([2, 1], 1)["self_check"]
            buckets = windows([1, 2], 0)["self_check"]
        self.assertEqual((totals["windows_checked"], totals["windows_inside_bounds"]), (2, 2))
        self.assertEqual(totals["windows_cut_by_the_totals"], 2)
        self.assertAlmostEqual(totals["totals_read_end_after_window_end_ms"]["median"], 2.5, delta=0.5)
        self.assertEqual(spilled["windows_inside_bounds"], 0, "a packet 3 ms in counted before a cut at 2.5 ms")
        self.assertEqual(buckets["windows_checked"], 0, "bucket totals of overloaded windows are not checked")


@unittest.skipUnless((RELEASE / "features" / "summary.py").exists(), "release repository not next to p4_ebpf")
class DatasetRowSkip(unittest.TestCase):
    def test_skip_windows_takes_the_dataset_windows(self):
        sm = load("switch_model", RELEASE / "features" / "switch_model.py")
        hm = load("host_model", RELEASE / "features" / "host_model.py")
        feats = sm.FEATURES + hm.FEATURES
        with tempfile.TemporaryDirectory() as d:
            src, out_a, out_b = Path(d) / "w.csv", Path(d) / "a.csv", Path(d) / "b.csv"
            with open(src, "w", newline="") as f:
                w = csv.DictWriter(f, fieldnames=["run_id", "window_id"] + feats)
                w.writeheader()
                for k in range(44):
                    # the 4 windows before the anchor carry junk; windows 4..43 carry k
                    row = {name: (1e6 if k < 4 else float(k)) for name in feats}
                    w.writerow(dict(row, run_id="r", window_id=k))
            only = Path(d) / "only.csv"
            with open(src, newline="") as f, open(only, "w", newline="") as g:
                rows = list(csv.DictReader(f))
                w = csv.DictWriter(g, fieldnames=list(rows[0]))
                w.writeheader()
                for r in rows[4:]:
                    w.writerow(dict(r, window_id=int(r["window_id"]) - 4))
            base = [sys.executable, str(REPO / "live_test" / "dataset_row.py"), "--execution-id", "x",
                    "--category", "benign", "--label", "0", "--release", str(RELEASE)]
            subprocess.run(base + [str(src), "--skip-windows", "4", "--out", str(out_a)], check=True,
                           capture_output=True)
            subprocess.run(base + [str(only), "--out", str(out_b)], check=True, capture_output=True)
            self.assertEqual(out_a.read_text(), out_b.read_text())
            short = subprocess.run(base + [str(src), "--skip-windows", "5", "--out", str(Path(d) / "c.csv")],
                                   capture_output=True, text=True)
            self.assertNotEqual(short.returncode, 0)
            self.assertIn("45 are needed", short.stderr)


if __name__ == "__main__":
    unittest.main()
