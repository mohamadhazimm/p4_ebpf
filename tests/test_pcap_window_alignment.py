import unittest
import tempfile
from pathlib import Path

import numpy as np
from scapy.all import Ether, IP, TCP, wrpcap

from analyze_p4_pcap_ablation import derive_p4_features, recover_frame_windows, utc_timestamp


class RecoverFrameWindowsTests(unittest.TestCase):
    def test_rate_window_convention_is_explicit(self):
        packet = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP() / TCP()
        packet.time = 1000.1
        rows = [{"window_start_utc": "1970-01-01T00:16:40+00:00",
                 "window_end_utc": "1970-01-01T00:16:40.400000+00:00", "net_packets_captured": "1"}]
        metadata = {"window_seconds": 0.5, "started_at_utc": rows[0]["window_start_utc"],
                    "finished_at_utc": rows[0]["window_end_utc"]}
        with tempfile.TemporaryDirectory() as directory:
            capture = Path(directory) / "known.pcap"
            wrpcap(str(capture), [packet])
            _, recorded, recorded_info = derive_p4_features(capture, rows, metadata, byte_layer="ethernet")
            _, nominal, nominal_info = derive_p4_features(capture, rows, metadata, byte_layer="ethernet", rate_window="nominal")
        self.assertAlmostEqual(recorded[0]["net_pkts_per_sec_delta"], 2.5)
        self.assertAlmostEqual(nominal[0]["net_pkts_per_sec_delta"], 2.0)
        self.assertEqual(recorded[0]["net_bytes_total_delta"], nominal[0]["net_bytes_total_delta"])
        self.assertEqual(recorded_info["p4_rate_window"], "recorded")
        self.assertEqual(nominal_info["p4_rate_window"], "nominal")

    def test_uses_recorded_jittered_window_intervals(self):
        telemetry_rows = [
            {
                "window_start_utc": "2026-01-01T00:00:00.000000Z",
                "window_end_utc": "2026-01-01T00:00:00.400000Z",
                "net_packets_captured": "1",
            },
            {
                "window_start_utc": "2026-01-01T00:00:00.400000Z",
                "window_end_utc": "2026-01-01T00:00:00.950000Z",
                "net_packets_captured": "2",
            },
            {
                "window_start_utc": "2026-01-01T00:00:00.950000Z",
                "window_end_utc": "2026-01-01T00:00:01.450000Z",
                "net_packets_captured": "1",
            },
        ]
        frame_times = np.asarray(
            [
                utc_timestamp("2026-01-01T00:00:00.100000Z"),
                utc_timestamp("2026-01-01T00:00:00.450000Z"),
                utc_timestamp("2026-01-01T00:00:00.900000Z"),
                utc_timestamp("2026-01-01T00:00:01.100000Z"),
                utc_timestamp("2026-01-01T00:00:01.500000Z"),
            ]
        )
        metadata = {
            "started_at_utc": "2026-01-01T00:00:00.000000Z",
            "finished_at_utc": "2026-01-01T00:00:02.000000Z",
            "sample_started_at_utc": "2026-01-01T00:00:00.000000Z",
            "window_seconds": 0.5,
        }

        assignments, diagnostics = recover_frame_windows(
            frame_times, telemetry_rows, metadata
        )

        self.assertEqual(assignments, [0, 1, 1, 2, None])
        self.assertEqual(diagnostics["alignment_status"], "unique")
        self.assertEqual(diagnostics["unique_packet_window_assignments"], 1)


if __name__ == "__main__":
    unittest.main()