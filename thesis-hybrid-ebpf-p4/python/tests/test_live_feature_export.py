from __future__ import annotations

import unittest

from live_feature_export import counter_delta, summarize_register_window


class LiveFeatureExportTests(unittest.TestCase):
    def test_directional_deltas_and_rates_match_the_model_sensor_fields(self):
        before = {
            17: {"pkts": 20, "bytes": 2000, "pkts_ab": 12, "bytes_ab": 1200},
        }
        after = {
            17: {"pkts": 30, "bytes": 3000, "pkts_ab": 19, "bytes_ab": 1900},
        }

        result = summarize_register_window(before, after, 2.0)

        self.assertEqual(
            result,
            {
                "net_bytes_captured": 1000,
                "net_bytes_per_second": 500.0,
                "net_bytes_recv": 300,
                "net_bytes_sent": 700,
                "net_flow_count": 1,
                "net_packets_captured": 10,
                "net_packets_per_second": 5.0,
                "net_packets_recv": 3,
                "net_packets_sent": 7,
            },
        )

    def test_counter_wrap_is_counted_modulo_register_width(self):
        self.assertEqual(counter_delta(2, (1 << 32) - 3), 5)

    def test_inconsistent_or_missing_counters_fail(self):
        with self.assertRaisesRegex(ValueError, "Directional P4 counters exceed totals"):
            summarize_register_window(
                {1: {"pkts": 1, "bytes": 1, "pkts_ab": 0, "bytes_ab": 0}},
                {1: {"pkts": 2, "bytes": 2, "pkts_ab": 2, "bytes_ab": 0}},
                1,
            )
        with self.assertRaisesRegex(ValueError, "missing P4 counters"):
            summarize_register_window(
                {1: {"pkts": 1, "bytes": 1, "pkts_ab": 0}},
                {1: {"pkts": 2, "bytes": 2, "pkts_ab": 1, "bytes_ab": 1}},
                1,
            )


if __name__ == "__main__":
    unittest.main()
