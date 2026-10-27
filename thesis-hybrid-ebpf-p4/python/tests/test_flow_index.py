from __future__ import annotations

import random
import unittest

from flow_index import compute_flow_index, compute_flow_index_symmetric, crc16_arc


class FlowIndexTests(unittest.TestCase):
    def test_crc16_arc_check_value(self):
        # Standard CRC-16/ARC check value for the ASCII string "123456789".
        self.assertEqual(crc16_arc(b"123456789"), 0xBB3D)

    def test_index_is_symmetric_in_both_directions(self):
        rng = random.Random(1)
        for _ in range(2000):
            a, b = rng.getrandbits(32), rng.getrandbits(32)
            sp, dp = rng.getrandbits(16), rng.getrandbits(16)
            proto = rng.choice((6, 17))
            self.assertEqual(compute_flow_index(a, b, sp, dp, proto),
                             compute_flow_index(b, a, dp, sp, proto))

    def test_known_vector_from_the_compiled_hash(self):
        # Bucket of the Phase 2.1 sanity connection under the @symmetric hash, as
        # evaluated from the compiled hash matrix (perf/tools/hash_matrix_check.py).
        self.assertEqual(compute_flow_index("10.99.0.1", "10.99.0.2", 40001, 5001, 6), 6886)
        self.assertEqual(compute_flow_index("10.99.0.2", "10.99.0.1", 5001, 40001, 6), 6886)

    def test_string_and_integer_addresses_agree(self):
        self.assertEqual(compute_flow_index("10.0.0.1", "10.0.0.2", 12345, 443, 6),
                         compute_flow_index(0x0A000001, 0x0A000002, 12345, 443, 6))

    def test_legacy_name_is_the_same_function(self):
        self.assertIs(compute_flow_index_symmetric, compute_flow_index)


if __name__ == "__main__":
    unittest.main()
