#!/usr/bin/env python3
"""Test double for hybrid_collector.py --p4-reader: fail chosen calls, run the real reader otherwise.

    FLAKY_STATE=/path/count FLAKY_FAIL_ON=2,3 FLAKY_FAIL_FROM=6 \
        hybrid_collector.py ... --p4-reader live_test/flaky_reader.py

FLAKY_STATE counts the calls (start from a missing file). Call n fails (exit 1
with a message on stderr, as a failed bfshell session does) if n is listed in
FLAKY_FAIL_ON or n >= FLAKY_FAIL_FROM; FLAKY_HANG=1 makes failing calls hang
instead, until the collector's read timeout kills them.
"""
import os
import sys
import time
from pathlib import Path

REAL_READER = Path(__file__).resolve().parents[1] / "thesis-hybrid-ebpf-p4" / "python" / "read_registers_with_index.py"

state = Path(os.environ["FLAKY_STATE"])
fail_on = {int(x) for x in os.environ.get("FLAKY_FAIL_ON", "").split(",") if x.strip()}
fail_from = int(os.environ.get("FLAKY_FAIL_FROM", "0"))
n = (int(state.read_text()) if state.exists() else 0) + 1
state.write_text(str(n))
if n in fail_on or (fail_from and n >= fail_from):
    if os.environ.get("FLAKY_HANG") == "1":
        time.sleep(3600)
    print(f"[ERROR] flaky_reader: simulated failure of call {n}", file=sys.stderr)
    sys.exit(1)
os.execv(sys.executable, [sys.executable, str(REAL_READER)] + sys.argv[1:])
