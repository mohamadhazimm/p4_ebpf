from __future__ import annotations

import math
from collections.abc import Mapping
from typing import Any


COUNTER_WIDTH = 32
CORE_COUNTERS = ("pkts", "bytes", "pkts_ab", "bytes_ab")


def counter_delta(current: int, previous: int, width: int = COUNTER_WIDTH) -> int:
    if width < 1:
        raise ValueError("Counter width must be positive")
    limit = 1 << width
    if not isinstance(current, int) or not isinstance(previous, int):
        raise ValueError("Counter values must be integers")
    if not 0 <= current < limit or not 0 <= previous < limit:
        raise ValueError(f"Counter values must be in [0, {limit})")
    return (current - previous) % limit


def summarize_register_window(
    before: Mapping[int, Mapping[str, Any]],
    after: Mapping[int, Mapping[str, Any]],
    duration_sec: float,
) -> dict[str, float | int]:
    if not before or not after:
        raise ValueError("P4 register snapshots must contain at least one flow index")
    if set(before) != set(after):
        raise ValueError("P4 register snapshots do not contain the same flow indexes")
    if not math.isfinite(duration_sec) or duration_sec <= 0:
        raise ValueError("Window duration must be a finite positive number")

    packets_total = 0
    bytes_total = 0
    packets_ab = 0
    bytes_ab = 0
    active_flows = 0

    for index in sorted(before):
        old = before[index]
        new = after[index]
        missing = set(CORE_COUNTERS) - old.keys() | (set(CORE_COUNTERS) - new.keys())
        if missing:
            raise ValueError(f"Flow index {index} is missing P4 counters: {sorted(missing)}")

        flow_packets = counter_delta(new["pkts"], old["pkts"])
        flow_bytes = counter_delta(new["bytes"], old["bytes"])
        flow_packets_ab = counter_delta(new["pkts_ab"], old["pkts_ab"])
        flow_bytes_ab = counter_delta(new["bytes_ab"], old["bytes_ab"])
        if flow_packets_ab > flow_packets or flow_bytes_ab > flow_bytes:
            raise ValueError(f"Directional P4 counters exceed totals at flow index {index}")

        packets_total += flow_packets
        bytes_total += flow_bytes
        packets_ab += flow_packets_ab
        bytes_ab += flow_bytes_ab
        active_flows += int(flow_packets > 0)

    packets_ba = packets_total - packets_ab
    bytes_ba = bytes_total - bytes_ab
    return {
        "net_bytes_captured": bytes_total,
        "net_bytes_per_second": bytes_total / duration_sec,
        "net_bytes_recv": bytes_ba,
        "net_bytes_sent": bytes_ab,
        "net_flow_count": active_flows,
        "net_packets_captured": packets_total,
        "net_packets_per_second": packets_total / duration_sec,
        "net_packets_recv": packets_ba,
        "net_packets_sent": packets_ab,
    }
