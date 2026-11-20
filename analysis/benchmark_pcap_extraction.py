#!/usr/bin/env python3
"""Benchmark offline PCAP decoding and P4-shaped feature reconstruction.

This measures Python/Scapy processing only. It does not measure a live P4
pipeline, eBPF collection, NIC throughput, or end-to-end hybrid performance.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import platform
import statistics
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import numpy as np
from scapy.layers.inet import IP, TCP, UDP
from scapy.utils import PcapReader

from analyze_p4_pcap_ablation import derive_p4_features, recover_frame_windows


PassResult = tuple[int, int, int]


def read_inputs(run_dir: Path) -> tuple[Path, list[dict[str, str]], dict[str, Any]]:
    pcap_path = run_dir / "packet_capture.pcap"
    metadata_path = run_dir / "run.json"
    telemetry_path = run_dir / "telemetry.csv"
    missing = [path.name for path in (pcap_path, metadata_path, telemetry_path) if not path.is_file()]
    if missing:
        raise FileNotFoundError(f"Missing required run files: {', '.join(missing)}")

    with metadata_path.open(encoding="utf-8") as source:
        metadata = json.load(source)
    with telemetry_path.open(newline="", encoding="utf-8-sig") as source:
        windows = list(csv.DictReader(source))
    if not windows:
        raise ValueError(f"No telemetry windows in {telemetry_path}")

    metadata["sample_started_at_utc"] = windows[0]["window_start_utc"]
    metadata["window_seconds"] = float(windows[0]["window_seconds"])
    return pcap_path, windows, metadata


def scan_pcap(pcap_path: Path) -> PassResult:
    frames = 0
    captured_frame_bytes = 0
    eligible_packets = 0
    with PcapReader(str(pcap_path)) as capture:
        for packet in capture:
            frames += 1
            captured_frame_bytes += len(packet)
            if packet.haslayer(IP) and (packet.haslayer(TCP) or packet.haslayer(UDP)):
                eligible_packets += 1
    return frames, captured_frame_bytes, eligible_packets


def scan_window_eligible_packets(
    pcap_path: Path,
    windows: list[dict[str, str]],
    metadata: dict[str, Any],
) -> int:
    with PcapReader(str(pcap_path)) as capture:
        packets = list(capture)
    frame_times = np.asarray([float(packet.time) for packet in packets])
    frame_windows, alignment = recover_frame_windows(frame_times, windows, metadata)
    if alignment["alignment_status"] != "unique":
        raise RuntimeError(f"PCAP/telemetry alignment is {alignment['alignment_status']}")
    return sum(
        window_index is not None
        and packet.haslayer(IP)
        and (packet.haslayer(TCP) or packet.haslayer(UDP))
        for packet, window_index in zip(packets, frame_windows, strict=True)
    )


def benchmark(
    operation: Callable[[], PassResult],
    expected: PassResult,
    repeats: int,
    batch_size: int,
) -> dict[str, float | int]:
    for _ in range(min(3, repeats)):
        if operation() != expected:
            raise RuntimeError("Warm-up pass returned inconsistent packet counts")

    wall_seconds_per_pass = []
    cpu_seconds_per_pass = []
    remaining = repeats
    while remaining:
        count = min(batch_size, remaining)
        wall_start = time.perf_counter()
        cpu_start = time.process_time()
        for _ in range(count):
            if operation() != expected:
                raise RuntimeError("Measured pass returned inconsistent packet counts")
        wall_seconds_per_pass.append((time.perf_counter() - wall_start) / count)
        cpu_seconds_per_pass.append((time.process_time() - cpu_start) / count)
        remaining -= count

    ordered = sorted(wall_seconds_per_pass)
    median_wall = statistics.median(wall_seconds_per_pass)
    median_cpu = statistics.median(cpu_seconds_per_pass)
    p95_wall = ordered[max(0, math.ceil(0.95 * len(ordered)) - 1)]
    frame_count, captured_bytes, _ = expected
    return {
        "passes": repeats,
        "batches": len(wall_seconds_per_pass),
        "median_wall_ms_per_pass": median_wall * 1000,
        "p95_batch_average_wall_ms_per_pass": p95_wall * 1000,
        "median_cpu_ms_per_pass": median_cpu * 1000,
        "median_frames_per_second": frame_count / median_wall if median_wall else 0.0,
        "median_captured_MiB_per_second": (
            captured_bytes / (1024 * 1024) / median_wall if median_wall else 0.0
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_dir", type=Path, help="Run directory with run.json, telemetry.csv, and packet_capture.pcap")
    parser.add_argument("--repeats", type=int, default=500)
    parser.add_argument("--batch-size", type=int, default=25)
    args = parser.parse_args()
    if args.repeats < 1 or args.batch_size < 1:
        parser.error("--repeats and --batch-size must be positive")

    run_dir = args.run_dir.expanduser().resolve()
    try:
        pcap_path, windows, metadata = read_inputs(run_dir)
        expected = scan_pcap(pcap_path)
        expected_window_eligible = scan_window_eligible_packets(
            pcap_path, windows, metadata
        )
        expected_extraction = (*expected[:2], expected_window_eligible)

        def extract_pass() -> PassResult:
            features, _, diagnostics = derive_p4_features(pcap_path, windows, metadata)
            if diagnostics["alignment_status"] != "unique":
                raise RuntimeError(
                    f"PCAP/telemetry alignment is {diagnostics['alignment_status']}"
                )
            return (
                int(diagnostics["pcap_frame_count"]),
                expected[1],
                int(diagnostics["p4_eligible_packets_in_windows"]),
            )

        feature_count = len(derive_p4_features(pcap_path, windows, metadata)[0])
        extraction_result = extract_pass()
        if extraction_result != expected_extraction:
            raise RuntimeError(
                f"Windowed extraction counts differ: {expected_extraction} != {extraction_result}"
            )
        decode_result = benchmark(
            lambda: scan_pcap(pcap_path), expected, args.repeats, args.batch_size
        )
        extraction_result = benchmark(
            extract_pass, expected_extraction, args.repeats, args.batch_size
        )
    except (OSError, ValueError, RuntimeError, KeyError) as error:
        parser.error(str(error))

    print(
        json.dumps(
            {
                "scope": "offline_python_scapy_only",
                "claims_live_p4_or_ebpf_performance": False,
                "environment": {
                    "python": platform.python_version(),
                    "kernel": platform.release(),
                    "warm_cache_repeated_passes": True,
                },
                "input": {
                    "run_dir": str(run_dir),
                    "pcap_bytes": pcap_path.stat().st_size,
                    "frames_per_pass": expected[0],
                    "captured_frame_bytes_per_pass": expected[1],
                    "p4_eligible_packets_per_pass": expected_extraction[2],
                    "telemetry_windows": len(windows),
                    "p4_shaped_features": feature_count,
                },
                "decode_only": decode_result,
                "p4_shaped_feature_extraction": extraction_result,
                "limitations": [
                    "This is an offline Python/Scapy path, not the P4 data plane or eBPF collector.",
                    "Repeated processing of a small captured trace does not establish line-rate capacity.",
                    "The full feature path loads the PCAP into memory and constructs per-packet Python state.",
                ],
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
