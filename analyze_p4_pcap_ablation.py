#!/usr/bin/env python3
"""Compare eBPF features with P4-shaped features derived from captured PCAPs.

This is an offline approximation of the P4 register feature families, not a
replacement for validating the values against a running P4 target.
"""

from __future__ import annotations

import argparse
import csv
from datetime import datetime
import json
import statistics
from pathlib import Path

import numpy as np
from scapy.layers.inet import IP, TCP, UDP
from scapy.utils import PcapReader
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_selection import SelectKBest, mutual_info_classif
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.pipeline import make_pipeline


P4_FEATURES = [
    "net_flow_count_seen",
    "net_pkts_total_delta",
    "net_bytes_total_delta",
    "net_pkts_ab_delta",
    "net_bytes_ab_delta",
    "net_pkts_ba_delta",
    "net_bytes_ba_delta",
    "net_min_len_mean",
    "net_max_len_mean",
    "net_min_len_min",
    "net_max_len_max",
    "net_avg_pkt_size_delta",
    "net_avg_pkt_size_ab_delta",
    "net_avg_pkt_size_ba_delta",
    "net_flow_duration_mean",
    "net_flow_duration_max",
    "net_bytes_per_sec_delta",
    "net_pkts_per_sec_delta",
    "net_down_up_ratio_delta",
    "net_ab_ratio_pkt_delta",
    "net_ba_ratio_pkt_delta",
    "net_ab_ratio_byte_delta",
    "net_ba_ratio_byte_delta",
    "net_syn_delta",
    "net_ack_delta",
    "net_rst_delta",
    "net_new_conn_dst_max",
    "net_flows_with_ab",
    "net_flows_with_ba",
    "net_dir_valid_count",
]
P4_WINDOW_STATS = ("mean", "max", "sum", "std", "active_windows")
P4_SAMPLE_FEATURES = [
    f"network__p4_{feature}__{statistic}"
    for feature in P4_FEATURES
    for statistic in P4_WINDOW_STATS
]


def load_telemetry_rows(sample_dir: Path) -> list[dict[str, str]]:
    paths = list(sample_dir.rglob("telemetry.csv"))
    if len(paths) != 1:
        raise ValueError(f"Expected one telemetry.csv under {sample_dir}, found {len(paths)}")
    with paths[0].open(newline="", encoding="utf-8-sig") as source:
        return list(csv.DictReader(source))


def utc_timestamp(value: str) -> float:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()


def recover_frame_windows(
    frame_times: np.ndarray,
    telemetry_rows: list[dict[str, str]],
    run_metadata: dict,
) -> tuple[list[int | None], dict[str, int | float | str]]:
    window_seconds = float(run_metadata["window_seconds"])
    target_counts = np.asarray(
        [int(float(row.get("net_packets_captured") or 0)) for row in telemetry_rows]
    )
    run_start = utc_timestamp(run_metadata["started_at_utc"])
    run_end = utc_timestamp(run_metadata["finished_at_utc"])
    sample_start_value = run_metadata.get("sample_started_at_utc")
    if sample_start_value:
        sample_start = utc_timestamp(sample_start_value)
        edges = sample_start + np.arange(len(telemetry_rows) + 1) * window_seconds
        bins = np.searchsorted(edges, frame_times, side="right") - 1
        assignment = [
            int(index)
            if 0 <= index < len(telemetry_rows) and frame_times[position] < edges[index + 1]
            else None
            for position, index in enumerate(bins)
        ]
        counts = np.bincount(
            [index for index in assignment if index is not None],
            minlength=len(telemetry_rows),
        )
        target_match = np.array_equal(counts, target_counts)
        return assignment, {
            "alignment_status": "unique" if target_match else "sample_start_counter_mismatch",
            "exact_offset_representatives": 1,
            "unique_packet_window_assignments": int(target_match),
            "offset_min_after_run_start_seconds": sample_start - run_start,
            "offset_max_after_run_start_seconds": sample_start - run_start,
        }
    if not len(frame_times):
        if target_counts.sum() == 0:
            return [], {
                "alignment_status": "unique",
                "exact_offset_representatives": 1,
                "unique_packet_window_assignments": 1,
                "offset_min_after_run_start_seconds": 0.0,
                "offset_max_after_run_start_seconds": 0.0,
            }
        return [], {
            "alignment_status": "no_exact_counter_match",
            "exact_offset_representatives": 0,
            "unique_packet_window_assignments": 0,
            "offset_min_after_run_start_seconds": 0.0,
            "offset_max_after_run_start_seconds": 0.0,
        }

    breakpoints = {run_start, run_end}
    for timestamp in frame_times:
        for window_index in range(len(telemetry_rows) + 1):
            candidate = float(timestamp - window_index * window_seconds)
            if run_start <= candidate <= run_end:
                breakpoints.add(candidate)
    ordered = sorted(breakpoints)
    candidate_origins = set(ordered)
    candidate_origins.update(
        (left + right) / 2 for left, right in zip(ordered, ordered[1:])
    )

    exact_origins = []
    assignments = set()
    for origin in candidate_origins:
        edges = origin + np.arange(len(telemetry_rows) + 1) * window_seconds
        bins = np.searchsorted(edges, frame_times, side="right") - 1
        assignment = tuple(
            int(index)
            if 0 <= index < len(telemetry_rows) and frame_times[position] < edges[index + 1]
            else -1
            for position, index in enumerate(bins)
        )
        counts = np.bincount(
            [index for index in assignment if index >= 0],
            minlength=len(telemetry_rows),
        )
        if np.array_equal(counts, target_counts):
            exact_origins.append(origin)
            assignments.add(assignment)

    if not exact_origins:
        status = "no_exact_counter_match"
        frame_windows = [None] * len(frame_times)
        assignment_count = 0
    elif len(assignments) != 1:
        status = "ambiguous_packet_assignment"
        frame_windows = [None] * len(frame_times)
        assignment_count = len(assignments)
    else:
        status = "unique"
        frame_windows = [None if index < 0 else index for index in next(iter(assignments))]
        assignment_count = 1

    return frame_windows, {
        "alignment_status": status,
        "exact_offset_representatives": len(exact_origins),
        "unique_packet_window_assignments": assignment_count,
        "offset_min_after_run_start_seconds": (
            min(exact_origins) - run_start if exact_origins else 0.0
        ),
        "offset_max_after_run_start_seconds": (
            max(exact_origins) - run_start if exact_origins else 0.0
        ),
    }


def derive_p4_features(
    pcap_path: Path,
    telemetry_rows: list[dict[str, str]],
    run_metadata: dict,
    active_ttl_windows: int = 3,
) -> tuple[dict[str, float], list[dict[str, float]], dict[str, int | float | str]]:
    if not telemetry_rows:
        raise ValueError(f"No telemetry windows found for {pcap_path}")

    window_seconds = float(run_metadata["window_seconds"])
    window_deltas: list[dict[tuple, dict[str, int]]] = [dict() for _ in telemetry_rows]
    window_new_conns: list[dict[tuple, int]] = [dict() for _ in telemetry_rows]
    packet_events: list[dict] = []
    frame_counts = [0] * len(telemetry_rows)
    first_source_by_flow: dict[tuple, tuple[str, int]] = {}
    with PcapReader(str(pcap_path)) as capture:
        packets = list(capture)
    frame_times = np.asarray([float(packet.time) for packet in packets])
    frame_windows, alignment = recover_frame_windows(
        frame_times, telemetry_rows, run_metadata
    )
    pcap_frame_count = len(packets)
    if alignment["alignment_status"] != "unique":
        telemetry_packet_count = sum(
            int(float(row.get("net_packets_captured") or 0))
            for row in telemetry_rows
        )
        return {}, [], {
            **alignment,
            "pcap_frame_count": pcap_frame_count,
            "pcap_frames_in_windows": telemetry_packet_count,
            "pcap_frames_outside_windows": pcap_frame_count - telemetry_packet_count,
            "telemetry_packet_count": telemetry_packet_count,
            "pcap_telemetry_packet_count_abs_error": 0,
            "p4_eligible_packets_in_windows": "",
            "telemetry_window_count": len(telemetry_rows),
        }

    for packet, window_index in zip(packets, frame_windows, strict=True):
        timestamp = float(packet.time)
        if window_index is not None:
            frame_counts[window_index] += 1
        else:
            continue
        if not packet.haslayer(IP) or not (
            packet.haslayer(TCP) or packet.haslayer(UDP)
        ):
            continue

        ip_layer = packet[IP]
        transport = packet[TCP] if packet.haslayer(TCP) else packet[UDP]
        source = (ip_layer.src, int(transport.sport))
        destination = (ip_layer.dst, int(transport.dport))
        key = (int(ip_layer.proto), *sorted((source, destination)))
        packet_length = len(packet)
        first_source = first_source_by_flow.setdefault(key, source)
        direction = "ab" if source == first_source else "ba"
        if packet.haslayer(TCP):
            flags = int(packet[TCP].flags)
            syn, ack, rst = int(bool(flags & 0x02)), int(bool(flags & 0x10)), int(bool(flags & 0x04))
            # reg_newconn_dst: SYN without ACK per (client, server, server port, protocol)
            if (flags & 0x12) == 0x02:
                new_conn_key = (ip_layer.src, ip_layer.dst, int(transport.dport), int(ip_layer.proto))
                new_conns = window_new_conns[window_index]
                new_conns[new_conn_key] = new_conns.get(new_conn_key, 0) + 1
        else:
            syn = ack = rst = 0
        event = {
            "key": key,
            "timestamp": timestamp,
            "window": window_index,
            "length": packet_length,
            "direction": direction,
            "syn": syn,
            "ack": ack,
            "rst": rst,
        }
        packet_events.append(event)
        delta = window_deltas[window_index].setdefault(
            key,
            {"packets": 0, "bytes": 0, "ab_packets": 0, "ab_bytes": 0,
             "ba_packets": 0, "ba_bytes": 0, "syn": 0, "ack": 0, "rst": 0},
        )
        delta["packets"] += 1
        delta["bytes"] += packet_length
        delta[f"{direction}_packets"] += 1
        delta[f"{direction}_bytes"] += packet_length
        delta["syn"] += syn
        delta["ack"] += ack
        delta["rst"] += rst

    packet_events.sort(key=lambda event: event["timestamp"])
    flow_state: dict[tuple, dict[str, float | int]] = {}
    last_seen_window: dict[tuple, int] = {}
    event_index = 0
    per_window: list[dict[str, float]] = []

    for window_index in range(len(telemetry_rows)):
        while (
            event_index < len(packet_events)
            and packet_events[event_index]["window"] <= window_index
        ):
            event = packet_events[event_index]
            key = event["key"]
            state = flow_state.setdefault(
                key,
                {
                    "packets": 0, "bytes": 0, "ab_packets": 0, "ab_bytes": 0,
                    "ba_packets": 0, "ba_bytes": 0, "min_len": event["length"],
                    "max_len": event["length"], "first_ts": event["timestamp"],
                    "last_ts": event["timestamp"], "syn": 0, "ack": 0, "rst": 0,
                },
            )
            state["packets"] += 1
            state["bytes"] += event["length"]
            state[f"{event['direction']}_packets"] += 1
            state[f"{event['direction']}_bytes"] += event["length"]
            state["min_len"] = min(state["min_len"], event["length"])
            state["max_len"] = max(state["max_len"], event["length"])
            state["first_ts"] = min(state["first_ts"], event["timestamp"])
            state["last_ts"] = max(state["last_ts"], event["timestamp"])
            state["syn"] += event["syn"]
            state["ack"] += event["ack"]
            state["rst"] += event["rst"]
            if event["window"] is not None:
                last_seen_window[key] = event["window"]
            event_index += 1

        active_keys = [
            key for key, last_seen in last_seen_window.items()
            if window_index - last_seen <= active_ttl_windows
        ]
        summary = {feature: 0.0 for feature in P4_FEATURES}
        summary["net_flow_count_seen"] = float(len(active_keys))
        min_lengths: list[int] = []
        max_lengths: list[int] = []
        durations: list[float] = []

        for key in active_keys:
            state = flow_state[key]
            delta = window_deltas[window_index].get(key, {})
            for feature, delta_key in (
                ("net_pkts_total_delta", "packets"),
                ("net_bytes_total_delta", "bytes"),
                ("net_pkts_ab_delta", "ab_packets"),
                ("net_bytes_ab_delta", "ab_bytes"),
                ("net_pkts_ba_delta", "ba_packets"),
                ("net_bytes_ba_delta", "ba_bytes"),
                ("net_syn_delta", "syn"),
                ("net_ack_delta", "ack"),
                ("net_rst_delta", "rst"),
            ):
                summary[feature] += delta.get(delta_key, 0)
            min_lengths.append(int(state["min_len"]))
            max_lengths.append(int(state["max_len"]))
            durations.append(float(state["last_ts"] - state["first_ts"]))
            summary["net_flows_with_ab"] += int(state["ab_packets"] > 0)
            summary["net_flows_with_ba"] += int(state["ba_packets"] > 0)
            summary["net_dir_valid_count"] += 1

        packets = summary["net_pkts_total_delta"]
        byte_count = summary["net_bytes_total_delta"]
        ab_packets = summary["net_pkts_ab_delta"]
        ab_bytes = summary["net_bytes_ab_delta"]
        ba_packets = summary["net_pkts_ba_delta"]
        ba_bytes = summary["net_bytes_ba_delta"]
        duration = window_seconds
        summary.update(
            {
                "net_min_len_mean": statistics.mean(min_lengths) if min_lengths else 0.0,
                "net_max_len_mean": statistics.mean(max_lengths) if max_lengths else 0.0,
                "net_min_len_min": min(min_lengths, default=0),
                "net_max_len_max": max(max_lengths, default=0),
                "net_avg_pkt_size_delta": byte_count / packets if packets else 0.0,
                "net_avg_pkt_size_ab_delta": ab_bytes / ab_packets if ab_packets else 0.0,
                "net_avg_pkt_size_ba_delta": ba_bytes / ba_packets if ba_packets else 0.0,
                "net_flow_duration_mean": statistics.mean(durations) if durations else 0.0,
                "net_flow_duration_max": max(durations, default=0.0),
                "net_bytes_per_sec_delta": byte_count / duration if duration else 0.0,
                "net_pkts_per_sec_delta": packets / duration if duration else 0.0,
                "net_down_up_ratio_delta": ba_bytes / ab_bytes if ab_bytes else 0.0,
                "net_ab_ratio_pkt_delta": ab_packets / packets if packets else 0.0,
                "net_ba_ratio_pkt_delta": ba_packets / packets if packets else 0.0,
                "net_ab_ratio_byte_delta": ab_bytes / byte_count if byte_count else 0.0,
                "net_ba_ratio_byte_delta": ba_bytes / byte_count if byte_count else 0.0,
                "net_new_conn_dst_max": max(window_new_conns[window_index].values(), default=0),
            }
        )
        summary["pcap_frames_in_window"] = frame_counts[window_index]
        summary["p4_eligible_packets_in_window"] = sum(
            values["packets"] for values in window_deltas[window_index].values()
        )
        per_window.append(summary)

    sample_features = {}
    for feature in P4_FEATURES:
        values = [window[feature] for window in per_window]
        aggregate_values = {
            "mean": statistics.mean(values),
            "max": max(values),
            "sum": sum(values),
            "std": float(np.std(values)),
            "active_windows": sum(value != 0 for value in values),
        }
        for statistic, value in aggregate_values.items():
            sample_features[f"network__p4_{feature}__{statistic}"] = value

    telemetry_packet_count = sum(int(float(row["net_packets_captured"] or 0)) for row in telemetry_rows)
    pcap_frames_in_windows = sum(frame_counts)
    p4_packets_in_windows = sum(
        sum(values["packets"] for values in deltas.values())
        for deltas in window_deltas
    )
    diagnostics = {
        **alignment,
        "pcap_frame_count": pcap_frame_count,
        "pcap_frames_in_windows": pcap_frames_in_windows,
        "pcap_frames_outside_windows": pcap_frame_count - pcap_frames_in_windows,
        "telemetry_packet_count": telemetry_packet_count,
        "pcap_telemetry_packet_count_abs_error": abs(pcap_frames_in_windows - telemetry_packet_count),
        "p4_eligible_packets_in_windows": p4_packets_in_windows,
        "telemetry_window_count": len(telemetry_rows),
    }
    return sample_features, per_window, diagnostics


def index_pcaps(runs_dir: Path) -> dict[str, Path]:
    pcaps: dict[str, Path] = {}
    for pcap in runs_dir.rglob("packet_capture.pcap"):
        artifact = pcap.parents[2].name
        if artifact in pcaps:
            raise ValueError(f"Multiple PCAPs found for {artifact} under {runs_dir}")
        pcaps[artifact] = pcap
    return pcaps


def load_rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8-sig") as source:
        return list(csv.DictReader(source))


def write_csv(path: Path, rows: list[dict], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as destination:
        writer = csv.DictWriter(destination, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def metrics_for(labels: np.ndarray, predictions: np.ndarray, probabilities: np.ndarray) -> dict:
    tn, fp, fn, tp = confusion_matrix(labels, predictions, labels=[0, 1]).ravel()
    return {
        "accuracy": float(accuracy_score(labels, predictions)),
        "balanced_accuracy": float(balanced_accuracy_score(labels, predictions)),
        "precision": float(precision_score(labels, predictions, zero_division=0)),
        "recall": float(recall_score(labels, predictions, zero_division=0)),
        "f1": float(f1_score(labels, predictions, zero_division=0)),
        "roc_auc": float(roc_auc_score(labels, probabilities)),
        "tn": int(tn),
        "fp": int(fp),
        "fn": int(fn),
        "tp": int(tp),
    }


def numeric_matrix(rows: list[dict[str, str]], features: list[str]) -> np.ndarray:
    matrix = np.full((len(rows), len(features)), np.nan)
    for row_index, row in enumerate(rows):
        for column_index, feature in enumerate(features):
            try:
                matrix[row_index, column_index] = float(row.get(feature, ""))
            except (TypeError, ValueError):
                continue
    return matrix


def feature_family_indices(features: list[str]) -> dict[str, list[int]]:
    families: dict[str, list[int]] = {}
    for index, feature in enumerate(features):
        family, separator, _ = feature.rpartition("__")
        if not separator:
            raise ValueError(f"Feature lacks a summary suffix: {feature}")
        families.setdefault(family, []).append(index)
    return families


def main() -> int:
    script_dir = Path(__file__).resolve().parent
    study_dir = script_dir.parent / "vbox-runs" / "hybrid-rf-study-20261010"
    revision_dir = study_dir / "data" / "benign" / "revision3"

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--study-dir", type=Path, default=study_dir)
    parser.add_argument(
        "--output-dir", type=Path, default=revision_dir / "p4_pcap_family_balanced_ablation"
    )
    parser.add_argument("--folds", type=int, default=5)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    dataset_path = args.study_dir / "data/benign/revision3/labeled_sample_dataset.csv"
    columns_path = args.study_dir / "data/benign/revision3/labeled_sample_dataset.feature_columns.json"
    malware_runs = args.study_dir / "data/malware/revision3/runs/malware-v3-full-20261011"
    benign_runs = args.study_dir / "data/benign/revision3/runs/benign-v3-full-20261011"
    source_rows = load_rows(dataset_path)
    all_source_rows = source_rows
    feature_sets = json.loads(columns_path.read_text(encoding="utf-8"))
    malware_pcaps = index_pcaps(malware_runs)
    benign_pcaps = index_pcaps(benign_runs)
    pcap_by_artifact = malware_pcaps | benign_pcaps
    expected = {row["sample_artifact"] for row in source_rows}
    if len(expected) != len(source_rows):
        parser.error("The source dataset contains duplicate sample artifacts")
    if set(pcap_by_artifact) != expected:
        missing = sorted(expected - set(pcap_by_artifact))
        unexpected = sorted(set(pcap_by_artifact) - expected)
        parser.error(f"PCAP/sample mismatch; missing={missing[:5]}, unexpected={unexpected[:5]}")

    derived_by_artifact = {}
    feature_rows = []
    window_feature_rows = []
    alignment_rows = []
    aligned_source_rows = []
    for row in source_rows:
        artifact = row["sample_artifact"]
        if row["label"] == "1":
            sample_dir = malware_runs / artifact
        else:
            sample_dir = benign_runs / artifact
        telemetry_rows = load_telemetry_rows(sample_dir)
        run_metadata = json.loads(
            next(sample_dir.rglob("run.json")).read_text(encoding="utf-8")
        )
        features, window_features, diagnostics = derive_p4_features(
            pcap_by_artifact[artifact], telemetry_rows, run_metadata
        )
        alignment_rows.append({"sample_artifact": artifact, **diagnostics})
        if diagnostics["alignment_status"] != "unique":
            continue
        derived_by_artifact[artifact] = features
        feature_rows.append({"sample_artifact": artifact, **features})
        aligned_source_rows.append(row)
        for telemetry_row, window_summary in zip(
            telemetry_rows, window_features, strict=True
        ):
            window_feature_rows.append(
                {
                    "sample_artifact": artifact,
                    "window_id": telemetry_row["window_id"],
                    "telemetry_packets_captured": telemetry_row["net_packets_captured"],
                    "pcap_frames_in_window": window_summary["pcap_frames_in_window"],
                    "p4_eligible_packets_in_window": window_summary[
                        "p4_eligible_packets_in_window"
                    ],
                    **{feature: window_summary[feature] for feature in P4_FEATURES},
                }
            )
    source_sample_count = len(source_rows)
    alignment_status_by_artifact = {
        row["sample_artifact"]: row["alignment_status"] for row in alignment_rows
    }
    label_audit_rows = []
    for row in source_rows:
        is_malware = row["label"] == "1"
        label_audit_rows.append(
            {
                "sample_artifact": row["sample_artifact"],
                "label": row["label"],
                "class_name": row["class_name"],
                "group_id": row["group_id"],
                "package_group": row["package_group"],
                "workload_family": row["workload_family"],
                "sample_status": row["sample_status"],
                "label_basis": (
                    "MalwareBazaar ransomware/DDoS source cohort per collection history; hash mapping unavailable"
                    if is_malware
                    else "benign workload manifest"
                ),
                "attack_type_label": (
                    "ransomware_or_ddos_unmapped" if is_malware else "not_applicable"
                ),
                "pcap_alignment_status": alignment_status_by_artifact[
                    row["sample_artifact"]
                ],
                "included_in_reconstructed_cv": int(
                    alignment_status_by_artifact[row["sample_artifact"]] == "unique"
                ),
            }
        )
    source_rows = aligned_source_rows
    if not source_rows or {int(row["label"]) for row in source_rows} != {0, 1}:
        parser.error("No unambiguously aligned sample set contains both labels")

    output_dir = args.output_dir.expanduser().resolve()
    feature_csv = output_dir / "p4_pcap_reconstructed_sample_features.csv"
    write_csv(feature_csv, feature_rows, ["sample_artifact", *P4_SAMPLE_FEATURES])
    window_feature_csv = output_dir / "p4_pcap_reconstructed_window_features.csv"
    write_csv(
        window_feature_csv,
        window_feature_rows,
        [
            "sample_artifact",
            "window_id",
            "telemetry_packets_captured",
            "pcap_frames_in_window",
            "p4_eligible_packets_in_window",
            *P4_FEATURES,
        ],
    )
    alignment_csv = output_dir / "p4_pcap_reconstruction_diagnostics.csv"
    write_csv(
        alignment_csv,
        alignment_rows,
        ["sample_artifact", *[key for key in alignment_rows[0] if key != "sample_artifact"]],
    )
    label_audit_csv = output_dir / "sample_label_audit.csv"
    write_csv(label_audit_csv, label_audit_rows, list(label_audit_rows[0]))

    dataset_rows = []
    network_features = P4_SAMPLE_FEATURES
    host_features = feature_sets["host"]
    for source_row in source_rows:
        artifact = source_row["sample_artifact"]
        row = {
            key: value
            for key, value in source_row.items()
            if not key.startswith("network__")
        }
        row.update(
            {
                feature: derived_by_artifact[artifact][feature]
                for feature in network_features
            }
        )
        dataset_rows.append(row)

    dataset_csv = output_dir / "p4_pcap_reconstructed_labeled_sample_dataset.csv"
    metadata_fields = [key for key in source_rows[0] if not key.startswith(("network__", "host__"))]
    write_csv(dataset_csv, dataset_rows, [*metadata_fields, *network_features, *host_features])
    dataset_columns = {
        "network": network_features,
        "host": host_features,
        "hybrid": network_features + host_features,
    }
    (output_dir / "p4_pcap_reconstructed_labeled_sample_dataset.feature_columns.json").write_text(
        json.dumps(dataset_columns, indent=2) + "\n", encoding="utf-8"
    )

    labels = np.asarray([int(row["label"]) for row in dataset_rows], dtype=int)
    groups = np.asarray([row["group_id"] for row in dataset_rows], dtype=str)
    network_matrix = numeric_matrix(dataset_rows, network_features)
    host_matrix = numeric_matrix(dataset_rows, host_features)
    host_families = feature_family_indices(host_features)
    expected_summaries = len(P4_WINDOW_STATS)
    if any(len(indices) != expected_summaries for indices in host_families.values()):
        parser.error("Host feature families must contain all five window summaries")
    if len(host_families) < len(P4_FEATURES):
        parser.error("Host feature pool has fewer signal families than the P4 pool")
    splits = list(
        StratifiedGroupKFold(
            n_splits=args.folds, shuffle=True, random_state=args.seed
        ).split(np.zeros((len(labels), 1)), labels, groups)
    )
    variants = (
        "network_p4",
        "host_ebpf",
        "hybrid_p4",
        "column_balanced_hybrid",
        "family_balanced_hybrid",
    )
    probabilities = {name: np.full(len(labels), np.nan) for name in variants}
    fold_ids = {name: np.zeros(len(labels), dtype=int) for name in variants}
    fold_metrics = {name: [] for name in variants}
    feature_selection_rows = []

    for fold_index, (train_indices, test_indices) in enumerate(splits, start=1):
        network_imputer = SimpleImputer(strategy="median").fit(network_matrix[train_indices])
        train_network = network_imputer.transform(network_matrix[train_indices])
        test_network = network_imputer.transform(network_matrix[test_indices])
        host_imputer = SimpleImputer(strategy="median").fit(host_matrix[train_indices])
        train_host = host_imputer.transform(host_matrix[train_indices])
        test_host = host_imputer.transform(host_matrix[test_indices])
        host_mutual_information = mutual_info_classif(
            train_host,
            labels[train_indices],
            random_state=args.seed + fold_index,
        )
        family_scores = {
            family: float(np.mean(host_mutual_information[indices]))
            for family, indices in host_families.items()
        }
        selected_families = sorted(
            family_scores,
            key=lambda family: (-family_scores[family], family),
        )[: len(P4_FEATURES)]
        selected_family_set = set(selected_families)
        family_selected_indices = [
            index
            for index, feature in enumerate(host_features)
            if feature.rpartition("__")[0] in selected_family_set
        ]
        if len(family_selected_indices) != len(P4_FEATURES) * expected_summaries:
            raise RuntimeError("Family-balanced selector did not preserve equal signal budgets")
        feature_selection_rows.extend(
            {
                "fold": fold_index,
                "host_signal_family": family,
                "mean_summary_mutual_information": family_scores[family],
                "selection_rank": rank,
                "host_signal_family_budget": len(P4_FEATURES),
                "p4_signal_family_budget": len(P4_FEATURES),
            }
            for rank, family in enumerate(selected_families, start=1)
        )
        train_host_family_selected = train_host[:, family_selected_indices]
        test_host_family_selected = test_host[:, family_selected_indices]
        selector = SelectKBest(
            lambda x, y: mutual_info_classif(x, y, random_state=args.seed + fold_index),
            k=len(network_features),
        ).fit(train_host, labels[train_indices])
        train_host_selected = selector.transform(train_host)
        test_host_selected = selector.transform(test_host)
        matrices = {
            "network_p4": (train_network, test_network),
            "host_ebpf": (train_host, test_host),
            "hybrid_p4": (
                np.hstack((train_host, train_network)),
                np.hstack((test_host, test_network)),
            ),
            "column_balanced_hybrid": (
                np.hstack((train_host_selected, train_network)),
                np.hstack((test_host_selected, test_network)),
            ),
            "family_balanced_hybrid": (
                np.hstack((train_host_family_selected, train_network)),
                np.hstack((test_host_family_selected, test_network)),
            ),
        }
        for name, (train_matrix, test_matrix) in matrices.items():
            model = make_pipeline(
                SimpleImputer(strategy="median"),
                RandomForestClassifier(
                    n_estimators=500,
                    max_features="sqrt",
                    min_samples_leaf=2,
                    class_weight="balanced_subsample",
                    random_state=args.seed + fold_index,
                    n_jobs=-1,
                ),
            )
            model.fit(train_matrix, labels[train_indices])
            fold_probabilities = model.predict_proba(test_matrix)[:, 1]
            probabilities[name][test_indices] = fold_probabilities
            fold_ids[name][test_indices] = fold_index
            predictions = (fold_probabilities >= 0.5).astype(int)
            fold_metrics[name].append(
                metrics_for(labels[test_indices], predictions, fold_probabilities)
            )

    alignment_status_counts = {
        status: sum(row["alignment_status"] == status for row in alignment_rows)
        for status in sorted({row["alignment_status"] for row in alignment_rows})
    }
    reports = {
        "samples": len(dataset_rows),
        "source_samples": source_sample_count,
        "class_counts": {
            "benign": sum(int(row["label"]) == 0 for row in source_rows),
            "malware": sum(int(row["label"]) == 1 for row in source_rows),
        },
        "label_coverage": {
            "full_dataset_binary_counts": {
                "benign": sum(row["label"] == "0" for row in all_source_rows),
                "malware": sum(row["label"] == "1" for row in all_source_rows),
            },
            "benign_package_families": len(
                {
                    row["package_group"]
                    for row in all_source_rows
                    if row["label"] == "0"
                }
            ),
            "benign_workload_families": sorted(
                {
                    row["workload_family"]
                    for row in all_source_rows
                    if row["label"] == "0"
                }
            ),
            "malware_samples_with_verified_behavior_subtype": 0,
            "malware_subtype_note": (
                "Collection history says the MalwareBazaar acquisition included ransomware "
                "and DDoS samples. The stored cohort merged these into one hash-named input "
                "directory without a per-hash category mapping, so subtypes remain unmapped."
            ),
            "malware_source_categories_per_collection_history": ["ransomware", "DDoS"],
            "malware_source_category_mapping": "unavailable_per_artifact",
        },
        "feature_pool_balance": {
            "p4_base_signal_families": len(P4_FEATURES),
            "ebpf_host_base_signal_families": len(host_families),
            "selected_host_signal_families_per_fold": len(P4_FEATURES),
            "summaries_per_signal_family": expected_summaries,
            "family_balanced_features_per_sensor": len(P4_FEATURES)
            * expected_summaries,
            "selector": "training-fold mean mutual information across each host family's five summaries",
        },
        "folds": args.folds,
        "method": (
            "Offline P4-shaped features derived from IPv4 TCP/UDP frames assigned to fixed "
            "sample-relative windows by exact matching against the collector's saved per-window "
            "PCAP packet counts. Only samples with a unique packet-to-window assignment are "
            "included; ambiguous samples are excluded. First captured in-window packet defines "
            "flow A-to-B direction. Features are aggregated with mean/max/sum/std/active_windows. "
            "This is not a live P4 target measurement."
        ),
        "alignment": {
            "source_samples": source_sample_count,
            "status_counts": alignment_status_counts,
            "pcap_frames_in_windows": sum(row["pcap_frames_in_windows"] for row in alignment_rows),
            "pcap_frames_outside_windows": sum(
                row["pcap_frames_outside_windows"] for row in alignment_rows
            ),
            "telemetry_packet_count": sum(row["telemetry_packet_count"] for row in alignment_rows),
            "pcap_telemetry_packet_count_abs_error": sum(
                row["pcap_telemetry_packet_count_abs_error"] for row in alignment_rows
            ),
        },
        "feature_sets": {},
    }
    prediction_rows = []
    for name in variants:
        if np.isnan(probabilities[name]).any():
            raise RuntimeError(f"Some samples lack out-of-fold predictions for {name}")
        predictions = (probabilities[name] >= 0.5).astype(int)
        pooled = metrics_for(labels, predictions, probabilities[name])
        reports["feature_sets"][name] = {
            "feature_count": (
                len(network_features)
                if name == "network_p4"
                else len(host_features)
                if name == "host_ebpf"
                else len(host_features) + len(network_features)
                if name == "hybrid_p4"
                else 2 * len(network_features)
            ),
            "pooled_oof": pooled,
            "fold_metrics": fold_metrics[name],
            "fold_accuracy_mean": float(np.mean([item["accuracy"] for item in fold_metrics[name]])),
            "fold_accuracy_std": float(np.std([item["accuracy"] for item in fold_metrics[name]], ddof=1)),
            "fold_roc_auc_mean": float(np.mean([item["roc_auc"] for item in fold_metrics[name]])),
            "fold_roc_auc_std": float(np.std([item["roc_auc"] for item in fold_metrics[name]], ddof=1)),
        }
        for index, row in enumerate(dataset_rows):
            prediction_rows.append(
                {
                    "feature_set": name,
                    "sample_artifact": row["sample_artifact"],
                    "label": labels[index],
                    "fold": fold_ids[name][index],
                    "probability_malware": probabilities[name][index],
                    "prediction": predictions[index],
                }
            )

    write_csv(
        output_dir / "p4_pcap_reconstructed_oof_predictions.csv",
        prediction_rows,
        list(prediction_rows[0]),
    )
    write_csv(
        output_dir / "p4_pcap_feature_family_selections.csv",
        feature_selection_rows,
        list(feature_selection_rows[0]),
    )
    (output_dir / "p4_pcap_reconstructed_cv_metrics.json").write_text(
        json.dumps(reports, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(reports, indent=2))
    print(f"P4-shaped sample features: {feature_csv}")
    print(f"P4-shaped window features: {window_feature_csv}")
    print(f"PCAP alignment diagnostics: {alignment_csv}")
    print(f"Sample label audit: {label_audit_csv}")
    print(f"Fold-wise host family selections: {output_dir / 'p4_pcap_feature_family_selections.csv'}")
    print(f"Ablation dataset: {dataset_csv}")
    print(f"Reports: {output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())