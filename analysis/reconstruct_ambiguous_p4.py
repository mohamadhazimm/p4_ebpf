#!/usr/bin/env python3
"""Marginalize P4 features over exact-counter-compatible window assignments."""

from __future__ import annotations

import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path

import numpy as np
from scapy.utils import PcapReader

import analyze_p4_pcap_ablation as analyzer


def load_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8-sig") as source:
        return list(csv.DictReader(source))


def write_csv(path: Path, rows: list[dict], fieldnames: list[str]) -> None:
    with path.open("w", newline="", encoding="utf-8") as destination:
        writer = csv.DictWriter(destination, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def enumerate_weighted_assignments(
    frame_times: np.ndarray,
    telemetry_rows: list[dict[str, str]],
    run_metadata: dict,
) -> tuple[list[tuple[tuple[int | None, ...], float]], float]:
    window_seconds = float(run_metadata["window_seconds"])
    target_counts = np.asarray(
        [int(float(row.get("net_packets_captured") or 0)) for row in telemetry_rows]
    )
    run_start = analyzer.utc_timestamp(run_metadata["started_at_utc"])
    run_end = analyzer.utc_timestamp(run_metadata["finished_at_utc"])
    breakpoints = {run_start, run_end}
    for timestamp in frame_times:
        for window_index in range(len(telemetry_rows) + 1):
            candidate = float(timestamp - window_index * window_seconds)
            if run_start <= candidate <= run_end:
                breakpoints.add(candidate)

    ordered = sorted(breakpoints)
    weights: dict[tuple[int | None, ...], float] = defaultdict(float)
    for left, right in zip(ordered, ordered[1:]):
        if right <= left:
            continue
        origin = (left + right) / 2
        edges = origin + np.arange(len(telemetry_rows) + 1) * window_seconds
        bins = np.searchsorted(edges, frame_times, side="right") - 1
        assignment = tuple(
            int(index)
            if 0 <= index < len(telemetry_rows)
            and frame_times[position] < edges[index + 1]
            else None
            for position, index in enumerate(bins)
        )
        counts = np.bincount(
            [index for index in assignment if index is not None],
            minlength=len(telemetry_rows),
        )
        if np.array_equal(counts, target_counts):
            weights[assignment] += right - left

    total_duration = sum(weights.values())
    if total_duration <= 0:
        raise ValueError("No positive-duration packet-window assignment matches counters")
    ordered_assignments = sorted(
        weights.items(),
        key=lambda item: tuple(
            -1 if index is None else index for index in item[0]
        ),
    )
    return (
        [
            (assignment, duration / total_duration)
            for assignment, duration in ordered_assignments
        ],
        total_duration,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", required=True, type=Path)
    parser.add_argument("--diagnostics", required=True, type=Path)
    parser.add_argument("--old-capture-sources", required=True, type=Path)
    parser.add_argument("--malware-runs", required=True, type=Path)
    parser.add_argument("--benign-runs", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()

    dataset_rows = load_csv(args.dataset)
    diagnostics = load_csv(args.diagnostics)
    old_capture_rows = load_csv(args.old_capture_sources)
    rows_by_artifact = {row["sample_artifact"]: row for row in dataset_rows}
    old_pcaps = {
        row["sample_artifact"]: Path(row["selected_pcap"])
        for row in old_capture_rows
    }

    def index_pcaps(root: Path) -> dict[str, list[Path]]:
        result: dict[str, list[Path]] = defaultdict(list)
        for pcap in root.rglob("packet_capture.pcap"):
            result[pcap.parents[2].name].append(pcap)
        return result

    malware_pcaps = index_pcaps(args.malware_runs)
    benign_pcaps = index_pcaps(args.benign_runs)
    p4_columns = analyzer.P4_SAMPLE_FEATURES
    feature_rows = {row["sample_artifact"]: dict(row) for row in load_csv(args.dataset)}
    candidate_rows = []
    uncertainty_rows = []
    reconstruction_rows = []
    summary_by_artifact = {}
    original_recover = analyzer.recover_frame_windows

    try:
        for diagnostic in diagnostics:
            artifact = diagnostic["sample_artifact"]
            sample = rows_by_artifact[artifact]
            if diagnostic["alignment_status"] == "unique":
                reconstruction_rows.append(
                    {
                        **diagnostic,
                        "label": sample["label"],
                        "p4_reconstruction_method": "unique_packet_window_assignment",
                        "counter_consistent_assignments": 1,
                        "feasible_offset_duration_seconds": "",
                        "varying_p4_features": 0,
                    }
                )
                summary_by_artifact[artifact] = {
                    "method": "unique_packet_window_assignment",
                    "candidate_count": 1,
                    "duration_seconds": "",
                }
                continue

            if sample["label"] == "1" and artifact in old_pcaps:
                pcap_path = old_pcaps[artifact]
            else:
                pcap_index = malware_pcaps if sample["label"] == "1" else benign_pcaps
                matches = pcap_index.get(artifact, [])
                if len(matches) != 1:
                    raise ValueError(
                        f"Expected one PCAP for ambiguous sample {artifact}, found {len(matches)}"
                    )
                pcap_path = matches[0]
            sample_dir = pcap_path.parents[2]
            telemetry_paths = list(sample_dir.rglob("telemetry.csv"))
            metadata_paths = list(sample_dir.rglob("run.json"))
            if len(telemetry_paths) != 1 or len(metadata_paths) != 1:
                raise ValueError(f"Expected one telemetry.csv and run.json under {sample_dir}")
            telemetry_rows = load_csv(telemetry_paths[0])
            run_metadata = json.loads(metadata_paths[0].read_text(encoding="utf-8"))
            with PcapReader(str(pcap_path)) as capture:
                frame_times = np.asarray([float(packet.time) for packet in capture])
            assignments, total_duration = enumerate_weighted_assignments(
                frame_times, telemetry_rows, run_metadata
            )

            candidate_vectors = []
            candidate_weights = []
            for candidate_index, (assignment, weight) in enumerate(assignments, start=1):
                def forced_assignment(
                    _frame_times,
                    _telemetry_rows,
                    _run_metadata,
                    assignment=assignment,
                ):
                    return list(assignment), {
                        "alignment_status": "unique",
                        "exact_offset_representatives": 1,
                        "unique_packet_window_assignments": 1,
                        "offset_min_after_run_start_seconds": 0.0,
                        "offset_max_after_run_start_seconds": 0.0,
                    }

                analyzer.recover_frame_windows = forced_assignment
                features, _, _ = analyzer.derive_p4_features(
                    pcap_path, telemetry_rows, run_metadata
                )
                vector = np.asarray([features[column] for column in p4_columns], dtype=float)
                candidate_vectors.append(vector)
                candidate_weights.append(weight)
                candidate_rows.append(
                    {
                        "sample_artifact": artifact,
                        "candidate_assignment": candidate_index,
                        "feasible_offset_weight": weight,
                        **dict(zip(p4_columns, vector, strict=True)),
                    }
                )

            stack = np.vstack(candidate_vectors)
            weights = np.asarray(candidate_weights, dtype=float)
            expected = np.average(stack, axis=0, weights=weights)
            variance = np.average((stack - expected) ** 2, axis=0, weights=weights)
            spread = np.ptp(stack, axis=0)
            feature_rows[artifact].update(dict(zip(p4_columns, expected, strict=True)))
            method = "duration_weighted_counter_consistent_assignments"
            summary_by_artifact[artifact] = {
                "method": method,
                "candidate_count": len(assignments),
                "duration_seconds": total_duration,
            }
            reconstruction_rows.append(
                {
                    **diagnostic,
                    "label": sample["label"],
                    "p4_reconstruction_method": method,
                    "counter_consistent_assignments": len(assignments),
                    "feasible_offset_duration_seconds": total_duration,
                    "varying_p4_features": int(np.sum(spread > 1e-10)),
                }
            )
            uncertainty_rows.extend(
                {
                    "sample_artifact": artifact,
                    "candidate_assignment_count": len(assignments),
                    "feature": column,
                    "duration_weighted_mean": expected[index],
                    "duration_weighted_std": float(np.sqrt(variance[index])),
                    "candidate_min": float(np.min(stack[:, index])),
                    "candidate_max": float(np.max(stack[:, index])),
                }
                for index, column in enumerate(p4_columns)
            )
    finally:
        analyzer.recover_frame_windows = original_recover

    if len(feature_rows) != len(dataset_rows) or len(reconstruction_rows) != len(diagnostics):
        raise RuntimeError("Reconstruction did not cover every dataset sample")
    if any(feature_rows[artifact].get(column, "") == "" for artifact in feature_rows for column in p4_columns):
        raise RuntimeError("Some P4 sample features are still missing")

    output_dir = args.output_dir.expanduser().resolve()
    dataset_metadata = [
        column
        for column in next(iter(dataset_rows))
        if not column.startswith(("network__", "host__"))
    ]
    extra_metadata = [
        "p4_reconstruction_method",
        "p4_candidate_assignment_count",
        "p4_feasible_offset_duration_seconds",
    ]
    enriched_rows = []
    for artifact, row in feature_rows.items():
        summary = summary_by_artifact[artifact]
        enriched_rows.append(
            {
                **row,
                "p4_reconstruction_method": summary["method"],
                "p4_candidate_assignment_count": summary["candidate_count"],
                "p4_feasible_offset_duration_seconds": summary["duration_seconds"],
            }
        )
    write_csv(
        args.dataset,
        enriched_rows,
        [*dataset_metadata, *extra_metadata, *[c for c in next(iter(dataset_rows)) if c.startswith(("network__", "host__"))]],
    )
    write_csv(
        output_dir / "p4_pcap_reconstructed_sample_features.csv",
        [
            {"sample_artifact": artifact, **{column: row[column] for column in p4_columns}}
            for artifact, row in feature_rows.items()
        ],
        ["sample_artifact", *p4_columns],
    )
    write_csv(
        output_dir / "p4_ambiguous_counter_consistent_feature_candidates.csv",
        candidate_rows,
        ["sample_artifact", "candidate_assignment", "feasible_offset_weight", *p4_columns],
    )
    write_csv(
        output_dir / "p4_ambiguous_feature_uncertainty.csv",
        uncertainty_rows,
        [
            "sample_artifact",
            "candidate_assignment_count",
            "feature",
            "duration_weighted_mean",
            "duration_weighted_std",
            "candidate_min",
            "candidate_max",
        ],
    )
    write_csv(
        args.diagnostics,
        reconstruction_rows,
        list(reconstruction_rows[0]),
    )
    inventory_path = output_dir / "cohort_feature_inventory.json"
    if inventory_path.exists():
        inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
        counts = {
            "malware": sum(row["label"] == "1" for row in enriched_rows),
            "benign": sum(row["label"] == "0" for row in enriched_rows),
        }
        inventory["p4_aligned_rows_label_counts"] = {
            "malware": counts["malware"]
            - sum(row["label"] == "1" and row["alignment_status"] != "unique" for row in reconstruction_rows),
            "benign": counts["benign"]
            - sum(row["label"] == "0" and row["alignment_status"] != "unique" for row in reconstruction_rows),
        }
        inventory["p4_feature_values_available_label_counts"] = counts
        inventory["p4_ambiguous_reconstruction"] = {
            "method": "duration-weighted expectation across every exact-counter-compatible sample-relative window assignment",
            "ambiguous_samples_reconstructed": sum(
                row["p4_reconstruction_method"] == "duration_weighted_counter_consistent_assignments"
                for row in reconstruction_rows
            ),
            "model_scoring_performed": False,
            "candidate_vectors_file": "p4_ambiguous_counter_consistent_feature_candidates.csv",
            "feature_uncertainty_file": "p4_ambiguous_feature_uncertainty.csv",
        }
        inventory_path.write_text(json.dumps(inventory, indent=2) + "\n", encoding="utf-8")

    print(
        json.dumps(
            {
                "samples_with_complete_p4_features": len(enriched_rows),
                "ambiguous_samples_marginalized": len(uncertainty_rows) // len(p4_columns),
                "candidate_assignment_vectors": len(candidate_rows),
                "candidate_feature_uncertainty_rows": len(uncertainty_rows),
                "model_scoring_performed": False,
                "output_dir": str(output_dir),
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())