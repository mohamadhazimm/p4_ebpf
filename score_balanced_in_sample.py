#!/usr/bin/env python3
"""Fit and score balanced P4/eBPF models on the same full labeled dataset."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_selection import mutual_info_classif
from sklearn.impute import SimpleImputer
from sklearn.pipeline import make_pipeline

from analyze_p4_pcap_ablation import (
    P4_FEATURES,
    P4_WINDOW_STATS,
    feature_family_indices,
    metrics_for,
    numeric_matrix,
)


def write_csv(path: Path, rows: list[dict], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as destination:
        writer = csv.DictWriter(destination, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", required=True, type=Path)
    parser.add_argument("--feature-columns", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    with args.dataset.open(newline="", encoding="utf-8-sig") as source:
        rows = list(csv.DictReader(source))
    columns = json.loads(args.feature_columns.read_text(encoding="utf-8"))
    labels = np.asarray([int(row["label"]) for row in rows], dtype=int)
    if set(labels) != {0, 1}:
        parser.error("The dataset must contain both benign and malware samples")

    network_features = columns["network"]
    host_features = columns["host"]
    network_families = feature_family_indices(network_features)
    host_families = feature_family_indices(host_features)
    expected_summaries = len(P4_WINDOW_STATS)
    if len(network_families) != len(P4_FEATURES):
        parser.error(f"Expected {len(P4_FEATURES)} P4 network signal families")
    if len(host_families) < len(P4_FEATURES):
        parser.error(f"Need at least {len(P4_FEATURES)} host signal families")
    if any(len(indices) != expected_summaries for indices in network_families.values()):
        parser.error("Every P4 network family must contain all five summaries")
    if any(len(indices) != expected_summaries for indices in host_families.values()):
        parser.error("Every eBPF host family must contain all five summaries")

    network_matrix = numeric_matrix(rows, network_features)
    host_matrix = numeric_matrix(rows, host_features)
    host_for_selection = SimpleImputer(strategy="median").fit_transform(host_matrix)
    host_mutual_information = mutual_info_classif(
        host_for_selection, labels, random_state=args.seed
    )
    host_family_scores = {
        family: float(np.mean(host_mutual_information[indices]))
        for family, indices in host_families.items()
    }
    selected_host_families = sorted(
        host_family_scores,
        key=lambda family: (-host_family_scores[family], family),
    )[: len(P4_FEATURES)]
    selected_host_set = set(selected_host_families)
    selected_host_indices = [
        index
        for index, feature in enumerate(host_features)
        if feature.rpartition("__")[0] in selected_host_set
    ]
    if len(selected_host_indices) != len(P4_FEATURES) * expected_summaries:
        raise RuntimeError("Host selection did not preserve the 50/50 signal-family budget")

    selected_host_matrix = host_matrix[:, selected_host_indices]
    model_matrices = {
        "network_p4": network_matrix,
        "host_ebpf_balanced": selected_host_matrix,
        "hybrid_balanced_50_50": np.hstack((network_matrix, selected_host_matrix)),
    }
    feature_counts = {
        "network_p4": len(network_features),
        "host_ebpf_balanced": len(selected_host_indices),
        "hybrid_balanced_50_50": len(network_features) + len(selected_host_indices),
    }
    malware_missing_network = sum(
        all(row.get(feature, "") == "" for feature in network_features)
        for row in rows
        if int(row["label"]) == 1
    )
    benign_missing_network = sum(
        all(row.get(feature, "") == "" for feature in network_features)
        for row in rows
        if int(row["label"]) == 0
    )

    output_dir = args.output_dir.expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    metrics = {
        "score_type": "in_sample_fit_and_score_on_same_rows",
        "warning": (
            "These same-data scores are optimistic and are not estimates of "
            "generalization to unseen samples."
        ),
        "samples": len(rows),
        "class_counts": {
            "benign": int(np.sum(labels == 0)),
            "malware": int(np.sum(labels == 1)),
        },
        "feature_pool": {
            "p4_network_signal_families": len(network_families),
            "selected_ebpf_host_signal_families": len(selected_host_families),
            "summaries_per_signal_family": expected_summaries,
            "network_features": len(network_features),
            "host_features": len(selected_host_indices),
            "hybrid_features": len(network_features) + len(selected_host_indices),
            "host_selector": (
                f"top {len(P4_FEATURES)} families by mean mutual information across five summaries, "
                "computed using the full labeled dataset"
            ),
        },
        "p4_network_median_imputation": {
            "malware_rows_missing_all_p4_features": int(malware_missing_network),
            "benign_rows_missing_all_p4_features": int(benign_missing_network),
            "strategy": "median fitted on the full dataset",
        },
        "models": {},
    }
    prediction_rows = []
    metadata_columns = [
        name
        for name in (
            "sample_artifact",
            "sample_name",
            "class_name",
            "sample_status",
            "group_id",
            "package_group",
            "workload_family",
        )
        if name in rows[0]
    ]
    for model_name, matrix in model_matrices.items():
        model = make_pipeline(
            SimpleImputer(strategy="median"),
            RandomForestClassifier(
                n_estimators=500,
                max_features="sqrt",
                min_samples_leaf=2,
                class_weight="balanced_subsample",
                random_state=args.seed,
                n_jobs=-1,
            ),
        )
        model.fit(matrix, labels)
        probabilities = model.predict_proba(matrix)[:, 1]
        predictions = (probabilities >= 0.5).astype(int)
        metrics["models"][model_name] = {
            "feature_count": feature_counts[model_name],
            **metrics_for(labels, predictions, probabilities),
        }
        model_path = output_dir / f"{model_name}_in_sample.joblib"
        joblib.dump(model, model_path)
        for index, row in enumerate(rows):
            prediction_rows.append(
                {
                    "model": model_name,
                    **{name: row.get(name, "") for name in metadata_columns},
                    "label": int(labels[index]),
                    "prediction": int(predictions[index]),
                    "probability_malware": float(probabilities[index]),
                    "correct": int(predictions[index] == labels[index]),
                    "is_in_sample_score": 1,
                }
            )

    metrics["selected_host_families"] = [
        {
            "signal_family": family,
            "mean_summary_mutual_information": host_family_scores[family],
            "selection_rank": rank,
        }
        for rank, family in enumerate(selected_host_families, start=1)
    ]
    (output_dir / "balanced_in_sample_metrics.json").write_text(
        json.dumps(metrics, indent=2) + "\n", encoding="utf-8"
    )
    write_csv(
        output_dir / "balanced_in_sample_predictions.csv",
        prediction_rows,
        list(prediction_rows[0]),
    )
    write_csv(
        output_dir / "balanced_in_sample_host_family_selection.csv",
        metrics["selected_host_families"],
        list(metrics["selected_host_families"][0]),
    )
    print(json.dumps(metrics, indent=2))
    print(f"Scores and predictions: {output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())