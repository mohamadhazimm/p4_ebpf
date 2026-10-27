#!/usr/bin/env python3
"""Evaluate balanced models on a half-per-family malware holdout."""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_selection import mutual_info_classif
from sklearn.impute import SimpleImputer
from sklearn.model_selection import GroupShuffleSplit
from sklearn.pipeline import make_pipeline

from analyze_p4_pcap_ablation import (
    P4_FEATURES,
    P4_WINDOW_STATS,
    feature_family_indices,
    metrics_for,
    numeric_matrix,
)


def load_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8-sig") as source:
        return list(csv.DictReader(source))


def write_csv(path: Path, rows: list[dict], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as destination:
        writer = csv.DictWriter(destination, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def split_malware_by_family(
    rows: list[dict[str, str]], labels: np.ndarray, seed: int
) -> tuple[np.ndarray, np.ndarray, dict[str, dict[str, int]]]:
    malware_indices = np.flatnonzero(labels == 1)
    by_family: dict[str, list[int]] = defaultdict(list)
    for index in malware_indices:
        family = rows[index].get("workload_family") or "unassigned"
        by_family[family].append(int(index))

    rng = np.random.default_rng(seed)
    training: list[int] = []
    unknown: list[int] = []
    counts = {}
    for family in sorted(by_family):
        indices = np.asarray(sorted(by_family[family]), dtype=int)
        shuffled = rng.permutation(indices)
        if len(shuffled) == 1:
            training_count = 0
        else:
            unknown_count = max(1, len(shuffled) // 2)
            training_count = len(shuffled) - unknown_count
        training.extend(shuffled[:training_count].tolist())
        unknown.extend(shuffled[training_count:].tolist())
        counts[family] = {
            "total": len(shuffled),
            "training": training_count,
            "unknown_test": len(shuffled) - training_count,
        }
    return (
        np.asarray(sorted(training), dtype=int),
        np.asarray(sorted(unknown), dtype=int),
        counts,
    )


def select_host_families(
    matrix: np.ndarray,
    features: list[str],
    labels: np.ndarray,
    training_indices: np.ndarray,
    family_indices: dict[str, list[int]],
    seed: int,
) -> tuple[list[str], dict[str, float]]:
    imputer = SimpleImputer(strategy="median").fit(matrix[training_indices])
    training_matrix = imputer.transform(matrix[training_indices])
    scores = mutual_info_classif(
        training_matrix, labels[training_indices], random_state=seed
    )
    family_scores = {
        family: float(np.mean(scores[indices]))
        for family, indices in family_indices.items()
    }
    selected = sorted(
        family_scores, key=lambda family: (-family_scores[family], family)
    )[: len(P4_FEATURES)]
    return selected, family_scores


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", required=True, type=Path)
    parser.add_argument("--feature-columns", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    rows = load_csv(args.dataset)
    columns = json.loads(args.feature_columns.read_text(encoding="utf-8"))
    labels = np.asarray([int(row["label"]) for row in rows], dtype=int)
    if set(labels) != {0, 1}:
        parser.error("The dataset must contain both malware and benign samples")

    malware_training, malware_unknown, family_counts = split_malware_by_family(
        rows, labels, args.seed
    )
    benign_indices = np.flatnonzero(labels == 0)
    package_groups = np.asarray([row["package_group"] for row in rows], dtype=str)
    benign_split = GroupShuffleSplit(
        n_splits=1, test_size=0.5, random_state=args.seed
    )
    benign_train_relative, benign_test_relative = next(
        benign_split.split(benign_indices, groups=package_groups[benign_indices])
    )
    benign_training = benign_indices[benign_train_relative]
    benign_unknown = benign_indices[benign_test_relative]
    training_groups = set(package_groups[benign_training])
    unknown_groups = set(package_groups[benign_unknown])
    if training_groups & unknown_groups:
        raise RuntimeError("Benign package groups crossed the training/test boundary")

    training_indices = np.asarray(
        sorted(set(malware_training.tolist()) | set(benign_training.tolist())),
        dtype=int,
    )
    unknown_indices = np.asarray(
        sorted(set(malware_unknown.tolist()) | set(benign_unknown.tolist())),
        dtype=int,
    )
    if set(training_indices) & set(unknown_indices):
        raise RuntimeError("A sample appears in both training and unknown test sets")
    if set(labels[training_indices]) != {0, 1} or set(labels[unknown_indices]) != {0, 1}:
        parser.error("Both train and unknown test sets must contain both classes")

    network_features = columns["network"]
    host_features = columns["host"]
    network_matrix = numeric_matrix(rows, network_features)
    host_matrix = numeric_matrix(rows, host_features)
    if len(feature_family_indices(network_features)) != len(P4_FEATURES):
        parser.error(f"P4 network pool must contain all {len(P4_FEATURES)} signal families")
    host_family_indices = feature_family_indices(host_features)
    expected_summaries = len(P4_WINDOW_STATS)
    if any(len(indices) != expected_summaries for indices in host_family_indices.values()):
        parser.error("Each host family must contain all five summaries")

    selected_host_families, family_scores = select_host_families(
        host_matrix,
        host_features,
        labels,
        training_indices,
        host_family_indices,
        args.seed,
    )
    selected_host_set = set(selected_host_families)
    selected_host_indices = [
        index
        for index, feature in enumerate(host_features)
        if feature.rpartition("__")[0] in selected_host_set
    ]
    if len(selected_host_indices) != len(P4_FEATURES) * expected_summaries:
        raise RuntimeError("Host selector did not preserve the balanced family budget")

    selected_host_matrix = host_matrix[:, selected_host_indices]
    model_matrices = {
        "network_p4": network_matrix,
        "host_ebpf_balanced": selected_host_matrix,
        "hybrid_balanced_50_50": np.hstack(
            (network_matrix, selected_host_matrix)
        ),
    }
    unknown_labels = labels[unknown_indices]
    family_training_set = {
        family
        for family, split in family_counts.items()
        if split["training"] > 0
    }
    per_family_predictions: dict[str, dict[str, dict]] = defaultdict(dict)
    prediction_rows = []
    output_dir = args.output_dir.expanduser().resolve()
    model_dir = output_dir / "models"
    model_dir.mkdir(parents=True, exist_ok=True)
    models_report = {}

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
        model.fit(matrix[training_indices], labels[training_indices])
        probabilities = model.predict_proba(matrix[unknown_indices])[:, 1]
        predictions = (probabilities >= 0.5).astype(int)
        models_report[model_name] = {
            "feature_count": matrix.shape[1],
            **metrics_for(unknown_labels, predictions, probabilities),
            "unknown_malware_test_count": len(malware_unknown),
            "unknown_malware_detected": int(
                sum(
                    predicted == 1
                    for index, predicted in zip(
                        unknown_indices, predictions, strict=True
                    )
                    if labels[index] == 1
                )
            ),
            "unknown_malware_missed": int(
                sum(
                    predicted == 0
                    for index, predicted in zip(
                        unknown_indices, predictions, strict=True
                    )
                    if labels[index] == 1
                )
            ),
        }
        joblib.dump(model, model_dir / f"{model_name}_family_split.joblib")
        for index, probability, prediction in zip(
            unknown_indices, probabilities, predictions, strict=True
        ):
            row = rows[index]
            family = row.get("workload_family") or "unassigned"
            if labels[index] == 1:
                per_family_predictions[model_name][family] = {
                    "label": 1,
                    "prediction": int(prediction),
                }
            prediction_rows.append(
                {
                    "model": model_name,
                    "sample_artifact": row["sample_artifact"],
                    "sample_role": "unknown_malware"
                    if labels[index] == 1
                    else "heldout_benign",
                    "malware_family": family if labels[index] == 1 else "",
                    "family_seen_in_training": int(family in family_training_set)
                    if labels[index] == 1
                    else "",
                    "label_for_evaluation_only": int(labels[index]),
                    "probability_malware": float(probability),
                    "prediction": int(prediction),
                }
            )

    per_family_report = {}
    for model_name in model_matrices:
        family_results = {}
        for family, split in family_counts.items():
            family_predictions = [
                row
                for row in prediction_rows
                if row["model"] == model_name
                and row["sample_role"] == "unknown_malware"
                and row["malware_family"] == family
            ]
            detected = sum(row["prediction"] == 1 for row in family_predictions)
            family_results[family] = {
                **split,
                "family_seen_in_training": split["training"] > 0,
                "detected": detected,
                "missed": len(family_predictions) - detected,
                "recall": detected / len(family_predictions)
                if family_predictions
                else None,
            }
        per_family_report[model_name] = family_results

    assignment_rows = []
    for index, row in enumerate(rows):
        if labels[index] == 1:
            family = row.get("workload_family") or "unassigned"
            role = "training" if index in set(malware_training.tolist()) else "unknown_test"
            family_seen = int(family in family_training_set)
        else:
            family = ""
            role = "training" if index in set(benign_training.tolist()) else "unknown_test"
            family_seen = ""
        assignment_rows.append(
            {
                "sample_artifact": row["sample_artifact"],
                "label": int(labels[index]),
                "malware_family": family,
                "role": role,
                "family_seen_in_training": family_seen,
                "benign_package_group": row.get("package_group", "")
                if labels[index] == 0
                else "",
            }
        )

    family_counts = {
        family: split for family, split in sorted(family_counts.items())
    }
    report = {
        "evaluation": "within-family stratified sample holdout",
        "seed": args.seed,
        "dataset_samples": len(rows),
        "training_samples": len(training_indices),
        "unknown_test_samples": len(unknown_indices),
        "training_malware_samples": len(malware_training),
        "unknown_malware_samples": len(malware_unknown),
        "training_benign_samples": len(benign_training),
        "unknown_benign_samples": len(benign_unknown),
        "benign_package_groups_disjoint": True,
        "malware_family_split_rule": (
            "For families with at least two samples, test floor(n/2) and train the rest; "
            "singleton families are test-only."
        ),
        "malware_family_counts": family_counts,
        "singleton_families_test_only": sorted(
            family for family, split in family_counts.items() if split["total"] == 1
        ),
        "feature_balance": {
            "network_families": len(P4_FEATURES),
            "host_families": len(P4_FEATURES),
            "summaries_per_family": expected_summaries,
            "network_features": len(network_features),
            "host_features": len(selected_host_indices),
            "hybrid_features": len(network_features) + len(selected_host_indices),
            "host_selector": "training-only mean summary mutual information",
        },
        "models": models_report,
        "per_family_test_metrics": per_family_report,
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "family_stratified_50_50_metrics.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )
    write_csv(
        output_dir / "family_stratified_50_50_predictions.csv",
        prediction_rows,
        list(prediction_rows[0]),
    )
    write_csv(
        output_dir / "family_stratified_50_50_assignments.csv",
        assignment_rows,
        list(assignment_rows[0]),
    )
    write_csv(
        output_dir / "family_stratified_50_50_host_selection.csv",
        [
            {
                "selection_rank": rank,
                "signal_family": family,
                "mean_summary_mutual_information": family_scores[family],
            }
            for rank, family in enumerate(selected_host_families, start=1)
        ],
        ["selection_rank", "signal_family", "mean_summary_mutual_information"],
    )
    print(json.dumps(report, indent=2))
    print(f"Family-stratified results: {output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())