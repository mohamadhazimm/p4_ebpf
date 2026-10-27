#!/usr/bin/env python3
"""Evaluate benign-only novelty and supervised unknown-cohort models."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
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


def benign_group_partition(
    rows: list[dict[str, str]], labels: np.ndarray, seed: int
) -> tuple[np.ndarray, np.ndarray, np.ndarray, dict]:
    benign_indices = np.flatnonzero(labels == 0)
    groups = np.asarray([row["package_group"] for row in rows], dtype=str)
    outer = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=seed)
    development_relative, evaluation_relative = next(
        outer.split(benign_indices, groups=groups[benign_indices])
    )
    development_indices = benign_indices[development_relative]
    evaluation_indices = benign_indices[evaluation_relative]
    inner = GroupShuffleSplit(n_splits=1, test_size=0.25, random_state=seed + 1)
    fit_relative, calibration_relative = next(
        inner.split(development_indices, groups=groups[development_indices])
    )
    fit_indices = development_indices[fit_relative]
    calibration_indices = development_indices[calibration_relative]
    fit_groups = set(groups[fit_indices])
    calibration_groups = set(groups[calibration_indices])
    evaluation_groups = set(groups[evaluation_indices])
    if (
        fit_groups & calibration_groups
        or fit_groups & evaluation_groups
        or calibration_groups & evaluation_groups
    ):
        raise RuntimeError("Benign package groups crossed fit/calibration/evaluation")
    audit = {
        "fit_samples": len(fit_indices),
        "calibration_samples": len(calibration_indices),
        "evaluation_samples": len(evaluation_indices),
        "fit_package_groups": sorted(fit_groups),
        "calibration_package_groups": sorted(calibration_groups),
        "evaluation_package_groups": sorted(evaluation_groups),
        "package_groups_disjoint": True,
    }
    return fit_indices, calibration_indices, evaluation_indices, audit


def select_host_families_by_variance(
    host_matrix: np.ndarray,
    host_features: list[str],
    fit_indices: np.ndarray,
    family_indices: dict[str, list[int]],
    family_budget: int,
    seed: int,
) -> tuple[list[str], dict[str, float]]:
    imputer = SimpleImputer(strategy="median").fit(host_matrix[fit_indices])
    fit_host = imputer.transform(host_matrix[fit_indices])
    variances = np.var(fit_host, axis=0)
    scores = {
        family: float(np.mean(np.log1p(variances[indices])))
        for family, indices in family_indices.items()
    }
    selected = sorted(scores, key=lambda family: (-scores[family], family))[:family_budget]
    return selected, scores


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", required=True, type=Path)
    parser.add_argument("--feature-columns", required=True, type=Path)
    parser.add_argument("--known-cohort", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--benign-alert-rate", type=float, default=0.05)
    args = parser.parse_args()
    if not 0 < args.benign_alert_rate < 1:
        parser.error("--benign-alert-rate must be between 0 and 1")

    rows = load_csv(args.dataset)
    known_rows = load_csv(args.known_cohort)
    columns = json.loads(args.feature_columns.read_text(encoding="utf-8"))
    labels = np.asarray([int(row["label"]) for row in rows], dtype=int)
    if set(labels) != {0, 1}:
        parser.error("The dataset must contain both classes")

    def normalize_artifact(value: str) -> str:
        return value.removesuffix(".zip").lower()

    known_malware_hashes = {
        normalize_artifact(row["sample_artifact"])
        for row in known_rows
        if row["label"] == "1"
    }
    malware_indices = np.flatnonzero(labels == 1)
    unknown_indices = np.asarray(
        [
            index
            for index in malware_indices
            if normalize_artifact(rows[index]["sample_artifact"])
            not in known_malware_hashes
        ],
        dtype=int,
    )
    known_indices = np.asarray(
        [
            index
            for index in malware_indices
            if normalize_artifact(rows[index]["sample_artifact"])
            in known_malware_hashes
        ],
        dtype=int,
    )
    if len(malware_indices) != 323 or len(known_indices) != 224 or len(unknown_indices) != 99:
        parser.error(
            "Expected 323 malware, with 224 known hashes and 99 disjoint unknown hashes"
        )

    network_features = columns["network"]
    host_features = columns["host"]
    network_matrix = numeric_matrix(rows, network_features)
    host_matrix = numeric_matrix(rows, host_features)
    if len(feature_family_indices(network_features)) != len(P4_FEATURES):
        parser.error(f"P4 network feature pool must contain all {len(P4_FEATURES)} signal families")
    host_families = feature_family_indices(host_features)
    expected_summaries = len(P4_WINDOW_STATS)
    if any(len(indices) != expected_summaries for indices in host_families.values()):
        parser.error("Each host signal family must have all five summaries")

    benign_fit, benign_calibration, benign_evaluation, group_audit = benign_group_partition(
        rows, labels, args.seed
    )
    host_novelty_families, novelty_family_scores = select_host_families_by_variance(
        host_matrix,
        host_features,
        benign_fit,
        host_families,
        len(P4_FEATURES),
        args.seed,
    )
    novelty_host_set = set(host_novelty_families)
    novelty_host_indices = [
        index
        for index, feature in enumerate(host_features)
        if feature.rpartition("__")[0] in novelty_host_set
    ]
    if len(novelty_host_indices) != len(P4_FEATURES) * expected_summaries:
        raise RuntimeError("Novelty host selector did not preserve the 50/50 family budget")

    novelty_matrices = {
        "network_p4": network_matrix,
        "host_ebpf_balanced": host_matrix[:, novelty_host_indices],
        "hybrid_balanced_50_50": np.hstack(
            (network_matrix, host_matrix[:, novelty_host_indices])
        ),
    }
    host_train_indices = np.asarray(
        sorted(set(benign_fit.tolist()) | set(benign_calibration.tolist())), dtype=int
    )
    supervised_train_indices = np.concatenate((known_indices, host_train_indices))
    supervised_host_imputer = SimpleImputer(strategy="median").fit(
        host_matrix[supervised_train_indices]
    )
    supervised_host_train = supervised_host_imputer.transform(
        host_matrix[supervised_train_indices]
    )
    host_mi = mutual_info_classif(
        supervised_host_train,
        labels[supervised_train_indices],
        random_state=args.seed,
    )
    supervised_family_scores = {
        family: float(np.mean(host_mi[indices]))
        for family, indices in host_families.items()
    }
    supervised_host_families = sorted(
        supervised_family_scores,
        key=lambda family: (-supervised_family_scores[family], family),
    )[: len(P4_FEATURES)]
    supervised_host_set = set(supervised_host_families)
    supervised_host_indices = [
        index
        for index, feature in enumerate(host_features)
        if feature.rpartition("__")[0] in supervised_host_set
    ]
    if len(supervised_host_indices) != len(P4_FEATURES) * expected_summaries:
        raise RuntimeError("Supervised host selector did not preserve the 50/50 budget")

    supervised_matrices = {
        "network_p4": network_matrix,
        "host_ebpf_balanced": host_matrix[:, supervised_host_indices],
        "hybrid_balanced_50_50": np.hstack(
            (network_matrix, host_matrix[:, supervised_host_indices])
        ),
    }
    novelty_evaluation_indices = np.concatenate((malware_indices, benign_evaluation))
    novelty_evaluation_labels = labels[novelty_evaluation_indices]
    supervised_evaluation_indices = np.concatenate((unknown_indices, benign_evaluation))
    supervised_evaluation_labels = labels[supervised_evaluation_indices]
    calibration_rows = []
    prediction_rows = []
    output_dir = args.output_dir.expanduser().resolve()
    model_dir = output_dir / "models"
    model_dir.mkdir(parents=True, exist_ok=True)

    novelty_report = {
        "method": "benign-only IsolationForest novelty detection",
        "malware_labels_used_for_fit_or_feature_selection": False,
        "benign_only_partition": group_audit,
        "unknown_malware_scored": len(malware_indices),
        "heldout_benign_evaluation_samples": len(benign_evaluation),
        "threshold_policy": {
            "target_benign_alert_rate": args.benign_alert_rate,
            "source": "separate benign calibration package groups",
        },
        "host_family_selector": f"top {len(P4_FEATURES)} mean log(1 + variance) families on benign fit rows",
        "models": {},
    }
    novelty_feature_rows = []
    for model_name, matrix in novelty_matrices.items():
        imputer = SimpleImputer(strategy="median").fit(matrix[benign_fit])
        transformed_fit = imputer.transform(matrix[benign_fit])
        detector = IsolationForest(
            n_estimators=500,
            contamination="auto",
            random_state=args.seed,
            n_jobs=-1,
        ).fit(transformed_fit)
        calibration_scores = -detector.score_samples(
            imputer.transform(matrix[benign_calibration])
        )
        threshold = float(
            np.quantile(calibration_scores, 1 - args.benign_alert_rate, method="higher")
        )
        evaluation_scores = -detector.score_samples(
            imputer.transform(matrix[novelty_evaluation_indices])
        )
        predictions = (evaluation_scores >= threshold).astype(int)
        metrics = metrics_for(
            novelty_evaluation_labels, predictions, evaluation_scores
        )
        calibration_predictions = calibration_scores >= threshold
        calibration_fpr = float(np.mean(calibration_predictions))
        novelty_report["models"][model_name] = {
            "feature_count": matrix.shape[1],
            "threshold": threshold,
            "calibration_benign_alert_rate": calibration_fpr,
            **metrics,
            "unknown_malware_detected": int(
                np.sum(predictions[: len(malware_indices)] == 1)
            ),
            "unknown_malware_missed": int(
                np.sum(predictions[: len(malware_indices)] == 0)
            ),
            "heldout_benign_false_alerts": int(
                np.sum(predictions[len(malware_indices) :] == 1)
            ),
        }
        joblib.dump(
            {"imputer": imputer, "detector": detector, "threshold": threshold},
            model_dir / f"novelty_{model_name}.joblib",
        )
        for index, score, prediction in zip(
            novelty_evaluation_indices, evaluation_scores, predictions, strict=True
        ):
            prediction_rows.append(
                {
                    "evaluation": "benign_only_novelty_all_323",
                    "model": model_name,
                    "sample_artifact": rows[index]["sample_artifact"],
                    "sample_role": "unknown_malware" if labels[index] == 1 else "heldout_benign",
                    "label_for_evaluation_only": int(labels[index]),
                    "score": float(score),
                    "threshold": threshold,
                    "prediction": int(prediction),
                }
            )
        novelty_feature_rows.extend(
            {
                "evaluation": "benign_only_novelty_all_323",
                "selection_rank": rank,
                "signal_family": family,
                "selection_score": novelty_family_scores[family],
                "selection_method": novelty_report["host_family_selector"],
            }
            for rank, family in enumerate(host_novelty_families, start=1)
        )

    supervised_report = {
        "method": "supervised RandomForest; evaluate only on disjoint unknown malware",
        "known_malware_training_samples": len(known_indices),
        "unknown_malware_scored": len(unknown_indices),
        "unknown_hash_overlap_with_training": 0,
        "training_benign_samples": len(host_train_indices),
        "heldout_benign_evaluation_samples": len(benign_evaluation),
        "benign_package_groups_disjoint": group_audit["package_groups_disjoint"],
        "threshold": 0.5,
        "host_family_selector": f"top {len(P4_FEATURES)} mean summary mutual-information families on training rows only",
        "models": {},
    }
    supervised_feature_rows = [
        {
            "evaluation": "supervised_new_99_only",
            "selection_rank": rank,
            "signal_family": family,
            "selection_score": supervised_family_scores[family],
            "selection_method": supervised_report["host_family_selector"],
        }
        for rank, family in enumerate(supervised_host_families, start=1)
    ]
    training_labels = labels[supervised_train_indices]
    for model_name, matrix in supervised_matrices.items():
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
        model.fit(matrix[supervised_train_indices], training_labels)
        probabilities = model.predict_proba(
            matrix[supervised_evaluation_indices]
        )[:, 1]
        predictions = (probabilities >= 0.5).astype(int)
        metrics = metrics_for(
            supervised_evaluation_labels, predictions, probabilities
        )
        supervised_report["models"][model_name] = {
            "feature_count": matrix.shape[1],
            **metrics,
            "unknown_malware_detected": int(
                np.sum(predictions[: len(unknown_indices)] == 1)
            ),
            "unknown_malware_missed": int(
                np.sum(predictions[: len(unknown_indices)] == 0)
            ),
            "heldout_benign_false_alerts": int(
                np.sum(predictions[len(unknown_indices) :] == 1)
            ),
        }
        joblib.dump(model, model_dir / f"supervised_{model_name}.joblib")
        for index, probability, prediction in zip(
            supervised_evaluation_indices,
            probabilities,
            predictions,
            strict=True,
        ):
            prediction_rows.append(
                {
                    "evaluation": "supervised_new_99_only",
                    "model": model_name,
                    "sample_artifact": rows[index]["sample_artifact"],
                    "sample_role": "unknown_malware" if labels[index] == 1 else "heldout_benign",
                    "label_for_evaluation_only": int(labels[index]),
                    "score": float(probability),
                    "threshold": 0.5,
                    "prediction": int(prediction),
                }
            )

    report = {
        "score_scope": "unknown-cohort evaluation; no target malware used for model fitting or feature selection",
        "dataset_rows": len(rows),
        "full_unknown_malware": len(malware_indices),
        "known_disjoint_training_malware": len(known_indices),
        "new_disjoint_unknown_malware": len(unknown_indices),
        "benign_package_partition": group_audit,
        "feature_balance": {
            "p4_network_families": len(P4_FEATURES),
            "ebpf_host_families_per_model": len(P4_FEATURES),
            "summaries_per_family": expected_summaries,
            "features_per_sensor": len(P4_FEATURES) * expected_summaries,
            "hybrid_feature_count": 2 * len(P4_FEATURES) * expected_summaries,
        },
        "benign_only_novelty": novelty_report,
        "supervised_new_99": supervised_report,
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "unknown_cohort_metrics.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )
    write_csv(
        output_dir / "unknown_cohort_predictions.csv",
        prediction_rows,
        list(prediction_rows[0]),
    )
    write_csv(
        output_dir / "unknown_cohort_host_family_selections.csv",
        novelty_feature_rows + supervised_feature_rows,
        list((novelty_feature_rows + supervised_feature_rows)[0]),
    )
    (output_dir / "benign_group_partition.json").write_text(
        json.dumps(group_audit, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(report, indent=2))
    print(f"Unknown-cohort results: {output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())