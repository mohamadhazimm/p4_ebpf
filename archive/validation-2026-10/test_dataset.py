from collections import defaultdict
import json

import pytest

from audit_helpers import (LEAKAGE, conflicting_vectors, missing_rates, number,
                           physical_issues, shortcut_diagnostics, single_label_cells)
from conftest import unavailable


def test_a3_label_mode_scenario(audit_dataset):
    assert {"mode", "scenario_name"} <= audit_dataset[0].keys(), "A3: mode/scenario provenance missing"
    assert not single_label_cells(audit_dataset), single_label_cells(audit_dataset)
    assert not any(row["mode"] == "pcap" for row in audit_dataset), "A3: exclude pcap rows from host/hybrid datasets"


def test_d1_model_feature_allowlist(audit_dataset, feature_columns):
    assert not set(feature_columns) & LEAKAGE, "D1: provenance/label column enters model"
    assert set(feature_columns) <= audit_dataset[0].keys(), "D1: feature absent from CSV"


def test_d2_physical_invariants(audit_dataset, request):
    assert not physical_issues(audit_dataset), physical_issues(audit_dataset)[:20]
    required = {"timeout_seconds", "min_frame_bytes", "max_frame_bytes"}
    if not all(required <= row.keys() for row in audit_dataset):
        unavailable(request, "D2: declared timeout and capture frame-size bounds missing; basic invariants checked")


def test_d3_missingness_by_class(audit_dataset, feature_columns, record_property):
    rates = missing_rates(audit_dataset, feature_columns)
    record_property("nan_rate_by_class", json.dumps(rates, sort_keys=True))
    assert all(row.get("host_sensor_valid") in ("true", "false", "True", "False", "0", "1")
               and row.get("net_sensor_valid") in ("true", "false", "True", "False", "0", "1")
               for row in audit_dataset), "D3: explicit sensor validity flags missing"
    for row in audit_dataset:
        for prefix in ("host", "net"):
            if row[f"{prefix}_sensor_valid"].lower() in ("false", "0"):
                assert all(number(row.get(name)) is None for name in feature_columns if name.startswith(prefix + "_")), (
                    "D3: unavailable sensor encoded as numeric observations")


def test_d4_dead_features(audit_dataset, feature_columns):
    dead = [name for name in feature_columns if len({number(row.get(name)) for row in audit_dataset}) <= 1]
    assert not dead, f"D4: constant features (review hook availability, not proof of failure): {dead}"


def test_d5_conflicting_duplicate_vectors(audit_dataset, feature_columns):
    assert conflicting_vectors(audit_dataset, feature_columns) == 0, "D5: identical vectors have conflicting labels"


def test_d6_activation_by_class(audit_dataset, record_property, request):
    if not all({"sample_active", "run_id", "exit_status"} <= row.keys() for row in audit_dataset):
        unavailable(request, "D6: sample_active/run_id/exit_status missing")
    active, total = defaultdict(set), defaultdict(set)
    for row in audit_dataset:
        total[row["label"]].add(row["run_id"])
        if row["sample_active"].lower() in ("true", "1"):
            active[row["label"]].add(row["run_id"])
    rates = {label: len(active[label]) / len(runs) for label, runs in total.items()}
    record_property("active_run_rate", json.dumps(rates))
    errors = {row["run_id"] for row in audit_dataset if row["exit_status"] in
              ("ENOEXEC", "wrong_architecture", "missing_args", "immediate_exit")}
    assert not errors, f"D6: nonactivating sample runs: {sorted(errors)}"
    assert all(value == 1.0 for value in rates.values()), rates


@pytest.fixture(scope="module")
def shortcuts(audit_dataset, feature_columns, request):
    assert not set(feature_columns) & LEAKAGE
    pytest.importorskip("sklearn")
    try:
        return shortcut_diagnostics(audit_dataset, feature_columns, request.config.getoption("--audit-seed"))
    except ValueError as error:
        pytest.fail(str(error))


def test_d7_single_feature_stumps(shortcuts, record_property):
    record_property("shortcut_diagnostics", json.dumps(shortcuts))
    assert not shortcuts["near_perfect_stumps"], shortcuts["near_perfect_stumps"]


def test_d8_shuffled_label_control(shortcuts, record_property):
    record_property("shuffled_label_diagnostics", json.dumps(shortcuts))
    assert shortcuts["shuffled_accuracy"] <= shortcuts["shuffled_95pct_threshold"], shortcuts


def test_d9_interpreter_artifact_confound(audit_dataset, request, record_property):
    if not all("sample_artifact_type" in row for row in audit_dataset):
        unavailable(request, "D9: sample_artifact_type missing; cannot infer interpreter from feature counts")
    cells = defaultdict(set)
    for row in audit_dataset:
        cells[row["sample_artifact_type"]].add(row["label"])
    record_property("artifact_label_crosstab", json.dumps({key: sorted(value) for key, value in cells.items()}))
    assert all(len(labels) > 1 for labels in cells.values()), "D9: artifact type predicts class; review startup-only counts"


def test_harness_rejects_impossible_counts():
    assert physical_issues([{"net_pkts_total_delta": "1", "net_pkts_ab_delta": "2", "net_pkts_ba_delta": "0"}])


def test_harness_finds_label_confound_and_duplicates():
    rows = [{"label": "benign", "mode": "command", "scenario_name": "idle", "host_x": "0"},
            {"label": "malware", "mode": "pcap", "scenario_name": "scan", "host_x": "0"}]
    assert single_label_cells(rows)
    assert conflicting_vectors(rows, ["host_x"]) == 1