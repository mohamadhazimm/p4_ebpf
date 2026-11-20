import csv
import json
import random
import subprocess
import sys

import pytest

from audit_helpers import repeatability_icc, shortcut_diagnostics, stratified_schedule, zero_failure_upper_bound
from conftest import ROOT


def test_repeatability_known_answers():
    assert repeatability_icc([[1] * 5, [10] * 5]) == 1.0
    assert repeatability_icc([[1, 2, 3], [3, 2, 1]]) < 0
    assert repeatability_icc([[1] * 5] * 10) is None


def test_rule_of_three_exact_binomial_bound():
    assert zero_failure_upper_bound(60) == pytest.approx(0.0487, abs=0.0001)
    with pytest.raises(ValueError):
        zero_failure_upper_bound(0)


def test_sampler_is_seeded_stratified_and_bounded():
    records = [{"label": label, "sample_id": f"{label}-{position}", "avclass_family": f"family-{position % 3}",
                "architecture": "x86_64" if position % 2 else "i386", "packed": bool(position % 2),
                "workload_kind": ["network-active", "long-running", "multi-process"][position % 3]}
               for label in ("malware", "benign") for position in range(40)]
    first = stratified_schedule(records, 20261019)
    assert first == stratified_schedule(records, 20261019)
    assert len(first["records"]) == 60
    assert {record["architecture"] for record in first["records"]} == {"x86_64", "i386"}
    assert any(first["records"][position]["label"] != first["records"][position + 1]["label"]
               for position in range(1, 59))
    with pytest.raises(ValueError):
        stratified_schedule(records, 20261019, 31)


def test_shortcut_probe_detects_injected_shortcut():
    pytest.importorskip("sklearn")
    rows = [{"run_id": f"run-{position}", "label": str(position % 2), "host_open_total": str(position % 2)}
            for position in range(60)]
    result = shortcut_diagnostics(rows, ["host_open_total"], 20261019)
    assert result["near_perfect_stumps"] == {"host_open_total": 1.0}
    assert result["run_count"] == 60
    assert result["shuffled_accuracy"] <= result["shuffled_95pct_threshold"]


def test_dataset_cli_accepts_known_valid_fixture(tmp_path):
    values = list(range(60))
    random.Random(20261019).shuffle(values)
    rows = [{"run_id": f"fixture-{position}", "label": str(position % 2), "mode": "command",
             "scenario_name": "shared", "host_open_total": value, "host_sensor_valid": "true",
             "net_sensor_valid": "true", "sample_artifact_type": "elf", "sample_active": "1",
             "exit_status": "completed", "timeout_seconds": "1", "min_frame_bytes": "20",
             "max_frame_bytes": "1500", "net_pkts_total_delta": "0", "net_pkts_ab_delta": "0",
             "net_pkts_ba_delta": "0", "net_flow_duration_max": "0"}
            for position, value in enumerate(values)]
    dataset = tmp_path / "known.csv"
    with dataset.open("w", newline="") as output:
        writer = csv.DictWriter(output, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    features = tmp_path / "features.json"
    features.write_text(json.dumps(["host_open_total"]))
    result = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "--rootdir", str(ROOT),
                             str(ROOT / "tests/validation/test_dataset.py"),
                             "--audit-csv", str(dataset), "--audit-features", str(features), "--audit-require-evidence"],
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr