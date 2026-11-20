from collections import Counter
import hashlib
import json
from pathlib import Path

import pytest

from audit_helpers import repeatability_icc
from conftest import ROOT, unavailable


VARIANTS = ("open", "openat", "openat2", "write", "pwrite", "writev", "mmap_write",
            "execve", "execveat", "memfd_fexecve", "fork", "vfork", "clone3", "double_fork",
            "tcp_connect", "udp_sendto", "raw_syn", "dns", "io_uring")
BUILDS = ("dynamic64", "static64", "compat32")


def section(bundle, name, request):
    if name not in bundle:
        unavailable(request, f"{name}: measured evidence absent")
    entry = bundle[name]
    assert isinstance(entry, dict) and entry.get("artifacts"), f"{name}: source artifacts required"
    for artifact in entry["artifacts"]:
        path = Path(bundle["_base"]) / artifact["path"]
        assert path.is_file(), f"Missing evidence artifact: {path}"
        assert hashlib.sha256(path.read_bytes()).hexdigest() == artifact["sha256"], f"Evidence changed: {path}"
    assert entry.get("collector_sha256") == hashlib.sha256((ROOT / "hybrid_collector.py").read_bytes()).hexdigest()
    assert entry.get("p4_sha256") == hashlib.sha256((ROOT / "thesis-hybrid-ebpf-p4/ingress.p4").read_bytes()).hexdigest()
    return entry


def test_a1_live_window_snapshots(audit_evidence, request):
    entry = section(audit_evidence, "A1", request)
    assert entry["expected_packets"] == [100, 0, 100]
    assert entry["observed_packets"] == entry["expected_packets"]
    assert len(entry["reads"]) == 3
    for position, read in enumerate(entry["reads"]):
        assert read["read_start_seconds"] <= read["read_end_seconds"]
        assert abs(read["read_start_seconds"] - (position + 1) * entry["window_seconds"]) <= entry["max_read_skew_seconds"]
        assert read["read_end_seconds"] - read["read_start_seconds"] <= entry["max_read_skew_seconds"]
    assert entry["max_read_skew_seconds"] <= entry["window_seconds"] * 0.1


def test_a2_full_reset_and_back_to_back_runs(audit_evidence, request):
    entry = section(audit_evidence, "A2", request)
    registers = {"pkts", "bytes", "pkts_ab", "bytes_ab", "ref_src_port", "ref_dst_port", "dir_valid",
                 "min_len", "max_len", "first_ts", "last_ts", "syn", "ack", "rst",
                 "ref_src_ip", "ref_dst_ip", "ref_proto", "collisions"}
    assert registers <= entry["initial_registers"].keys()
    for name in registers:
        values = entry["initial_registers"][name]
        assert len(values) == 65536 and all(value == 0 for value in values), name
    assert entry["unclamped_negative_deltas"] == 0
    assert entry["run_one"] == entry["run_two"], "A2: exact counter features must repeat; assess timing via ICC"


def test_a3_idle_tooling_contribution(audit_evidence, collector, request, record_property):
    entry = section(audit_evidence, "A3", request)
    path = Path(audit_evidence["_base"]) / entry["idle_hostmon_log"]
    windows = collector.parse_host_windows(path.read_text())
    assert windows, "A3: empty idle log cannot establish absence of contamination"
    totals = Counter()
    for window in windows:
        for row in window["rows"]:
            totals[row["comm"]] += row["total_syscalls"]
    record_property("idle_comm_syscalls", json.dumps(dict(totals), sort_keys=True))
    assert sum(totals.values()) == 0, f"A3: unrelated idle events remain: {dict(totals)}"


@pytest.mark.parametrize("count", [100, 1000, 10000])
def test_b1_switch_scan_ground_truth(audit_evidence, request, count):
    entry = section(audit_evidence, "B1", request)
    scan = entry["scans"][str(count)]
    assert scan["distinct_flows"] == count
    assert scan["pcap_packets"] == scan["register_packets"] + scan["collision_mismatches"]
    assert scan["collision_mismatches"] == scan["ground_truth_colliding_flows"]
    assert scan["unidentified_collisions"] == 0


def test_b2_switch_direction_and_zero(audit_evidence, request):
    entry = section(audit_evidence, "B2", request)
    assert entry["forward_index"] == entry["reverse_index"]
    assert entry["index_zero_expected_packets"] > 0
    assert entry["index_zero_observed_packets"] == entry["index_zero_expected_packets"]
    assert entry["equal_port_ab_packets"] == entry["equal_port_ba_packets"] == 1


def test_b3_every_run_four_way_packet_accounting(audit_evidence, request):
    entry = section(audit_evidence, "B3", request)
    assert entry["runs"]
    for run in entry["runs"]:
        assert run["signature_mismatches"] == 0, "Collision-contaminated runs must be rejected"
        assert run["packet_scope"] == "same-epoch-ipv4-tcp-udp-all-ingress"
        full_dump = run["register_pkts"]
        assert len(full_dump) == 65536 and all(value >= 0 for value in full_dump)
        indexes = set(run["collector_indexes"])
        assert all(0 <= index < 65536 for index in indexes)
        totals = (sum(full_dump), sum(full_dump[index] for index in indexes),
                  run["eligible_link_packets"], run["eligible_tcpdump_packets"])
        assert len(set(totals)) == 1, f"B3: {run['run_id']}: {totals}"
        assert run["pcap_drops"] == run["cpu_report_drops"] == 0


def test_b4_replay_within_measured_capacity(audit_evidence, request):
    entry = section(audit_evidence, "B4", request)
    assert entry["sustained_lossless_pps"] > 0
    assert entry["replays"]
    for replay in entry["replays"]:
        assert replay["peak_bin_pps"] <= entry["sustained_lossless_pps"]
        assert replay["capture_drops"] == replay["switch_drops"] == 0
        assert replay["max_gap_error_seconds"] <= entry["gap_tolerance_seconds"]


@pytest.mark.parametrize("build", BUILDS)
@pytest.mark.parametrize("variant", VARIANTS)
def test_b5_known_answer_sensor_coverage(audit_evidence, request, variant, build):
    entry = section(audit_evidence, "B5", request)
    key = f"{build}/{variant}"
    if key not in entry["cases"]:
        unavailable(request, f"B5: no measured known-answer trace for {key}")
    case = entry["cases"][key]
    assert case["supported"], f"B5: {key} unavailable; record kernel/compiler limitation, not a sensor pass"
    assert case["fixture_exit_code"] == 0
    assert case["baseline_repeats"] >= 1
    assert case["expected_operation_count"] == 1
    assert case["control_subtracted_operation_count"] == 1, f"B5: {key} missing/overcounted"
    assert case["lost_events"] == 0
    assert case["abi_tag"] == ("i386" if build == "compat32" else "x86_64")
    if variant == "double_fork":
        assert case["reparented_descendant_attributed"]
    if variant == "dns":
        assert case["resolver_attribution_documented"]


def test_b6_benign_network_scenarios_succeed(audit_evidence, request):
    entry = section(audit_evidence, "B6", request)
    for name in ("benign_http_browsing", "benign_local_tcp"):
        scenario = entry["scenarios"][name]
        assert scenario["successes"] > 0 and scenario["failures"] == 0
        assert scenario["payload_bytes_received"] > 0
    assert {8088, 9099} <= set(entry["listening_ports"])


def test_c1_c6_every_run_hygiene(audit_evidence, request):
    entry = section(audit_evidence, "C6", request)
    assert entry["runs"]
    for run in entry["runs"]:
        assert run["parse_failures"] == run["skipped_data_lines"] == 0
        assert run["snapshot_canary_absent"] and run["registers_verified_zero"]
        assert run["management_packets_on_veth1"] == run["uplink_egress_packets"] == 0
        assert run["bpf_attached_start"] and run["bpf_attached_end"]
        assert run["lost_bpf_events"] == 0 and run["loss_counter_available"]
        assert run["nic_modes"] and set(run["nic_modes"]) <= {"intnet", "none"}


def test_d10_archived_switch_offline_differential(audit_evidence, request):
    entry = section(audit_evidence, "D10", request)
    assert entry["seed"] == request.config.getoption("--audit-seed")
    assert entry["flows"]
    for flow in entry["flows"]:
        assert flow["canonical_5tuple"] and 0 <= flow["index"] < 65536
        for feature in ("pkts", "bytes", "pkts_ab", "bytes_ab", "min_len", "max_len", "syn", "ack", "rst"):
            assert flow["switch"][feature] == flow["offline"][feature], (flow["canonical_5tuple"], feature)
        assert flow["switch"]["duration_seconds"] == pytest.approx(flow["offline"]["duration_seconds"], abs=1e-6)


def test_repeatability_ten_by_five(audit_evidence, request, record_property):
    entry = section(audit_evidence, "repeatability", request)
    assert entry["seed"] == request.config.getoption("--audit-seed")
    assert len(entry["sample_ids"]) == len(set(entry["sample_ids"])) == 10
    values = {}
    for name, matrix in entry["features"].items():
        assert len(matrix) == 10 and all(len(row) == 5 for row in matrix)
        values[name] = repeatability_icc(matrix)
    assert values
    record_property("icc_1_1", json.dumps(values))
    assert all(value is not None and value > 0.5 for value in values.values()), values


def test_real_sample_budget_and_interleaving(audit_evidence, request):
    entry = section(audit_evidence, "sample_manifest", request)
    assert entry["seed"] == request.config.getoption("--audit-seed")
    records = entry["records"]
    assert records
    counts = Counter()
    identities = set()
    for record in records:
        assert record["label"] in ("malware", "benign")
        key = (record["label"], record["sample_id"])
        if key not in identities:
            identities.add(key)
            counts[record["label"]] += 1
        required = ("avclass_family", "architecture", "packed") if record["label"] == "malware" else ("workload_kind",)
        assert all(record.get(name) not in (None, "", "unknown") for name in required)
    assert counts["malware"] <= 30 and counts["benign"] <= 30
    assert min(counts.values()) > 0 and len(counts) == 2
    assert any(records[position]["label"] != records[position + 1]["label"] for position in range(1, len(records) - 1)), (
        "Cohorts must be interleaved, not one class block followed by another")
    benign_kinds = {record["workload_kind"] for record in records if record["label"] == "benign"}
    assert {"network-active", "long-running", "multi-process"} <= benign_kinds