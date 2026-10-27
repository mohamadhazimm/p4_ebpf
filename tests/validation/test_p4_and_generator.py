import ast
import csv
from collections import Counter
from contextlib import nullcontext
from datetime import datetime, timezone
import json
import random
from types import SimpleNamespace

import pytest

from conftest import ROOT


@pytest.fixture
def listener(source_module):
    pytest.importorskip("scapy")
    return source_module("thesis-hybrid-ebpf-p4/python/listen_cpu_reports.py")


@pytest.mark.parametrize("count", [100, 1000, 10000])
def test_b1_distinct_flow_collisions_are_rejected(listener, collector, request, count, record_property):
    seed = request.config.getoption("--audit-seed")
    randomizer = random.Random(seed)
    flows = set()
    while len(flows) < count:
        flows.add((f"10.{randomizer.randrange(256)}.{randomizer.randrange(256)}.{randomizer.randrange(1, 255)}",
                   "192.0.2.1", randomizer.randrange(1, 65536), randomizer.randrange(1, 65536), 6))
    buckets = Counter(listener.compute_flow_index_symmetric(*flow) for flow in sorted(flows))
    pairs = sum(occupancy * (occupancy - 1) // 2 for occupancy in buckets.values())
    record_property("collision_measurement", json.dumps({"seed": seed, "flows": count,
                    "occupied_slots": len(buckets), "excess_flows": count - len(buckets),
                    "colliding_pairs": pairs, "scope": "software hash; not switch replay"}))
    rows = [{"idx": index, "pkts": occupancy, "collisions": occupancy - 1} for index, occupancy in buckets.items()]
    windows = [{"indexes": list(buckets), "register_snapshot": {"complete": True, "rows": rows},
                "initial_snapshot": {"reset_verified": True, "rows": []}}]
    if pairs:
        with pytest.raises(ValueError, match="collision"):
            collector.build_net_summaries("unused", windows, 1.0)
    else:
        assert collector.build_net_summaries("unused", windows, 1.0)[0]["net_pkts_total_delta"] == count


def test_b1_endpoint_pairing_is_not_erased(listener):
    first = listener.compute_flow_index_symmetric("10.0.0.1", "10.0.0.2", 12000, 443, 6)
    different = listener.compute_flow_index_symmetric("10.0.0.1", "10.0.0.2", 443, 12000, 6)
    assert first != different, "B1: deterministic pre-hash alias, not merely birthday collision"


def test_b2_reverse_direction_same_slot(listener):
    forward = listener.compute_flow_index_symmetric("10.0.0.1", "10.0.0.2", 12000, 443, 6)
    backward = listener.compute_flow_index_symmetric("10.0.0.2", "10.0.0.1", 443, 12000, 6)
    assert forward == backward


def test_b2_crc_reference_vector(listener):
    assert listener.crc16_tofino(b"123456789") == 0xBB3D


def test_b3_missing_report_does_not_erase_flow(collector, monkeypatch):
    windows = [{"indexes": [], "register_snapshot": {"complete": True,
                "rows": [{"idx": 7, "pkts": 10, "bytes": 400}]},
                "initial_snapshot": {"reset_verified": True, "rows": []}}]
    summary = collector.build_net_summaries("unused", windows, 1.0)[0]
    assert summary["net_pkts_total_delta"] == 10, "B3: occupied bucket is never read without CPU report"


def test_b4_replay_preserves_capture_gaps(source_module, monkeypatch, tmp_path):
    scapy = pytest.importorskip("scapy.all")
    replay = source_module("thesis-hybrid-ebpf-p4/python/replay_pcaps_with_index.py")
    packets = [scapy.Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") /
               scapy.IP(src="10.0.0.1", dst="10.0.0.2") / scapy.TCP() for _ in range(3)]
    for packet, timestamp in zip(packets, [1000.0, 1000.1, 1000.4]):
        packet.time = timestamp
    sent, waits = [], []
    clock = [0.0]
    monkeypatch.setattr(replay, "rdpcap", lambda *args: packets)
    monkeypatch.setattr(replay, "sendp", lambda *args, **kwargs: sent.append(args[0]))
    def advance(seconds):
        waits.append(seconds)
        clock[0] += seconds
    monkeypatch.setattr(replay.time, "sleep", advance)
    monkeypatch.setattr(replay.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(replay.argparse.ArgumentParser, "parse_args", lambda self: SimpleNamespace(
        pcap="unused", internal_cidr="10.0.0.0/24", int_iface="unused", ext_iface="unused",
        limit=0, interval=0.0, unique_only=False, index_file=str(tmp_path / "indexes.txt")))
    replay.main()
    assert len(sent) == 3
    assert waits == pytest.approx([0.1, 0.3]), f"B4: replay scheduling ignores pkt.time: {waits}"


def test_a2_forwarding_setup_resets_all_registers(source_module):
    forwarder = source_module("thesis-hybrid-ebpf-p4/python/program_forwarding.py")
    setup = forwarder.build_bfrt_script(0, 1, 2, 1, 64)
    assert "reg_dir_valid" in setup and "reg_pkts_ab" in setup, "A2: forwarding setup never resets register state"


@pytest.mark.parametrize("times,capacity,error", [([1.0, 1.01], 10.0, "capacity"), ([2.0, 1.0], 10.0, "chronological")])
def test_replay_rejects_bad_timing_before_sending(source_module, monkeypatch, tmp_path, times, capacity, error):
    scapy = pytest.importorskip("scapy.all")
    replay = source_module("thesis-hybrid-ebpf-p4/python/replay_pcaps_with_index.py")
    packets = [scapy.Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / scapy.IP() / scapy.TCP() for _ in times]
    for packet, timestamp in zip(packets, times):
        packet.time = timestamp
    sends = []
    monkeypatch.setattr(replay, "rdpcap", lambda *args: packets)
    monkeypatch.setattr(replay, "sendp", lambda *args, **kwargs: sends.append(args))
    monkeypatch.setattr(replay.argparse.ArgumentParser, "parse_args", lambda self: SimpleNamespace(
        pcap="unused", internal_cidr="10.0.0.0/24", int_iface="unused", ext_iface="unused", limit=0,
        interval=0.0, max_pps=capacity, max_timing_error=0.01, unique_only=False,
        index_file=str(tmp_path / "indexes.txt")))
    with pytest.raises(ValueError, match=error):
        replay.main()
    assert sends == []


def test_b6_generator_starts_its_servers():
    tree = ast.parse((ROOT / "hybrid_data_generator.py").read_text())
    parent = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "run_parent")
    calls = {node.func.id for node in ast.walk(parent) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)}
    assert {"start_local_http_server", "start_tcp_sink"} <= calls, "B6: both server startup calls are commented out"


@pytest.mark.parametrize("exit_code", [0, 7])
def test_a4_generator_mixed_children_are_joined(collector, source_module, monkeypatch, tmp_path, exit_code):
    generator = source_module("hybrid_data_generator.py")
    clock = iter([0.0, 0.0, 2.0])
    monkeypatch.setattr(generator.time, "time", lambda: next(clock))
    monkeypatch.setattr(generator, "create_http_files", lambda *args: None)
    monkeypatch.setattr(generator, "launch_child", lambda *args: SimpleNamespace(pid=123, poll=lambda: exit_code))
    monkeypatch.setattr(generator, "safe_sleep", lambda *args: None)
    monkeypatch.setattr(generator, "start_local_http_server", lambda *args, **kwargs:
                        SimpleNamespace(shutdown=lambda: None, server_close=lambda: None))
    monkeypatch.setattr(generator, "start_tcp_sink", lambda **kwargs: SimpleNamespace(set=lambda: None))
    stamps = iter([datetime.fromtimestamp(value, timezone.utc).isoformat() for value in [0, 1]])
    monkeypatch.setattr(generator, "utc_now", lambda: next(stamps))
    monkeypatch.setattr(generator.random, "choice", lambda scenarios: scenarios[-1])
    with pytest.raises(RuntimeError, match="children failed") if exit_code else nullcontext():
        generator.run_parent(SimpleNamespace(workdir=str(tmp_path), duration=1, out=str(tmp_path / "labels.csv"),
                                            min_gap=0, max_gap=0))
    with (tmp_path / "labels.csv").open(newline="") as source:
        child = next(entry for entry in csv.DictReader(source) if entry["finished_at_utc"])
    monkeypatch.setattr(generator.time, "time", lambda: 2.0)
    hosts = [{"host_window_id": 0, "host_window_start_sec": 0.0, "host_window_end_sec": 1.0,
              "host_window_duration_sec": 1.0, "rows": []}]
    args = SimpleNamespace(scenario_name="fixture", label="benign", mode="command", window_sec=1.0,
                           child_labels=str(tmp_path / "labels.csv"), run_origin_utc=0.0)
    window = collector.build_rows(args, "fixture", hosts, [], [])[0]
    assert window["label"] == child["label"], "A4: benign run label overrides suspicious child launch"
    assert window["label_valid"] == (exit_code == 0)
    assert window["child_pids"] == "[123]"


def test_d10_offline_byte_unit_matches_p4(source_module, tmp_path):
    scapy = pytest.importorskip("scapy.all")
    pytest.importorskip("sklearn")
    offline = source_module("analyze_p4_pcap_ablation.py")
    packet = (scapy.Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") /
              scapy.IP(src="10.0.0.1", dst="10.0.0.2") / scapy.TCP())
    packet.time = 1000.1
    capture = tmp_path / "known.pcap"
    scapy.wrpcap(str(capture), [packet])
    utc = lambda value: datetime.fromtimestamp(value, timezone.utc).isoformat()
    telemetry = [{"window_start_utc": utc(1000), "window_end_utc": utc(1001), "net_packets_captured": "1"}]
    metadata = {"window_seconds": 1, "started_at_utc": utc(1000), "finished_at_utc": utc(1001)}
    _, windows, diagnostic = offline.derive_p4_features(capture, telemetry, metadata)
    assert diagnostic["alignment_status"] == "unique"
    assert "meta.pkt_len = hdr.ipv4.totalLen" in (ROOT / "thesis-hybrid-ebpf-p4/ingress_parser.p4").read_text()
    assert windows[0]["net_bytes_total_delta"] == len(bytes(packet[scapy.IP])), "D10: offline counts Ethernet bytes; P4 counts IPv4 bytes"
    assert diagnostic["p4_byte_layer"] == "ipv4.totalLen"
    _, legacy, legacy_diagnostic = offline.derive_p4_features(capture, telemetry, metadata, byte_layer="ethernet")
    assert legacy[0]["net_bytes_total_delta"] == len(bytes(packet))
    assert legacy_diagnostic["p4_byte_layer"] == "legacy-captured-ethernet"