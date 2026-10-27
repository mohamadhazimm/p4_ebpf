from argparse import Namespace
import csv
import inspect

import pytest


def register_row(pkts=100, **updates):
    row = {"idx": 7, "pkts": pkts, "bytes": pkts * 64, "pkts_ab": pkts,
           "bytes_ab": pkts * 64, "min_len": 64, "max_len": 64}
    row.update(updates)
    return row


def host_text(collector, comm="known-answer", total="10"):
    values = [comm, "123", "0", "1", "0", "0", "0", "0", "0", total,
              "2", "1", "0.5", "1", "1", "1", "0", "2", "2"]
    return ("==== HOST WINDOW 0 START=0.000 END=1.000 DUR=1.000 ====\n"
            + ",".join(collector.HOST_HEADER) + "\n" + ",".join(values))


def arguments():
    return Namespace(scenario_name="fixture", label="benign", mode="command", window_sec=1.0)


def net_window(window_id=0):
    return {"net_window_id": window_id, "net_window_start_sec": float(window_id),
            "net_window_end_sec": float(window_id + 1), "net_window_duration_sec": 1.0,
            "indexes": []}


def snapshot_window(row, indexes=None):
    return {"indexes": [row["idx"]] if indexes is None else indexes,
            "register_snapshot": {"complete": True, "rows": [row]},
            "initial_snapshot": {"reset_verified": True, "rows": []}}


def test_a1_packets_belong_to_their_window(collector, monkeypatch):
    windows = [snapshot_window(register_row(100)), snapshot_window(register_row(100), []),
               snapshot_window(register_row(200))]
    summaries = collector.build_net_summaries("unused", windows, 1.0)
    observed = [row["net_pkts_total_delta"] for row in summaries]
    assert observed == [100, 0, 100], f"A1: final-state reads misallocate packets: {observed}"


def test_a2_stale_registers_do_not_change_identical_run(collector, monkeypatch):
    windows = [snapshot_window(register_row(100))]
    first = collector.build_net_summaries("unused", windows, 1.0)
    second = collector.build_net_summaries("unused", windows, 1.0)
    assert first == second
    with pytest.raises(ValueError, match="baseline"):
        collector.build_net_summaries("unused", windows, 1.0,
                                      initial_snapshot={"reset_verified": True, "rows": [register_row(100)]})


def test_a2_decreasing_counters_are_rejected(collector, monkeypatch):
    with pytest.raises((ValueError, RuntimeError)):
        collector.build_net_summaries("unused", [snapshot_window(register_row(100)),
                                                snapshot_window(register_row(10))], 1.0)


def test_a3_tooling_not_in_workload_totals(collector):
    rows = collector.parse_host_windows(host_text(collector, "python3"))[0]["rows"]
    assert collector.summarize_host_window(rows)["host_total_syscalls_total"] == 0, (
        "A3: unrelated collector Python is admitted; fixture is not an idle measurement")


def test_a3_pcap_host_features_are_unavailable(collector):
    args = arguments()
    args.mode = "pcap"
    hosts = collector.parse_host_windows(host_text(collector))
    rows = collector.build_rows(args, "fixture", hosts, [], [])
    assert rows[0].get("host_sensor_valid") is False, "A3: replay host features are not marked invalid"


def test_a4_windows_expose_workload_activity(collector):
    rows = collector.build_rows(arguments(), "fixture", [], [net_window()], [])
    assert "sample_active" in rows[0], "A4: inactive/drain windows cannot be distinguished"


def test_b2_bucket_zero_is_retained(collector, monkeypatch):
    rows = collector.build_net_summaries("unused", [snapshot_window(register_row(1, idx=0))], 1.0)
    assert rows[0]["net_pkts_total_delta"] == 1


def test_b2_reader_backward_fallback_matches_total(collector, monkeypatch):
    row = register_row(10, pkts_ab=6, bytes_ab=384, pkts_ba=0, bytes_ba=0)
    rows = collector.build_net_summaries("unused", [snapshot_window(row)] * 2, 1.0)
    assert rows[1]["net_pkts_ba_delta"] == 0, "B2: absent BA registers cause repeated backward traffic"


def test_b2_inconsistent_direction_is_rejected(collector, monkeypatch):
    with pytest.raises((ValueError, RuntimeError)):
        collector.build_net_summaries("unused", [snapshot_window(register_row(10, pkts_ab=20))], 1.0)


@pytest.mark.parametrize("comm,total", [("with,comma", "10"), ("plain", "not-a-number")])
def test_c1_malformed_host_rows_are_not_silent(collector, comm, total):
    with pytest.raises((ValueError, RuntimeError)):
        collector.parse_host_windows(host_text(collector, comm, total))


@pytest.mark.parametrize("parser", ["safe_int", "safe_float"])
def test_c1_bad_numbers_are_not_zero(collector, parser):
    with pytest.raises((ValueError, RuntimeError)):
        getattr(collector, parser)("broken")


def test_c2_timestamp_identifies_window(collector, monkeypatch):
    monkeypatch.setattr(collector.time, "time", lambda: 1000.0)
    rows = collector.build_rows(arguments(), "fixture", [], [net_window(0), net_window(1)], [])
    assert rows[1]["timestamp"] - rows[0]["timestamp"] == 1.0


def test_c3_nanosecond_duration_is_seconds(collector, monkeypatch):
    row = register_row(2, first_ts=1000000000, last_ts=1500000000)
    rows = collector.build_net_summaries("unused", [snapshot_window(row)], 1.0)
    assert rows[0]["net_flow_duration_max"] == pytest.approx(0.5)


def test_a1_final_only_observations_are_rejected(collector):
    with pytest.raises(ValueError):
        collector.build_net_summaries("unused", [{"indexes": [7]}], 1.0)


def test_b1_collision_counters_fail_closed(collector):
    with pytest.raises(ValueError, match="collision"):
        collector.build_net_summaries("unused", [snapshot_window(register_row(1, collisions=1))], 1.0)


def test_c4_default_ttl_is_documented_by_signature(collector):
    assert inspect.signature(collector.build_net_summaries).parameters["active_ttl_windows"].default == 3


def test_c5_existing_csv_schema_is_checked(collector, tmp_path):
    path = tmp_path / "schema.csv"
    collector.append_csv_rows(str(path), [{"old": 1}])
    with pytest.raises((ValueError, RuntimeError)):
        collector.append_csv_rows(str(path), [{"new": 2}])


def test_c5_every_row_has_source_hashes(collector):
    row = collector.build_rows(arguments(), "fixture", [], [net_window()], [])[0]
    assert {"collector_git_hash", "p4_program_sha256"} <= row.keys()


def test_d3_absent_sensors_are_not_zero(collector):
    row = collector.build_rows(arguments(), "fixture", [], [net_window()], [])[0]
    assert row["host_total_syscalls_total"] is None, "D3: unavailable HostMon is encoded as observed zero"


def test_host_parser_known_answer(collector):
    rows = collector.parse_host_windows(host_text(collector))[0]["rows"]
    summary = collector.summarize_host_window(rows, workload_pids={123})
    assert summary["host_total_syscalls_total"] == 10
    assert summary["host_open_total"] == 1


def test_csv_same_schema_round_trip(collector, tmp_path):
    path = tmp_path / "valid.csv"
    collector.append_csv_rows(str(path), [{"value": 1}])
    collector.append_csv_rows(str(path), [{"value": 2}])
    with path.open(newline="") as source:
        assert list(csv.DictReader(source)) == [{"value": "1"}, {"value": "2"}]