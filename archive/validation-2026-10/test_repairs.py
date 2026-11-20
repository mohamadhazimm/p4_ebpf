import json
import re
import csv
from datetime import datetime, timezone
import shutil
import subprocess
from types import SimpleNamespace

import pytest
from conftest import ROOT


def test_complete_snapshot_captures_without_cpu_report(collector, monkeypatch, tmp_path):
    clock = [0.0]
    monkeypatch.setattr(collector.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(collector.time, "sleep", lambda seconds: clock.__setitem__(0, clock[0] + seconds))
    values = iter([100, 100, 200, 200])
    def read(*args, **kwargs):
        return {"complete": True, "bucket_count": 65536,
                "rows": [{"idx": 0, "pkts": next(values), "pkts_ab": 0}]}
    monkeypatch.setattr(collector, "run_p4_reader_json", read)
    process = SimpleNamespace(poll=lambda: 0 if clock[0] >= 3 else None)
    windows = collector.collect_windowed_indexes_for_proc("unused", process, 1.0, 0, 0,
                                                         initial_snapshot={"reset_verified": True, "rows": []},
                                                         evidence_dir=tmp_path)
    summaries = collector.build_net_summaries("unused", windows, 1.0)
    assert [row["net_pkts_total_delta"] for row in summaries] == [100, 0, 100]
    assert windows[0]["indexes"] == [0]
    assert len(list(tmp_path.glob("window-*.json"))) == 3
    assert json.loads((tmp_path / "window-000000.json").read_text()) == windows[0]


def test_slow_snapshot_is_rejected(collector, monkeypatch):
    clock = [0.0]
    monkeypatch.setattr(collector.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(collector.time, "sleep", lambda seconds: clock.__setitem__(0, clock[0] + seconds))
    def read(*args, **kwargs):
        clock[0] += 0.2
        return {"complete": True, "bucket_count": 65536, "rows": []}
    monkeypatch.setattr(collector, "run_p4_reader_json", read)
    with pytest.raises(RuntimeError, match="skew"):
        collector.collect_windowed_indexes_for_proc("unused", SimpleNamespace(poll=lambda: 0), 1, 0, 0,
                                                    initial_snapshot={"reset_verified": True})


def test_reader_resets_and_checks_every_register(source_module, capsys):
    reader = source_module("thesis-hybrid-ebpf-p4/python/read_registers_with_index.py")
    class Register:
        def __init__(self):
            self.values = [5, 6]
        def clear(self):
            self.values = [0, 0]
        def dump(self, **kwargs):
            return [SimpleNamespace(to_dict=lambda index=index, value=value:
                    {"key": {"$REGISTER_INDEX": index}, "data": {"Ingress.register.f1": [value]}})
                    for index, value in enumerate(self.values)]
    registers = {name: Register() for name in reader.REG_NAMES}
    bfrt = SimpleNamespace(basic=SimpleNamespace(pipe=SimpleNamespace(Ingress=SimpleNamespace(**registers))),
                           complete_operations=lambda: None)
    exec(reader.build_bfrt_script(reset=True, bucket_count=2), {"bfrt": bfrt})
    result = json.loads(capsys.readouterr().out)
    assert result["reset_verified"] and result["rows"] == []
    assert all(register.values == [0, 0] for register in registers.values())


def test_reader_does_not_zero_missing_register(source_module):
    reader = source_module("thesis-hybrid-ebpf-p4/python/read_registers_with_index.py")
    bfrt = SimpleNamespace(basic=SimpleNamespace(pipe=SimpleNamespace(Ingress=SimpleNamespace())))
    with pytest.raises(AttributeError):
        exec(reader.build_bfrt_script(bucket_count=2), {"bfrt": bfrt})


def test_p4_and_reader_register_schemas_match(source_module):
    reader = source_module("thesis-hybrid-ebpf-p4/python/read_registers_with_index.py")
    ingress = (ROOT / "thesis-hybrid-ebpf-p4/ingress.p4").read_text()
    declared = set(re.findall(r"Register<[^;]+\)\s+(reg_\w+)\s*;", ingress))
    assert declared == set(reader.REG_NAMES)
    assert "Register<bit<64>, bit<16>>(FLOW_BUCKETS) reg_first_ts;" in ingress
    assert "Register<bit<64>, bit<16>>(FLOW_BUCKETS) reg_last_ts;" in ingress
    assert "collision_inc.execute(idx)" in ingress
    assert "(sip == ref_dip)" in ingress


def test_hostmon_health_is_strict(collector):
    assert collector.parse_host_windows("HOSTMON_READY,123\nHOSTMON_HEALTH,0,0,0,0\n") == []
    for line in ("HOSTMON_HEALTH,1,0,0,0", "HOSTMON_HEALTH,0,1,0,0", "HOSTMON_HEALTH,0,0,1,0", "HOSTMON_HEALTH,0,0,0,1"):
        with pytest.raises(ValueError, match="reported"):
            collector.parse_host_windows(line)


def test_hostmon_readiness_requires_scope_ack(collector, monkeypatch, tmp_path):
    log = tmp_path / "host.log"
    log.write_text("HOSTMON_READY,123\n")
    collector.wait_hostmon_ready(SimpleNamespace(poll=lambda: None), str(log), 123)
    with pytest.raises(RuntimeError, match="exited"):
        collector.wait_hostmon_ready(SimpleNamespace(poll=lambda: 1), str(log), 999)


def test_hostmon_bpf_is_cgroup_scoped_and_reports_loss():
    source = (ROOT / "libbpf-bootstrap/examples/c/hostmon.bpf.c").read_text()
    assert "bpf_get_current_cgroup_id() != workload_cgroup_id" in source
    assert source.count("e = reserve_workload_event();") == 6
    assert "__sync_fetch_and_add(lost, 1)" in source
    assert "id = ctx->id" in source
    loader = (ROOT / "libbpf-bootstrap/examples/c/hostmon.c").read_text()
    assert "hostmon_bpf__open_and_load()" not in loader
    assert "if (noisy_comm(e->comm))" not in loader


def test_expired_bucket_still_rejects_resets(collector):
    windows = [{"indexes": [], "register_snapshot": {"complete": True, "rows": [{"idx": 7, "pkts": value} ]},
                "initial_snapshot": {"reset_verified": True, "rows": []}} for value in [100, 100, 100, 100, 100, 1]]
    with pytest.raises(ValueError, match="reset or overflow"):
        collector.build_net_summaries("unused", windows, 1.0)


def test_mixed_failed_and_idle_child_labels(collector, tmp_path):
    path = tmp_path / "labels.csv"
    fields = ["pid", "started_at_utc", "finished_at_utc", "label", "exit_code"]
    stamp = lambda value: datetime.fromtimestamp(value, timezone.utc).isoformat()
    with path.open("w", newline="") as target:
        writer = csv.DictWriter(target, fieldnames=fields)
        writer.writeheader()
        writer.writerows([dict(zip(fields, [1, stamp(0), stamp(2), "benign", 0])),
                          dict(zip(fields, [2, stamp(1), stamp(3), "suspicious", 0])),
                          dict(zip(fields, [3, stamp(2), stamp(4), "suspicious", 7]))])
    windows = [{"net_window_id": index, "net_window_start_sec": index, "net_window_end_sec": index + 1,
                "net_window_duration_sec": 1.0, "indexes": []} for index in range(5)]
    args = SimpleNamespace(scenario_name="fixture", label="benign", mode="command", window_sec=1.0,
                           child_labels=str(path), run_origin_utc=0.0)
    rows = collector.build_rows(args, "fixture", [], windows, [])
    assert [row["label"] for row in rows] == ["benign", "mixed", "suspicious", "suspicious", "unknown"]
    assert [row["label_valid"] for row in rows] == [True, False, False, False, False]
    assert rows[-1]["sample_active"] is False


def test_generator_http_failure_is_not_suppressed(source_module, monkeypatch):
    generator = source_module("hybrid_data_generator.py")
    def fail(*args, **kwargs):
        raise OSError("fixture unreachable")
    monkeypatch.setattr(generator.urllib.request, "urlopen", fail)
    with pytest.raises(OSError, match="fixture unreachable"):
        generator.child_benign_http("http://unused", "unused")


def test_generator_cli_rejects_unjoined_labels(collector, monkeypatch, capsys):
    monkeypatch.setattr(collector.sys, "argv", ["hybrid_collector.py", "--mode", "command", "--label", "benign",
                        "--scenario-name", "fixture", "--timestamp-tick-seconds", "1e-9",
                        "--command", "python3 hybrid_data_generator.py --duration 1"])
    with pytest.raises(SystemExit) as error:
        collector.main()
    assert error.value.code == 2
    assert "require --child-labels" in capsys.readouterr().err


def test_hostmon_c_aggregation_and_csv(collector, tmp_path):
    compiler = shutil.which("cc")
    if compiler is None:
        pytest.skip("C compiler unavailable for userspace aggregation harness")
    includes = tmp_path / "bpf"
    includes.mkdir()
    (includes / "libbpf.h").write_text("""
#include <stddef.h>
struct bpf_map { int unused; };
struct ring_buffer { int unused; };
static inline int bpf_map__fd(struct bpf_map *map) { return 0; }
static inline struct ring_buffer *ring_buffer__new(int fd, int (*callback)(void *, void *, size_t), void *context, void *options) { return NULL; }
static inline int ring_buffer__poll(struct ring_buffer *buffer, int timeout) { return 0; }
static inline int ring_buffer__consume(struct ring_buffer *buffer) { return 0; }
static inline void ring_buffer__free(struct ring_buffer *buffer) {}
""")
    (includes / "bpf.h").write_text("static inline int bpf_map_lookup_elem(int fd, const void *key, void *value) { return 0; }\n")
    (tmp_path / "hostmon.skel.h").write_text("""
struct hostmon_rodata { unsigned long long workload_cgroup_id; };
struct hostmon_bpf {
    struct hostmon_rodata *rodata;
    struct { struct bpf_map *events; struct bpf_map *lost_events; } maps;
};
static inline struct hostmon_bpf *hostmon_bpf__open(void) { return NULL; }
static inline int hostmon_bpf__load(struct hostmon_bpf *skeleton) { return 0; }
static inline int hostmon_bpf__attach(struct hostmon_bpf *skeleton) { return 0; }
static inline void hostmon_bpf__destroy(struct hostmon_bpf *skeleton) {}
""")
    source = tmp_path / "hostmon-harness.c"
    production = ROOT / "libbpf-bootstrap/examples/c/hostmon.c"
    source.write_text("#define main hostmon_program_main\n#include " + json.dumps(str(production)) + "\n#undef main\n" + r'''
int main(void) {
    collector_start = 100.0;
    window_sec = 1.0;
    struct event event = { .monotonic_ns = 100100000000ULL, .pid = 123,
                           .comm = "a,b\"c", .type = EVENT_SYSCALL, .syscall_id = 39 };
    handle_event(NULL, &event, sizeof(event));
    event.monotonic_ns = 101100000000ULL;
    event.type = EVENT_OPEN;
    strcpy(event.path1, "/usr/workload-owned-file");
    handle_event(NULL, &event, sizeof(event));
    print_and_reset(window_id, 1.0, 2.0);
    return capacity_errors || late_events;
}
''')
    executable = tmp_path / "hostmon-harness"
    compiled = subprocess.run([compiler, "-std=gnu11", "-I", str(tmp_path), str(source), "-lm", "-o", str(executable)],
                              capture_output=True, text=True)
    assert compiled.returncode == 0, compiled.stderr
    result = subprocess.run([str(executable)], capture_output=True, text=True, check=True)
    windows = collector.parse_host_windows(result.stdout)
    assert len(windows) == 2
    assert windows[0]["rows"][0]["comm"] == 'a,b"c'
    assert windows[0]["rows"][0]["total_syscalls"] == 1
    assert windows[1]["rows"][0]["total_syscalls"] == 0
    assert windows[1]["rows"][0]["open"] == 1