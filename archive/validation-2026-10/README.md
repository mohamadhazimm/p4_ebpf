# Collector Validation

These tests audit measurements, not detection accuracy. They never invoke the
collector CLI, attach BPF, start a switch/VM, replay onto a real interface, or run
malware. The repair pass changes production sources and adds regressions;
[REPAIRS.md](REPAIRS.md) records **61 passed, zero failed, 82 unverified**, plus
14/14 separate study tests. The original audit remains historical evidence.
Known defects are ordinary **failing tests**, not xfails. Green offline tests
are not deployment or dataset certification. The C aggregation harness executes
synthetic events against stubbed BPF APIs; the known-answer workloads are not run.

## Run

Use Python 3.10+ with pytest, NumPy, Scapy, and scikit-learn. The latter three are
already available in this workspace's `/usr/bin/python3`, not its editor venv.
Pytest 9.1.1 was installed outside the workspace because neither venv has pip:

```sh
cd /home/ali/Desktop/Hazim/p4_ebpf
PYTHONPATH=/tmp/hazim-validation-deps-20261019 /usr/bin/python3 -m pytest tests/validation tests/test_pcap_window_alignment.py -q -rs --tb=short -o junit_family=legacy --junitxml=tests/validation/repair-results.xml
```

For another environment, install `pytest numpy scapy scikit-learn` with its package
manager and run `python -m pytest tests/validation`. Scapy is used only for local
packet construction/PCAP serialization; replay `sendp` is replaced with a stub.
Explicit fixture MAC addresses avoid route/ARP lookups. All files written by
tests go into pytest temporary directories, except an explicitly requested report.

Run actual dataset gates with explicit inputs:

```sh
python -m pytest tests/validation -q -rs -o junit_family=legacy \
  --audit-csv /absolute/path/to/final_windows.csv \
  --audit-features /absolute/path/to/model_features.json \
  --audit-evidence /absolute/path/to/evidence.json \
  --audit-seed 20261019 --audit-require-evidence \
  --junitxml=/tmp/collector-validation.xml
```

`model_features.json` must be the actual model input list as a JSON string array,
not a list inferred from CSV numeric columns. No dataset is guessed automatically.
The current collection's sample-aggregated CSVs have a different schema and are
not silently substituted for this collector's window CSV.

## Results And Limits

- `test_collector_contracts.py`: real Python collector functions, mocked BFRT input.
- `test_p4_and_generator.py`: actual software hash, stubbed replay, generator-label
  repro, tiny PCAP through the existing offline extractor; no detector evaluation.
- `test_dataset.py`: A3 and D1-D9 over the supplied final CSV and feature allowlist.
- `test_measurement_evidence.py`: archived live-measurement gates, including all 57
  B5 operation/build combinations. No missing measurement becomes PASS.
- `test_known_answer_builds.py`: compile only; no fixture binaries are executed.
- `test_audit_helpers.py`: known-answer harness, ICC, sampler, and diagnostic controls.
- `test_repairs.py`: boundary acquisition/reset/skew, provenance archival,
  workload readiness/health, label regressions, and actual C aggregation with stubs.

Absent inputs are `SKIP: UNVERIFIED` by default. `--audit-require-evidence` makes
missing measurement inputs and unsupported C builds fail. Optional missing Scapy
or sklearn still produces a dependency skip; provision dependencies before a
release gate. No live measurements were supplied or collected during this pass.
JUnit properties retain collision counts, NaN rates, selected run IDs, seed, ICC,
stump warnings, and shuffled-label diagnostics. Use `junit_family=legacy` to retain
these properties without pytest's xunit2 compatibility warning.

## Dataset Contract

The host_/net_ columns are checked directly. Required metadata must describe the
actual run; remaining external inputs are not inferred from feature values:

- D2: `timeout_seconds`, `min_frame_bytes`, `max_frame_bytes` must describe the same
  byte layer as counters (L3 IP versus L2 captured frame). No hardcoded 64/1500-byte
  Ethernet assumption is imposed on L3 counts, VLAN, offload, or jumbo captures.
- D3: `host_sensor_valid`, `net_sensor_valid` are booleans serialized as
  true/false or 1/0. Unavailable sensor features must be blank/NaN, not zero.
- D6: `sample_active`, `run_id`, `exit_status`; expected launch errors include
  ENOEXEC, wrong_architecture, missing_args, immediate_exit. A timeout alone does
  not prove activation; active status must derive from PID/time/behavior evidence.
- D9: `sample_artifact_type`, ideally derived from ELF/shebang metadata, not a
  feature-value heuristic. Inspect startup-only open/syscall stumps as well.

D7/D8 average each declared feature within run, use a single stratified split of
disjoint run IDs, and cap diagnostics at 2,000 runs. Selected IDs and seed are
recorded. This is run-grouped, **not family-held-out**. D7 flags test AUC >=0.98 for
manual review; it cannot establish causation. D8 uses 20 seeded permutations and
a depth-three diagnostic tree, comparing mean accuracy with a conservative
majority-plus-binomial sampling threshold. A lucky single shuffle is not proof of
leakage; a clean result cannot certify an external training pipeline. No detector
is retrained or persisted. Dataset invariants inspect all provided rows.

## Evidence Bundle

Supply a JSON object with sections `A1`, `A2`, `A3`, `B1`, `B2`, `B3`, `B4`, `B5`,
`B6`, `C6`, `D10`, `repeatability`, and `sample_manifest`. Each section must contain:

```json
{
  "collector_sha256": "64-hex-source-digest",
  "p4_sha256": "64-hex-ingress-source-digest",
  "artifacts": [{"path": "relative-or-absolute-raw-artifact", "sha256": "64-hex-digest"}]
}
```

Artifacts resolve relative to the bundle. Hash checks protect against accidental
changes; they do not authenticate a claimed measurement or prove a binary was
built from the source. Keep raw PCAPs, BFRT JSON, BPF logs, reader start/end times,
link baselines, command logs, environment/ABI/compiler versions, schema, VM
snapshot, sample IDs, and actual deployed binary hashes beside the bundle. Parsed
summary fields below are evidence supplied by the operator; validators do not
independently reconstruct every summary from arbitrary raw artifact formats.

Required measurement fields (the test functions are the executable schema):

| Section | Fields |
| --- | --- |
| A1 | expected_packets, observed_packets, window_seconds, max_read_skew_seconds, reads[] with read_start_seconds/read_end_seconds |
| A2 | initial_registers: 18 arrays of 65,536 slots, unclamped_negative_deltas, run_one, run_two |
| A3 | idle_hostmon_log; report groups by COMM like analyse_hostmon.py, without its top-level argv side effects |
| B1 | scans keyed 100/1000/10000: distinct_flows, pcap_packets, register_packets, collision_mismatches, ground_truth_colliding_flows, unidentified_collisions |
| B2 | forward_index, reverse_index, index_zero_expected_packets, index_zero_observed_packets, equal_port_ab_packets, equal_port_ba_packets |
| B3 | runs[]: run_id, signature_mismatches=0, packet_scope, register_pkts[65536], collector_indexes, eligible_link_packets, eligible_tcpdump_packets, pcap_drops, cpu_report_drops |
| B4 | sustained_lossless_pps, gap_tolerance_seconds, replays[]: peak_bin_pps, capture_drops, switch_drops, max_gap_error_seconds |
| B5 | cases keyed build/variant: supported, fixture_exit_code, baseline_repeats, expected_operation_count, control_subtracted_operation_count, lost_events, abi_tag; double_fork also reparented_descendant_attributed; dns also resolver_attribution_documented |
| B6 | listening_ports; scenarios keyed benign_http_browsing/benign_local_tcp with successes, failures, payload_bytes_received |
| C6 | runs[]: parse_failures, skipped_data_lines, snapshot_canary_absent, registers_verified_zero, management_packets_on_veth1, uplink_egress_packets, bpf_attached_start/end, lost_bpf_events, loss_counter_available, nic_modes |
| D10 | seed; flows[]: canonical_5tuple, index, switch/offline dictionaries with pkts, bytes, pkts_ab, bytes_ab, min_len, max_len, syn, ack, rst, duration_seconds |
| repeatability | seed, sample_ids[10], features mapping each name to a 10x5 numeric matrix |
| sample_manifest | seed; ordered records[] with label malware/benign, sample_id; malware avclass_family/architecture/packed; benign workload_kind |

B3's `packet_scope` must be `same-epoch-ipv4-tcp-udp-all-ingress`. Raw `ip -s link`
includes ARP and other packets that P4 ignores; restrict the synthetic traffic or
account for those separately. Split replay injects both veth1 and veth3: veth1
alone is not the bidirectional ingress total. Use consistent RX/TX direction,
baseline deltas, eligibility, pipes, and time boundaries; record those choices.

## Known-Answer Programs

The compile checks produce dynamic64/static64/compat32 builds in temporary
directories. On this host the first two build; compat32 lacks multilib headers.
`known_answer.c` accepts `operation scratch-path [--baseline]`; variants are in
`test_measurement_evidence.py::VARIANTS`. This is **not an execution harness**.
Never run the fixture as part of a malware collection on a shared or busy guest.

For a separately authorized isolated sensor pilot, run one case and a matched
`--baseline` with identical startup/setup, and compare the intended operation,
not every syscall caused by libc/startup. The operation target is one, not always
one syscall: double-fork intentionally forks twice; memfd copies its executable;
glibc fork may use clone; mmap write and io_uring do not issue write syscalls.
Subtract startup/teardown, decode ABI explicitly, and compare named semantic
events and generic syscall coverage separately. A raw syscall row is not proof of
path-level open/write/exec coverage. Current collector output lacks several of
these semantic event fields entirely.

Network fixtures target loopback only and require a prepared local TCP sink at
9099 and DNS responder at 53. UDP completion at sendto is not proof a server read
the payload. Raw SYN requires CAP_NET_RAW and is only a syscall-path probe; its
crafted TCP checksum is not a valid wire-acceptance oracle. There is no network
load generator in this suite. `io_uring` requires liburing and compilation with
`-DVALIDATION_LIBURING -luring`; otherwise the program reports unsupported with
exit 77. Kernel ENOSYS/permission failures are limitations, not clean coverage.

Real-sample scheduling helper `stratified_schedule` is dry-run only: seed 20261019,
round-robin family/architecture/packing strata, <=30 unique samples per class,
randomized malware/benign pairs. Include network-active, long-running and
multi-process benign ELF controls. Save the chosen IDs and any uncovered strata;
the cap may make full factorial coverage impossible. Do not increase it to obtain
significance. The separate evidence gate counts unique samples across repeats.

Repeatability requires 10 samples x5 observations. ICC(1,1) <=0.5 is a warning/fail;
constant features have undefined ICC and are not silently declared repeatable.
No repeats were collected here. The rule of three only applies to independent,
clean comparisons of one defined failure condition: 60 clean comparisons give
approximately 5% (exact binomial upper bound 4.87%) at 95% confidence, not a proof
of unbiased features or class coverage.