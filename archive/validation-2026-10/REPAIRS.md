# Collector Repairs: 2026-10-19

**Local verification: 61 PASS, 0 FAIL, 82 UNVERIFIED/SKIP. Not certified for modeling or deployment.**
The separate study collector unit suite also passed all 14 tests. The original
27-failure audit remains in [REPORT.md](REPORT.md) and [results.xml](results.xml).
Post-repair results are in [repair-results.xml](repair-results.xml).

## Repairs And Checks

| Area | Implemented Repair | Focused Verification |
| --- | --- | --- |
| A1/A2 | Complete boundary snapshots; full zero readback; no final-counter rebinning; reject decreasing counters even after TTL expiry | Synthetic cumulative [100,100,200] produces [100,0,100]; dirty/reset runs rejected |
| A3 | Required cgroup-v2 workload scope, inherited membership, attach/readiness acknowledgement; no COMM denylist attribution | Mocked readiness/health; source contracts; real C userspace aggregation with stubbed BPF APIs |
| A4 | Seeded generator child interval/exit manifests; overlap joins; mixed/unknown labels invalid; direct generator commands require --child-labels | Successful/failed child cases; mixed and idle windows; CLI refusal before launch |
| B1/B2 | Endpoint-preserving canonical key; exact IP/port/protocol reference; collision counter and run rejection; equal-port direction; retain index zero | Seeded hash scans; reverse/CRC known answers; mismatch rejection; P4/reader schema check |
| B3 | Discover all slots without relying on first-flow CPU reports | Mocked complete snapshots with no CPU report |
| B4 | Original capture-time deadlines; reject nonchronological or over-capacity captures before sending; late pacing fails | Mocked sends/clock; capacity and chronology refusals |
| B6 | Start HTTP/TCP services; bind TCP before reporting startup; stable HTTP directory; child logs and surfaced request/exit failures | Startup source check; failed-request and failed-child tests; no live connections |
| C1/C2 | Strict finite/integer parsing, CSV quoting, common monotonic origin, interval-based host/network join, UTC observation timestamps | Comma/quote/numeric contracts; real C CSV round trip; window timestamp tests |
| C3/C4 | Seconds conversion using an explicit target tick; 64-bit timestamp registers; activity-refreshed TTL=3 | Tick conversion; source schema; monotonic counter checks; target build still required |
| C5/C6 | Reject incompatible CSV append; source/schema provenance; distinct run manifest/baseline/window JSON; ring-buffer loss and capacity/late-event reporting | Schema append tests; snapshot archival; health-error refusals; no kernel attachment |
| D3/D10 | Invalid sensors produce nulls, not zeros; P4/offline use IPv4 totalLen; recorded-window rate denominators | Availability contracts; 40-byte L3 known answer; existing jittered-alignment test |

The generic syscall hook also had an incompatible context declaration: its
ordinary `tracepoint/raw_syscalls/sys_enter` section now uses
`trace_event_raw_sys_enter::id`, not raw-tracepoint argument indexing.

Three test setups changed to exercise the repaired contract rather than require
impossible behavior: window tests supply saved boundary snapshots; CRC16 tests
require collision detection/rejection, not collision-free 10,000-flow hashing;
host aggregation requires explicit attribution instead of identifying unrelated
Python by its process name. Generator-label tests supply the actual interval file.
No defect was hidden with xfail, negative-delta clamping, or fabricated live evidence.

## Compatibility And Operation

The live collector schema is `2026-10-19.2`. Existing CSV headers cannot accept
these rows. Use a new output file and evidence directory. Command mode requires
an existing empty, delegated cgroup-v2 child with `cgroup.kill`; the launcher joins
it before executing the command. HostMon must be rebuilt together with its BPF
object/skeleton; old binaries cannot acknowledge this protocol.

`--timestamp-tick-seconds` must describe the deployed target, not a guessed unit.
PCAP mode requires `--max-replay-pps` from a measured lossless-capacity experiment.
Generator commands require `--child-labels` pointing to the generator's `--out`.
Child intervals are observed lifecycle bounds, not proof of malicious activation.
The current `sample_active` process-liveness flag likewise is not D6 certification.

The offline extractor defaults to IPv4 bytes and reports its byte-layer schema.
The separate study's `scripts/rebuild_versioned_p4_csvs.py` explicitly requests
legacy Ethernet counting. Its existing chronological/parity test passed after
this compatibility repair. Do not merge L2 and L3 feature exports. The frozen
VM runner, snapshots, captures, and paused collection were not modified or resumed.

## Remaining Gates

- No P4 compiler or clang is installed here. P4 compilation, resource/stage fit,
  timestamp width support, BPF verification/load, actual BFRT structured-entry
  behavior, and kernel cgroup/loss behavior remain unverified. The C harness
  compiles real userspace code against stubs, not a complete deployment.
- Complete BFRT reads are not atomic. Reads exceeding 10% of a window are rejected;
  bounded read time alone does not establish coherent snapshots. A target may
  require epoch-buffered banks before practical collection is possible.
- The 82 skips are 10 dataset gates, 71 live-evidence gates (including all 57 B5
  operation/build cases), and one missing compat32 toolchain. Several B5 semantic
  feature families still have no named hook. No coverage or unbiasedness claim is made.
- A final window CSV, actual feature allowlist, activation/exit/artifact metadata,
  live differential captures, and repeatability measurements are still required.
  Strict evidence mode fails missing inputs; it is not a green release gate here.
- No malware/benign workload samples, known-answer workload programs, VM operations,
  live replay, BPF attachment, or detection-model retraining occurred. Only a C
  synthetic-event userspace harness was executed.

## Reproduce

From `p4_ebpf`:

```sh
PYTHONPATH=/tmp/hazim-validation-deps-20261019 /usr/bin/python3 -m pytest \
  tests/validation tests/test_pcap_window_alignment.py -q -o junit_family=legacy \
  --junitxml=tests/validation/repair-results.xml
```

From `vbox-runs/hybrid-rf-study-20261010`:

```sh
/usr/bin/python3 -m unittest tests.test_malware_runner_hostmon -v
```

Repair source SHA-256 values:

| Source | SHA-256 |
| --- | --- |
| live hybrid_collector.py | fed43e468d5e6f02e2ed1d6a641238f6c1496cb3a57f30ec926e8531cc640b50 |
| ingress.p4 | 675bf553cdd6d50edf14807aa1f4ac765b04eabff1c9568e0fbcfcbbe5d32b7a |
| hostmon.bpf.c | 1cefdfc026a6c282315d48ac39d2692bd7bfc73f99bc41d63f5052fda05945a1 |
| hostmon.c | 2b143b4abee47d06d76d918f70c7876eba2e605bdd5111cfa671695a90db6a4b |
| offline extractor | 6d47b219df092e0f0ff4e939f5a76e54e4e816731ff80044c61c6c49e9ee8179 |
| legacy reconstruction wrapper | a094e9cd4969b1fb8e371cc3898bafaf59e98d2922d43e3e7a02eacdbd422c46 |

These are source hashes, not deployed binary attestations. The unchanged VM
runner remains `faf7997fdadba9e71bfbb67ff0d7600746ffffecac762d7f8ed3622bd08215f9`
with its separate `2026-10-18.1` schema.