# Historical Audit

This report preserves the pre-repair findings and source hashes. The subsequent
repair pass has **61 PASS, 0 FAIL, 82 UNVERIFIED/SKIP**, plus 14/14 separate study
unit tests. See [REPAIRS.md](REPAIRS.md) for changes, hashes, and deployment limits.

# P4 + eBPF Measurement Validation Audit

Date: 2026-10-19. Scope: source inspection, small offline/crafted-input tests,
and evidence-gated validation. **Disposition: do not use this collector's output
as validated per-window hybrid measurements. Final dataset validity is not
established.** This is not an evaluation of a trained detector.

## Outcome And Boundaries

The full new suite executed 124 tests in 2.47 seconds: **27 failed, 15 passed,
82 skipped/unverified**, with no harness errors or xfails. The separate existing
PCAP window-alignment regression passed (1 test). Editor diagnostics reported no
errors in the added suite. Machine-readable results, including failure details
and seeded collision measurements: [results.xml](results.xml). Compact table:
[SUMMARY.md](SUMMARY.md). Commands and input contracts: [README.md](README.md).

No real malware or benign sample was drawn, launched, recollected, or resumed;
budget used: **0 malware + 0 benign**. No VM or network configuration changed.
No detection model was retrained. The requested stump/null diagnostics ran only
on invented harness rows, not study samples, and are not persisted detectors.
C fixtures were compiled, never executed. No BPF was attached. Replay sends were
mocked; synthetic PCAPs were written locally with explicit MAC addresses.

The workspace ledger was read. In particular, the paused 500-benign collection
was left untouched, and neither the older Sink-down results nor the exploratory
224/138 classifier metrics were reused as validation evidence. The study's
separate versioned VM runner is not this live-switch collector. A source finding
here does not establish the same defect in every versioned telemetry capture.
Existing production edits, including the offline alignment repair, were preserved.
Only validation tests, fixture source, documentation, and the XML report were added.

### What Was Unavailable

No final window CSV or actual model feature list was supplied. A targeted search
of the collector tree (depth four, including ignored files) found no CSV, HostMon
log, register JSON, or PCAP to audit; expected exact filenames were also absent
from workspace search. This is not a claim that the much larger study archive
contains no data. No matching live-switch evidence bundle was supplied. A
read-only process check found no `tofino-model` or `bf_switchd` process on this
host. The code's default SDE/collector paths refer to another user's machine;
their deployment/binary provenance was not established.

Accordingly, live-switch replay, sustained pps, idle tooling totals, actual
loss rates, compat ABI behavior, final-CSV crosstabs/NaN/activation/shortcut
statistics, and 10x5 repeatability are **UNVERIFIED**, not PASS. Evidence-only
tests inspect supplied, hash-pinned artifacts plus operator-derived summaries;
they do not themselves perform collection or authenticate a deployed binary.
Use `--audit-require-evidence` for a release gate. Missing optional dependencies
must also be provisioned; dependency skips are not release evidence.

## Source Provenance

Collector repository HEAD: `20219049a57935d235e27094bb2b5d29f5a1dd9c`.
Source hashes below, rather than an assumed clean checkout, identify this audit.

| Source | SHA-256 |
| --- | --- |
| [hybrid_collector.py](../../hybrid_collector.py) | `e7cc1bd29cbd6d36f5ee3216016bf2181b3f525241a5c097da2dab0e1b454c04` |
| [hybrid_data_generator.py](../../hybrid_data_generator.py) | `0ab8614e3fe02a068745125583025ee63bd0894ed836ba7e9d0bd620ce2f73fe` |
| [hostmon.bpf.c](../../libbpf-bootstrap/examples/c/hostmon.bpf.c) | `ba8ac3e19ab93676e700d936cba40cc8d4a77f94cf33bc03ca3b5e64fa9d0bb5` |
| [hostmon.c](../../libbpf-bootstrap/examples/c/hostmon.c) | `5fa0ab79cd784d03d1ba771d470e62b9c9f455c2da813f425ec0fa63612b3292` |
| [ingress.p4](../../thesis-hybrid-ebpf-p4/ingress.p4) | `30a9c1700c568545fb13859d932dc5bdd4de2ab67a18bf324c6df2a0b7510a50` |
| [ingress_parser.p4](../../thesis-hybrid-ebpf-p4/ingress_parser.p4) | `b11abc8ec49cede9bc1a25fff52d84cadf72d009942508c2f7e0b7d7e0eb8ebd` |
| [listen_cpu_reports.py](../../thesis-hybrid-ebpf-p4/python/listen_cpu_reports.py) | `64aa76172f1ba180cfc6a0971fa72271c0daf1e6cda74a68b7730638eea0450a` |
| [read_registers_with_index.py](../../thesis-hybrid-ebpf-p4/python/read_registers_with_index.py) | `eaa891a4839fb22442c68ea09da32e9cd5e9122f52c5b79fe2a493d2de17f3ea` |
| [replay_pcaps_with_index.py](../../thesis-hybrid-ebpf-p4/python/replay_pcaps_with_index.py) | `a68a128d8d5509c1f3c9c6b6148a191a531b6f1c86cd4619743aba0cd6e5b805` |
| [program_forwarding.py](../../thesis-hybrid-ebpf-p4/python/program_forwarding.py) | `2d005d9bb2d41a45e55fa9a04599e19017c5383cb95f4e804bbcd707a34b8d9f` |
| [analyze_p4_pcap_ablation.py](../../analyze_p4_pcap_ablation.py) | `8d1098c21a52ca80c878df205d74400b7191d3d43ceafa9dc8ed30368d5a2f46` |

The duplicate [thesis_hostmon/hostmon.bpf.c](../../thesis_hostmon/hostmon.bpf.c)
has the same BPF-source hash. The reference-evaluation ingress is different
(`b5211450e69e280a0d8c0c69ed4b846d8412fdc38c55badfc1a2a0d062bfc264`)
and was not substituted for the thesis ingress selected by collector defaults.
No compiled BPF skeleton, deployed executable, SDE build, runner snapshot,
telemetry schema, or sample IDs were validated in this offline-only pass.

## Actual Sensor Behavior

### HostMon

**Confirmed in code:** BPF uses ordinary tracepoint sections, not kprobes or LSM:
`tracepoint/raw_syscalls/sys_enter` for the generic syscall stream, plus named
`syscalls/sys_enter_execve`, `openat`, `renameat`, `unlinkat`, and `connect`.
The raw_syscalls section is a tracepoint, not `raw_tracepoint/sys_enter`.
All use a 16-MiB BPF ring buffer, not perf events. A failed ring-buffer reserve
returns immediately without incrementing any loss counter. No PID, cgroup,
descendant, or workload filter is applied in BPF. Attribution stores the upper
32 bits of `bpf_get_current_pid_tgid()` (TGID, labeled PID) and current COMM.
The event struct has no kernel timestamp, ABI tag, TID, parent PID, or operation
return value. Named counters count attempted entries, not successful operations.

**Confirmed in userspace:** own PID, `hostmon`, `sudo`, and a long COMM denylist
are excluded. Thus the proposed claim that sudo is necessarily included is
incorrect for this source. `python3`, `tofino-model`, and `bf_switchd` are not
excluded by the denylist. Named path events under `/proc`, `/sys`, `/dev`,
`/run`, `/usr`, `/lib`, `/snap` are suppressed; raw syscall events are not.
Only 128 process slots and 64 distinct IPs/ports per process are retained;
exhaustion silently drops/limits information. Process IDs can be reused and
threads are merged into TGID order. All host events still consume the BPF buffer
before userspace exclusions, potentially displacing workload events.

Windows are assigned when userspace polls the ring buffer (100-ms poll timeout)
and resets metrics, not from kernel event timestamps. No exact event-time
window attribution is possible from the current event struct. This matters for
subsecond windows. **Unverified:** deployed kernel layouts, actual loss rate,
named compat tracepoint behavior, successful operations, and binary equivalence.
The generic stream may see 32-bit syscall numbers, but there is no ABI decoding;
blanket claims that all compat syscalls are invisible are not supported here.

### P4 Ingress

**Confirmed in code:** CRC16 yields a 16-bit index over 65,536 slots. It hashes
IP XOR/sum and port XOR/sum plus protocol; sums use fixed-width arithmetic.
Reversing both endpoints preserves the index. This is symmetric compression,
not a collision-free sorted-endpoint 5-tuple. Swapping ports without swapping
IPs also preserves the input, producing deterministic aliases before CRC16.
Zero is a legitimate index; no P4 output remapping reserves it.

Fourteen registers exist: `pkts`, `bytes`, `pkts_ab`, `bytes_ab`, `ref_src_port`,
`ref_dst_port`, `dir_valid`, `min_len`, `max_len`, `first_ts`, `last_ts`, `syn`,
`ack`, `rst` (all prefixed `reg_`). There is no FIN, BA, IAT, epoch, full flow
signature, or collision counter register. First use of `dir_valid` emits one
mirrored CPU report per occupied slot, not per packet/window. Direction compares
only first-seen source/destination ports. Equal source/destination ports cannot
distinguish reverse direction. Collision fallback is AB.

The parser measures IPv4 `totalLen` (L3), accepts only directly encapsulated IPv4
TCP/UDP, and does not explicitly handle VLAN, IPv6, IP options, or fragments.
Timestamps truncate `ingress_mac_tstamp` to 32 bits. **Unverified:** compiled
target equivalence, timestamp tick units, live CRC parameters/serialization,
pipe coverage, parser behavior for malformed/options/fragment packets.

### Listener, Reader, Replay, Forwarding

**Confirmed in code:** the listener uses Scapy `sniff` on veth5, deduplicates
indexes, prints each new report, and records no capture-loss counter. It
reconstructs the index from a 16-byte BEEF report using software CRC16/IBM
parameters. The software `123456789 -> 0xBB3D` vector and reversal test pass;
neither proves a live SDE implements identical parameters.

The reader launches bfshell/BFRT and calls each register's `get(..., from_hw=True)`
sequentially. There is no atomic snapshot or read start/end timestamp. Missing
registers and read/parsing exceptions return zero. The reader requests obsolete
BA/FIN/IAT registers too. It extracts a first list value using text regexes;
per-pipe aggregation is not established. It neither resets counters nor uses an
epoch. Forwarding setup clears only forwarding entries and mirror session 1,
then maps ports 0<->1 and reports to port 2; it never clears flow registers.

Replay reads the whole PCAP, sends each frame with a separate `sendp`, and sleeps
a fixed `--interval` after each frame (default zero). Packet capture timestamps
are ignored. Internal-source packets go to veth1, external-source packets to
veth3; non-IP/TCP/UDP packets still get injected through the internal interface.
Python sends, printing, and socket overhead also alter timing. There is no pps
budget, backpressure verification, or throughput calibration. **Unverified:**
live sniff drops, actual reports, forwarding deployment, queue delay and pps.

## Part A: Critical Correctness

### A1: End-of-run Counters Used As Window Snapshots

**Critical; FAIL; confirmed in code and synthetic execution.**
[main](../../hybrid_collector.py#L824) waits for exit, stops HostMon, then invokes
[build_net_summaries](../../hybrid_collector.py#L481). Its first baseline is empty.
Mocked final registers for a 100/0/100-packet workload produce **[200,0,0]**.
This test does not require or claim a live 200-packet replay. Continued traffic
during reads could change results further; reads need not even be identical.

Proposed fix: snapshot at observation boundaries while the workload runs. Use
epoch-selected double-buffered banks for robust consistency, include epoch and
read start/end timestamps, quantify skew, and avoid resetting the bank being
updated. Archive window snapshots so accounting can be independently reproduced.

### A2: Persistent Register State And Hidden Negative Deltas

**Critical; FAIL; confirmed in code and synthetic execution.** No collector or
forwarder reset exists. The manual commands clear only ack/bytes/FIN/pkts/rst/SYN
(bytes twice), omitting eight existing registers and referring to nonexistent
FIN. A stale `dir_valid` also suppresses the next run's first-seen report, not
just its counters. Synthetic identical runs with cumulative 100 then 200 packets
produce different features. Decreasing counters are clamped rather than rejected.
This is not a measured back-to-back switch run.

Proposed fix: clear and read back all fourteen registers over all slots and
relevant pipes before each run, or implement epoch-tagged state. Remove clamps
in diagnostic builds; distinguish resets, wraparound and collisions explicitly.
Do not silently turn invalid measurements into plausible zero deltas.

### A3: Host-wide Tooling And Replay Workload

**Critical; FAIL in code/synthetic input; actual idle totals and label crosstab
UNVERIFIED.** [summarize_host_window](../../hybrid_collector.py#L273) sums all
rows, with no workload identity. Ten synthetic collector-Python syscalls become
ten host-feature syscalls. Userspace excludes sudo, but not Python or simulator
tools. Packet sniffing therefore has an admissible path into host features;
the magnitude and relationship with traffic/class were not measured. PCAP-mode
workload is the Scapy interpreter, not captured malware, and host fields lack an
invalidity flag. No idle trace exists to quote an exact measured COMM breakdown.

Proposed fix: place workload and descendants in a dedicated cgroup, filter in
BPF, and archive root/cgroup identity. A fork-lineage implementation must survive
reparenting and exec and handle PID reuse. Exclude replay rows from host/hybrid
training. Run filtered idle control and final label x mode x scenario audit;
record residual COMM contributions rather than claiming they are approximately zero.

### A4: Global Labels Override Child And Activity State

**Critical; FAIL; confirmed in code and synthetic launch/row construction.** The
generator can select benign and suspicious scenarios in any parent invocation.
A stubbed suspicious child is logged as suspicious while the collector outputs
the supplied benign run label. Its label CSV is never joined. Labels mark
scenario intent, not verified malicious behavior. There is no `sample_active`.
Malicious labels also persist through extra windows where the sample may be gone.

Proposed fix: archive child start/end, identity, process lineage and per-window
overlap. Join PID/time labels with explicit mixed/unknown states; do not infer
end times from launch records alone. Record sample-active, outcome and drain
flags; separate class membership from proof of observed malicious activity.

Additional timing issue, **confirmed in code**: HostMon starts before a 0.2-second
sleep, then the network origin/workload starts, then the sniff listener opens.
Rows are paired by list position even when lengths differ. This shifts host and
network windows and creates a first-report race. Use a ready barrier and one
timestamp origin with explicit interval joins.

## Part B: Potential Class-correlated Silent Errors

The error mechanisms below are established where stated. **Their actual
class-correlation is unmeasured** without matched class/traffic/architecture
evidence. High-volume workloads are plausibly more exposed; this is a hypothesis,
not a measured malware-versus-benign effect.

### B1: Hash Aliases And Collision Accounting

**High; FAIL; confirmed in code and software-hash experiment.** Seed `20261019`,
unique crafted source/port tuples, fixed destination, TCP, no packets transmitted:

| Distinct flows | Occupied slots | Excess flows | Colliding pairs | Excess-flow fraction |
| --- | --- | --- | --- | --- |
| 100 | 100 | 0 | 0 | 0% |
| 1,000 | 988 | 12 | 12 | 1.2% |
| 10,000 | 9,278 | 722 | 761 | 7.22% |

These are exact software-hash counts for this draw, not switch replay loss or
collision probabilities. The 100-flow pass does not disprove approximately 7.3%
probability of at least one collision under uniform hashing; probabilities are
about 49.6% at 300 and 99.95% at 1,000. Sum/XOR compression can be nonuniform and
has deterministic aliases, so birthday estimates are not a target measurement.

Proposed fix: hash ordered complete endpoints without losing their pairing;
store a strong flow signature/epoch and count mismatches. Define and test a
collision policy (reject/mark aggregate/secondary resolution), not arbitrary AB
mixing. Replay the three crafted counts on the target and compare per-flow and
aggregate PCAP ground truth. Collisions alone need not reduce aggregate packets;
they corrupt identity, direction, sizes and timing. Live totals remain UNVERIFIED.

### B2: Direction, Zero, And Backward-baseline Defect

**High; partial PASS/FAIL.** Reverse endpoint hashing passes offline. Index zero
is valid in P4 but Python removes `x <= 0`; a one-packet zero-slot fixture returns
zero packets. Equal-port reverse direction is indistinguishable in the port-only
P4 comparison (**confirmed in code**, live result unverified).

Additional confirmed reader/collector mismatch: reader emits `pkts_ba=0` and
`bytes_ba=0` because those registers do not exist. Collector recomputes current
BA as total-minus-AB, but uses the reader's explicit zero as previous BA. A
constant 10-total/6-AB fixture adds **four backward packets again** on its second
read despite total delta zero. Invalid AB > total is also silently accepted.

Proposed fix: accept `0 <= idx < 65536`; derive both current and previous BA
consistently or persist normalized state. Validate AB+BA=total and reject
negative differences. Use full endpoint identity for direction; validate zero,
reverse traffic, equal ports, and collisions against a real target.

### B3: First-report Loss Eliminates Bucket Discovery

**High; FAIL in code/synthetic input; actual loss UNVERIFIED.** Without an index
report, a known nonzero mocked bucket is never queried and becomes zero features.
One-time reporting plus a listener started after workload launch increases risk.
No CPU capture/drop counter is checked.

Proposed fix: ready-before-launch capture, reliable/periodic discovery or complete
epoch-scoped dumps, loss counters, and after-each-run four-way reconciliation.
Compare all slots, known slots, eligible link deltas and eligible capture counts
within identical epochs/pipes/ingress directions. veth1 alone cannot equal all
ingress when replay injects both veth1 and veth3; raw link counts also include
noneligible traffic. Keep raw counters and explicitly account for these differences.

### B4: Replay Timing And Simulator Capacity

**High; timing FAIL; capacity UNVERIFIED.** Captured gaps 0.1/0.3 seconds generate
no replay sleeps at the default interval; timestamps are ignored. Per-frame
Python/socket/logging overhead is part of replay timing. No sustainable lossless
pps measurement exists here. Proposed fix: monotonic deadline scheduling from
original capture deltas, bounded-rate queueing, achieved-gap measurements and
same-configuration pps/drop calibration; invalidate timing when pacing fails.

### B5: ABI, Fileless And Operation Coverage

**High; coverage gaps confirmed in code; runtime coverage UNVERIFIED.** Generic
syscall entry collection is broader than named hooks, so it is incorrect to
conclude that every unhooked variant is invisible to every feature. However,
semantic `open` only has openat, exec only execve, connect only IPv4 connect;
no named write, mmap-write, UDP-sendto, DNS, io_uring, fork/lineage or execveat hook
exists. Raw syscall IDs do not provide path/return-code/ABI-equivalent semantics.
io_uring setup/enter can appear while the underlying file operation does not;
mmap modifications do not issue write. Failed named operations are still counted.

The fixture contains 19 operation variants x3 build modes. Dynamic64/static64
compile; compat32 compilation fails because `bits/wordsize.h` is unavailable.
All **57 sensor-observation cases are skipped/unverified**, separately from two
successful compiler checks. Optional liburing operation is disabled unless
explicitly built with liburing; raw SYN is syscall visibility only, not valid-wire
TCP proof. Double-fork synchronization awaits reparenting; it was not executed.

Proposed fix: determine intended semantic coverage, use appropriate VFS/LSM,
scheduler and network hooks and success/exit events, decode ABI separately, and
add loss/process-capacity counters. On an authorized isolated target, subtract
matched controls and check exact logical operations, success and attribution
for every supported case. Unsupported architecture/kernel/build cases must not
become zero-valued behavior. No broad claim of compat support is justified yet.

### B6: Silent Benign Connection Failure

**High; startup/exception handling confirmed in code; listener availability
UNVERIFIED.** Both local server calls in the generator are commented out, and
HTTP/TCP children swallow exceptions. Startup messages therefore do not prove
services are running. An independently supplied listener on 10.0.0.2 could exist;
this audit did not inspect that isolated namespace or claim all traffic was RST.

Proposed fix: provision verified reachable responders, record each child's
success/failure, return codes, received bytes and HTTP status. Require successful
payload exchange before calling a benign scenario network-active. The evidence
gate requires listening ports and successful HTTP/TCP payload receipts.

## Part C: Robustness And Reproducibility

| Check | Result And Evidence | Severity | Proposed Fix |
| --- | --- | --- | --- |
| C1 | FAIL, executed: comma COMM is skipped; bad numeric returns zero; reader errors also become zero. Actual skipped-row count unverified. | High | Proper CSV quoting/parser, strict typed conversion, separate parse/read errors and per-run counters; fail closed on any data loss. |
| C2 | FAIL, executed: frozen wall time gives identical timestamps in different windows. Code calls int(time.time()) per row, so identical timestamps are common, not guaranteed for every run. | Medium | Save run UTC/monotonic origin and actual window bounds; keep write time separate. |
| C3 | FAIL, executed: 1e9->1.5e9 input yields 500,000,000 duration, not 0.5 seconds under the ns convention. P4 truncates timestamps to 32 bits; if ticks are ns, wrap is 4.294967296 seconds. Live tick unit unverified. | High | Verify target units; wide timestamps or epoch-aware wrap logic; convert to seconds; reject cross-epoch stale state. |
| C4 | Confirmed semantics, not an active-flow measure: helper TTL default=3; main passes 5; inclusive <= retains current plus five subsequent windows. First-slot report, not packet activity, refreshes TTL. | Medium | Rename to reported-buckets-in-TTL, or track actual last packet activity; document main/default and expiration. |
| C5 | FAIL, executed: second append with a different same-width header succeeds and corrupts column meaning; no per-row collector/P4 hashes. | High | Exact ordered schema check, explicit schema version, immutable run manifest plus collector/P4 source and deployed-binary hashes in rows. |
| C6 | UNVERIFIED: no per-run canary/reset/isolation/management/attachment evidence. Source has no ring-buffer loss counter, so a zero-loss claim cannot be made. | High | Verify snapshot, all-slot reset, management bypass, no uplink, BPF IDs/attachments and measured losses before/after every run; archive proof. |

## Part D: Final Dataset Gates

Except for D3 builder and D10 byte-unit findings, the actual final dataset results
below are **UNVERIFIED**. The complete CSV-gate path does pass on a deliberately
valid 60-run invented fixture. That validates the harness only.

| Check | Implemented Gate / Actual Result | Severity | Proposed Fix / Interpretation |
| --- | --- | --- | --- |
| D1 | Actual feature JSON required; excludes label/run/scenario/mode/time/hash IDs and artifact/family provenance. No actual list supplied. | Critical | Explicit model allowlist; audit preprocessing/selection before fitting. |
| D2 | Nonnegative numeric values, AB+BA totals, mean within extrema, declared duration and byte bounds. No final CSV supplied. | High | Layer-aware bounds and timeout provenance; blanks cannot satisfy availability. |
| D3 | Builder FAIL: absent HostMon becomes 0; no validity flags. Final per-class NaN rates unverified. | High | NaN for unavailable sensor, true zero only with valid observation; archive class-wise missingness. |
| D4 | Flags all constant selected columns. No final CSV supplied. | Medium | Inspect hooks and raw traces; a constant can be valid inactivity or redundant design, not necessarily a dead hook. |
| D5 | Groups full selected vectors, including missingness, and flags conflicting labels. No final CSV supplied. | High | Resolve ambiguous empty/duplicate runs and label provenance; do not arbitrarily deduplicate by label. |
| D6 | Requires sample_active/exit_status; reports active-run rates by class and flags launch failures. No final CSV supplied. | High | Verify arch/args/exit/activity and endpoint reachability; lack of C2 reply alone does not prove inactivity. |
| D7 | Run-grouped single-split stumps; flags held-out AUC >=0.98; injected shortcut detected in harness. Real stump results unverified. | High | Review duration/event totals/open/unique-call fields and drop/collision counters; replace startup/workload confounds with matched controls. |
| D8 | Twenty seeded shuffled-label depth-three trees; records accuracy distribution and majority/uncertainty. Synthetic harness passes, real pipeline unverified. | High | Inspect train-only preprocessing, run/family boundaries and target-derived inputs. Above-majority one-off accuracy is not proof of leakage. |
| D9 | Artifact-type x label crosstab plus D7 startup-related stumps. Actual artifact/startup data unverified. | High | Compare identically launched diverse benign native ELF and malware; add controlled startup-only evidence before causal attribution. |
| D10 | FAIL on tiny PCAP: offline 54 bytes vs P4-parser L3 40 bytes. Software extractor also uses canonical endpoints and seconds, not live hash buckets/32-bit timestamps. Live per-flow differential unverified. | Critical | Align byte layer, key/collision policy, direction, window/TTL and timestamps, then compare all primitives flow-by-flow on a small archived target replay. |

The offline extractor refreshes last-seen on packet activity and keeps complete
canonical endpoint keys; the live collector refreshes a TTL on first reports of
hash buckets. These are further code-confirmed semantic differences, even when
packet totals happen to agree. The existing alignment regression passing does
not establish live P4 equivalence. The paper's PCAP-derived feature claim should
remain explicitly **P4-shaped/offline reconstruction**, not validated live P4
measurements, until D10 target comparison succeeds.

## Statistics And Collection Plan

No error-rate confidence bound or ICC is estimated from real samples in this
audit. The tested zero-error binomial helper yields 4.87% at 60 independent clean
comparisons (rule of three approximately 5%). Do not count correlated windows,
compiler success, or synthetic hash draws as 60 clean real comparisons.

For a later, explicitly authorized pilot, freeze seed `20261019`, selected IDs,
labels and all runner/schema/snapshot hashes first. The dry-run sampler caps at
30 malware and 30 benign, round-robins malware AVClass/architecture/packing
strata, and randomizes class-interleaved pairs. Include network-active,
long-running and multi-process benign programs; document uncovered strata rather
than increasing the cap. No launch automation was added. Preserve isolation and
do not compete with another collection or resume the paused coordinator.

For repeatability use ten selected samples x5 runs, still within the unique-sample
cap, interleaved across repetitions. ICC(1,1) compares between- and within-sample
variance; the gate flags <=0.5 and undefined constant-feature ICC. This threshold
is an explicit review policy, not a universal significance result. No 10x5
measurements or sample manifests were supplied, so their gates remain unverified.

## Recommended Repair Order

1. Fix A1/A2/A3/A4, source availability/error reporting and shared window origin
   before new collections. Pin a new collector/P4/BPF build; do not mutate old
   hash-pinned snapshots or relabel old measurements as repaired.
2. Resolve P4/offline byte/key/direction/time differences; preserve collision,
   drop and coverage counters as audit metadata, not silent detector shortcuts.
3. Establish known-answer operation/ABI, live differential and per-run hygiene
   evidence with benign crafted fixtures before any malware pilot.
4. Apply the dataset allowlist, activity, missingness, confound and null gates
   to an explicitly selected final dataset. Keep the old datasets immutable and
   report exclusions; do not retrain a detector as part of this validation pass.

No production fixes were applied in this audit. An all-green certified dataset
requires both resolved failing contracts and the currently missing evidence.