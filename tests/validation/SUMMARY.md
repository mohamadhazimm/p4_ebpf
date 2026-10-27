# Validation Audit: Summary

**Post-repair result: 61 PASS, 0 FAIL, 82 UNVERIFIED/SKIP.** The separate study
suite passes 14/14. See [REPAIRS.md](REPAIRS.md) and
[repair-results.xml](repair-results.xml). P4/BPF deployment and live/dataset
evidence remain unverified; this is not modeling certification.

## Historical Initial Audit

2026-10-19. **Not certified for modeling.** Offline suite: **27 FAIL, 15 PASS,
82 UNVERIFIED/SKIP** in 2.47 s. No malware/benign samples executed; no detector
retrained. FAIL means code/synthetic defect, not measured class effect. Severity
on UNVERIFIED checks describes the potential risk. Details: [REPORT.md](REPORT.md).

| Check | Result | Severity | Proposed Fix / Required Evidence |
| --- | --- | --- | --- |
| A1 Window accounting | FAIL: [200,0,0], not [100,0,100] | Critical | Boundary snapshots; epoch banks; read intervals |
| A2 Run isolation | FAIL: no reset; decreasing deltas hidden | Critical | Clear/read back all 14 registers or epoch-tag |
| A3 Host attribution | FAIL in code; idle/crosstab unverified | Critical | Workload cgroup; invalidate pcap host features |
| A4 Window labels | FAIL: suspicious child labeled benign | Critical | PID/time child-label join; active-window flag |
| B1 Flow collisions | FAIL: 12/761 pairs at 1k/10k | High | Endpoint-preserving key; signature/mismatch counter |
| B2 Direction / zero | Reverse hash PASS; zero/BA FAIL | High | Keep zero; correct BA baseline; endpoint direction |
| B3 Missed reports | FAIL: unseen bucket vanishes; loss rate unverified | High | Reliable discovery; scoped four-way reconciliation |
| B4 Replay / capacity | Timing FAIL; switch capacity unverified | High | Timestamp pacing; lossless pps/queue measurements |
| B5 ABI / operation coverage | Partial hooks confirmed; 57 live cases unverified | High | Correct semantic hooks; ABI-tagged known answers |
| B6 Benign connectivity | Startup disabled; deployed listeners unverified | High | Verify responders; log/assert payload success |
| C1 Parsing | FAIL: comma row lost; bad numeric becomes 0 | High | CSV quoting; strict parse/error counters |
| C2 Timestamp | FAIL: write time, not window time | Medium | Shared monotonic origin; explicit UTC bounds |
| C3 Timestamp units | FAIL: raw ticks; 32-bit truncation | High | Verify ns; wide timestamps; seconds conversion |
| C4 Flow count meaning | TTL semantics confirmed, not active flows | Medium | Rename; document main TTL=5 and first-report latch |
| C5 Schema / provenance | FAIL: unchecked append; no source hashes | High | Validate header; immutable source/binary hashes |
| C6 Run hygiene | UNVERIFIED; no loss counter exists | High | Archived reset/isolation/attachment/loss checks |
| D1 Leakage exclusion | UNVERIFIED: no actual model column list | Critical | Explicit allowlist; exclude identifiers/hashes |
| D2 Physical invariants | UNVERIFIED on final CSV | High | Counts/direction/duration/layer-aware byte gates |
| D3 Missing vs zero | FAIL in builder; class rates unverified | High | Sensor validity + NaN; per-class missing rates |
| D4 Dead features | UNVERIFIED on final CSV | Medium | Flag constants; distinguish inactivity from missing hook |
| D5 Conflicting duplicates | UNVERIFIED on final CSV | High | Resolve labels and empty/duplicate runs |
| D6 Activation | UNVERIFIED on final CSV | High | Per-run exit/ABI/args/activity evidence |
| D7 Shortcut stumps | Harness PASS; real-data result unverified | High | Run-grouped per-feature review, startup controls |
| D8 Shuffled labels | Harness PASS; real pipeline unverified | High | Seeded null diagnostic; inspect preprocessing/splits |
| D9 Interpreter bias | UNVERIFIED on final CSV | High | Diverse native controls; startup-only comparison |
| D10 P4 / offline parity | FAIL: 54 L2 bytes vs 40 L3; switch unverified | Critical | Align byte layer/hash/direction/time; live differential |
| Repeatability / statistics | Helpers PASS; 10x5 experiment unverified | Medium | ICC; independent comparison counts and uncertainty |

No final CSV, actual feature list, idle trace, or matching live-switch bundle was
designated for either pass. The table above records the original source, not the
repaired implementation. Strict mode still fails unavailable evidence. A passing
offline subset must not be used as a dataset-validity claim.