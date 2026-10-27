# P4 data plane on the Tofino: hardware performance

This document reports the hardware evaluation of the P4 half of the hybrid P4/eBPF
malware detector (`thesis-hybrid-ebpf-p4`) on the NETLAB Tofino, 26 October 2026. It
covers:
- the P4 program's resources, packet rate, latency and flow table;
- the problems found in the program, and their fixes;
- a comparison with published P4 systems;
- what is still missing for a paper.

The eBPF side runs on a separate server and is analysed separately. Detection accuracy
is evaluated elsewhere. Raw data (per-command logs, P4 builds, pcaps, register dumps)
stays in `perf/results/` on PC1 and is not tracked by git (Section 11).

## Summary

- **No loss, exact counting.** About 238 million frames per program went through at up
  to 0.37 Mpps with zero loss. The per-flow packet and byte counters equal the port
  counters. That rate is the traffic generator's limit (≤ 4% of line rate), not the
  switch's (Section 3).
- **Latency.** The detector adds a constant 69–70 ns over a forwarding-only program at
  every frame size (ingress parser to egress parser, ASIC clock). p99 stays within 8 ns
  of the median (Section 4).
- **Resources.** The detector uses 5 of 12 ingress stages, 20.5% of SRAM, 34% of map RAM,
  1% of TCAM and 14 of 48 stateful ALUs. 2¹⁶ buckets is the largest flow table that
  compiles (Section 2).
- **Flow hash fixed.** The compiled hash was not symmetric, so each connection was split
  over two buckets. It is fixed with `@symmetric`, and the fix was checked against
  software and on the switch (Section 5.1).
- **Collision detection (variant).** A 16-bit flow fingerprint per bucket flags every
  shared bucket, including crafted ones. It costs 14 RAMs (+1.5%), 2 stateful ALUs and
  one more stage, with no measurable latency. It was tested on the switch but is not
  deployed (Section 5.3).
- **Compared with 20 systems published with Tofino results** (Section 7):
  - the latency overhead is in the range of the only two systems that report one;
  - the stage count is the lowest of the systems that keep per-flow state;
  - SRAM use is mid-range.

  Throughput is the gap: they measured up to 100 Gbps per port, this evaluation only
  0.37 Mpps.
- **Still open:** a line-rate test with the switch's own packet generator (Section 8).

## 1. Setup

### 1.1 Testbed

| Item | Value |
|---|---|
| Switch | Edgecore Wedge100BF-32X, Tofino 1 (BFN-T10-032D, 2 active pipes, 12 MAU stages per pipe), PCIe Gen2 x4 to the switch CPU (Pentium D1517, 4 cores, 1.6 GHz, 7.7 GiB); Debian 9, kernel 4.14.151-OpenNetworkLinux |
| Software | SDE 9.6.0, bf-p4c 9.6.0 (SHA f6d0a70); bfrt_python embeds Python 3.4. Every build was compiled with bf-p4c directly into `/root/hazim_perf/build/<variant>`, because the lab procedure's `p4_build.sh` would have overwritten the shared SDE's installed `basic` |
| Path | PC1 `eth1` → front port 1/0 = dev_port 132 → `forwarding` → 2/0 = dev_port 140 → PC2; 100G RS-FEC, autoneg off. Counters confirm the mapping: 1000 frames from PC1 = +1000 RX on 132 = +1000 TX on 140 |
| CPU reports | mirror session 1 → PCIe CPU port 192 (`lld_get_pcie_cpu_port()`: 192 with 2 active pipes, 320 with 4) → `enp5s0` on the switch (`bf_kpkt`), 64 B per copy |
| Traffic | PC1: KVM guest, 2 vCPUs (2.19 GHz), 3.8 GiB; Ubuntu 20.04.6, kernel 5.15; Mellanox ConnectX-4 (MT27700) by PCI passthrough; tcpreplay 4.3.2, scapy 2.4.3. At most about 0.37 Mpps, with one vCPU saturated |
| Clocks | Latencies use the ASIC's nanosecond timestamps. Host clocks only stamp the logs (the switch clock runs about 7 h 52 min ahead of PC1) |
| Repetitions | 3–5 per point; medians with ranges |

### 1.2 Program under test

Ingress, for IPv4 packets with TCP or UDP only:
- A 16-bit flow index selects one bucket of 14 register arrays (65,536 entries each):
  - 32 bits: `pkts`, `bytes`, `pkts_ab`, `bytes_ab`, `first_ts`, `last_ts`, `syn`, `ack`
    and `rst`;
  - 16 bits: `ref_src_port`, `ref_dst_port`, `min_len` and `max_len`;
  - 8 bits: `dir_valid`.

  That is 9 × 32 + 4 × 16 + 8 = 360 bits (45 B) per flow.
- The first packet of a bucket stores the reference ports and sends one CPU report
  (mirror session 1). Later packets count as A→B when their ports match the stored
  order, as B→A when reversed, and as A→B when neither matches.
- Timestamps are the low 32 bits of `ingress_mac_tstamp` (ns). `pkt_len` is the IPv4
  `totalLen`.
- `forwarding` is an exact match on `ingress_port` (`send_using_port`, default `drop`,
  256 entries).

Egress has one table, `packet_size_hist` (range match on the packet length, direct
counter). No script installs entries, so as deployed it counts nothing.

Builds:
- **detector**: `basic.p4` as deployed on 26 October (working tree).
- **detector (fixed)**: after the fixes of Section 5.1.
- **baseline**: forwarding only, with the same `forwarding` table and actions
  (`perf/variants/baseline.p4`).
- **fingerprint**: the fixed build plus collision detection (Section 5.3).
- **\*_lat**: the same programs wrapped for latency measurement (`perf/variants/lat/`).

### 1.3 Method and tools

All tools are in `perf/tools/`:
- **Builds and resources:** `sw_compile.sh` and `parse_resources.py`.
- **Hash checks:** `hash_matrix_check.py` and `hash_block_identify.py` evaluate the
  compiled hash from `mau.hashes.log`; `hash_quality.py` checks hash choices for
  collisions offline.
- **Switch sessions:** `run_bfrt.sh`, `bfrt_gen.py`, `sw_bfshell_b.py` and
  `sw_switchd.sh` run scripted, SIGHUP-safe bfshell sessions.
- **Experiments and checks:** `run_pktrate.py`, `run_lat.py`, `run_report_capacity.py`,
  `make_test_pcaps.py`, `make_fill_pcap.py`, `fp_test.py`, `check_sanity.py` and
  `check_readout.py`.

Every run clears all registers first. It reads the port, NIC and TM counters before and
after, instead of resetting them.

## 2. Resources

Whole pipe (12 MAU stages, shared by ingress and egress). The latency figures are the
compiler's estimates in pipeline cycles.

| Program | Stages ig/eg | SRAM | Map RAM | Stateful ALUs | TCAM | Hash bits | Latency ig/eg (cycles) |
|---|---|---|---|---|---|---|---|
| baseline | 1/0 | 1/960 | 0/576 | 0/48 | 0/288 | 10 | 54/168 |
| same parser, no registers | 1/1 | 3 | 2 | 0 | 3 | 10 | 54/170 |
| registers, no CPU reports | 5/1 | 197 | 196 | 14 | 3 | 284 | 129/170 |
| **detector** | 5/1 | 197 (20.5%) | 196 (34.0%) | 14 (29.2%) | 3 | 284 | 131/170 |
| **detector (fixed)** | 5/1 | 197 (20.5%) | 196 (34.0%) | 14 (29.2%) | 3 | 172 | 131/170 |

- **Map RAM is the binding resource.**
  - A 65,536-entry register needs 17 RAMs and 17 map RAMs at 32 bits, 9 at 16 bits and
    5 at 8 bits.
  - A stage has 48 map RAMs, so it holds at most two 32-bit registers.
  - Map-RAM use in stages 0–4 is 85/71/92/90/71%; stages 5–11 are free.
- **Feature registers cost +75 ingress cycles** (54 → 129), and the CPU-report mirror
  +2. The egress latency is padded to about 170 cycles in every build.
- **Flow-table size: 2¹⁶ buckets is the maximum.** At 2¹⁷, the final placement needed
  12 of the 12 ingress stages (13 in one variant), and bf-p4c then crashed with an
  internal compiler error for all three hash variants tried. At 2¹⁸, a 32-bit register
  needs 65 map RAMs in one stage, which does not fit.
- The fix (Section 5.1) changes no resource except the hash bits. The fingerprint
  variant's resources are in Section 5.3.

## 3. Packet rate and loss

RFC 2544 frame sizes (wire, FCS included), one UDP flow per size, tcpreplay at full
speed for 20 s, 5 repetitions. Offered load is PC1's PHY counter.

| Frame (B) | Detector, Mpps median (min–max) | Baseline, Mpps median (min–max) | % of 100G line rate |
|---|---|---|---|
| 64 | 0.359 (0.334–0.369) | 0.359 (0.344–0.374) | 0.24% |
| 128 | 0.354 (0.339–0.371) | 0.368 (0.354–0.373) | 0.42–0.44% |
| 256 | 0.355 (0.345–0.361) | 0.348 (0.330–0.358) | 0.77–0.78% |
| 512 | 0.345 (0.327–0.352) | 0.345 (0.339–0.346) | 1.47% |
| 1024 | 0.333 (0.327–0.338) | 0.329 (0.323–0.337) | 2.75–2.78% |
| 1280 | 0.326 (0.324–0.330) | 0.318 (0.305–0.334) | 3.30–3.39% |
| 1518 | 0.319 (0.298–0.333) | 0.321 (0.299–0.329) | 3.92–3.95% |

- **No loss.** 238,356,035 frames (detector) and 238,398,035 (baseline) crossed the
  switch in 70 runs, with no switch loss, link loss, buffer-full drops or errors.
- **Exact counting under load.** In all 35 detector runs, the flow's `reg_pkts` delta
  equals the switch's received-frame count, and `reg_bytes` matches (mod 2³²).
- **No line-rate claim follows from this test.** Detector and baseline differ by −3.9%
  to +2.5%, with overlapping ranges (sender noise).

### 3.1 Why the measured rate is low

The limit is the sender, PC1:
- **Same rate without the detector.** The forwarding-only baseline reached the same rate
  (0.359 Mpps at 64 B for both).
- **Flat across frame sizes.** The rate falls only from 0.36 Mpps at 64 B to 0.32 Mpps at
  1518 B. Over that range 100G line rate falls from 148.8 to 8.1 Mpps, so a link- or
  switch-bound rate would fall about 18×. A nearly constant packet rate means a fixed
  CPU cost per packet in the sender.
- **Sender saturated.** One of PC1's two vCPUs was at 98–100% in every run, and the
  switch dropped nothing.
- **Why PC1 is slow.** tcpreplay passes every packet to the kernel with its own system
  call, on one thread. PC1 is a KVM guest with 2 vCPUs of a generic emulated CPU
  (`QEMU Virtual CPU version 2.5+`, 2.19 GHz, no AVX).

The systems in Section 7 that report about 100 Gbps used one of:
- DPDK generators on dedicated servers (BoS, Peregrine);
- hardware generators (HorusEye: Spirent N11U; Mousika: Keysight XGS12-SDL);
- the switch's own packet generator (NetWarden, P4Control);
- traffic looped through all switch ports (Planter, IIsy).

## 4. ASIC latency

From the ingress parser to the egress parser, on the ASIC clock: exact minimum, and
p50/p99 from 8 ns histogram bins. Every packet leaving on dev_port 140 is measured:
84 runs and 297,370,084 packets, with the measured count equal to the port counter in
every run and no histogram overflow. Rates: 1000 pkt/s and PC1's full rate, 3
repetitions each.

| Frame (B) | Baseline min / p50 / p99 (ns) | Detector min / p50 / p99 (ns) | Detector cost (Δ min) |
|---|---|---|---|
| 64 | 251 / 252 / 252 | 321 / 324 / 324 | 70 ns |
| 128 | 253 / 252 / 260 | 323 / 324 / 324 | 70 ns |
| 256 | 269 / 268 / 276 | 339 / 340 / 348 | 70 ns |
| 512 | 282 / 284 / 284 | 352 / 356 / 356 | 70 ns |
| 1024 | 307 / 308 / 308 | 377 / 380 / 380 | 70 ns |
| 1280 | 319 / 324 / 324 | 389 / 388 / 396 | 70 ns |
| 1518 | 332 / 332 / 332 | 401 / 404 / 404 | 69 ns |

- **The detector adds a constant 69–70 ns**, at every size and at both rates. That is
  +28% at 64 B and +21% at 1518 B on this interval. The compiler predicted 75 cycles.
- **Deterministic.** p99 is within one bin (8 ns) of p50, and the maximum within 4–19 ns
  of the minimum. There is no load effect at these rates, i.e. no queueing.
- **Frame length** adds about 80 ns from 64 to 1518 B, in both programs alike. That
  comes from the switch, not the P4 program. MAC→egress is a constant 24–25 ns longer
  than parser→egress.
- **After the fix** (Section 5.1), an instrumented copy of the fixed build measures the
  same: 321 / 324 / 324 ns at 64 B and 401 / 404 / 404 ns at 1518 B (Section 5.3).
- **Caveats.**
  - The measured programs carry a 9-byte bridge header inside the switch only.
  - In the detector copy, one table sits one stage later, with an unchanged latency
    estimate.
  - The egress MAU (padded, the same in all builds) and transmission are not covered.

## 5. Flow table

### 5.1 Hash and report fixes

| Problem | Change | Verified |
|---|---|---|
| bf-p4c 9.6.0 drops arithmetic inside a Hash field list. `{sip^dip, sip+dip, sp^dp, sp+dp, pr}` compiled to CRC-16/ARC of the raw 5-tuple, so every connection was split over two buckets and `pkts_ab = pkts`. Materialising the inputs in metadata does not help: the compiler folds them back | `@symmetric("hdr.ipv4.srcAddr", "hdr.ipv4.dstAddr")` and `@symmetric("meta.l4_sport", "meta.l4_dport")` on the Hash, with the raw fields as input. Compiled function: CRC-16/ARC over `(0, sip^dip, 0, sp^dp, proto)` | All 16 index computations equal `flow_index.py` and are symmetric (5000/5000 random tuples each) |
| The CPU report carried only the 5-tuple, so a reader had to recompute the bucket | `cpu_report_t` gets `flow_index`: 18 bytes, new magic `0xBEF1` | Reports on `enp5s0` carry the bucket |
| The first fixed build sent `flow_index = 0`. Register addresses take the hash result straight from the hash unit, and bf-p4c never wrote it into the PHV field the report copied | A second hash instance (`crc16_report_hasher`, same `@symmetric`) assigned directly to the report field. The assembler then writes it (`set H8, hash_dist`) | Reports carry 6886 and 44993 = `flow_index.py` |

On the switch (fixed build), a 100-packet test connection sent in both directions lands
in one bucket (6886):
- pkts 100 = 51 A→B + 49 B→A; bytes 32440 = 24068 + 8372;
- SYN 2, ACK 98, RST 2; lengths 40–1500;
- reference ports 40001→5001; duration 0.990 s.

Each connection or flow sends exactly one CPU report.

### 5.2 Collisions

- **Measured.** With the deployed hash, 30,000 flows filled 23,651 buckets: 39.0% of the
  flows shared a bucket, against 36.7% for a random hash (the Section 6.2 fill).
- **Inherent.** With 65,536 buckets, even a perfect hash leaves 13.8% of 20,000 and
  30.0% of 50,000 concurrent flows without a bucket of their own. Flows that share a
  bucket are merged, and only the first one reports.
- **Hash quality** (offline, `hash_quality.py`, with the compiled function):
  - On uniform random traffic, a horizontal /16 scan, the clients of one server and a
    spoofed SYN flood, the compiled index is within 0.2 points of a random hash.
  - On a vertical port scan it has no collisions at all, because a 16-bit CRC maps any
    single 16-bit field one-to-one.
  - The sequential test flows of Section 6.1 are an unlucky case for this polynomial:
    22.3% of 20,000 flows got no bucket of their own, against 13.8% for a random hash.
  - Other 16-bit polynomials stay within 0.3 points of a random hash on every pattern
    tested, at the same resource cost. One example is 0x8BB7 (CRC-16/T10-DIF,
    reflected). Not deployed.
- **XOR folding.** Flows with equal `sip^dip` and `sp^dp` always share a bucket, whatever
  the hash. In all-to-all traffic inside one /24 on fixed ports (e.g. 137↔137), 98.7% of
  the flows get no bucket of their own.
  - Hashing the min/max of the address pair and of the port pair keeps the index
    symmetric. With polynomial 0x8BB7 that brings this case to 0.0%; with CRC-16/ARC it
    only reaches 64.9%.
  - This likely needs one more pipeline stage, since the hash unit cannot compute
    min/max. Not implemented.
- **Crafted collisions.** The hash is public. For any flow to another port or host,
  exactly one source port puts it into a chosen bucket, so it raises no report and is
  merged. The fingerprint variant (Section 5.3) detects this.
  - With a public fingerprint polynomial, an attacker who controls both ports (e.g. its
    own C2 server) can still solve for a flow that matches both the index and the
    fingerprint.
  - Keeping that polynomial secret would prevent it.

### 5.3 Collision detection with a flow fingerprint (tested on the switch, not deployed)

`perf/variants/fingerprint/` (`fingerprint.patch`, applied by `make_fp_sources.sh`)
adds two registers to the fixed build. Counters still merge; the switch only detects
and reports the sharing.
- **`reg_fp` (16 bits per bucket).** The first packet of a bucket stores a fingerprint
  of its raw 5-tuple (CRC 0x8BB7, reflected). A later packet belongs to the bucket's
  flow if its forward or its reverse fingerprint matches. Both directions of the flow
  match; flows with equal `sip^dip` and `sp^dp` do not.
- **`reg_shared` (8 bits per bucket).** It is set by the first packet of another flow,
  which also sends a CPU report with `reason` 2 and its own 5-tuple. Further foreign
  packets send nothing.

| | Fixed build | With fingerprint |
|---|---|---|
| Ingress stages | 5 | 6 |
| SRAM / map RAM | 197 / 196 | 211 / 210 (map RAM 36.5%) |
| Stateful ALUs | 14 | 16 |
| Hash bits | 172 | 252 |
| PHV, 16-bit containers | 13 | 17 |
| Latency estimate ig/eg (cycles) | 131 / 170 | 131 / 170 |

- **Compile:** bf-p4c 9.6.0, no warnings.
- **Hashes:** `hash_block_identify.py` checked every compiled hash against software.
  The 21 index slices equal `flow_index.py`, and the two fingerprint slices equal the
  forward and reverse CRC.
- **Logic:** in the assembly, the fingerprint test compares the stored value with both
  fingerprints. The collision action writes its report's `flow_index` and takes the
  mirror type from `reg_shared`. Its gateway uses the same encoding as the SYN/ACK/RST
  counters, which were exact on the switch.
- **On the switch** (`fp_test.py`; 145 packets at 100 pkt/s, all forwarded): 14 of 14
  checks passed.

  | Traffic | Expected | Hardware |
  |---|---|---|
  | The Section 5.1 test connection, both directions (bucket 6886) | new-flow report | ✓ |
  | UDP flow between the same hosts, ports chosen into 6886 | collision report with its own 5-tuple | ✓ |
  | A second such flow | nothing (bucket already shared) | ✓ |
  | TCP flow, both directions (bucket 9149) | new-flow report | ✓ |
  | Both its ports XOR-shifted, i.e. equal `sip^dip` and `sp^dp` (same bucket) | collision report | ✓ |
  | Control UDP flow, both directions (bucket 28506) | new-flow report, never shared | ✓ |

  The reverse directions of the flows raised no collisions. `reg_fp` held the
  software fingerprint of each bucket's first packet, `reg_shared` was 1 / 1 / 0 and
  `reg_pkts` was 110 / 15 / 20 (the merged packets included).
- **Latency.** Instrumented copies of both builds were measured back to back with the
  Section 4 method: 64 and 1518 B, at 1000 pkt/s and at PC1's full rate, 3 runs each.
  That is 85.7 million packets, all counted, with no histogram overflow.

  | Frame | Fixed build, min / p50 / p99 (ns) | With fingerprint, min / p50 / p99 (ns) |
  |---|---|---|
  | 64 B | 321 / 324 / 324 | 321 / 324 / 324 |
  | 1518 B | 401 / 404 / 404 | 401 / 404 / 404 |

  The fingerprint adds no measurable latency: at both sizes and rates, the exact
  minimum (1 ns resolution) and the 8 ns histogram percentiles are identical.
  Inside the wrapper both copies use 6 ingress stages. The deployed fingerprint build
  uses one stage more than the fixed build, which the compiler also estimates at no
  extra latency.
- **Placement:** the new registers took spare room in stages 2 and 3 and pushed
  `reg_pkts_ab` into stage 5. The compiler's latency estimate is unchanged.
- **Simulated effect** (random index):

  | Concurrent flows | Never reported, without | Never reported, with fingerprint |
  |---|---|---|
  | 7,300 | 5.4% | 0.23% |
  | 20,000 | 13.9% | 1.4% |
  | 50,000 | 30.1% | 6.7% |

  Every bucket that holds more than one flow is flagged. A reported newcomer becomes
  visible, but its packets still count in the shared bucket.
- **Before use:** the readers of the CPU reports must handle `reason` 2, and `reg_fp`
  and `reg_shared` must be cleared together with the 14 counters.

## 6. Switch CPU side

These two measurements cover the switch CPU and its driver, not the P4 program. The P4
program's part is to mirror one 64-byte report per new bucket.

### 6.1 CPU reports

Fixed build. Each run clears all registers, then PC1 sends K distinct one-packet UDP flows
(64 B) at R new flows/s, with K = min(50,000, 20 s × R). One report is due per distinct
bucket (`flow_index.py`). Reports are counted at the traffic manager (drops towards CPU
port 192), at the switch kernel's `enp5s0` counters, in a raw tcpdump on the switch, and
in a capture over SSH. Three repetitions, with the rates shuffled in each.

| New flows/s | PC1 achieved | Flows | Reports due | Burst | Reports/s in the burst | Reports received, median (range) |
|---|---|---|---|---|---|---|
| 1,000 | 1,001 | 20,000 | 15,532 | 20 s | 777 | 100% (all runs) |
| 5,000 | 5,005 | 50,000 | 34,262 | 10 s | 3,430 | 100% |
| 10,000 | 10,000–10,020 | 50,000 | 34,262 | 5.0 s | 6,852–6,866 | 100% |
| 20,000 | 20,000–20,080 | 50,000 | 34,262 | 2.5 s | 13,705–13,760 | 100% |
| 50,000 | 50,000 | 50,000 | 34,262 | 1.0 s | 34,262 | 100% |
| 100,000 | 96,094–100,001 | 50,000 | 34,262 | 0.50–0.52 s | 65,848–68,525 | 98.4% (91.1–99.6%) |
| 200,000 | 131,543–164,963 | 50,000 | 34,262 | 0.30–0.38 s | 90,139–113,039 | 96.1% (95.8–98.4%) |
| PC1 maximum | 146,596–183,888 | 50,000 | 34,262 | 0.27–0.34 s | 100,454–126,007 | 95.3% (89.3–96.9%) |

- **Every report arrived up to 50,000 new flows/s**, i.e. 34,262 reports in 1 s, in all
  15 runs at those rates. Above that, 0.4–10.7% of the reports were lost.
- **The loss is not in the P4 program or the traffic manager.** The traffic manager
  dropped nothing towards port 192; its queue peaked at 190 cells, about 15 KB. In every
  run, the kernel's `enp5s0` counters and both captures agree exactly, with no kernel,
  socket or tcpdump drops. The missing copies were lost between the ASIC's CPU port and
  the `bf_kpkt` driver (DMA or driver receive ring), where no counter was available.
- **The reports are exact.** Each of the 752,734 reports in the 24 runs carries the
  bucket `flow_index.py` computes for its 5-tuple. None was duplicated or came from an
  unexpected bucket.
- **Conservative setup.** Two captures ran at once on the switch CPU. Bursts above 20,000
  new flows/s lasted at most 1 s, because one run cannot use more than the 65,536
  buckets.

### 6.2 Register readout

The control plane reads only the buckets named by CPU reports. Measured with 30,000 flows
in the registers (23,651 buckets). All methods returned the expected values for all
14 registers × 65,536 buckets in every repetition.

| Method (on the switch CPU) | Per cell | Per flow (14 registers) | 5,000 flows |
|---|---|---|---|
| Per-cell hardware read (`from_hw=True`) | 99–101 µs | 1.40 ms | 7.05 s |
| Register sync (37–40 ms for all 14) + reads from the shadow copy | 81.6 µs | 1.14 ms | 5.71 s |
| gRPC, batched keys (SDE Python 2.7 client, bound) | 293–323 µs | ≈ 4.4 ms | 22.6 s |

- A scripted bfshell session costs 1.39–1.50 s before any read.
- That allows about 7,300 flows per 10 s window with one session per window, and 8,700
  with one persistent session. Fewer registers per flow scale these up linearly.
- Whole-table reads take 62 s from hardware, 55 s via sync, and 245 s with the gRPC
  Python 2.7 client. The per-call software cost on the switch CPU dominates; the hardware
  sync itself takes 2–3 ms per register.

## 7. Comparison with published P4 systems

Hardware cost and performance as reported in 22 papers on P4 security systems and
in-network ML, read on 27 October 2026. Every value comes from the paper's text; "derived"
values were computed from it. n.r. = not reported. Detection accuracy is not compared.
Percentages are as printed. Most papers do not say whether they are per pipe or for the
whole chip; ours are per pipe.

**Where this work stands:**
- **Latency.** NetWarden (+3–101 ns) and P4Control (+100–110 ns) are the only systems
  that report an overhead over forwarding, and this work's +70 ns lies in that range.
  The others report absolute times of 365 ns to 2 µs, over different intervals. Here it
  is 321–404 ns from ingress parser to egress parser.
- **Stages.** This work uses 5. Every system with per-flow state that reports its stages
  uses 9–12; Peregrine uses 12 in one pipe and 11 in the other. Only the stateless
  per-packet models use fewer.
- **Memory.**
  - SRAM is 20.5%, against 7–39% for the systems with per-flow state. FlowLens and
    Peregrine, the closest designs (features in the switch, decision elsewhere), use
    37–39%.
  - TCAM at 1% is among the lowest.
  - The 45 B per flow lie between FlowLens's 20–302 B and the 4–20 B of designs that keep
    only what their in-switch model needs.
- **Stateful ALUs.** This work uses 14 of 48 (29.2%). Only iGuard (19.62%), Peregrine
  (meter ALU 72.9% in pipe 0) and P4Control (meter ALU 2.1%) report theirs.
- **Flows.**
  - This work tracks 65,536, as NetBeacon, BoS and Flowrest do.
  - NetWarden, P4Control and P4-DGA are sized for 110,000–220,000.
  - Leo, SpliDT and Pegasus size for 1M without testing that many.
- **Throughput.** The others measured up to about 100 Gbps per port (HorusEye, NetBeacon,
  BoS, Mousika, NetWarden, P4Control), or 6.4 Tbps with traffic looped through all ports
  (Planter, IIsy). This evaluation reached 0.37 Mpps (Section 3.1).

| System | Venue | Switch | In the switch | Flows (state per flow) | Stages | SRAM / TCAM | Stateful ALUs | Latency | Throughput |
|---|---|---|---|---|---|---|---|---|---|
| **This work** | – | Tofino 1, Wedge100BF-32X | per-flow features; detection off the switch | 65,536 (45 B) | 5 ingress | 20.5% / 1.0% | 14 of 48 (29.2%) | +70 ns over forwarding (ASIC timestamps); 321–404 ns parser to egress parser | no loss up to 0.37 Mpps (PC1-bound) |
| FlowLens | NDSS 2021 | Tofino (compiled; no hardware traffic test) | packet-length and inter-arrival histograms; switch CPU classifies | n.r. (NDA); 20–302 B | n.r. | 38.54% / 0.00% (stage average) | n.r. | n.r. | n.r. (line speed claimed) |
| Peregrine | arXiv 2024 | Tofino 1, Wedge 100BF-32X | ~100 features, records to a server | n.r. | 100% / 91.7% of pipes 0 / 1 | 37.2% + 6.4% / 6.9% + 9.7% | meter ALU 72.9% / 6.9% | n.r. | end to end at 100G (DPDK pktgen); 6.4 Tbps from compile |
| HorusEye | USENIX Sec 2023 | Tofino, H3C S9830-32H-H | burst features + iForest whitelist; autoencoder on a GPU decides | 32,000–64,000 (design analysis) | 9 (derived) | 9.90% / 2.78% | n.r. | 1027–1142 ns per packet (Spirent) | 100G on one port, zero loss (Spirent N11U) |
| NetBeacon | USENIX Sec 2023 | Tofino 1 | features + multi-phase trees | 65,536 | 9–12 | 11.11–17.29% / 1.85–34.03% | n.r. | n.r. | 99.12–99.18 Gbps on one port |
| BoS | NSDI 2024 | Tofino 1, Wedge 100BF-32X | features + binary RNN; ≤ 5% of flows to a GPU server | 65,536 | 12 ingress + 10 egress (derived, Fig. 8) | 18.33–23.44% / 0.69–1.74% | n.r. | n.r. | 100 Gbps aggregate (DPDK pktgen); 1.6 Tbps simulated |
| iGuard | CoNEXT 2024 | Tofino 1, Edgecore 32X | features + iForest rules | n.r. | 12 | 11.51% / 13.34% | 19.62% | 532.8 ns (method n.r.) | 39.6 Gbps on a 40G link (tcpreplay) |
| Leo | NSDI 2024 | compile (SDE 9.11.1); latency on a Wedge-100BF-32x | features + runtime-programmable tree | 1.04M (7 B), provisioned | tree only, depth 10: ≈ 6–11 | table entries only | n.r. | ≈ 500 ns incl. L2 forwarding (switch timestamps) | n.r. (line rate claimed) |
| Flowrest | INFOCOM 2023, ToN 2025 | Tofino 1, Wedge100BF-QS | features + random forest | 65,536 (default) | n.r. | bar charts only (< 15% on average) | n.r. | 364.75–436.07 ns (compiler estimate + measured 98 ns offset) | n.r. (line rate claimed) |
| Jewel | INFOCOM 2024 | Tofino 1, Wedge 100BF-QS | features + joint packet/flow forest | n.r. | n.r. | relative only | n.r. | n.r. | n.r. |
| SpliDT | NSDI 2026 | Tofino 1, Wedge 100-32X | windowed features + partitioned trees (recirculation) | 100K–1M (4–20 B of feature registers) | all 12 allocated | TCAM 174–587 entries | n.r. | n.r. | n.r. |
| Pegasus | SIGCOMM 2025 | Tofino 2 | features + deep learning | 1M (sizing); 44–48 bits | n.r. | 7.12% / 13.33% | n.r. | n.r. | n.r. (argued) |
| P4-DGA | Computers & Security 2024 | Tofino (model n.r.) | DNS inspection + per-host features + forest (DGA malware) | ≈ 110,000 hosts | n.r. | n.r. | n.r. | 1–2 µs incl. inspection and recirculation | n.r. |
| NetWarden | USENIX Sec 2020 | Wedge 100BF-32X | covert-channel defence | 200K connections (compile) | n.r. | n.r. | n.r. | +3–101 ns over forwarding | 99.98 Gbps per port (on-switch generator) |
| P4Control | IEEE S&P 2024 | Tofino 1, Wedge 100BF-32X; with host eBPF | information-flow control (prevention) | > 220K connections (compile) | n.r. | 26% / 25% | meter ALU 2.1% | +100–110 ns over forwarding | 99.9 Gbps (on-switch generator) |
| Jaqen | USENIX Sec 2021 | Tofino | DDoS sketches + mitigation; controller detects | sketches; tested with 1,048,576 connections | n.r. | normalized only | n.r. | no µs-level change | 380 Gbps aggregate (MoonGen) |
| Poseidon | NDSS 2020 | Tofino | DDoS primitives; detection outside | n.r. | 1–3 per primitive | formulas | 0–6 per primitive | "hundreds of ns" end to end | ≤ 40 Gbps measured |
| Mousika | INFOCOM 2022 | Tofino, Wedge 100BF-65X | per-packet tree, no flow state | – | 2 | 0.2% / 1.7% | n.r. | 466 ns at 100 Gbps (method n.r.) | 40 and 100 Gbps, zero loss (Keysight XGS12) |
| Planter | CCR 2024 | Tofino, APS BF6064X | per-packet models | – | 2–4 | memory 1.18–3.94% | n.r. | 39–46% of switch.p4 (NDA) | 6.4 Tbps (snake) |
| IIsy | ToN 2024 | Tofino, 64×100G | per-packet models + backend | – | 2–3 | memory 1.11–1.89% | n.r. | 29–36% of switch.p4 | 6.4 Tbps (snake) |

Not on Tofino: pForest (BMv2 and simulation; only its basic operations were checked on
a Tofino), SwitchTree (BMv2 only), and IIsy's HotNets 2019 version (NetFPGA).

- **What the numbers are.** Most of these systems run a model in the switch, so their
  stages and memory include it. Several values come from compiling or sizing, not from
  traffic: FlowLens, Leo, SpliDT and Pegasus, and the connection counts of NetWarden and
  P4Control.
- **Scope.** Only P4-DGA targets malware itself; the others target malicious traffic,
  botnets, intrusions or DDoS.

Sources:
- FlowLens: ndss-symposium.org/wp-content/uploads/ndss2021_7C-2_24067_paper.pdf
- Peregrine: arXiv:2403.18788. No peer-reviewed full version was found; there is a
  SIGCOMM 2023 poster.
- HorusEye: usenix.org/system/files/usenixsecurity23-dong-yutao.pdf
- NetBeacon: usenix.org/system/files/usenixsecurity23-zhou-guangmeng.pdf
- BoS: usenix.org/system/files/nsdi24-yan.pdf
- iGuard: conferences.sigcomm.org/co-next/2024/files/papers/p55.pdf
- Leo: usenix.org/system/files/nsdi24-jafri.pdf
- Flowrest: doi:10.1109/INFOCOM53939.2023.10229100 and doi:10.1109/TON.2025.3564465
- Jewel: doi:10.1109/INFOCOM52122.2024.10621365
- SpliDT: usenix.org/system/files/nsdi26-parvez.pdf
- Pegasus: doi:10.1145/3718958.3750529 (read as arXiv:2506.05779)
- P4-DGA: doi:10.1016/j.cose.2024.104007
- NetWarden: usenix.org/system/files/sec20-xing.pdf
- P4Control: doi:10.1109/SP54263.2024.00147 (read as arXiv:2405.14970)
- Jaqen: usenix.org/system/files/sec21-liu-zaoxing.pdf
- Poseidon: ndss-symposium.org/wp-content/uploads/2020/02/24007-paper.pdf
- Mousika: doi:10.1109/INFOCOM48880.2022.9796936
- Planter: doi:10.1145/3687230.3687232
- IIsy: doi:10.1109/TNET.2024.3364757 and doi:10.1145/3365609.3365864
- pForest: arXiv:1909.05680
- SwitchTree: doi:10.1007/s00521-020-05440-2 (read as HAL preprint hal-02968593)

## 8. Notes for the paper

**Strong as is:**
- The latency overhead is measured as a delta over a forwarding-only build, on the ASIC
  clock, with the method stated (Section 4). Only NetWarden and P4Control report a delta,
  and neither describes its method.
- The stage count is the lowest of the systems in Section 7 that keep per-flow state and
  report their stages.
- Counting is exact under load (Section 3). The compiled hash matches software bit for
  bit, so the offline collision numbers of Section 5.2 hold for the switch.

**Open: line rate.** Section 3 reaches only 0.37 Mpps, while the systems in Section 7
measured up to 100 Gbps per port. NetWarden and P4Control did so on the same switch model
with the switch's own packet generator ("software packet generators cannot saturate the
switch linespeed", NetWarden). The test, not yet done or approved:
- **Wrapper:** like `perf/variants/lat/`, it parses the packet generator's header on its
  internal port and then runs the unchanged detector. The SDE includes an example
  (`p4-examples/p4_16_programs/tna_pktgen`).
- **Traffic:** 64 B and 1518 B packets at 100G, generated inside the switch and sent
  through the detector and out of a 100G port.
- **Pass criterion:** generated count = the detector's register count = transmitted
  count, with zero drops.

Optional:
- the same test with every packet a new flow, so that the CPU reports overflow, to show
  that forwarding is unaffected;
- resources against flow-table size (2¹² to 2¹⁶ buckets), compile only.

**Likely reviewer questions:**
- **Collisions.** Flowrest, Jewel and BoS keep a 32-bit flow ID in each bucket. The
  deployed build keeps none; the fingerprint variant (Section 5.3) adds a 16-bit one, at
  no measured latency.
- **Scale.** 45 B per flow and 65,536 flows, the largest table that compiles. NetBeacon,
  BoS and Flowrest also use 65,536 flows. Leo, SpliDT and Pegasus size for 1M with 4–20 B
  per flow, but do not test that many.

**Not worth the time:**
- iperf3 and ping, which measure PC1;
- more latency runs;
- a collision sweep on the switch.

**For a 6-page paper:**
- the resource table (Section 2);
- latency per frame size (Section 4);
- the line-rate result;
- 6–8 rows of the comparison table (Section 7).

Section 6 measures the switch CPU, not the P4 program, and can be left out.

## 9. Limitations

- **Throughput** was measured only up to PC1's limit (≤ 4% of line rate; Section 3.1).
- **Latency** covers ingress parser to egress parser in instrumented copies, without
  queueing.
- **Timestamps** are 32-bit nanoseconds, so durations of flows longer than 4.295 s alias.
  `first_ts` is also re-stamped if a first packet's timestamp has its low 32 bits all
  zero (once in 2³² ns).
- **Multiple pipes:** registers are per pipe. A flow whose two directions enter on ports
  of different pipes is counted in two register copies, and its direction split is not
  meaningful.
- **Parser semantics:**
  - L4 ports are always read at frame offset 34, since IHL is ignored, so IPv4 options
    shift them.
  - There is no VLAN parsing.
  - Non-first IPv4 fragments are parsed as TCP/UDP.
  - Flows with `sp == dp` always count as A→B.
- **`enp5s0`** must be up on the switch for reports; switchd restarts bring it down.
- **Not measured:**
  - line rate (Section 8);
  - TCP/UDP throughput with iperf3 and RTT with ping, which would measure PC1;
  - the collision rate on the switch over several flow counts. One point was measured
    (Section 5.2); the other numbers are offline, with the verified compiled hash.

## 10. Reproducing the measurements

Run these from the repository root on PC1.
- The tools are in `perf/tools/`.
- The `sw_*` tools run on the switch from `/root/hazim_perf/tools/` (copy them with
  `scp perf/tools/sw_* root@172.168.1.2:/root/hazim_perf/tools/`).
- `ASROOT` names a wrapper that runs one command as root; tcpreplay needs it.
- `logrun.sh` and `swrun.sh` keep one log per command and an `INDEX.tsv` in the run
  directory.

| Step | Commands |
|---|---|
| Compile (switch) | `sw_compile.sh SRC_DIR basic.p4 /root/hazim_perf/build/VARIANT [-DP4_ENABLE_…=0]`; then on PC1 `parse_resources.py OUT_PREFIX BUILD_DIR…` and `hash_matrix_check.py BUILD_DIR` |
| Load (switch) | `sw_switchd.sh start /root/hazim_perf/build/VARIANT/basic.conf LOG_DIR`, then `sw_switchd.sh safety` |
| Ports, forwarding, mirror | `run_bfrt.sh RUN_DIR LABEL setup --prog basic --ports 132,140 --fwd 132:140,140:132 --mirror-sid 1` |
| Port map, sanity | `make_test_pcaps.py portmap\|sanity OUT_DIR`, replay, `run_bfrt.sh RUN_DIR LABEL read-regs --prog basic --idx …`, `check_sanity.py EXPECTED READ` |
| 3 (packet rate) | `run_pktrate.py RUN_DIR --prog basic --regs`, then `--prog baseline` |
| 4 (latency) | sources from `perf/variants/lat/make_lat_sources.sh`; `run_lat.py RUN_DIR --prog basic_lat`, then `--prog baseline_lat` |
| 5.2 (hash quality, offline) | `hash_quality.py [--sizes 20000,50000]` |
| 5.3 (fingerprint build) | `perf/variants/fingerprint/make_fp_sources.sh thesis-hybrid-ebpf-p4 OUT_DIR`, compile as above, `hash_block_identify.py BUILD_DIR` |
| 5.3 (on the switch) | `fp_test.py make OUT_DIR SANITY_PCAP`; clear with `clear-regs --extra-registers reg_fp,reg_shared`; replay at 100 pkt/s while capturing `enp5s0`; `read-regs … --extra-registers reg_fp,reg_shared`; `fp_test.py check` |
| 5.3 (latency) | `make_lat_sources.sh` on both source trees (main files renamed `basic_fix_lat.p4`, `basic_fp_lat.p4`); `run_lat.py RUN_DIR --prog basic_fix_lat --sizes 64,1518`, then `--prog basic_fp_lat` |
| 6.1 (CPU reports) | `ip link set enp5s0 up` on the switch; `run_report_capacity.py RUN_DIR` |
| 6.2 (readout) | `make_fill_pcap.py RUN_DIR/pcap --flows 30000`; replay at 10,000 pkt/s; `run_bfrt.sh RUN_DIR LABEL readout --out-dir SWITCH_DIR --label rN`; `check_readout.py RUN_DIR`. gRPC: `python2.7 sw_grpc_readout.py OUT.json.gz --prog basic --from-hw 1 --bind 1` on the switch |

`make_test_pcaps.py sanity` predicts the buckets of the deployed hash, of the old
collector's function and of the fixed hash ("symfix"). `make_fill_pcap.py` predicts only
the deployed hash. On the fixed build, compute the buckets with `flow_index.py` instead.

Notes on the switch:
- **bfshell safety.**
  - In Phase 0, one `bfshell -h` call stopped another project's `bf_switchd`. This SDE's
    bfshell connects even on an unknown option. Its disconnect hung up the PTY that had
    become the controlling terminal of that switchd, which had been launched in a new
    session (`setsid`) and has no SIGHUP handler. That switchd is still down.
  - Ours runs under `nohup` in a tmux pane (`sw_switchd.sh`).
  - Before every scripted session, the tools check that it ignores SIGHUP and is not a
    session leader (`sw_switchd.sh safety`).
- **`run_bfshell.sh` waits 300 s here:** its readiness check asks `localhost`, which does
  not resolve on the switch. `sw_switchd.sh ready` checks 127.0.0.1:7777 instead.
- `bfshell -b` needs its stdin held open (`sw_bfshell_b.py`, `bfshell_run.py`).
- bfrt_python runs scripts with separate globals and locals, so all helpers go inside one
  function.
- gRPC reads need a client bound to the program, at `127.0.0.1:50052`.

## 11. Raw data

Raw data is in `perf/results/` on PC1, one directory per run. Each run directory holds
one log per command and an `INDEX.tsv`. Most also have a README with more detail.
Section 6.1 has `summary.md`, `results.jsonl` and `console.log` instead. The Phase 0
notes are in `DISCOVERY.md` and `INCIDENT_bf_switchd_exit.md`.

| Section | Run directory |
|---|---|
| 1, and the Phase 0 incident (Section 10) | `p0_discovery_20261026_121125` (`INCIDENT_bf_switchd_exit.md`), `p0_pc1_setup_20261026_124753`, `p0_resume_20261026_140734` |
| 2 | `p1_compile_20261026_141824` |
| Port map, register sanity (deployed build) | `p2_bringup_20261026_144700` |
| 3 | `p2_3_pktrate_20261026_150840` |
| 4 | `p2_5_lat_compile_20261026_154902` (design, builds), `p2_5_lat_20261026_155720` |
| 5.1 and Appendix A (patch, files before and after, builds, hash checks) | `fix_20261026_174315` |
| 5.1 and Appendix A.2 (validation on the switch) | `fix_hwval_20261026_190643` |
| 5.3 (sources, builds, resources, hash check, switch test) | `fp_20261026_201808` |
| 5.3 latency | `fp_lat_20261026_204335` |
| 6.1, and clear and re-report | `p3_3_reports_20261026_192142` |
| 6.2 | `p3_readout_20261026_164647` |

The `*_smoke_*` directories hold short checks of the tools before each test.

## Appendix A. Changes outside the P4 program

### A.1 Collector and scripts (`thesis-hybrid-ebpf-p4/python`, `hybrid_collector.py`)

| Problem | Change |
|---|---|
| Five scripts had five different index functions (CCITT, MODBUS, ARC over the raw tuple, ARC over the symmetric blob); none matched the switch | One `flow_index.py`, used by `listen_cpu_reports.py`, `replay_pcaps_with_index.py`, `send.py`, `hash_idx.py` and `commands.txt` |
| `listen_cpu_reports.py` recomputed the index, needed Python ≥ 3.9 and scapy | Uses the report's `flow_index` (old `0xBEEF` reports still parse); `ReportCollector` captures in the background, locally (scapy) or on the switch over SSH (`tcpdump -w -`, no Python packages on the switch); runs on Python 3.8 |
| `read_registers_with_index.py` could not run on SDE 9.6: its bfrt_python script used f-strings and top-level helpers (Python 3.4, separate globals/locals) | Rewritten embedded script: Python 3.4 syntax, closures, ordered JSON (3.4 dicts are unordered) |
| It read only pipe 0 (the test ports are in pipe 1, so all zeros), returned 0 for 8 registers that do not exist, and read the 14 registers at different instants | Reads every pipe and combines them (`multi_pipe` flag); only the 14 real registers, with `pkts_ba`, `bytes_ba` and `duration_ns` derived; `--snapshot sync` (default) reads one consistent copy |
| `bfshell -b` without a terminal disconnects before its script runs, silently doing nothing | `bfshell_run.py` keeps bfshell's stdin open; used by the reader and `program_forwarding.py`, locally or over SSH (`--ssh`), with a check that switchd survives a CLI disconnect |
| `hybrid_collector.py` read all windows only after the workload ended, so every window saw the final counters | Live windows: reports are captured in the background and the active buckets are read at the end of every window |
| An index left the active set 5 windows after its single report, even while the flow kept sending | An index stays active while its packet counter changes |
| Registers were never cleared: after N distinct flows, a new flow got a report with probability about e^(−N/65536); the rest merged silently into old buckets | `--clear-idle-windows` (default 3): a bucket unchanged for 3 reads is cleared right after its read (only if still unchanged, same session), and the collector restarts its delta baseline. On the switch, a cleared bucket re-reported the same flow and counted from zero |
| The report port was never passed to `program_forwarding.py` (on hardware the mirror would point to dev_port 2); index 0 was dropped; durations were dropped when the 32-bit timestamp wrapped | `--forward-report-port`, `--mirror-sid`, `--switch-ssh`, `--p4-snapshot`, `--active-ttl-windows`; index 0 kept; duration `(last_ts − first_ts) mod 2³²` |
| `commands.txt`: the clear list missed 9 registers and named a non-existent `reg_fin`; its hash snippets used CRC-16/MODBUS | All 14 registers; the shared index function |

23 unit tests (`cd thesis-hybrid-ebpf-p4/python && python3 -m unittest discover -s tests`)
cover:
- the CRC-16/ARC check value, symmetry, and a vector from the compiled hash;
- both report formats and the tcpdump stream parser;
- the reader's embedded script, run with SDE 9.6 semantics (no f-strings, separate
  globals/locals);
- pipe combining, the sync fallback, clearing, and bfshell's held-open stdin;
- live window deltas, active-index refresh, idle clearing and the timestamp wrap.

### A.2 Validation on the switch (fixed build, fixed scripts over SSH)

| Check | Result |
|---|---|
| `program_forwarding.py --ssh … --int-port 132 --ext-port 140 --report-port 192` | `[OK] Forwarding + mirroring programmed` |
| Test connection and CPU reports | As in Section 5.1 |
| Reader over SSH on the Section 6.2 fill (deployed build, read-only) | 45/45 buckets equal the expected values; sync 45 ms, 95 ms in total |
| Clear and re-report (bucket 42639, a 5-packet UDP flow) | Sent twice: one report, `pkts` 10. Read with `--clear-if-unchanged 42639:10`: cleared, then read zero (`dir_valid` 0). Sent again: a new report, `pkts` 5 |

### A.3 Running it on the NETLAB switch

```sh
# on the switch, once per switchd start (bf_kpkt recreates the interface down):
ip link set enp5s0 up
# on the collector host:
sudo python3 hybrid_collector.py --mode pcap ... \
	--switch-ssh root@172.168.1.2 \
	--forward-int-port 132 --forward-ext-port 140 \
	--forward-report-port 192 --cpu-iface enp5s0
```

## Appendix B. Errata

- An earlier note claimed the collector's `crc16_tofino()` is not CRC-16/ARC. It is: it
  reflects every input byte and the result. The mismatch was only the input (symmetric
  blob vs raw 5-tuple).
- The Phase 2.1 note named bucket 48121 as the collector's choice for the test
  connection. It is 31246, computed with a corrected copy of the function. That bucket
  was empty too, so the conclusion is unchanged.
