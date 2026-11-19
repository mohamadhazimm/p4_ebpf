# P4 data plane on the Tofino: hardware performance

This document reports the hardware evaluation of the P4 half of the hybrid P4/eBPF
malware detector (`thesis-hybrid-ebpf-p4`) on the NETLAB Tofino, 26–29 October 2026. It
covers:
- the P4 program's resources, packet rate, latency and flow table;
- the problems found in the program, and their fixes;
- a comparison with published P4 systems;
- what is still missing for a paper.

The eBPF side runs on a separate server and is analysed separately. Detection accuracy
is evaluated elsewhere. Raw data (per-command logs, P4 builds, pcaps, register dumps)
stays in `perf/results/` on PC1 and is not tracked by git (Section 11).

## Summary

- **Line rate, no loss, exact counting.** With the switch's own packet generator, the
  detector forwarded 99.9% of 100G line rate at 128–1518 B in every run, with no loss,
  and its per-flow counters matched every packet: 13.1 billion packets in 27 runs. Fed
  up to 150% of a port's line rate, it still counted every packet; only the 100G output
  port dropped the excess. At 64 B the generator tops out at 91% of line rate. The
  forwarding-only baseline behaves identically (Section 3.2). PC1 alone reaches only
  0.37 Mpps (Section 3).
- **Latency.** The detector adds a constant 69–70 ns over a forwarding-only program at
  every frame size (ingress parser to egress parser, ASIC clock). p99 stays within 8 ns
  of the median (Section 4). With the per-packet report method of the DNS water-torture
  detector (`reference_evaluation/P4_Code`), the current build adds 91 ns (337 vs
  246 ns), against that detector's 181 ns (Section 4.1).
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
- **New-connection counter (working tree, not deployed).** `reg_newconn_dst` counts TCP
  SYNs without ACK per client, server and server port, against connection floods. With
  65,536 buckets, as specified, the compiler spreads the program over 7 ingress stages
  (+27 cycles estimated); with 16,384 buckets it fits the existing 5 stages at an
  unchanged estimate. Both passed 12 of 12 checks on the switch, and the offline
  reconstruction gives the same counts (Section 5.4).
- **Compared with 20 systems published with Tofino results** (Section 7):
  - the latency overhead is in the range of the only two systems that report one;
  - the stage count is the lowest of the systems that keep per-flow state (5, or 7
    with Section 5.4's counter, against 9–12);
  - SRAM use is mid-range.

  Throughput is on par: 99.9% of line rate on a 100G port, measured like NetWarden and
  P4Control with the switch's own packet generator.
- **Still open:** the Section 4.1 runs on the reference's own path (collector on PC2),
  and 64-B line rate, which needs an external generator (Section 8).

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
- **new-conn**: the fixed build plus the per-destination new-connection counter, as in
  the working tree since 27 October; **new-conn 16k** with 16,384 instead of 65,536
  destination buckets (Section 5.4).
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
  to +2.5%, with overlapping ranges (sender noise). Section 3.2 measures line rate with
  the switch's own packet generator.

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

### 3.2 Line rate with the switch's packet generator (29 October)

The generator of pipe 1 sends one UDP flow back to back, inside the switch. Its 6-byte
header takes the place of the destination MAC, which the detector never reads, so the
programs run unchanged: the working-tree detector (with Section 5.4's counter, 7 ingress
stages) and the forwarding-only baseline. The only addition is a forwarding entry from
the generator's port to 16/0. That port (pipe 0, no cable) runs at 100G in MAC near-end
loopback, so nothing leaves the switch: its TX counter gives the rate, and the
looped-back copies are counted again in pipe 0 and dropped there.
- **Paced:** each timer tick (about 4 µs) sends a burst, 99.9% of line rate on average;
  3 runs per size, 10 s measured each.
- **Saturating:** the generator at its maximum, 1 run per size.
- **Checked in every run:** the generator's packet count, the sink's TX and RX counters,
  the TM's drops at the sink, and the flow's `reg_pkts` and `reg_bytes` in both pipes.

| Frame (B) | 100G line rate (Mpps) | Paced, detector | Paced, baseline | Saturating: offered / sent |
|---|---|---|---|---|
| 64 | 148.81 | 91.09% (generator maximum) | 91.09% | – |
| 128 | 84.46 | 99.88% | 99.88% | 111% / 100.00% |
| 256 | 45.29 | 99.89% | 99.89% | 128% / 100.00% |
| 512 | 23.50 | 99.87% | 99.87% | 140% / 100.00% |
| 1024 | 11.97 | 99.89% | 99.89% | 148% / 100.00% |
| 1280 | 9.62 | 99.88% | 99.88% | 149% / 100.00% |
| 1518 | 8.13 | 99.88% | 99.88% | 150% / 100.00% |

Percentages are of the 100G line rate (L1: 20 B of preamble and gap per frame), so 99.88%
at 1518 B is 99.88 Gbps. The 3 paced runs of each size agree within 0.01 points, and the
saturating runs are the same for both programs.
- **Line rate with no loss.** In every paced run and at 64 B, generated = transmitted =
  received, and the TM dropped nothing.
- **Exact counting at line rate.** In all 27 detector runs, the flow's `reg_pkts` in
  pipe 1 grew by exactly the generated count and `reg_bytes` by the generated bytes
  (mod 2³²); pipe 0 counted exactly the looped-back copies. That is 13.1 billion packets.
- **Beyond line rate.** At its maximum, the generator offers 111–150% of one port's line
  rate. The sink then sends 100.00%, the TM drops exactly the rest, and the detector's
  pipe-1 counters still equal the generated count: up to 93.8 Mpps (128 B) and 150 Gbps
  (1518 B) went through its pipeline.
- **No cost over forwarding:** the baseline's rates are the same within 0.01 points.
- **64 B:** one pipe's generator tops out at 135.5 Mpps, 91% of line rate; two generator
  apps give the same total. Both programs were lossless and exact at that rate. 100% at
  64 B needs an external generator.
- **Limits:** one flow, since the generator cannot vary header fields; one CPU report per
  run. bfrt_python cannot reach the generator in SDE 9.6, so `perf/tools/sw_pktgen_run.py`
  uses BF Runtime gRPC, as the SDE's `tna_pktgen` test does.

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

### 4.1 With the method of the DNS water-torture detector (29 October)

The DNS water-torture detector of `reference_evaluation/P4_Code` was measured with
per-packet reports. That method is applied here unchanged:
- **In the program** (`perf/variants/hwl/`, generated from the unmodified sources):
  ingress writes `ig_prsr_md.global_tstamp` into an 8-byte bridge header; egress inserts
  the package's 20-byte `HWL1` report (ingress and egress-parser timestamps) after the
  Ethernet header of IPv4/UDP packets and sets EtherType 0x88BC. CPU reports skip the
  bridge parse.
- **PC side**, the package's scripts unchanged: `send_probes.py` (82-byte DNS queries,
  1010 per run, 100 pkt/s) and `collect_reports.py` (checks that every probe arrived
  unchanged; 10 warm-up probes excluded). 3 runs per program.
- **Builds:** the working tree (with Section 5.4's counter) and the forwarding-only
  baseline, both with the instrumentation. It leaves the detector's ingress unchanged
  (7 stages, 158-cycle estimate) and adds one egress stage.

| Program | min | median | mean | p99 | max (ns) |
|---|---|---|---|---|---|
| Baseline | 244 | 246 | 245.6 | 247 | 247–248 |
| Detector | 336 | 337 | 337.5 | 341 | 342 |
| DNS water-torture detector: its baseline (reference) | 256 | 258 | 257.7 | 261 | 262–263 |
| DNS water-torture detector (reference) | 437 | 439 | 438.7 | 441 | 442 |

- **The detector adds 91 ns** (median 337 vs 246 ns); the DNS water-torture detector adds
  181 ns over its own baseline. Both show the same 4–6 ns spread at 100 pkt/s.
- **Not like for like:** the DNS detector parses query names and runs its random forest
  in the switch; this detector extracts features and leaves the decision to the model.
- **Against Section 4:** the build without Section 5.4's counter measured +70 ns there.
  The counter's 2 extra ingress stages (+27 cycles estimated) likely explain most of the
  difference; this was not measured separately.
- **All 6 runs:** 1010 of 1010 reports, none malformed or missing. The first probe of each
  detector run sent one correct CPU report.
- **Path:** PC1 → 1/0 → switch → 1/0 → PC1, reports captured on PC1 and decoded with
  `collect_reports.py --pcap`. The reference used PC1 → 1/0 → switch → 2/0 → PC2. The
  egress port lies outside the measured interval; the runs on the reference's path,
  with the collector on PC2, are still to be done.

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

### 5.4 New connections per destination (working tree, tested on the switch, not deployed)

Specified in `thesis-hybrid-ebpf-p4/P4_new_conn_rate_feature.md` (27 October). `reg_syn`
counts per flow bucket, so a connection flood (thousands of 5-tuples from one client to
one service, e.g. GoldenEye) leaves about one SYN in each bucket. The new register counts
per destination instead:
- **`reg_newconn_dst` (32 bits).** Every TCP segment with SYN set and ACK clear adds 1.
  SYN+ACK, which `reg_syn` also counts, does not.
- **Its own index, `crc16_dsthash`:** CRC16 over `{srcAddr, dstAddr, l4_dport, protocol}`,
  without the source port and without `@symmetric`. All connections of one client to one
  service port share a bucket; the index is directional.
- **Control plane.** The index is not in the CPU report. The collector derives it from
  each TCP report's 5-tuple (`flow_index.compute_newconn_dst_index()`) and reads those
  buckets in the same session as the flow buckets (`read_registers_with_index.py
  --dst-indexes`). The register is never cleared. The window feature
  `net_new_conn_dst_max` is the largest increase of one bucket since its previous read;
  `analyze_p4_pcap_ablation.py` computes it offline (Appendix A.4).

| | Fixed build | 65,536 buckets (as specified) | 16,384 buckets |
|---|---|---|---|
| Ingress stages | 5 | 7 | 5 |
| SRAM / map RAM | 197 / 196 | 214 / 213 (map RAM 37.0%) | 202 / 201 (34.9%) |
| Stateful ALUs | 14 | 15 | 15 |
| Hash bits | 172 | 252 | 186 |
| Latency estimate ig/eg (cycles) | 131 / 170 | 158 / 170 | 131 / 170 |
| Power estimate, ingress (W) | 7.49 | 8.12 | 7.88 |

- **Compile:** bf-p4c 9.6.0, no warnings.
- **Placement as specified.** At 32 bits, 65,536 entries need 17 map RAMs, and none of
  stages 0–4 has that many free (Section 2). The compiler put the register into stage 1,
  next to its hash, and moved 8 flow registers one or two stages later. They now span
  stages 0–6 with stage 3 almost empty, although the dependency chain is still 4 stages.
  Pinning the update to stage 5 (`@stage(5)` on a table) gave 8 ingress stages.
- **16,384 buckets** (14-bit index: the low 14 bits of the same CRC) need 5 map RAMs. The
  register goes into stage 0 (46 of 48 map RAMs), and no other register moves.
- **Decision (27 October): 65,536 for now.** 16,384 stays the option if the two extra stages
  matter; the spec (`P4_new_conn_rate_feature.md`, Section 5) carries the same note.
- **Hashes:** in the 65,536 build, `hash_block_identify.py` matched the new stage-1 slice
  to `compute_newconn_dst_index()` on 5,000 of 5,000 random tuples (inputs: exactly the
  four fields), and the 20 index slices to `flow_index.py`. In the 16,384 build, stage 0
  `result[32..45]` equals the low 14 bits on 3,000 of 3,000.
- **On the switch** (`perf/tools/newconn_test.py`; 154 packets at 100 pkt/s, all
  forwarded; read with the collector's `read_registers_with_index.py --ssh …
  --dst-indexes`): 12 of 12 checks passed on both builds.

  | Traffic | Expected `reg_newconn_dst` | Hardware |
  |---|---|---|
  | 40 handshakes 10.99.6.1 → 10.99.6.2:80, a new source port each | 40 | 40 |
  | One SYN sent 3 times | 3 | 3 |
  | 2 SYNs with ECE and CWR (ECN setup) | 2 | 2 |
  | 5 SYNs of the same client to port 8080 | 5 | 5 |
  | One SYN+FIN | 1 | 1 |
  | The flood's SYN+ACKs, keyed server → client | 0 | 0 |
  | ACK, FIN+ACK and RST only | 0 | 0 |
  | UDP (key with protocol 17) | 0 | 0 |

  All counts were in pipe 1 only. The 51 CPU reports were the expected ones, and the
  destination buckets derived from them include every counted key. In the first flood
  connection's flow bucket, `reg_pkts` was 3 and `reg_syn` 2: `reg_syn` still counts the
  SYN+ACK.
- **Offline parity.** `derive_p4_features` on the same 154 packets, re-timed into two
  windows (the flood, then the rest), gives `net_new_conn_dst_max` = 40 and 5, the largest
  hardware bucket of each part. Its `net_syn_delta` for the flood window is 80.
- **Not measured yet:** latency, packet rate and line rate of these builds. The switch
  runs the fixed build again.
- **Limits.** The key includes the client address, so a SYN flood from random spoofed
  sources spreads over many buckets with about one SYN each; its volume still shows in
  `net_syn_delta`. Aliasing only adds counts. Of K active keys, a key shares its bucket
  with probability about K/16,384 or K/65,536.
- **Before use:** clear `reg_newconn_dst` with the 14 counters (`bfrt_gen.py clear-regs
  --extra-registers reg_newconn_dst`). The collector's CSV and the offline datasets gain
  the column `net_new_conn_dst_max`, so the P4 signal families go from 29 to 30: the
  datasets that the `evaluate_*` scripts read must be regenerated.

### 5.5 Build without the new-connection counter (31 October)

The paper's build has no `reg_newconn_dst`: it keeps the 14 per-flow registers of
Section 1.2. Sections 3.2 and 4.1 measured the working tree with the counter, so both were
repeated on the build without it. The tools, parameters and switch setup were unchanged;
only the program differed.
- **Sources:** `git archive a0bcf95^` (commit `c7a5a35`), byte-identical to the fixed build
  of Section 5.1. Of the 8 `.p4` files, only `ingress.p4` differs from HEAD, by the
  counter, its hash and its update. It declares 14 registers, none of them `reg_newconn_dst`.
- **Compile** (bf-p4c 9.6.0, fresh builds, no warnings):

  | Build | Stages ig/eg | SRAM | Map RAM | Stateful ALUs | TCAM | Hash bits | Latency ig/eg (cycles) |
  |---|---|---|---|---|---|---|---|
  | Without the counter | 5/1 | 197 (20.5%) | 196 (34.0%) | 14 (29.2%) | 3 | 172 | 131/170 |
  | With the counter (HEAD) | 7/1 | 214 (22.3%) | 213 (37.0%) | 15 (31.2%) | 3 | 252 | 158/170 |
  | Without the counter, with the Section 4.1 instrumentation | 5/2 | 197 | 196 | 14 | 3 | 172 | 131/172 |
  | Baseline with the Section 4.1 instrumentation | 1/2 | 1 | 0 | 0 | 0 | 10 | 56/172 |

  The first two rows equal "detector (fixed)" (Section 2) and the build of Sections 3.2
  and 4.1 in every column. The instrumentation adds one egress stage and leaves the
  ingress placement unchanged.
- **The 2 extra stages come from placement, not logic.** In both builds the compiler's
  critical path through the table dependency graph is 4 stages.
  - Without the counter, stages 0–4 have 7, 14, 4, 5 and 14 map RAMs free; the counter
    needs 17.
  - With it, the compiler puts `reg_newconn_dst` into stage 1, in `reg_rst`'s place, and
    moves 8 flow registers one or two stages later: `reg_rst`, `reg_ref_src_port`,
    `reg_min_len`, `reg_max_len`, `reg_bytes`, `reg_pkts`, `reg_bytes_ab` and
    `reg_pkts_ab`. Stage 3 keeps only 9 map RAMs. The placement took 4 rounds instead of 1.
- **Hashes:**
  - `hash_matrix_check.py` finds 16 index functions in stages 0–4, each symmetric on 5000
    of 5000 random tuples.
  - `hash_block_identify.py` matches all 17 compiled slices to `flow_index.py`.
  - The generator's flow is in bucket 44993, as before.
- **Line rate** (Section 3.2's matrix, unchanged):

  | Frame (B) | 100G line rate (Mpps) | Paced, without the counter (3 runs) | Paced, with the counter (Section 3.2) | Saturating: offered / sent |
  |---|---|---|---|---|
  | 64 | 148.81 | 91.09% / 91.09% / 91.09% (generator maximum) | 91.09% | – |
  | 128 | 84.46 | 99.88% / 99.88% / 99.88% | 99.88% | 111% / 100.00% |
  | 256 | 45.29 | 99.89% / 99.89% / 99.89% | 99.89% | 128% / 100.00% |
  | 512 | 23.50 | 99.87% / 99.87% / 99.87% | 99.87% | 140% / 100.00% |
  | 1024 | 11.97 | 99.90% / 99.90% / 99.89% | 99.89% | 148% / 100.00% |
  | 1280 | 9.62 | 99.88% / 99.88% / 99.89% | 99.88% | 149% / 100.00% |
  | 1518 | 8.13 | 99.88% / 99.88% / 99.88% | 99.88% | 150% / 100.00% |

  - **Lossless:** in every paced run and at 64 B, generated = transmitted = received, and
    the TM dropped nothing. In the saturating runs, the TM dropped exactly the excess.
  - **Exact counting:** in all 27 runs, the flow's `reg_pkts` in pipe 1 grew by exactly the
    generated count and `reg_bytes` by the generated bytes (mod 2³²), and pipe 0 counted
    the looped-back copies. That is 13.1 billion packets.
  - **Baseline:** rerun the same day, it is within 0.01 points of the detector.
  - **64 B paced:** three extra runs paced to 99.9% also gave 91.09%. Each timer tick sent
    its full burst, but the ticks came late.
- **Latency** (Section 4.1's method, unchanged; hairpin path; 3 runs per program; every run
  had 1010 of 1010 reports, none malformed or missing):

  | Program | min | median | mean | p99 | max (ns) |
  |---|---|---|---|---|---|
  | Baseline | 244 | 246 | 245.62–245.64 | 247 | 247–248 |
  | Detector without the counter | 314 | 315 | 315.38–315.42 | 318–319 | 320 |
  | Detector with the counter (Section 4.1) | 336 | 337 | 337.50–337.57 | 341 | 342 |

  - The detector without the counter adds **69 ns** (median 315 vs 246 ns), the same as
    the 69–70 ns of Section 4.
  - The counter's two stages cost 22 ns (337 vs 315 ns); the compiler estimates 27 cycles.
    This accounts for the gap between Sections 4 and 4.1.
  - The baseline reproduces its 29 October values.
- **For the paper:** these are the numbers of the build it describes. Sections 3.2 and 4.1
  describe the build with the counter.

### 5.6 Global totals (build `gtot`, 15-16 November, tested on the switch; the thesis replay rows use `basic_gtot_ba`)

Under a flood the control plane reads ~500 buckets per 0.5 s window while ~30,000 are active, so window
totals summed over the buckets read show 6–35% of the packets (PC1.md, part 4c). The test build adds seven
one-entry registers that every counted packet updates, with the values the flow registers use: packets,
bytes, A→B packets and bytes, SYN, ACK, RST. PC1.md part 4d has the collector side and the replays (floods
97.6–100% of their packets seen instead of 6–73%).

PC1.md part 4e reran all 109 captures on it, with the totals read from hardware in one request right after each
window boundary (a reader and collector change; the P4 program is the one measured here). Every packet then
counts in the 40 dataset windows in all 109 runs. The calm captures match the published rows as on `basic_fix`
(median 95 of the 95 total-based columns). The 11 that overload `basic_fix` go from a median of 4 to 41 of those
columns. The seven registers are read one after another, ~0.4 ms apart, so in a flood B→A = total − A→B
picked up packets that were never sent (6–26 in six floods). `-DP4_GLOBAL_TOTALS_SPLIT=1` (build
`basic_gtot_ba`, PC1.md part 4f) counts B→A in place of the packet and byte totals. It uses the same seven registers,
6 stages and 21 stateful ALUs; the compiler estimates 133 ingress cycles against 135. Latency and line rate were
measured on 17 November (at the end of this section): median 317 ns, the same rates as `basic_fix`. On it the six floods have no such packets, and they match 29–83 of the 95 columns instead of 16–37.
PC1.md part 4g reran all 109 captures on `basic_gtot_ba`. Every packet counts, and no window has more A→B
packets than packets in all. The calm captures' B→A sum equals the published rows' (78,400). The mean over the
109 is 77.8 of the 95 columns, against 76.3 on `gtot` and 73.1 on `basic_fix`. The thesis replay rows come from
this build. Between runs the switch runs `basic_fix`.
- **Sources:** `perf/variants/gtot/`: the fixed build of Section 5.5 (`basic_fix`, same hashes) with the seven
  registers in `ingress.p4`; `-DP4_ENABLE_GLOBAL_TOTALS=0` compiles `basic_fix`. The instrumented copy for the
  latency is `perf/variants/hwl/make_hwl_sources.sh perf/variants/gtot OUT_DIR`; it differs from Section 5.5's
  instrumented build only by the seven registers.
- **Compile** (bf-p4c 9.6.0; `perf/results/gtot_build_20261115/`, `perf/results/latency_gtot_20261115/builds/`):

  | Build | Stages ig/eg | SRAM | Map RAM | Stateful ALUs | Latency ig/eg (cycles) |
  |---|---|---|---|---|---|
  | basic_fix (Section 5.5) | 5/1 | 197 (20.5%) | 196 (34.0%) | 14 (29.2%) | 131/170 |
  | gtot | 6/1 | 211 (22.0%) | 210 (36.5%) | 21 (43.8%) | 135/170 |
  | basic_fix, Section 4.1 instrumentation | 5/2 | 197 | 196 | 14 | 131/172 |
  | gtot, Section 4.1 instrumentation | 6/2 | 211 | 210 | 21 | 135/172 |

  Each one-entry register takes 2 RAMs, 2 map RAMs and one stateful ALU. The compiler adds one ingress stage,
  moves five flow registers one stage later (`reg_pkts`, `reg_bytes`, `reg_pkts_ab`, `reg_bytes_ab`,
  `reg_min_len`) and `reg_first_ts` from stage 0 to stage 3; the critical path stays at 4 stages.
- **Latency** (Section 4.1's method as Section 5.5 ran it: hairpin, 1010 probes at 100 pkt/s, 10 warm-up
  probes excluded, 3 runs per program, all three programs on the same day, `hwl_runs.sh`; every run had
  1010 of 1010 reports, none malformed or missing):

  | Program | min | median | mean | p99 | max (ns) |
  |---|---|---|---|---|---|
  | Baseline | 244 | 246 | 245.59–245.62 | 247 | 247–248 |
  | basic_fix (detector without the counter) | 314 | 315 | 315.39–315.43 | 319 | 319–322 |
  | gtot | 317 | 319 | 318.66–318.70 | 322 | 323–324 |

  - **The global totals cost 4 ns** (median 319 vs 315 ns; 3.3 ns in the mean), the compiler's 4 cycles. The
    detector's cost over the baseline goes from 69 to 73 ns.
  - The baseline and `basic_fix` reproduce Section 5.5's values to the nanosecond.
- **Line rate** (Section 3.2's matrix as Section 5.5 ran it: 27 runs, 10 s measured each;
  `sw_pktgen_run.py --global-totals` also reads the seven totals before and after each run;
  `perf/results/linerate_gtot_20261115/`):

  | Frame (B) | Paced, gtot (3 runs) | Paced, basic_fix (Section 5.5) | Saturating: offered / sent, gtot |
  |---|---|---|---|
  | 64 | 91.09% / 91.09% / 91.09% (generator maximum) | 91.09% | – |
  | 128 | 99.88% / 99.88% / 99.88% | 99.88% | 111% / 100.00% |
  | 256 | 99.89% / 99.89% / 99.89% | 99.89% | 128% / 100.00% |
  | 512 | 99.87% / 99.87% / 99.87% | 99.87% | 140% / 100.00% |
  | 1024 | 99.89% / 99.89% / 99.89% | 99.89% | 148% / 100.00% |
  | 1280 | 99.88% / 99.88% / 99.88% | 99.88% | 149% / 100.00% |
  | 1518 | 99.88% / 99.88% / 99.88% | 99.88% | 150% / 100.00% |

  - **Same rates as `basic_fix`**, within 0.01 points, and lossless: in every paced run and at 64 B, generated
    = transmitted = received and the TM dropped nothing; in the saturating runs it dropped exactly the excess.
  - **The totals count exactly at line rate.** In all 27 runs (13.1 billion packets) the pipe-1 totals grew by
    exactly the generated packets, the pipe-0 totals by exactly the looped-back ones, the byte totals as the
    flow's `reg_bytes` (mod 2³²), `pkts_ab` and `bytes_ab` as `pkts` and `bytes` (one flow, one direction) and
    SYN/ACK/RST not at all (UDP). The flow's `reg_pkts` in pipe 1 equalled the generated count as well.
  - **Wrap:** at 99.9 Gbps a 32-bit byte total wraps every 0.34 s; the collector's 0.5 s windows would see an
    ambiguous difference above ~69 Gbps per pipe (Section 5.6 is a test build for the dataset's traffic).
- The switch runs `basic_fix` again (checked with a replay, 9 of 9 packets).
- **`basic_gtot_ba`, measured 17 November** (PC1.md part 9A; `perf/results/part9_20261117/`, archive
  `live_test/committee_replay/pc1_20261117_part9.tar.xz`). The same method, with the baseline and `basic_fix` of
  the same day:

  | Program | Stages ig/eg | Latency ig/eg (cycles) | min | median | mean | p99 | max (ns) |
  |---|---|---|---|---|---|---|---|
  | Baseline | 1/2 | 56/172 | 244 | 246 | 245.62–245.64 | 247 | 247–248 |
  | basic_fix (detector without the counter) | 5/2 | 131/172 | 314 | 315 | 315.36–315.41 | 318–319 | 319–320 |
  | basic_gtot_ba (`gtot -DP4_GLOBAL_TOTALS_SPLIT=1`) | 6/2 | 133/172 | 316 | 317 | 317.02–317.06 | 320–321 | 322 |

  - **The split totals cost 2 ns over `basic_fix`** (median 317 vs 315 ns), 2 ns less than `gtot`'s 319: the
    compiler's 133 against 135 ingress cycles. Every run had 1010 of 1010 reports; the baseline and `basic_fix`
    reproduce the values above to the nanosecond.
  - **Line rate:** the same 27-run matrix with `sw_pktgen_run.py --global-totals` (which now reads the split
    registers): the same rates as `basic_fix` within 0.01 points, lossless, the totals exact for 13.1 billion
    packets (pipe 1's `pkts_ab` = generated, pipe 0's = looped back, `pkts_ba` and `bytes_ba` 0: one flow, one
    direction).
  - **Uninstrumented build** (`perf/results/part9_20261117/builds/`): 6/1 stages, 211 SRAM, 210 map RAM,
    21 stateful ALUs, 133/170 cycles, the same RAMs and ALUs as `gtot`.

### 5.7 Window features in the data plane (build `exact`, 16 November, tested on the switch)

The aim: a program whose rows have no leak and no drop. A packet should count in its own window and direction,
and no flow should go unread under a flood. **Where the remaining errors came from (offline,
`perf/results/exact_gap_analysis/`):**
- A copy of `features/switch_model.py` run on the 110 captures reproduces all 110 published rows, which confirms
  the window grid.
- With ideal reads and ideal cuts, `basic_fix`'s design would match all 135 non-duration columns in 89 of the 110.
  - **Shared buckets** cost 4 floods (syn_fan_40k/100k/150k, Chaos).
  - **Ethernet padding** cost 21 captures. The dataset counts frames as the guest's capture saw them: 27,813
    received frames padded to 60 B, 40,395 sent 54 B frames unpadded. IPv4 totalLen + 14 misses the padding.
  - **The parser** differs from the model on VLAN tags, IPv4 options and fragments, but none occur in the dataset.
- On the switch, three more causes add to these:
  - each window's cut lands a few ms after its boundary, later when the collector falls behind;
  - the replay runs late in floods;
  - the reads cover only part of the active buckets under overload.

**The program** (`perf/variants/exact/`, header comment of `ingress.p4`):
- **Windows.** A window marker frame (EtherType 0x88B5, carrying the new window's number) advances `reg_epoch`.
  - Every window register has two banks (epoch & 1). The control plane reads the finished window's bank while the
    next window counts into the other.
  - The cut is where the marker sits in the packet sequence, for all registers at once.
  - In deployment the packet generator's timer advances the epoch instead (first `-DTIMER_PORT=196`; since
    `basic_exact_v3`, `-DTIMER_LOCAL_PORT=68` on any pipe).
- **Flows.** The key orders the two (address, port) endpoints, so flows whose ports pair differently with the same
  two addresses stay apart.
  - Four ways of 16,384 slots hold a 32-bit signature each. A flow takes the first way whose slot is free or
    holds its signature, and keeps it for the run, as the model does.
  - A flow that finds no slot is still counted, as A→B, and its packets go into a separate total, so the window is
    marked inexact.
- **Direction.** A→B is the first packet's source, compared by address and port; `basic_fix` compares ports only.
- **Features.** All 29 are computed in the data plane. Per window, every packet adds its flow's change. A flow's
  first packet in the window also adds the flow's previous value, under its class (the windows since its last
  packet, 1–3, or 0 for new or expired flows). From these, `window_features.py` rebuilds the sums over the active
  flows (3-window TTL), and the minima and maxima come from per-window extremes.
- **Bytes.** `frame_len` counts the frame minimum toward the guest (10.0.0.10), as its capture saw received frames.
- **Parser.** It takes VLAN tags, skips IPv4 options while forwarding them, and does not count fragments.

**Control plane** (`thesis-hybrid-ebpf-p4/python/`):
- `window_reader.py`, on the switch, reads one window in 51 cells and clears its 3 extreme cells.
- `window_features.py` rebuilds the 29 features from those reads.
- `exact_model.py` is a software model of the program; `tests/test_exact_windows.py` checks it against the model
  on random traffic.
- `live_test/replay_absolute.py --markers` sends the 41 markers in order with the capture's frames, and
  `live_test/exact_replay.py` drives one run.

- **Compile** (`perf/results/exact_build_20261116/`):

  | Build | Stages ig/eg | SRAM | Map RAM | Stateful ALUs | Latency ig/eg (cycles) |
  |---|---|---|---|---|---|
  | basic_fix (Section 5.5) | 5/1 | 197 (20.5%) | 196 (34.0%) | 14 (29.2%) | 131/170 |
  | exact | 11/1 | 120 (12.5%) | 117 (20.3%) | 23 (47.9%) | 260/170 |
  | exact, Section 4.1 instrumentation | 11/2 | 120 | 117 | 23 | 260/172 |

  - The per-flow state is 7 registers of 65,536 slots plus the 4 signature ways. The 14 per-flow counters of
    `basic_fix` are gone, so SRAM drops.
  - The chain is: compare, order the key, 4 way probes, per-flow state, contributions, window registers.
  - `-DWAY_BITS=15` (131,072 slots) made bf-p4c 9.6.0 fail with an internal error while it split the 32-bit time
    registers across stages.
  - The batch's build and a compile of the committed source give the same assembler program, apart from generated
    table names and paths.
- **Latency** (Section 4.1's method, `perf/results/latency_exact_20261116/hwl_runs.sh`, 3 runs per program, all
  three programs on the same day; every run had 1010 of 1010 reports):

  | Program | min | median | mean | p99 | max (ns) |
  |---|---|---|---|---|---|
  | Baseline | 244 | 246 | 245.60–245.65 | 247 | 247–248 |
  | basic_fix (detector without the counter) | 314 | 315 | 315.38–315.45 | 318–319 | 319–320 |
  | exact | 420 | 421 | 421.14–421.15 | 424–425 | 425–426 |

  - **The exact build costs 106 ns more than `basic_fix`** (421 against 315 ns), 175 ns over the baseline. That
    matches the compiler's 129 extra cycles.
  - The baseline and `basic_fix` reproduce Section 5.5 to the nanosecond.
- **Line rate** (Section 3.2's matrix, 27 runs; `sw_pktgen_run.py --window-totals` reads `reg_w_tot` before and
  after each run; `perf/results/linerate_exact_20261116/`):

  | Frame (B) | Paced, exact (3 runs) | Paced, basic_fix (Section 5.5) | Saturating: offered / sent, exact |
  |---|---|---|---|
  | 64 | 91.09% / 91.09% / 91.09% (generator maximum) | 91.09% | – |
  | 128 | 99.88% / 99.88% / 99.88% | 99.88% | 111% / 100.00% |
  | 256 | 99.89% / 99.89% / 99.89% | 99.89% | 128% / 100.00% |
  | 512 | 99.87% / 99.87% / 99.87% | 99.87% | 140% / 100.00% |
  | 1024 | 99.89% / 99.89% / 99.89% | 99.89–99.90% | 148% / 100.00% |
  | 1280 | 99.88% / 99.88% / 99.88% | 99.88–99.89% | 149% / 100.00% |
  | 1518 | 99.88% / 99.88% / 99.88% | 99.88% | 150% / 100.00% |

  - **Same rates as `basic_fix`**, and lossless: in every paced run and at 64 B, generated = transmitted = received
    with no TM drop. In the saturating runs the TM dropped exactly the excess.
  - **The window totals count exactly at line rate.** Over the 27 runs (13.1 billion packets), the pipe-1 total
    grew by the generated packets and the pipe-0 total by the looped-back ones. The bytes grew by the IPv4 length
    each (mod 2³²), and every packet was tracked (one flow).
- **Timer** (`perf/tools/sw_window_timer.py`, build `-DTIMER_PORT=196`, later `-DTIMER_LOCAL_PORT=68`): the generator's 500 ms timer advanced the
  window 40 times in 20 s, 0.4999 s apart as polled (min 0.4983, max 0.5025). No tick was counted as traffic.
- **The 109 captures** (PC1.md, part 6), with the markers at the capture's window boundaries:
  - **102 rows match all 135 non-duration columns of the published row.** All 96 calm captures match, against 61
    on `basic_fix` and 63 on `basic_gtot_ba`. 6 of the 11 that overload `basic_fix` match too.
  - No window was read late, and no packet fell outside the 41 markers. A window's read took at most 56 ms.
  - The 7 others:
    - **Two bulk uploads:** their frames over the MTU cannot be replayed, the replay's limit.
    - **Five floods with more distinct flows than slots:**

      | Capture | Packets of flows without a slot |
      |---|---|
      | Chaos | 1,930 |
      | syn_fan_40k | 363 |
      | udp_fan_60k | 98 |
      | syn_fan_100k | 35,194 |
      | syn_fan_150k | 83,936 |

      Their packet, byte and flag totals stay exact, and so do the directions in syn_fan_40k and udp_fan_60k. In
      the other three, the B→A packets of flows without a slot count as A→B. syn_fan_100k and syn_fan_150k have
      99,639 and 149,423 distinct flows, more than any single-stage register on Tofino 1 holds per flow.
  - **Durations come from the switch's clock** (65.536 µs units): median relative error 4.5·10⁻⁵, at most 17% on
    short flows, from the replay's timing.
- **Hardening (build `basic_exact_v3`, PC1.md part 6b):**
  - **Markers only from configured ports:** the parser value set `marker_ports` is filled by the reader (the
    CPU port for live collection, the replay host's port for a replay). Any other marker is dropped and counted.
    Five forged markers from a host port did not move the clock and were all counted.
  - **Timer per pipe in a deployment build** (`-DTIMER_LOCAL_PORT=68`, any pipe's generator): 40 ticks in 20 s,
    0.5000 s apart as polled. The default build has no timer port.
  - **Reader:** it combines only pipes whose clock passed the window and reports a lagging pipe's packets. A late
    clear or a change of clocked pipes marks the window lost.
  - **Resources:** the same 11 stages, 23 stateful ALUs and 260 cycles, plus 2 SRAM blocks for the counter.
  - **Line rate:** unchanged and lossless; the window totals stayed exact for 13.1 billion packets
    (`perf/results/linerate_exact_v3_20261116/`).
  - **Latency:** median 421 ns, as before (1010 of 1010 reports in each of 3 runs;
    `perf/results/latency_exact_v3_20261116/`).
- **`hybrid_collector.py --switch-program exact`** (PC1.md part 6b):
  - **Markers:** from the switch's CPU port at the collector's window boundaries (live), or in band from the
    replayer (`replay_capture.py --exact`).
  - **Features:** `window_features.py`, the code the standalone driver uses.
  - **Live test:** all 24,008 packets of a 1 s-window replay counted, every checkable window within its bounds,
    the markers on the clock 2.8 ms after they were sent.
  - **All 109 captures:** all 4,796 windows equal the frames the replayer sent between their markers, with no
    window lost. All 109 rows equal the standalone driver's in the 135 non-duration columns, and 102 equal the
    published row.
- **The timer with traffic, and a second pipe** (PC1.md part 6d, `perf/results/exact_timer_traffic_20261116/`):
  - **Timer windows:** `basic_exact_v3_timer` with a timer on each pipe's generator, the captures replayed
    without markers. slowloris_500 and session_1000 give 47 and 35 windows: none lost, every packet counted, and
    every window exact in the 27 non-duration features against the dataset's model on the frames as the
    switch's windows cut them. The cut points fit one tick every 0.5 s, to within the two clocks' rate
    difference.
  - **Fault found and fixed:** the two pipes' timers tick about 1 ms apart, and the reader read each window as
    soon as the first pipe had ticked. That marked 15 of 47 windows lost, and left one window unmarked with
    8.6 billion packets. A window's bank had last been read with another set of pipes.
    - The reader now waits up to 50 ms for a pipe that has reached the window, and marks lost the next window
      of each bank after a change of pipes.
    - `net_window_lost` also marks the 3 windows rebuilt from a lost one.
  - **Two pipes combined:** with generator traffic in pipe 0 as well, the windows hold 282,124 packets, the
    replay's 12,000 plus pipe 0's 270,124, with none lost and none unclocked.
  - **A pipe without a clock:** with markers from port 132 (pipe 1), all 270,088 of pipe 0's packets were
    reported as unclocked and none counted in a window. The capture's row still equals the published one.
  - **Generator:** on the Wedge a generator port other than 68 sends only while port 68 of the same pipe is a
    generator port too. Port 69 enabled alone stalled pipe 0's generator until switchd restarted.
  - **`hybrid_collector.py --window-markers timer`** (PC1.md part 6e): the reader starts every pipe's timer.
    The timers are configured first and enabled one window before the collector's window 0, so the first tick
    starts window 0. Tested with bulk2000 in 1 s windows (stub host monitor) and session_1000 under the dataset
    profile with the eBPF host monitor in its cgroup: every packet counted, none lost, both pipes combined.
    The ticks came 2.4-3.8 ms after the collector's boundaries; with the configuration in the same step they had
    come 19 ms late.
- The switch runs `basic_fix` again (checked with a replay, 9 of 9 packets).

### 5.8 The bucket table read by the data plane (build `sweep`, 17 November, tested on the switch)

- **Idea.** Section 5.7's gap analysis (`perf/results/exact_gap_analysis`, perfect reads and cuts) gives the bucket
  table, read in full at each window boundary and with the frame minimum counted, the same parity as the exact
  build: 106 of the 110 captures equal to the published row in the 135 non-duration columns, the same 4 floods
  failing. The exact build's gain comes from reading every flow at the boundary, not from its 4-way table. So
  `perf/variants/sweep` keeps `basic_gtot_ba`'s bucket table and adds a probe path: a probe names one bucket and
  leaves as a 104-byte record of its 14 registers (bucket 0 also the seven totals and a sweep number). A sweep of
  probes at each boundary, from the packet generator or in band from a replay host, replaces the control plane's
  ~500 reads per 0.5 s window. Design: `perf/variants/sweep/README.md` and `ingress.p4`'s header comment.
- **Offline** (`live_test/sweep_offline_check.py`, the program's software model `sweep_features.SweepModel` with
  in-band probes, all 110 captures): 106 of 110 rows equal to the published row in the 135 non-duration columns,
  all 101 calm captures among them; the 4 others are Chaos and the three SYN fan-outs. In every window the totals
  equal the buckets' sum. 475,839 probes in all, one per bucket changed since the previous boundary.
- **Compile** (bf-p4c 9.6.0; PC1.md "Results, part 9" and "part 9b"; `perf/results/part9_20261117/builds/`):
  - **The first version fails table placement**, also with `-DSWEEP_SHARED_INDEX=1`. Its probe branch reads every
    register from tables of its own. A register sits in one stage with every table that uses it; the probe's reads
    depend on nothing and are placed early, so the data path's updates cannot follow.
  - **Fix A, the probe's reads pinned (`@stage`) to the data path's stages: fails too**, with both index
    variants. The pins hold, but the data path and the probe address one stateful ALU from different sources (the
    hash, the MAC); with the shared index the probe's write of `meta.ridx` keeps its stage-0 reads out of stage 0.
  - **Fix B, one table per register for both paths ("merged"): compiles.** Each table's key picks the data path's
    RegisterAction or the probe's read. It needs the shared index ("Incompatible attached indexing between actions"
    without it), the probe's values that the data path also reads routed through the same metadata fields (an
    assembler error otherwise), and the two writes of `meta.ridx` in one if/else. The stage pins then fit it into
    6 stages. `perf/variants/sweep` is this version.

  | Build | Stages ig/eg | Critical path | SRAM | TCAM | Stateful ALUs | Ingress cycles | Median latency |
  |---|---|---|---|---|---|---|---|
  | basic_gtot_ba | 6/1 | 4 | 211 | 3 | 21 | 133 | 317 ns |
  | sweep, merged, pinned (`perf/variants/sweep`) | 6/1 | 5 | 239 | 20 | 22 | 158 | 337 ns |
  | sweep, merged, no pins (`-DSWEEP_PIN_STAGES=0`) | 7/1 | 5 | 239 | 20 | 22 | 166 | 344 ns |
  | sweep with the collision counter (`basic_sweep_coll`, `perf/variants/sweep` now) | 7/1 | 5 | 245 | 20 | 23 | 164 | 342 ns |
  | exact (Section 5.7, its first build) | 11/1 | – | 120 | – | 23 | 260 | 421 ns |

  - **Latency:** hairpin as in Section 4.1, 3 runs per program, baseline 246 ns the same day. The data path reaches its
    first register in stage 1 instead of 0 (the shared index): +25 cycles, +20 ns.
  - **The control build** (`-DP4_ENABLE_SWEEP=0 -DP4_FRAME_LEN=0`) has exactly `basic_gtot_ba`'s resources.
- **Line rate** (Section 3.2's 27-run matrix, `--global-totals`): the same rates as `basic_fix` within 0.01 points,
  lossless, the totals and the flow's registers exact for 13.1 billion packets.
- **In-band replays** (`live_test/sweep_replay.py`, 5 captures): the switch's row equal to the model's in all 135
  non-duration columns, and probes = exports = the model's in every run. Against the published row: the first cohort
  capture, `bulk2000` and `slowloris_500` 135 (`slowloris_500` overloads `basic_fix`'s reader), `syn_fan_40k` 120
  and Chaos 67, as the model predicted. Chaos: 221,733 packets, 106,363 probes and exports, none lost.
- **Generator** (`live_test/sweep_generator_check.py`): 15 whole sweeps of 65,536 probes every 0.5 s (500,000,001 to
  500,000,004 ns apart), every record after the traffic equal to the model's, at 2 µs (a sweep in 131 ms), 0.5 µs
  (33 ms) and the generator's full rate (0.64 ms), no export lost. Stopping the generator in the middle of a batch
  left the pipe's timer dead until switchd was restarted; `sweep_reader.py` now stops it between sweeps.
- **The exact build's 109 captures** (PC1.md "Results, part 9c", `perf/results/part9_20261117/sweep_replays/`):
  - **Against its model:** the switch's row equals the model's in all 135 non-duration columns in 107 of 109 runs.
    The other two are `bulkup_200` and `bulkup_400`, whose GSO super-frames eth1's MTU refuses. Probes and exports
    are 475,080 of each, none lost.
  - **Against the published rows:** 103 of 109 equal in all 135 columns, against 102 for the exact build, 63 for
    `basic_gtot_ba` and 61 for `basic_fix`; mean 131.8 against the exact build's 131.9.
  - **Where they differ:** the sweep build is better on `udp_fan_60k` (135 against 123: the exact build's table
    overflows) and worse on Chaos (67 against 71) and `syn_fan_150k` (67 against 77), where flows share buckets.
    The other 106 captures score the same on both.
  - **The cost:** the same parity as the exact build with 6 ingress stages instead of 11 and 337 instead of 421 ns.
- **The collision counter** (`basic_sweep_coll`, PC1.md "Results, part 9d"). The bucket table merges colliding flows
  without saying so, so the build now counts them.
  - `reg_coll` keeps one byte per bucket, saturating at 255. A data packet adds 1 when it matches neither direction of
    its bucket's reference ports, which makes it a second flow in the bucket. A probe reads the count into its record.
  - The host gets, per window, the colliding packets and the active buckets that merge flows
    (`net_sweep_coll_pkts`, `net_sweep_merged_active`), so it knows which windows the bucket table cannot make exact.
    The exact build has its untracked count for the same purpose. Two flows with the same ports and different
    addresses are not seen, because the bucket keeps no addresses.
  - Cost: a seventh ingress stage, +6 cycles and +5 ns (342 against 337 ns, 3 runs each, the same day). The counts
    change nothing else.
  - **Tested:** 4 in-band replays (Chaos and `syn_fan_40k` among them) equal to the model in every window, collision
    counts included: Chaos 55,245 colliding packets in 14,899 buckets, `syn_fan_40k` 10,050 in 8,185. The generator
    check also passes.
  - **Line rate:** the 27-run matrix gives the same rates as without the counter to within 0.01 points, lossless,
    the totals and the flow's registers exact for 13.1 billion packets.
  - **The 109 captures** (PC1.md part 9d): 103 rows equal to the published row and 107 to the model, mean 131.8. Every
    capture has the same score as without the counter. Exactly 4 captures have collisions: `syn_fan_150k` (90,599
    colliding packets), Chaos (55,245), `syn_fan_100k` (48,461) and `syn_fan_40k` (10,050). They are the 4 floods whose
    rows are not exact, so the counter flags every inexact row and no exact one (the 2 bulk uploads are limited by the
    replay's MTU).
- **The line rate beside the generator's sweep** (PC1.md 9E, "Results, part 9f"). Line-rate traffic from pipe 0's
  generator was looped into pipe 1 while pipe 1's generator swept its registers every 0.5 s. It ran at 99.99% (1518 B)
  and 91.09% (64 B, the generator's maximum), the same as without the sweep, with no drop and exact counts.
  - A line-rate app on the same pipe's generator as the sweep loses the sweep's share of the time instead (73.88%
    against 99.99%, at 131 ms per 500 ms). The generator runs one app at a time.
- **The receiver of the exports** (PC1.md "Results, part 9e"). The switch exported every record. PC1's NIC, with its
  default 1,024 receive descriptors, lost a few (251 of 193,009 at a 2 µs gap with 30,000 flows; 3,406 of 174,251 at
  0.5 µs). With 8,192 descriptors it lost none at 2, 1 and 0.5 µs. At the generator's full rate (a sweep in 0.64 ms)
  it lost about half either way.
- **`hybrid_collector.py --switch-program sweep`** (PC1.md "Results, part 9g"). The collector drives the generator
  through `sweep_reader.py --serve`, takes the exports with tcpdump into `/dev/shm` and builds each window from two
  consecutive sweeps.
  - **In-band probes:** every window of 4 replayed captures, Chaos included, equals the model's. The rows equal the
    direct replays' (135, 135, 120, 67).
  - **Generator probes (the deployment), 0.5 µs gap:** every packet counted, but fewer windows equal the dataset's
    perfect cut. The cohort capture matched in 44 of 46 windows, its row 91 of 135. `bulk2000` matched in 6 of 46, its
    row 44.
  - The cause is the cut. Bucket *i* is read *i* × 0.5 µs after the boundary, over 33 ms, so a packet in that time
    counts in the window before for the buckets probed after it. The dataset's captures begin a few ms after their
    anchor.
  - **So the 103 of 109 holds with in-band probes.** With the generator, a replay's rows lose parity. On PC1 (2 cores)
    a flood replay also cost exports at the NIC and once hung the host.

### 5.9 Block rules on a malicious verdict (build `exact_block`, 19 November, tested on the switch)

- **Idea.** `perf/variants/exact_block` is Section 5.7's exact build plus one ternary table, `block_rules`, on the
  ingress port and the 5-tuple, looked up for every IPv4 packet of the data path. A match is dropped at the end of
  ingress, after the window registers have counted it, so the windows (and the verdicts after the block) still see the
  attack. When the detector's probability reaches 0.5, the control plane (`window_reader.py`, `block_policy.py`,
  `hybrid_collector.py --block-on-alarm`) has the switch drop everything the flagged host sends: one entry per source
  address, plus one for its switch port with `--block-host-port`. With `--block-scope flows` it blocks the program's
  5-tuples only. PC1.md "Results, part 11", "part 11b" and "part 11c"; `perf/results/part11_20261119/`.
- **Placement, the result of two compiles** (bf-p4c 9.6.0):
  - **The first version** looked the table up right after `forwarding.apply()` and counted the indirect `blocked_pkts`
    and the per-entry direct `block_hits` in its action. bf-p4c refused the action ("all indirect externs to be
    addressed with the same expression across all actions"). Without the direct counter it compiled into all 12
    ingress stages: `forwarding` and `block_drop` both write `drop_ctl`, so the table could not share stage 0, and the
    `is_flow` gateway that follows it in control order started the flow-table chain one stage later.
  - **The build now** counts `blocked_pkts` on `block_rules.apply().hit`, outside the action, and looks the table up as
    the data path's last step. It compiles with the direct counter into the exact build's 11 stages and cycles; the
    table lands in stage 10.

  | Build | Stages ig/eg | Critical path | SRAM | Map RAM | TCAM | Stateful ALUs | Ingress cycles | Median latency |
  |---|---|---|---|---|---|---|---|---|
  | exact v3 (Section 5.7) | 11/1 | 9 | 122 | 119 | 7 | 23 | 260 | 421 ns |
  | **exact_block** (lookup last, direct counter) | **11/1** | **9** | **127** | **123** | **13** | **23** | **260** | **421 ns** |
  | exact_block, first version, `-DBLOCK_DIRECT_COUNTER=0` | 12/1 | 10 | 125 | 121 | 13 | 23 | 279 | 437 ns |

  - The 1,024-entry, 113-bit table costs the expected 6 TCAM blocks and no stateful ALU.
  - **Power:** bf-p4c's estimate is 2.11 W (ingress) against 0.56 W for exact v3, for the 6 TCAM blocks searched per
    packet. The first version's 0.52 W left the table off the estimate's worst-case path; it searched the same blocks.
  - **Latency:** hairpin as in Section 4.1, 3 runs of 1,010 probes per build, none missing, baseline 246 ns the same
    day. The table costs nothing measurable; the first version's 12th stage cost 19 cycles and 16 ns.
- **Capacity.** With the direct counter the Wedge takes 1,023 entries: the 1,024th add fails with `RESOURCE_EXHAUSTED`,
  and BF Runtime keeps the entries of the batch before it. Without the counter all 1,024 fit. 1,023 entries are written
  in one request in 183-187 ms. Read from the hardware each entry with its counter costs 51 ms; one `SyncCounters`
  operation and a read from software list all 1,023 in 0.6 s.
- **Line rate** (Section 3.2's 27-run matrix, `--window-totals`, both versions): the same rates as exact v3 at every
  size, lossless, the window totals exact for 18.0 billion packets per matrix. With the table full of entries that match
  nothing, the 1518 B paced and maximum runs and the 64 B maximum runs give the same rates again, and nothing is
  blocked.
- **The windows are unchanged.** Ten distinct captures (Chaos, the floods and calm runs) through each version, with and
  without entries, give every window equal to the exact build's in all 27 non-duration features, and every
  collector-path replay's self-check is exact (44 of 44 windows). The packets dropped by the rule are still counted.
- **The block on the switch** (replays into port 132, a 132 -> 132 hairpin so that PC1 captures what passed):
  - **Timing:** one entry is written in 1.5-2.4 ms on the switch and 3-5 ms from the collector's request.
  - **Exactness:** every frame from the blocked host sent after the reply is dropped, the frames toward it pass, and
    `blocked_pkts` equals the frames dropped exactly. In `bulk2000`, 9,849 frames were sent after the reply, and all
    were dropped and counted on the host's entry.
  - **Port block:** a port entry drops everything entering port 132 from the write on. A frame that matches both
    entries counts on one, so the host's frames counted on the host entry (9,873) and the replies toward it on the port
    entry (9,874); together they are the 19,747 of `blocked_pkts`.
  - **A second client:** it can add entries while the collector's reader owns the program. It must use another BF
    Runtime client id; with the same id it cannot subscribe.
- **Time to containment** (real network verdicts on 7 replays, each capture's group held out of the training, both
  versions):
  - **Alarms:** all 4 attacks alarm on their first 0.5-s window (p 0.871-0.983), 200-316 ms after it ends. That delay
    is the reader's read and the forest's 80-145 ms of scoring on PC1.
  - **Drops:** the host block then drops 36-58% of the attacker's frames. Only `syn_fan_40k`'s flood is over before
    the block (0%).
  - **False alarm:** `dns_10k` (benign) alarms on window 0 (p 0.700), so 32-37% of its frames are dropped.
- **Live** (PC1.md 11F and part 11c):
  - **The host block, the default,** stops everything from the host. The entry was in place 3.0-3.3 ms after the
    alarm, PC2 accepted no connection from the host afterwards, and every later connection attempt was dropped (11 and
    4 SYNs, equal to `blocked_pkts`). Another program on the same host was cut off too: the switch sees addresses, not
    programs.
  - **Blocking only the flagged program's flows does not stop it** when it opens short connections. Each flow is
    blocked one window after it appears, so every connection ended before its entry was written, and nothing was
    dropped. A long session (`interactive`) was cut.
  - **Verdict timing:** the stacked detector's verdict came a median 270-275 ms after its window on PC1, about 160 ms
    of it scoring.
- **The final build on all 109 captures** (PC1.md part 12A):
  - **Replays:** every replay exact.
  - **Rows:** 102 of 109 equal the published rows in all 135 non-duration columns (mean 131.86); all 109 equal the
    exact build's.
  - **Detection** (the network detector without each capture's group): all 67 attacks alarmed, 53 at the first
    window, a median 213 ms after the window's end.
  - **Containment:** the host block caught on average 82% of a malware run's frames and 48% of a flood's (2-87%).
  - **False alarms:** 11 of 42 benign runs (ftp, telnet, DNS).
- **Shorter windows** (part 12B):
  - **The data plane takes any window length:** the markers or the timer set it.
  - **The reader on the switch does not:** its cycle is about 100 ms per window (a read of 37-40 ms, a clear of 4 ms).
    At 0.25 s every window is exact (80 of 80, none lost); at 0.1 s it falls a window behind (47-200 of 200 windows
    exact).
  - **For 0.1 s:** a faster reader, or more than two banks, would give the reads more slack.
  - **What shorter windows buy, offline** (the network detector retrained on the 110 captures at each length):
    accuracy does not change (balanced accuracy 0.83-0.84), and the first alarm comes one window in. The host block
    would catch on average 55% (0.5 s), 71% (0.25 s) and 83% (0.1 s) of a flood's packets, with the block 50 ms after
    the alarm.
- **Live attacks through the whole loop** (part 12D/E): `hping3` floods from the monitored host.
  - **Detection:** a SYN flood, a UDP flood and a port scan were each alarmed at window 0, with the original and with
    the recalibrated detector. The alarm came 274-381 ms after the window's end and the block 2.9-3.7 ms later.
  - **Drops:** the switch dropped 71-85% of the attack packets, and the rest reached the target exactly as counted.
  - **Recalibration:** with the detectors also trained on 74 live benign runs, live benign false alarms fell from
    56.8% to 2.7% (stacked, cross-validated), and the 7 live workloads alarmed none.

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
  that report an overhead over forwarding, and this work's +70 ns lies in that range, as
  do the +91 ns of the build with Section 5.4's counter under the reference method
  (Section 4.1).
  The others report absolute times of 365 ns to 2 µs, over different intervals. Here it
  is 321–404 ns from ingress parser to egress parser.
- **Stages.** This work uses 5, or 7 with Section 5.4's counter. Every system with per-flow state that reports its stages
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
  (Planter, IIsy). This work: 99.9% of line rate (99.88 Gbps) per 100G port with no loss
  at 128–1518 B, with the switch's own generator like NetWarden and P4Control; at 64 B
  that generator stops at 91% (Section 3.2).

| System | Venue | Switch | In the switch | Flows (state per flow) | Stages | SRAM / TCAM | Stateful ALUs | Latency | Throughput |
|---|---|---|---|---|---|---|---|---|---|
| **This work** | – | Tofino 1, Wedge100BF-32X | per-flow features; detection off the switch | 65,536 (45 B) | 5 ingress (7 with Section 5.4) | 20.5% / 1.0% | 14 of 48 (29.2%) | +70 ns over forwarding (ASIC timestamps); 321–404 ns parser to egress parser; +91 ns with Section 5.4 (reference method) | 99.9% of 100G line rate, no loss (on-switch generator, 128–1518 B; 91% at 64 B) |
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
- Line rate with no loss, measured as NetWarden and P4Control did (Section 3.2), and the
  latency under the method of the DNS water-torture detector (Section 4.1).
- Counting is exact at line rate (Section 3.2). The compiled hash matches software bit
  for bit, so the offline collision numbers of Section 5.2 hold for the switch.

**Line rate: done** (Section 3.2), with the switch's own packet generator, as NetWarden
and P4Control did ("software packet generators cannot saturate the switch linespeed",
NetWarden). The pass criterion, generated = the detector's register count = transmitted
with zero drops, holds at 99.9% of line rate for 128–1518 B. No wrapper was needed: the
generator's header replaces the destination MAC, which the detector does not read.

**Open:**
- the Section 4.1 runs on the reference's path, with the collector on PC2;
- 64-B line rate, which needs an external generator (one pipe's generator stops at 91%).

Optional:
- the line-rate test with every packet a new flow, so that the CPU reports overflow, to
  show that forwarding is unaffected (needs distinct 5-tuples, which the generator
  cannot make);
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
- latency per frame size (Sections 4 and 4.1);
- the line-rate result (Section 3.2);
- 6–8 rows of the comparison table (Section 7).

Section 6 measures the switch CPU, not the P4 program, and can be left out.

## 9. Limitations

- **Throughput** was measured for one flow from the switch's generator: 99.9% of line
  rate at 128–1518 B and 91% at 64 B, the generator's limit (Section 3.2). PC1 alone
  reaches ≤ 4% (Section 3.1).
- **Latency** covers ingress parser to egress parser in instrumented copies, at low rates
  without queueing.
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
  - 64-B line rate (Section 3.2);
  - TCP/UDP throughput with iperf3 and RTT with ping, which would measure PC1;
  - the collision rate on the switch over several flow counts. One point was measured
    (Section 5.2); the other numbers are offline, with the verified compiled hash.

- **The exact build (Section 5.7)** removes several of these: it parses VLAN tags, IPv4 options and fragments
  as the dataset's model does; it decides direction by address and port; it takes durations from a 48-bit clock
  (65.536 µs units). Its own limits (`perf/variants/exact/README.md`):
  - **The flow table holds every flow of a run (65,536 slots, no aging).** A flow without a slot is counted in
    the totals and reported per window, but not in the flow features. 5 floods of the dataset exceed it.
  - **Every pipe has its own window clock.** The reader leaves out, and reports, the packets of a pipe whose
    clock lags. With markers, only the pipe of the marker port has a clock. With a timer on each pipe, the
    pipes are combined if their ticks are less than 50 ms apart; the timers started back to back are 1 ms
    apart. With the timer (`--window-markers timer`), the switch's windows drift against the host's by the two
    clocks' rate difference: under 40 ppm on the Wedge, about 1 ms over a 27 s run, so long runs drift
    further.
  - **A window must be read within one window of slack**, or it is marked lost.
  - **11 ingress stages:** 421 ns of latency against 315 ns.
  - **No per-flow counters**, so the live test's socket-level join still needs `basic_fix`.

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
| 3.2 (line rate) | load the build; on the switch `python2.7 sw_pktgen_run.py OUT.json --prog basic --size S [--rate-pct 99.9] --seconds 10 --flow-index 44993` (the run's `matrix.sh` covers all sizes); `pktgen_summary.py RUN_DIR LABEL` |
| 4 (latency) | sources from `perf/variants/lat/make_lat_sources.sh`; `run_lat.py RUN_DIR --prog basic_lat`, then `--prog baseline_lat` |
| 4.1 (reference method) | `perf/variants/hwl/make_hwl_sources.sh thesis-hybrid-ebpf-p4 OUT_DIR`, compile `basic_hwl` and `baseline_hwl`; the run's `hwl_hairpin_runs.sh RUN_DIR BUILD PROG 3`; on the reference's path, `reference_evaluation/P4_Code/scripts/send_probes.py` on PC1 and `collect_reports.py` on PC2 |
| 5.2 (hash quality, offline) | `hash_quality.py [--sizes 20000,50000]` |
| 5.3 (fingerprint build) | `perf/variants/fingerprint/make_fp_sources.sh thesis-hybrid-ebpf-p4 OUT_DIR`, compile as above, `hash_block_identify.py BUILD_DIR` |
| 5.3 (on the switch) | `fp_test.py make OUT_DIR SANITY_PCAP`; clear with `clear-regs --extra-registers reg_fp,reg_shared`; replay at 100 pkt/s while capturing `enp5s0`; `read-regs … --extra-registers reg_fp,reg_shared`; `fp_test.py check` |
| 5.3 (latency) | `make_lat_sources.sh` on both source trees (main files renamed `basic_fix_lat.p4`, `basic_fp_lat.p4`); `run_lat.py RUN_DIR --prog basic_fix_lat --sizes 64,1518`, then `--prog basic_fp_lat` |
| 5.4 (new-conn builds) | `sw_compile.sh` on `thesis-hybrid-ebpf-p4` (16,384 buckets: `src/basic_newconn_16k` of the run); `parse_resources.py`; `hash_block_identify.py BUILD_DIR` (16,384: the run's `check14.py`) |
| 5.4 (on the switch) | `newconn_test.py make OUT_DIR [--index-bits 14]`; the run's `hw_cycle.sh RUN_DIR BUILD EXPECTED_JSON 65536\|16384` (load, set up, clear, capture, replay, read, check); then restore the fixed build |
| 5.4 (offline parity) | the run's `offline_parity.py`, with Python ≥ 3.10, scikit-learn and scapy |
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
| 3.2 | `pktgen_20261029_123642` |
| 4 | `p2_5_lat_compile_20261026_154902` (design, builds), `p2_5_lat_20261026_155720` |
| 4.1 | `hwl_20261029_112932` |
| 5.1 and Appendix A (patch, files before and after, builds, hash checks) | `fix_20261026_174315` |
| 5.1 and Appendix A.2 (validation on the switch) | `fix_hwval_20261026_190643` |
| 5.3 (sources, builds, resources, hash check, switch test) | `fp_20261026_201808` |
| 5.3 latency | `fp_lat_20261026_204335` |
| 5.4 (sources, builds, resources, hash checks, switch tests, offline parity) | `newconn_20261027_090913` |
| 5.5 (sources, builds, resources, placement, hash checks, line rate, latency) | `nonewconn_20261031_094244` |
| 6.1, and clear and re-report | `p3_3_reports_20261026_192142` |
| 6.2 | `p3_readout_20261026_164647` |

The `*_smoke_*` directories hold short checks of the tools before each test.

Only the per-probe latencies of the hairpin runs are tracked by git, as
`RUN/BUILD_hairpin_rN/packet_latencies.csv` and `summary.json`, the output of
`collect_reports.py`:
- **Builds:** in `hwl_20261029_112932` (Section 4.1, with the counter), `basic_hwl` and
  `baseline_hwl`. In `nonewconn_20261031_094244` (Section 5.5, the paper's build),
  `basic_hwl_nonewconn` and `baseline_hwl_nonewconn`.
- **Rows:** one per probe, 1010 per run: `seq`, `qname`, `ingress_ns` and `egress_ns` (ASIC
  timestamps), `latency_ns` = `egress_ns` − `ingress_ns`, `score`, `tier`, and
  `original_sha256` (of the probe as sent).
- **Warm-up:** probes 0–9 are warm-up and excluded from the statistics in `summary.json`.

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

28 unit tests (`cd thesis-hybrid-ebpf-p4/python && python3 -m unittest discover -s tests`)
cover:
- the CRC-16/ARC check value, symmetry, and a vector from the compiled hash;
- both report formats and the tcpdump stream parser;
- the reader's embedded script, run with SDE 9.6 semantics (no f-strings, separate
  globals/locals);
- pipe combining, the sync fallback, clearing, and bfshell's held-open stdin;
- live window deltas, active-index refresh, idle clearing and the timestamp wrap;
- the new-connection index (vectors from the compiled hash), the reader's destination
  buckets and the collector's `net_new_conn_dst_max` (Appendix A.4).

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

### A.4 New-connection counter (Section 5.4)

| File | Change |
|---|---|
| `python/flow_index.py` | `compute_newconn_dst_index()`: CRC-16/ARC over sip, dip, dport and protocol |
| `python/read_registers_with_index.py` | `--dst-indexes`: reads `reg_newconn_dst` in the same session and sync as the flow registers and returns `dst_rows`. It is never cleared. A build without the register gives an error entry, not a failure |
| `hybrid_collector.py` | One destination bucket per TCP report, kept active like a flow bucket (TTL, or while its count changes); writes `net_new_conn_dst_max` |
| `analyze_p4_pcap_ablation.py` | The same feature offline: per window, SYN-without-ACK segments per (src, dst, dport, protocol), maximum over the keys; added to `P4_FEATURES` |
| `evaluate_*.py`, `score_balanced_in_sample.py` | Messages and descriptions use `len(P4_FEATURES)` instead of a fixed 29 |
| `../p4_ebpf-dataset-construction/src/analyze_p4_emulated_scenarios.py` | Contract entry for the new column (it requires its contract, `NET_ZERO` and `P4_FEATURES` to match) |
| `commands.txt` | The clear list includes `reg_newconn_dst` |
| `perf/tools/hash_block_identify.py`, `perf/tools/newconn_test.py` | Candidate for the new index; the hardware test |

`analyze_p4_pcap_ablation.py` here is older than the version `tests/test_pcap_window_alignment.py`
expects (`byte_layer`, `rate_window`); the change is four small hunks to carry over.

## Appendix B. Errata

- An earlier note claimed the collector's `crc16_tofino()` is not CRC-16/ARC. It is: it
  reflects every input byte and the result. The mismatch was only the input (symmetric
  blob vs raw 5-tuple).
- The Phase 2.1 note named bucket 48121 as the collector's choice for the test
  connection. It is 31246, computed with a corrected copy of the function. That bucket
  was empty too, so the conclusion is unchanged.
