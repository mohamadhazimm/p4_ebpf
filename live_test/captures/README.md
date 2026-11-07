# Dataset captures for replay through the switch

Two packet captures from the thesis dataset's runs, for replaying from PC1 into the
Wedge100BF-32X (RUNBOOK.md Sections 11.2 and 13.4), each with its ground truth in the
format of `make_benign_pcap.py --truth`, so `analyze_run.py --truth` reads it.

| file | what | SHA-256 |
|---|---|---|
| `bulk2000.pcap` | benign: a download loop to the lab's HTTP server | `daf6aa89a4bd48fd17938d1c2b5e153bb800eee30dbf3ba0e54f0cdd3b8df5f7` |
| `syn_fan_40k.pcap` | attack: a SYN fan-out flood | `787dac854e76ad6c42263ce4a30f401e0f0c739a363ce204568112147057265d` |
| `*_truth.json` | ground truth of each capture (`pcap_truth.py`) | |

## Where they come from

Both were captured by the dataset collector (runner schema `2026-10-24.21`) on the
interface of the monitored guest (`10.0.0.10`), in the isolated lab network whose only other
host is the emulated internet server `10.0.0.1`. The traffic comes from the lab's own
generator (`flood_gen`), not from malware. They are the runs `bulk2000` (attempt
`flood21-collect/20261026T151240756153Z`, run `run_20261026T152044Z_flood_gen`) and
`syn_fan_40k` (attempt `flood21-collect/20261026T154421063760Z`, run
`run_20261026T154521Z_flood_gen`) of the 240-run dataset, copied byte for byte. Each
capture also holds the collector's two capture probes (a TCP connection attempt to
`10.0.0.1:80` before and after the observation) and a few ARP frames.

## What is in them

| | `bulk2000.pcap` | `syn_fan_40k.pcap` |
|---|---|---|
| frames / IPv4 TCP packets | 24,010 / 24,008 | 40,212 / 39,863 |
| length | 22.2 s | 23.3 s |
| traffic | 2,002 HTTP connections from `10.0.0.10` to `10.0.0.1:80` (1,830 distinct 5-tuples, as source ports are reused), ~1,100-1,400 packets/s for 19 s | 39,855 SYNs from `10.0.0.10` to 29,888 addresses in `10.0.1.5`-`10.0.255.255`, port 23, **within 0.70 s (57,000 per second)**; the rest of the capture is idle |
| frame sizes | 60-324 B | 74 B |
| flow buckets (`flow_index`) | 1,830, none shared | 29,843; 8,163 of them shared by 18,177 flows |
| per 1 s window (from the first packet; 3-window TTL) | up to 116 new and 456 active buckets | up to 28,501 new and 29,843 active buckets |
| totals the data plane counts | pkts 24,008, bytes 2,184,448, pkts_ab 12,006, bytes_ab 728,328, SYN 4,004, ACK 22,006, RST 2 | pkts 39,863, bytes 2,391,748, SYN 39,859, ACK 6, RST 2 |

Bytes are IPv4 totalLen, as `ingress.p4` counts them. `pkts_ab` follows the direction of each
flow's first packet as `ingress.p4` decides it (ports compared). Where flows share a bucket,
the registers add them up and the direction follows the bucket's first packet: the truth
gives both `totals` (per flow) and `totals_bucket_model` (per bucket, equal to the switch's
sums when no shared bucket is cleared between its flows). For `bulk2000` no bucket is
shared, so every total is exact. `syn_fan_40k` lists no flows (39,857 would be megabytes),
only the totals and the bucket and window figures.

## Replay from PC1

Use the collector command of RUNBOOK Section 11.2 (`--profile switch`, `--switch-ssh`,
`--cpu-iface enp5s0`, ...), each with its own `--out-csv` and `--reader-timing-file`, and
these scenario commands:

```sh
# (b) heavy benign traffic at its original timing (22 s)
tcpreplay -i eth1 live_test/captures/bulk2000.pcap
# (c1) the SYN flood spread to 2,000 packets/s (20 s), comparable to the stand-in of Sections 12-13
tcpreplay -i eth1 --pps 2000 live_test/captures/syn_fan_40k.pcap
# (c2) the SYN flood at its original timing: 0.70 s at 57,000 SYNs/s, then idle
tcpreplay -i eth1 live_test/captures/syn_fan_40k.pcap
```

What to expect:

- **(b):** no overload and no overrun (about 65 + 456 x 0.62 ms ≈ 350 ms per read), and the
  CSV sums of pkts, bytes, pkts_ab, bytes_ab, SYN, ACK and RST equal `totals` exactly. The CPU
  reports lie between 1,830 and 2,002: a reused 5-tuple reports again when its bucket was
  cleared between the two connections.
- **(c1):** as in Section 13 (`net_overload` 1, buckets cleared from window 4 on, the end-of-run
  clear), with the dataset's real flows. CPU reports at least 29,843 (the distinct buckets;
  more where a cleared bucket is hit again).
- **(c2):** one window with ~28,500 new buckets. This is above the 50,000 new flows/s at which
  the CPU-report path was measured lossless, so fewer reports than buckets measures that
  path's loss. The collector stamps a report when it parses it, so reports of the burst may
  land in the next window. Afterwards the clear backlog drains (~4,000 unconditional clears
  per 1 s window on the raw route), and the occupancy after the run should be ~0.
- After (c1) or (c2), (d) as in Section 13 (`ab_mix.pcap` x59 with `--no-register-reset`)
  should report all 2,768 flows.

## Regenerating the truth

```sh
python3 live_test/pcap_truth.py live_test/captures/bulk2000.pcap --truth live_test/captures/bulk2000_truth.json
python3 live_test/pcap_truth.py live_test/captures/syn_fan_40k.pcap --truth live_test/captures/syn_fan_40k_truth.json
```

The totals agree with an independent scapy pass over both captures.
