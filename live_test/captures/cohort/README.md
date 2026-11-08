# Cohort captures for the replays through the switch (RUNBOOK 19.7.3)

These are the 77 captures of RUNBOOK 19.7.3, for step 2 of 19.5.7: replay each one through the
Wedge100BF-32X at 1 s windows and compare the switch's windows with the offline extractor. The
packager is `live_test/package_cohort.py`, run on the lab workstation, where the collections are.

## What is here

| file | content |
|---|---|
| `<execution_id>.pcap` | 77 captures: 52 malware, 25 benign (38 + 19 training, 14 + 6 test) |
| `manifest.csv` | one row per capture, in `dataset/features.csv` order, with the overloading run last |
| `not_replayed.csv` | the other 127 of the 204 runs: no IPv4 TCP/UDP packet in their observation, so their switch windows are zero |
| `rule_effects.csv` | per capture, how many 1 s windows each switch rule alone changes compared with the published extractor |
| `checks.json` | the packager's checks per run, and the hashes of its inputs |
| `SHA256SUMS` | every file in this folder |

The captures total 22 MB, 224,158 frames.

## Where they come from

- **Runs:** the 204 malware and CLI-benign executions of the release's `dataset/features.csv`
  (rows 0-203). Every one is a run of `revision5-collection/20261025T100025568989Z`: runner schema
  `2026-10-24.21`, 0.5 s windows, 40 windows, a fixed 20 s observation.
- **The 36 other rows are left out:** 15 DoS runs, 18 network-active benign runs and 3 nulls stay
  offline (RUNBOOK 19.6).
- **Each capture is tied to its dataset row:** the published extractor (`features/switch_model.py`,
  0.5 s, 40 windows) on each original capture reproduces its row's 145 network columns, all 204
  runs, to a relative difference of 1.7e-15.
- **Inputs:**
  - `features.csv`: `6d15da30a4bc1b9bcea47bce1b96c00f74ae5ddadd68255a17ed5d0b46c19c16`
  - the 240-row pool that names each row's run directory: `5c71c08f3257b59ff4f3970bd9848a88095bbc256c826b7ea148c8f8bc234248`
  - release `switch_model.py`: `d5a140fd5cda04afc9e6d73a28da354146ed184c9b381ca4d89a20543791eb80`

## How they were made

1. **The replay set:** the runs with any IPv4 TCP/UDP packet in the observation
   [anchor, anchor + 20 s). The anchor is `sample_started_wall_us`, in whole microseconds, and
   the runner bins packets the same way. That gives 77 runs, as 19.7.3 expected.
2. **Trimmed to the observation:** the capture probes before and after it, the ARP frames and the
   1 s drain are dropped.
3. **Sanitized:**
   - only IPv4 frames are kept;
   - each frame keeps its Ethernet header, its IPv4 header and its TCP header (to its data
     offset) or UDP header, and at least the 20 (TCP) or 8 (UDP) bytes the parser reads at
     byte 34;
   - every later byte is zero, and every length and timestamp is kept;
   - the TCP/UDP checksum is recomputed (a UDP checksum of 0 stays 0).

## Checks (all passed)

**The packager's own checks:**
- **Same features from both captures:** the switch-exact model (below) gives the same features in
  every window on the original and the sanitized capture, at 1 s (20 windows) and 0.5 s (40). So
  does the published extractor.
- **The 127 runs outside the replay set** are all zero under the switch rules as well.
- **The model with every switch rule off** equals the published extractor window by window, on
  all 204 runs.
- **Totals:** under the switch rules, the window sums equal the packets and IPv4 bytes in every
  capture.

**Separately, with other parsers:**
- **scapy:** all 224,158 frames have the original's timestamp and length, headers equal to the
  original apart from the checksum, nothing non-zero after the transport header, and a valid
  TCP/UDP checksum.
- **strings:** the originals hold 515 printable strings of 8 or more characters (HTTP, host
  names). These captures hold 2, both from random header bytes, and no HTTP request, `Host:`
  line or domain name.

The captures carry no payload. What is left are headers, the sandbox addresses (10.0.0.x) and the
scan targets of the scanning malware.

## The manifest

The columns of RUNBOOK 19.7.3:

| column | meaning |
|---|---|
| `execution_id` | the key in `dataset/features.csv` |
| `run_id` | the collection run (`run_<UTC>` under `runs/<sample>/output/`), to pair the capture with its eBPF windows |
| `category`, `label`, `cv_group` | as in `features.csv` |
| `capture` | the file in this folder |
| `sha256_original` | the original `packet_capture.pcap` |
| `sha256` | the file in this folder |
| `anchor_us` | `sample_started_wall_us`, the start of dataset window 0 |
| `first_frame_us` | the original capture's first frame (the pre-window probe, 0.94-1.27 s before the anchor) |
| `anchor_offset_s` | the anchor minus the first frame of this capture, between -5.08 and -0.003 s. Pass it as `--anchor-offset`. |
| `ipv4_packets` | the frames in this capture; all are IPv4 TCP/UDP here |
| `expect_overload` | 1 if a 1 s window has more than 1,000 active buckets under the switch rules |

Additional columns:

| column | meaning |
|---|---|
| `first_kept_frame_us` | this capture's first frame |
| `tcpudp_packets` | the packets the registers count |
| `flow_buckets`, `colliding_buckets` | CRC-16 buckets used, and those shared by more than one flow |
| `max_active_buckets_1s` | the largest active set in a 1 s window |
| `family`, `project`, `program`, `mode`, `split` | as in `features.csv` |

## What to expect on the switch

**Overload:** one run, the Chaos scanner `d538053a...`. It has 221,733 packets, 30,449 buckets
(14,899 of them shared by colliding flows) and up to 16,422 active buckets in a 1 s window. It is
the last row of the manifest; replay it last and report it on its own (19.7.3). The next busiest
run, Mirai `07146515...`, has at most 120 active buckets.

**What each switch rule changes:** this is each rule alone at 1 s, compared with the published
extractor at 1 s. There are 961 windows with traffic across the 77 runs.

| rule | runs | windows | why |
|---|---|---|---|
| 1 lengths | 77 | 961 | IPv4 `totalLen` against the Ethernet frame: 14 B less per packet, and no padding |
| 2 parsing | 0 | 0 | the captures have no VLAN tags, IPv4 options or fragments |
| 3 key | 1 | 20 | CRC-16 collisions: the Chaos run only |
| 4 direction | 0 | 0 | no flow has sport = dport |
| 5 time | 34 | 358 | durations past 4.295 s alias. A further ~0.2 us difference in every window is only the published extractor's float-seconds rounding. |
| 6 idle | 26 | 126 | connections idle for 3 s or more restart as new flows after the idle clear |

## Replaying

From the p4_ebpf root on PC1, in manifest order:

```sh
# columns 1, 6 and 11: execution_id, capture, anchor_offset_s (no field contains a comma)
tail -n +2 live_test/captures/cohort/manifest.csv | cut -d, -f1,6,11 | while IFS=, read -r eid cap off; do
  sudo python3 live_test/replay_capture.py live_test/captures/cohort/"$cap" \
      --out perf/results/replay_cohort/"$eid" --anchor-offset "$off" --align-window 2 < /dev/null
done
```

- **Window mapping:** collector window 2 + j is dataset window j, for j = 0..19.
- **What to commit (19.7.4):** `windows.csv`, `summary.json` and `compare.json` go under
  `perf/replay_cohort/<execution_id>/`. The other files stay in the git-ignored results folder
  unless the run fails a check.

## The switch-exact model in the packager

`package_cohort.SwitchRules` implements RUNBOOK 19.7.2's six rules (each one switchable) and the
collector's readout:
- the active set is the buckets changed in the last 3 windows;
- each bucket's registers are compared with its previous read;
- the idle clear happens after 3 unchanged reads.

It is the packager's own implementation, written for these checks. When the release's
`--switch-exact` mode exists, run both on these captures and compare.
