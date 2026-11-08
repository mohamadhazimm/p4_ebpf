#!/usr/bin/env python3
"""Package the cohort captures for the replays through the switch (RUNBOOK 19.7.3).

    python3 live_test/package_cohort.py --runs REV5/runs --pool POOL.json --release RELEASE_DIR \
        --out live_test/captures/cohort

  --runs     the revision5 collection's runs/ directory (one directory per execution, as collected)
  --pool     the 240-row pool in features.csv order (paper-check-20261028/independent_pool.json): its
             "sample" field names each row's run directory
  --release  a checkout of p4-ebpf-malware-detection (dataset/features.csv, features/switch_model.py,
             p4/control_plane/flow_index.py)

For the 204 malware and CLI-benign executions of dataset/features.csv (rows 0-203):

 1. The published extractor (features/switch_model.py, 0.5 s, 40 windows) on the run's capture must
    give the row's 145 network columns, so that every capture is tied to its dataset row.
 2. The replay set is the runs with any IPv4 TCP/UDP packet in the observation [anchor, anchor + 20 s),
    anchor = run.json sample_started_wall_us (whole microseconds; the runner bins packets the same way).
 3. Each replay capture is trimmed to the observation and sanitized: IPv4 frames only; in each frame
    the Ethernet header, the IPv4 header with options, the TCP header to its data offset or the UDP
    header, and at least the 20 (TCP) or 8 (UDP) bytes the parser reads at byte 34 are kept; every
    later byte is zeroed, every length kept, the TCP/UDP checksum of complete unfragmented datagrams
    recomputed (a UDP checksum of 0 stays 0). The switch reads nothing past those bytes.
 4. Checks (all must hold, else the run is reported and the packager exits 1):
    - the switch-exact model (below) gives the same features in every window, at 1 s (20 windows)
      and 0.5 s (40), on the original and on the sanitized capture; so does the published extractor;
    - runs outside the replay set come out all zero under the switch-exact model as well;
    - the model with every switch rule off equals the published extractor window by window.

The switch-exact model (SwitchRules) implements RUNBOOK 19.7.2's six rules, each switchable:
  1 lengths   IPv4 totalLen for bytes, min_len and max_len (ingress_parser.p4: meta.pkt_len)
  2 parsing   EtherType at byte 12 only, a fixed 20-byte IPv4 header, TCP/UDP at byte 34, no fragment
              check; frames under 60 B are zero-padded as on the wire
  3 key       the CRC-16 bucket (flow_index.py); colliding flows merge
  4 direction the bucket's first packet's (sport, dport); A->B if equal, B->A if swapped, else A->B
  5 time      low 32 bits of a ns clock; duration = (last - first) mod 2^32, in seconds
  6 idle      a bucket with no packet in windows s+1..s+3 is cleared after the read of window s+3
and the collector's readout (hybrid_collector.collect_windows_live + NetSummarizer): the active set
is the buckets changed in the last 3 windows (4 reads), the window's deltas are each bucket's
registers minus its previous read, a ratio over 0 is 0. Offline every active bucket is read, so the
unconditional clear of expired buckets never applies. It is the packager's own implementation for
these checks; compare it with the release's --switch-exact mode once that exists.

Outputs in --out: <execution_id>.pcap (the replay set), manifest.csv, not_replayed.csv,
rule_effects.csv, checks.json, SHA256SUMS. Standard library only.
"""
import argparse
import csv
import glob
import hashlib
import json
import math
import struct
import sys
from decimal import Decimal
from pathlib import Path

OBS_US = 20_000_000
TTL = 3
IDLE = 3
OVERLOAD_BUCKETS_1S = 1000      # RUNBOOK 19.6.1 item 4: above roughly this many active buckets a 1 s read is budgeted
RULES = ("lengths", "parsing", "key", "direction", "time", "idle")

MANIFEST_COLUMNS = [
    "execution_id", "run_id", "category", "label", "cv_group", "capture", "sha256_original", "sha256",
    "anchor_us", "first_frame_us", "anchor_offset_s", "ipv4_packets", "expect_overload",
    # additional columns
    "first_kept_frame_us", "tcpudp_packets", "flow_buckets", "colliding_buckets", "max_active_buckets_1s",
    "family", "project", "program", "mode", "split",
]


# ------------------------------------------------------------------ pcap

def read_pcap(path):
    """(header bytes, [(sec, usec, origlen, frame)]) of a classic microsecond pcap with Ethernet framing."""
    with open(path, "rb") as f:
        head = f.read(24)
        if head[:4] != b"\xd4\xc3\xb2\xa1":
            raise ValueError("%s: expected a little-endian microsecond pcap" % path)
        if struct.unpack("<I", head[20:24])[0] != 1:
            raise ValueError("%s: not Ethernet" % path)
        records = []
        while True:
            r = f.read(16)
            if len(r) < 16:
                break
            sec, usec, cap, orig = struct.unpack("<IIII", r)
            frame = f.read(cap)
            if len(frame) != cap:
                raise ValueError("%s: truncated record" % path)
            records.append((sec, usec, orig, frame))
    return head, records


def write_pcap(path, head, records):
    with open(path, "wb") as f:
        f.write(head)
        for sec, usec, orig, frame in records:
            f.write(struct.pack("<IIII", sec, usec, len(frame), orig))
            f.write(frame)


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# ------------------------------------------------------------------ sanitizing

def _csum(data):
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def l4_checksum(frame, l3, total, proto):
    """The TCP/UDP checksum over the IPv4 pseudo-header and the datagram as it stands in the frame."""
    seg = bytearray(frame[14 + l3:14 + total].ljust(total - l3, b"\x00"))
    pos = 16 if proto == 6 else 6
    seg[pos:pos + 2] = b"\x00\x00"
    pseudo = frame[26:34] + struct.pack("!BBH", 0, proto, total - l3)
    c = _csum(pseudo + bytes(seg))
    return 0xFFFF if (c == 0 and proto == 17) else c


def sanitize(frame):
    """The frame with every byte the switch does not read zeroed (lengths kept), or None if not IPv4."""
    if len(frame) < 34 or frame[12:14] != b"\x08\x00":
        return None
    l3 = max(20, (frame[14] & 0x0F) * 4)
    total = (frame[16] << 8) | frame[17]
    proto = frame[23]
    frag = ((frame[20] & 0x1F) << 8) | frame[21]
    more = frame[20] & 0x20
    keep = 14 + l3
    if proto == 6:
        doff = (frame[14 + l3 + 12] >> 4) * 4 if (frag == 0 and len(frame) > 14 + l3 + 12) else 20
        keep = max(keep, 14 + l3 + max(20, doff), 34 + 20)
    elif proto == 17:
        keep = max(keep, 14 + l3 + 8, 34 + 8)
    keep = min(keep, len(frame))
    out = bytearray(frame[:keep]) + bytearray(len(frame) - keep)
    if proto in (6, 17) and frag == 0 and not more and l3 + (20 if proto == 6 else 8) <= total:
        pos = 14 + l3 + (16 if proto == 6 else 6)
        if pos + 2 <= len(out):
            if proto == 17 and out[pos:pos + 2] == b"\x00\x00":
                pass                    # UDP without checksum
            else:
                out[pos:pos + 2] = struct.pack("!H", l4_checksum(bytes(out), l3, total, proto))
    return bytes(out)


# ------------------------------------------------------------------ the switch-exact model

class SwitchRules:
    """Window features of a capture under the switch's rules (each of the six switchable)."""

    def __init__(self, release, window_seconds, windows, rules=RULES, ttl=TTL, idle=IDLE):
        self.sm, self.crc = release
        self.window_seconds, self.windows = window_seconds, windows
        self.window_us = int(round(window_seconds * 1_000_000))
        self.rules = set(rules)
        unknown = self.rules - set(RULES)
        if unknown:
            raise ValueError("unknown rules %s" % sorted(unknown))
        self.ttl, self.idle = ttl, idle

    # one packet -> (key, src endpoint, ports, proto, flags, length) or None
    def parse(self, frame):
        r = self.rules
        if "parsing" in r:
            f = frame if len(frame) >= 60 else frame + bytes(60 - len(frame))
            if f[12:14] != b"\x08\x00" or f[23] not in (6, 17):
                return None
            proto = f[23]
            sip, dip = f[26:30], f[30:34]
            sp, dp = (f[34] << 8) | f[35], (f[36] << 8) | f[37]
            flags = ((f[46] & 0x01) << 8 | f[47]) if proto == 6 else 0
            total = (f[16] << 8) | f[17]
        else:
            p = self.sm.parse_flow_packet(frame)
            if p is None:
                return None
            src, dst, proto, (sp, dp), flags = p
            sip, dip = bytes(map(int, src.split("."))), bytes(map(int, dst.split(".")))
            off = 14
            while (frame[off - 2] << 8 | frame[off - 1]) in (0x8100, 0x88A8):
                off += 4
            total = (frame[off + 2] << 8) | frame[off + 3]
        length = total if "lengths" in r else len(frame)
        if "key" in r:
            key = self.crc(struct.unpack("!I", sip)[0], struct.unpack("!I", dip)[0], sp, dp, proto)
        else:
            key = (proto, *sorted(((sip, sp), (dip, dp))))
        return key, (sip, sp), (sp, dp), proto, flags, length

    def run(self, records, start_us):
        """records: [(sec, usec, origlen, frame)] in time order. Returns a list of per-window dicts."""
        r = self.rules
        buckets = {}          # key -> registers
        order = {}            # first-seen order of keys (exact-key mode iterates in it, as switch_model does)
        last_change = {}      # key -> window of its last packet
        prev = {}             # key -> registers at its previous read
        out, current = [], 0
        mask = (1 << 32) - 1

        def read(w):
            rows = sorted(last_change) if "key" in r else [k for k in order if k in last_change]
            rows = [k for k in rows if 0 <= w - last_change[k] <= self.ttl]
            feats = dict.fromkeys(self.sm.FEATURES, 0)
            if not rows:
                return feats
            mins, maxs, durs = [], [], []
            tot = dict.fromkeys(("p", "b", "pa", "ba_", "pb", "bb", "syn", "ack", "rst"), 0)
            for k in rows:
                s, q = buckets[k], prev.get(k)
                pkts_ba, bytes_ba = max(0, s["pkts"] - s["pkts_ab"]), max(0, s["bytes"] - s["bytes_ab"])
                if q is None:
                    q = {"pkts": 0, "bytes": 0, "pkts_ab": 0, "bytes_ab": 0, "syn": 0, "ack": 0, "rst": 0}
                q_pba, q_bba = max(0, q["pkts"] - q["pkts_ab"]), max(0, q["bytes"] - q["bytes_ab"])
                tot["p"] += max(0, s["pkts"] - q["pkts"])
                tot["b"] += max(0, s["bytes"] - q["bytes"])
                tot["pa"] += max(0, s["pkts_ab"] - q["pkts_ab"])
                tot["ba_"] += max(0, s["bytes_ab"] - q["bytes_ab"])
                tot["pb"] += max(0, pkts_ba - q_pba)
                tot["bb"] += max(0, bytes_ba - q_bba)
                for flag in ("syn", "ack", "rst"):
                    tot[flag] += max(0, s[flag] - q[flag])
                mins.append(s["min_len"])
                maxs.append(s["max_len"])
                if "time" in r:
                    durs.append(((s["last_ts"] - s["first_ts"]) % (1 << 32)) / 1e9)
                else:
                    durs.append(max(s["last_ts"] - s["first_ts"], 0.0))
                feats["net_flows_with_ab"] += int(s["pkts_ab"] > 0 or s["bytes_ab"] > 0)
                feats["net_flows_with_ba"] += int(pkts_ba > 0 or bytes_ba > 0)
                feats["net_dir_valid_count"] += 1
                prev[k] = dict(s)
            ws = self.window_seconds
            p, b, pa, ba, pb, bb = tot["p"], tot["b"], tot["pa"], tot["ba_"], tot["pb"], tot["bb"]
            feats.update({
                "net_flow_count_seen": len(rows), "net_pkts_total_delta": p, "net_bytes_total_delta": b,
                "net_pkts_ab_delta": pa, "net_bytes_ab_delta": ba, "net_pkts_ba_delta": pb, "net_bytes_ba_delta": bb,
                "net_syn_delta": tot["syn"], "net_ack_delta": tot["ack"], "net_rst_delta": tot["rst"],
                "net_min_len_mean": sum(mins) / len(mins), "net_max_len_mean": sum(maxs) / len(maxs),
                "net_min_len_min": min(mins), "net_max_len_max": max(maxs),
                "net_avg_pkt_size_delta": b / p if p else 0.0,
                "net_avg_pkt_size_ab_delta": ba / pa if pa else 0.0,
                "net_avg_pkt_size_ba_delta": bb / pb if pb else 0.0,
                "net_flow_duration_mean": sum(durs) / len(durs), "net_flow_duration_max": max(durs),
                "net_bytes_per_sec_delta": b / ws, "net_pkts_per_sec_delta": p / ws,
                "net_down_up_ratio_delta": bb / ba if ba else 0.0,
                "net_ab_ratio_pkt_delta": pa / p if p else 0.0, "net_ba_ratio_pkt_delta": pb / p if p else 0.0,
                "net_ab_ratio_byte_delta": ba / b if b else 0.0, "net_ba_ratio_byte_delta": bb / b if b else 0.0,
            })
            if "idle" in r:
                for k in rows:
                    if w - last_change[k] >= self.idle:
                        del buckets[k], last_change[k]
                        prev.pop(k, None)
            return feats

        for sec, usec, _orig, frame in records:
            t_us = sec * 1_000_000 + usec
            offset = t_us - start_us
            if offset < 0 or offset // self.window_us >= self.windows:
                continue
            w = offset // self.window_us
            if w < current:
                raise ValueError("packets are not in timestamp order")
            while current < w:
                out.append(read(current))
                current += 1
            p = self.parse(frame)
            if p is None:
                continue
            key, src, ports, proto, flags, length = p
            s = buckets.get(key)
            if s is None:
                ts0 = (t_us * 1000) & mask if "time" in r else float(Decimal(sec) + Decimal(usec).scaleb(-6))
                s = buckets[key] = {"pkts": 0, "bytes": 0, "pkts_ab": 0, "bytes_ab": 0, "syn": 0, "ack": 0, "rst": 0,
                                    "min_len": length, "max_len": length, "first_ts": ts0, "last_ts": ts0,
                                    "ref_src": src, "ref_ports": ports}
                order.setdefault(key, None)
                ab = True
            elif "direction" in r:
                ref = s["ref_ports"]
                ab = not (ports != ref and ports == (ref[1], ref[0]))
            else:
                ab = src == s["ref_src"]
            ts = (t_us * 1000) & mask if "time" in r else float(Decimal(sec) + Decimal(usec).scaleb(-6))
            s["pkts"] += 1
            s["bytes"] += length
            if ab:
                s["pkts_ab"] += 1
                s["bytes_ab"] += length
            s["syn"] += int(bool(flags & 0x002))
            s["ack"] += int(bool(flags & 0x010))
            s["rst"] += int(bool(flags & 0x004))
            s["min_len"] = min(s["min_len"], length)
            s["max_len"] = max(s["max_len"], length)
            s["last_ts"] = ts
            last_change[key] = w
        while current < self.windows:
            out.append(read(current))
            current += 1
        return out


# ------------------------------------------------------------------ comparison helpers

def windows_equal(a, b, features, rel=1e-9):
    """Index of the first differing window (with the feature), or None."""
    if len(a) != len(b):
        return ("length", len(a), len(b))
    for i, (x, y) in enumerate(zip(a, b)):
        for f in features:
            u, v = float(x[f]), float(y[f])
            if u != v and abs(u - v) > rel * max(abs(u), abs(v), 1e-12):
                return (i, f, u, v)
    return None


def five(windows, features):
    out = {}
    for f in features:
        v = [float(w[f]) for w in windows]
        m = sum(v) / len(v)
        out[f + "__mean"] = m
        out[f + "__max"] = max(v)
        out[f + "__sum"] = sum(v)
        out[f + "__std"] = math.sqrt(sum((x - m) ** 2 for x in v) / len(v))
        out[f + "__active_windows"] = float(sum(1 for x in v if x != 0))
    return out


def load_release(release):
    sys.path.insert(0, str(release / "features"))
    sys.path.insert(0, str(release / "p4" / "control_plane"))
    import switch_model  # noqa: E402
    from flow_index import compute_flow_index  # noqa: E402
    return switch_model, compute_flow_index


# ------------------------------------------------------------------ main

def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--runs", type=Path, required=True)
    ap.add_argument("--pool", type=Path, required=True)
    ap.add_argument("--release", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--rows", type=int, default=204, help="the first ROWS rows of features.csv (the non-flood runs)")
    args = ap.parse_args()

    release = load_release(args.release)
    sm = release[0]
    feats = sm.FEATURES
    fc_path = args.release / "dataset" / "features.csv"
    fc = list(csv.DictReader(open(fc_path, newline="")))
    pool = json.load(open(args.pool))
    args.out.mkdir(parents=True, exist_ok=True)
    if any(args.out.glob("*.pcap")):
        sys.exit("%s already holds captures; give an empty directory" % args.out)

    exact = {ws: SwitchRules(release, ws, int(round(20 / ws))) for ws in (1.0, 0.5)}
    rules_off = SwitchRules(release, 0.5, 40, rules=())
    single = {rule: SwitchRules(release, 1.0, 20, rules=(rule,)) for rule in RULES}
    published_1s = SwitchRules(release, 1.0, 20, rules=())

    manifest, skipped, effects, failures = [], [], [], []
    checks = {"rows": args.rows, "features_csv_sha256": sha256(fc_path), "pool_sha256": sha256(args.pool),
              "release_switch_model_sha256": sha256(args.release / "features" / "switch_model.py"),
              "packager_sha256": sha256(Path(__file__)), "runs": {}}
    max_dataset_diff = 0.0
    for i in range(args.rows):
        row, prow = fc[i], pool[i]
        if row["category"] not in ("malware", "benign"):
            sys.exit("row %d is %s: --rows must cover only the malware and CLI-benign runs" % (i, row["category"]))
        if row["category"] == "malware" and prow["sample"] != row["execution_id"] + ".zip":
            sys.exit("row %d: pool sample %s does not name execution %s" % (i, prow["sample"], row["execution_id"]))
        run = args.runs / prow["sample"]
        rj = glob.glob(str(run / "output" / "run_*" / "run.json"))
        if len(rj) != 1:
            sys.exit("%s: expected one run.json" % run)
        meta = json.load(open(rj[0]))
        if meta.get("window_seconds") != 0.5 or meta.get("timeout_seconds") != 20.0:
            sys.exit("%s: not a 0.5 s / 20 s run" % run)
        pcap = Path(rj[0]).parent / "packet_capture.pcap"
        anchor = int(meta["sample_started_wall_us"])
        head, records = read_pcap(pcap)
        res = {"run_id": meta["run_id"], "anchor_us": anchor}

        # 1. the capture gives the dataset row (published extractor, 0.5 s x 40)
        pub = sm.window_features(str(pcap), anchor, 0.5, 40)
        summary = five(pub, feats)
        diff = max(abs(summary[k] - float(row[k])) / max(1.0, abs(float(row[k]))) for k in summary)
        max_dataset_diff = max(max_dataset_diff, diff)
        res["dataset_row_max_rel_diff"] = diff
        if diff > 1e-9:
            failures.append((row["execution_id"], "capture does not give its dataset row", diff))

        # the model with every rule off is the published extractor
        d = windows_equal(rules_off.run(records, anchor), pub, feats, rel=1e-12)
        if d is not None:
            failures.append((row["execution_id"], "rules-off model differs from switch_model", d))

        obs = [rec for rec in records if 0 <= (rec[0] * 1_000_000 + rec[1]) - anchor < OBS_US]
        tcpudp = [rec for rec in obs if sm.parse_flow_packet(rec[3]) is not None]
        sw = {ws: m.run(records, anchor) for ws, m in exact.items()}
        if not tcpudp:
            nonzero = [(ws, k) for ws, rows in sw.items() for k, w in enumerate(rows) if any(float(w[f]) for f in feats)]
            res["replay"] = False
            if nonzero:
                failures.append((row["execution_id"], "outside the replay set but not zero under the switch rules", nonzero[:3]))
            skipped.append({"execution_id": row["execution_id"], "run_id": meta["run_id"], "category": row["category"],
                            "label": row["label"], "cv_group": row["cv_group"], "anchor_us": anchor,
                            "observation_frames": len(obs), "reason": "no IPv4 TCP/UDP packet in the observation"})
            checks["runs"][row["execution_id"]] = res
            continue

        # 2-3. trim and sanitize
        kept = []
        for sec, usec, orig, frame in obs:
            s = sanitize(frame)
            if s is not None:
                if len(s) != len(frame):
                    failures.append((row["execution_id"], "sanitize changed a length", len(frame)))
                kept.append((sec, usec, orig, s))
        name = row["execution_id"] + ".pcap"
        write_pcap(args.out / name, head, kept)
        _, back = read_pcap(args.out / name)
        if [(a, b, c) for a, b, c, _ in back] != [(a, b, c) for a, b, c, _ in kept]:
            failures.append((row["execution_id"], "written capture does not read back"))

        # 4. checks on the delivered capture
        for ws, m in exact.items():
            d = windows_equal(m.run(back, anchor), sw[ws], feats, rel=0)
            if d is not None:
                failures.append((row["execution_id"], "sanitized capture differs under the switch rules at %s s" % ws, d))
        d = windows_equal(sm.window_features(str(args.out / name), anchor, 0.5, 40), pub, feats, rel=0)
        if d is not None:
            failures.append((row["execution_id"], "sanitized capture differs under switch_model", d))
        bad_csum = 0
        for _s, _u, _o, frame in back:
            l3 = max(20, (frame[14] & 0x0F) * 4)
            total, proto = (frame[16] << 8) | frame[17], frame[23]
            frag = ((frame[20] & 0x1F) << 8) | frame[21]
            if proto in (6, 17) and frag == 0 and not frame[20] & 0x20 and 14 + total <= len(frame):
                pos = 14 + l3 + (16 if proto == 6 else 6)
                stored = (frame[pos] << 8) | frame[pos + 1]
                if not (proto == 17 and stored == 0) and stored != l4_checksum(frame, l3, total, proto):
                    bad_csum += 1
        if bad_csum:
            failures.append((row["execution_id"], "checksums not recomputed", bad_csum))
        sums_ok = (sum(w["net_pkts_total_delta"] for w in sw[1.0]) == len(tcpudp)
                   and sum(w["net_bytes_total_delta"] for w in sw[1.0])
                   == sum((f[16] << 8) | f[17] for _s, _u, _o, f in tcpudp))
        if not sums_ok:
            failures.append((row["execution_id"], "switch-rule totals differ from the packets"))

        keys = {}
        for _s, _u, _o, f in tcpudp:
            k = exact[1.0].parse(f)
            if k is not None:
                keys.setdefault(k[0], set()).add((f[23], *sorted(((f[26:30], (f[34] << 8) | f[35]),
                                                                  (f[30:34], (f[36] << 8) | f[37])))))
        max_active = max(w["net_flow_count_seen"] for w in sw[1.0])
        first_kept = kept[0][0] * 1_000_000 + kept[0][1]
        first_frame = records[0][0] * 1_000_000 + records[0][1]
        manifest.append({
            "execution_id": row["execution_id"], "run_id": meta["run_id"], "category": row["category"],
            "label": row["label"], "cv_group": row["cv_group"], "capture": name,
            "sha256_original": sha256(pcap), "sha256": sha256(args.out / name),
            "anchor_us": anchor, "first_frame_us": first_frame,
            "anchor_offset_s": "%.6f" % ((anchor - first_kept) / 1e6), "ipv4_packets": len(kept),
            "expect_overload": int(max_active > OVERLOAD_BUCKETS_1S),
            "first_kept_frame_us": first_kept, "tcpudp_packets": len(tcpudp), "flow_buckets": len(keys),
            "colliding_buckets": sum(1 for v in keys.values() if len(v) > 1), "max_active_buckets_1s": max_active,
            "family": row["family"], "project": row["project"], "program": row["program"], "mode": row["mode"],
            "split": row["split"],
        })

        # what each rule alone changes at 1 s, against the published extractor at 1 s
        base = published_1s.run(records, anchor)
        eff = {"execution_id": row["execution_id"]}
        for rule, m in single.items():
            got = m.run(records, anchor)
            eff[rule] = sum(1 for a, b in zip(got, base) if windows_equal([a], [b], feats) is not None)
        eff["all_six"] = sum(1 for a, b in zip(sw[1.0], base) if windows_equal([a], [b], feats) is not None)
        eff["busy_windows"] = sum(1 for w in base if w["net_flow_count_seen"])
        effects.append(eff)
        res.update({"replay": True, "frames_kept": len(kept), "tcpudp_packets": len(tcpudp), "max_active_1s": max_active})
        checks["runs"][row["execution_id"]] = res
        print("[package] %-66s %6d frames  %6d buckets  max active %d" % (name, len(kept), len(keys), max_active), flush=True)

    # the Chaos scanner and other overloads go last (RUNBOOK 19.7.3)
    manifest.sort(key=lambda m: m["expect_overload"])
    with open(args.out / "manifest.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=MANIFEST_COLUMNS, lineterminator="\n")
        w.writeheader()
        w.writerows(manifest)
    with open(args.out / "not_replayed.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(skipped[0]), lineterminator="\n")
        w.writeheader()
        w.writerows(skipped)
    with open(args.out / "rule_effects.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["execution_id", "busy_windows", *RULES, "all_six"], lineterminator="\n")
        w.writeheader()
        w.writerows(effects)
    checks.update({"replay_set": len(manifest), "not_replayed": len(skipped),
                   "replay_by_category": {c: sum(1 for m in manifest if m["category"] == c) for c in ("malware", "benign")},
                   "dataset_row_max_rel_diff": max_dataset_diff, "failures": [list(map(str, x)) for x in failures]})
    with open(args.out / "checks.json", "w") as f:
        json.dump(checks, f, indent=1)
    names = sorted(p.name for p in args.out.iterdir() if p.is_file() and p.name != "SHA256SUMS")
    with open(args.out / "SHA256SUMS", "w") as f:
        for n in names:
            f.write("%s  %s\n" % (sha256(args.out / n), n))
    print("[package] %d replay captures (%s), %d runs without IPv4 TCP/UDP; dataset rows reproduced to %.1e; %d failures"
          % (len(manifest), checks["replay_by_category"], len(skipped), max_dataset_diff, len(failures)))
    for x in failures[:20]:
        print("[package] FAIL", x)
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
