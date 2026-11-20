#!/usr/bin/env python3
"""The 29 window features from the records of switch/variants/sweep (its probes' exports).

switch/variants/sweep is basic_gtot_ba (the deployed bucket table plus seven one-entry totals) whose registers the data
plane reads itself: a probe names one bucket, reads its 14 registers (and, for bucket 0, the seven totals and the sweep
number) into a 90-byte sweep_t and leaves for the export port (switch/variants/sweep/headers.p4 and ingress.p4). One
sweep, the probes sent at one window boundary, is the state of the buckets at that boundary; a window's features are
the differences of two sweeps, as the collector takes them from two reads (hybrid_collector.NetSummarizer), but over
every bucket instead of the ~500 a 0.5 s window's reads cover.

This module has:
    RECORD, parse_export(), probe_frame(), generator_template()   the wire formats
    compact(), expand()                                            a record as the socket-level join keeps it
    read_exports(), group_sweeps()                                 exports (a pcap) -> sweeps
    SweepWindows                                                   sweeps -> the 29 features per window (of all
                                                                   buckets, or of a selection)
    SweepModel                                                     a software model of the program (tests, offline checks)
    probe_plan()                                                   the probes an in-band replay sends at each boundary
    summarize()                                                    a run's 40 windows -> the release's row

The features follow the dataset's model (the release's features/switch_model.py) as the bucket table can: a bucket is a
flow, active in window w while its last packet is in windows w-3..w (TTL 3); per window the packet, byte and flag sums
of its packets; per active bucket its min / max length, duration, whether it has had A->B and B->A packets. With every
bucket read at every boundary this is the "bucket" design of p4_perf.md 5.7's gap analysis (perfect reads and cuts).
Bytes are counted as frames (byte_layer "frame", the dataset profile): the switch counts the IPv4 totalLen, or the frame
minimum toward the dataset's guest (frame_len), and 14 B per packet are added here.

Python 3 (PC1 and the lab); the switch side is sweep_reader.py.
"""
import operator
import struct
import sys
from pathlib import Path

ETHERTYPE_SWEEP = 0x88B6
SWEEP_MAGIC = 0x5357
M32 = (1 << 32) - 1
TS_WRAP_S = (1 << 32) / 1e9
ETHERNET_HEADER_BYTES = 14
TTL = 3

FIELDS = ("magic", "idx", "gen", "batch", "seq", "t",
          "pkts", "bytes", "pkts_ab", "bytes_ab", "first_ts", "last_ts", "syn", "ack", "rst",
          "ref_sp", "ref_dp", "min_len", "max_len", "dir_valid", "coll",
          "g_pkts_ab", "g_bytes_ab", "g_pkts_ba", "g_bytes_ba", "g_syn", "g_ack", "g_rst")
RECORD = struct.Struct("!HHHHII" + "I" * 9 + "HHHH" + "BB" + "I" * 7)
assert RECORD.size == 90, RECORD.size
FRAME_BYTES = 14 + RECORD.size          # 104 (+ 4 B FCS on the wire)
BUCKET_REGS = ("pkts", "bytes", "pkts_ab", "bytes_ab", "first_ts", "last_ts", "syn", "ack", "rst",
               "ref_sp", "ref_dp", "min_len", "max_len", "dir_valid", "coll")
COLL_MAX = 255                          # reg_coll saturates
TOTALS = ("g_pkts_ab", "g_bytes_ab", "g_pkts_ba", "g_bytes_ba", "g_syn", "g_ack", "g_rst")
COMPACT = ("idx", "t") + BUCKET_REGS    # what the socket-level join keeps of a record (compact(), expand())

FEATURES = [
    "net_flow_count_seen", "net_pkts_total_delta", "net_bytes_total_delta", "net_pkts_ab_delta",
    "net_bytes_ab_delta", "net_pkts_ba_delta", "net_bytes_ba_delta", "net_min_len_mean", "net_max_len_mean",
    "net_min_len_min", "net_max_len_max", "net_avg_pkt_size_delta", "net_avg_pkt_size_ab_delta",
    "net_avg_pkt_size_ba_delta", "net_flow_duration_mean", "net_flow_duration_max", "net_bytes_per_sec_delta",
    "net_pkts_per_sec_delta", "net_down_up_ratio_delta", "net_ab_ratio_pkt_delta", "net_ba_ratio_pkt_delta",
    "net_ab_ratio_byte_delta", "net_ba_ratio_byte_delta", "net_syn_delta", "net_ack_delta", "net_rst_delta",
    "net_flows_with_ab", "net_flows_with_ba", "net_dir_valid_count",
]
STATS = ("mean", "max", "sum", "std", "active_windows")
DURATION_FEATURES = ("net_flow_duration_mean", "net_flow_duration_max")


# ---------------------------------------------------------------------------------------------- wire formats
def pack_record(**values):
    vals = dict.fromkeys(FIELDS, 0)
    vals["magic"] = SWEEP_MAGIC
    vals.update(values)
    return RECORD.pack(*[int(vals[f]) for f in FIELDS])


def mac_bytes(mac):
    if isinstance(mac, (bytes, bytearray)):
        return bytes(mac)
    return bytes.fromhex(mac.replace(":", ""))


def probe_frame(src_mac, idx):
    """An in-band probe of bucket idx: the bucket in the low 16 bits of the destination MAC (where the packet
    generator writes its packet id), EtherType ETHERTYPE_SWEEP, a sweep_t with its magic and zeros."""
    dst = b"\x02\x00\x00\x00" + struct.pack("!H", idx & 0xFFFF)
    return dst + mac_bytes(src_mac) + struct.pack("!H", ETHERTYPE_SWEEP) + pack_record()


def generator_template(src_mac=b"\x02\x00\x00\x00\x88\xb6"):
    """The packet generator's frame: its first 6 bytes are where the generator writes its header (pipe, app, batch,
    packet id); the generator's buffer holds the rest (frame[6:], 98 bytes)."""
    return b"\x00" * 6 + mac_bytes(src_mac) + struct.pack("!H", ETHERTYPE_SWEEP) + pack_record()


def parse_export(frame):
    """A dict of the record's fields, or None for a frame that is not an export."""
    if len(frame) < FRAME_BYTES or frame[12:14] != b"\x88\xb6":
        return None
    rec = dict(zip(FIELDS, RECORD.unpack(frame[14:FRAME_BYTES])))
    if rec["magic"] != SWEEP_MAGIC:
        return None
    return rec


def pipe_of(rec):
    """The generator's pipe (destination MAC bits 44:43, gen bits 12:11); an in-band probe's gen is its sender's."""
    return (rec["gen"] >> 11) & 0x3


_COMPACT_GET = operator.itemgetter(*COMPACT)


def compact(rec):
    """A record as a tuple of COMPACT: the bucket, its probe's switch time and its registers. The collector keeps
    the records that changed in each sweep this way for the socket-level join (hybrid_collector.py). An export's
    record has every field (itemgetter: about 0.15 us a record, against 1.1 us field by field); a record written
    by hand may leave some out (0)."""
    try:
        return _COMPACT_GET(rec)
    except KeyError:
        return tuple(int(rec.get(k, 0)) for k in COMPACT)


def expand(values):
    """compact()'s tuple as a record (the fields SweepWindows reads)."""
    return dict(zip(COMPACT, values))


# ---------------------------------------------------------------------------------------------- pcaps
def read_pcap(path):
    """[(seconds, frame)] of every record (classic pcap, us or ns timestamps)."""
    out = []
    with open(path, "rb") as f:
        head = f.read(24)
        if len(head) < 24:
            return out
        order, scale = {b"\xd4\xc3\xb2\xa1": ("<", 1e-6), b"\xa1\xb2\xc3\xd4": (">", 1e-6),
                        b"\x4d\x3c\xb2\xa1": ("<", 1e-9), b"\xa1\xb2\x3c\x4d": (">", 1e-9)}[head[:4]]
        rec = struct.Struct(order + "IIII")
        while True:
            h = f.read(16)
            if len(h) < 16:
                break
            sec, frac, incl, _ = rec.unpack(h)
            out.append((sec + frac * scale, f.read(incl)))
    return out


def read_pcap_us(path):
    """[(whole microseconds, frame)] of every record, as features/switch_model.py times them (replay_absolute.py)."""
    out = []
    with open(path, "rb") as f:
        head = f.read(24)
        if len(head) < 24:
            return out
        order, digits = {b"\xd4\xc3\xb2\xa1": ("<", 6), b"\xa1\xb2\xc3\xd4": (">", 6),
                         b"\x4d\x3c\xb2\xa1": ("<", 9), b"\xa1\xb2\x3c\x4d": (">", 9)}[head[:4]]
        rec = struct.Struct(order + "IIII")
        while True:
            h = f.read(16)
            if len(h) < 16:
                break
            sec, frac, incl, _ = rec.unpack(h)
            out.append((sec * 1000000 + (frac if digits == 6 else frac // 1000), f.read(incl)))
    return out


def write_pcap(path, frames):
    """frames: [(seconds, frame)] -> a classic microsecond pcap (tests)."""
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1))
        for t, fr in frames:
            sec = int(t)
            usec = int(round((t - sec) * 1e6))
            if usec >= 1000000:
                sec, usec = sec + 1, usec - 1000000
            f.write(struct.pack("<IIII", sec, usec, len(fr), len(fr)) + fr)


def read_exports(path):
    """[(arrival seconds, record)] of the exports in a capture, in arrival order."""
    out = []
    for t, frame in read_pcap(path):
        rec = parse_export(frame)
        if rec is not None:
            out.append((t, rec))
    return out


def group_sweeps(exports):
    """Exports -> sweeps in order, one per (gen, seq): dict(seq, gen, pipe, t_first / t_last (the probes' switch
    times, ns mod 2^32), host_first / host_last (arrival), totals (from bucket 0's record, None without it), buckets
    {idx: record} of the buckets with dir_valid != 0, records, duplicates)."""
    sweeps = {}
    order = []
    for host_t, rec in exports:
        key = (rec["gen"], rec["seq"])
        s = sweeps.get(key)
        if s is None:
            s = sweeps[key] = dict(seq=rec["seq"], gen=rec["gen"], pipe=pipe_of(rec), totals=None, buckets={},
                                   records=0, duplicates=0, t_first=rec["t"], t_last=rec["t"],
                                   host_first=host_t, host_last=host_t)
            order.append(key)
        s["records"] += 1
        s["host_last"] = host_t
        # probe times modulo 2^32 within a sweep (well under 4.3 s): span from the first record
        if ((rec["t"] - s["t_first"]) & M32) > ((s["t_last"] - s["t_first"]) & M32):
            s["t_last"] = rec["t"]
        if rec["idx"] == 0:
            s["totals"] = dict((k, rec[k]) for k in TOTALS)
        if rec["dir_valid"] != 0:
            if rec["idx"] in s["buckets"]:
                s["duplicates"] += 1
            s["buckets"][rec["idx"]] = rec
    out = [sweeps[k] for k in order]
    for s in out:
        s["span_ns"] = (s["t_last"] - s["t_first"]) & M32
    return out


# ---------------------------------------------------------------------------------------------- features
def derived(out, mins, maxs, durs, nflows, window_s):
    """The release's derived features (features/switch_model.py), as in p4_perf.md 5.7's gap analysis."""
    packets, size = out["net_pkts_total_delta"], out["net_bytes_total_delta"]
    ab_packets, ab_bytes = out["net_pkts_ab_delta"], out["net_bytes_ab_delta"]
    ba_packets, ba_bytes = out["net_pkts_ba_delta"], out["net_bytes_ba_delta"]
    out.update({
        "net_flow_count_seen": nflows,
        "net_min_len_mean": mins[0] / nflows if nflows else 0.0,
        "net_max_len_mean": maxs[0] / nflows if nflows else 0.0,
        "net_min_len_min": mins[1], "net_max_len_max": maxs[1],
        "net_avg_pkt_size_delta": size / packets if packets else 0.0,
        "net_avg_pkt_size_ab_delta": ab_bytes / ab_packets if ab_packets else 0.0,
        "net_avg_pkt_size_ba_delta": ba_bytes / ba_packets if ba_packets else 0.0,
        "net_flow_duration_mean": durs[0] / nflows if nflows else 0.0,
        "net_flow_duration_max": durs[1],
        "net_bytes_per_sec_delta": size / window_s, "net_pkts_per_sec_delta": packets / window_s,
        "net_down_up_ratio_delta": ba_bytes / ab_bytes if ab_bytes else 0.0,
        "net_ab_ratio_pkt_delta": ab_packets / packets if packets else 0.0,
        "net_ba_ratio_pkt_delta": ba_packets / packets if packets else 0.0,
        "net_ab_ratio_byte_delta": ab_bytes / size if size else 0.0,
        "net_ba_ratio_byte_delta": ba_bytes / size if size else 0.0,
    })
    return out


class SweepWindows:
    """Window features from consecutive sweeps. add(sweep) with the first sweep (the state at window 0's start) sets
    the baselines and returns None; each later sweep returns the features of the window that ended at it.

    A bucket a sweep does not carry keeps its last record: with the generator every used bucket is in every sweep; an
    in-band replay may probe only the buckets that changed (probe_plan "changed"). The totals' differences (bucket 0's
    record) are a check: they count every packet, so a bucket the sweep missed shows as totals_mismatch.

    add(sweep, select): the features of the buckets in `select` only (a set of bucket indexes; the socket-level join,
    hybrid_collector.sweep_socket_join). Every bucket of the sweep still updates the state, so a bucket that joins the
    selection later has its earlier record. A sweep that carries only the buckets that changed gives the same features
    as the whole sweep (a bucket without a packet adds nothing); last_changed names them after each add()."""

    def __init__(self, window_sec=0.5, header=ETHERNET_HEADER_BYTES, ttl=TTL):
        self.window_sec, self.header, self.ttl = window_sec, header, ttl
        self.state = {}             # idx -> last record
        self.seen = {}              # idx -> the last window with a packet
        self.first_window = {}      # idx -> the window of its first packet
        self.prev_totals = None
        self.n_sweeps = 0
        self.last_changed = []      # the buckets whose registers changed in the last add() (all, for the first)

    def duration_s(self, idx, rec):
        d_mod = ((rec["last_ts"] - rec["first_ts"]) & M32) / 1e9
        est = (self.seen.get(idx, 0) - self.first_window.get(idx, 0)) * self.window_sec
        k = max(0, int(round((est - d_mod) / TS_WRAP_S)))
        return d_mod + k * TS_WRAP_S

    def add(self, sweep, select=None):
        buckets = sweep["buckets"]
        if self.n_sweeps == 0:
            self.n_sweeps = 1
            for idx, rec in buckets.items():
                self.state[idx] = rec
            self.last_changed = list(buckets)
            self.prev_totals = sweep.get("totals")
            return None
        w = self.n_sweeps - 1
        self.n_sweeps += 1
        h = self.header
        out = dict.fromkeys(FEATURES, 0)
        sums = dict(pkts=0, bytes=0, pkts_ab=0, bytes_ab=0, pkts_ba=0, bytes_ba=0, syn=0, ack=0, rst=0)
        coll_pkts, coll_saturated = 0, 0
        changed = []
        for idx, rec in buckets.items():
            prev = self.state.get(idx)
            # every data packet increments pkts (a bucket's other registers change only with it)
            d_pkts = (rec["pkts"] - (prev["pkts"] if prev else 0)) & M32
            if prev is None or d_pkts:
                changed.append(idx)
            if d_pkts > 0:
                self.seen[idx] = w
                self.first_window.setdefault(idx, w)
            if select is None or idx in select:
                # reg_coll saturates at 255: a bucket at 255 may hide more (counted in net_sweep_coll_saturated)
                coll_pkts += max(0, rec.get("coll", 0) - (prev.get("coll", 0) if prev else 0))
                if select is None:
                    coll_saturated += int(rec.get("coll", 0) >= COLL_MAX)
                d = {}
                for k in ("pkts", "bytes", "pkts_ab", "bytes_ab", "syn", "ack", "rst"):
                    d[k] = (rec[k] - (prev[k] if prev else 0)) & M32
                for k in ("pkts", "bytes", "pkts_ab", "bytes_ab", "syn", "ack", "rst"):
                    sums[k] += d[k]
                sums["pkts_ba"] += (d["pkts"] - d["pkts_ab"]) & M32
                sums["bytes_ba"] += (d["bytes"] - d["bytes_ab"]) & M32
            self.state[idx] = rec
        self.last_changed = changed
        active = [i for i, seen in self.seen.items() if 0 <= w - seen <= self.ttl]
        if select is not None:
            active = [i for i in active if i in select]
            # the selected buckets known so far (a sweep of the changed buckets does not carry the others)
            coll_saturated = sum(1 for i in select if self.state.get(i, {}).get("coll", 0) >= COLL_MAX)
        mins, maxs, durs = [], [], []
        for idx in active:
            rec = self.state[idx]
            if rec["min_len"]:
                mins.append(rec["min_len"] + h)
            if rec["max_len"]:
                maxs.append(rec["max_len"] + h)
            durs.append(self.duration_s(idx, rec))
            out["net_flows_with_ab"] += int(rec["pkts_ab"] > 0)
            out["net_flows_with_ba"] += int(((rec["pkts"] - rec["pkts_ab"]) & M32) > 0)
            out["net_dir_valid_count"] += int(rec["dir_valid"] != 0)
        out["net_pkts_total_delta"] = sums["pkts"]
        out["net_bytes_total_delta"] = sums["bytes"] + h * sums["pkts"]
        out["net_pkts_ab_delta"] = sums["pkts_ab"]
        out["net_bytes_ab_delta"] = sums["bytes_ab"] + h * sums["pkts_ab"]
        out["net_pkts_ba_delta"] = sums["pkts_ba"]
        out["net_bytes_ba_delta"] = sums["bytes_ba"] + h * sums["pkts_ba"]
        out["net_syn_delta"], out["net_ack_delta"], out["net_rst_delta"] = sums["syn"], sums["ack"], sums["rst"]
        derived(out, (sum(mins), min(mins, default=0)), (sum(maxs), max(maxs, default=0)),
                (sum(durs), max(durs, default=0.0)), len(active), self.window_sec)
        # check against the totals (gtot_ba's seven registers, read by bucket 0's probe); a selection of the buckets
        # has no totals to check against (-1)
        totals = sweep.get("totals")
        tot_pkts = None
        if select is None and totals is not None and self.prev_totals is not None:
            dt = dict((k, (totals[k] - self.prev_totals[k]) & M32) for k in TOTALS)
            tot_pkts = dt["g_pkts_ab"] + dt["g_pkts_ba"]
            out["net_sweep_totals_mismatch"] = int(
                tot_pkts != sums["pkts"] or dt["g_pkts_ab"] != sums["pkts_ab"] or
                ((dt["g_bytes_ab"] + dt["g_bytes_ba"]) & M32) != (sums["bytes"] & M32) or
                dt["g_syn"] != sums["syn"] or dt["g_ack"] != sums["ack"] or dt["g_rst"] != sums["rst"])
        else:
            out["net_sweep_totals_mismatch"] = -1
        out["net_sweep_totals_pkts"] = -1 if tot_pkts is None else tot_pkts
        if totals is not None:
            self.prev_totals = totals
        # collisions (reg_coll): packets of a second flow in a bucket, as far as its ports show it. The rows of
        # windows with merged active buckets are the ones the bucket table cannot make exact.
        out["net_sweep_coll_pkts"] = coll_pkts
        out["net_sweep_coll_saturated"] = coll_saturated
        out["net_sweep_merged_active"] = sum(1 for idx in active if self.state[idx].get("coll", 0) > 0)
        if select is None:
            out["net_sweep_merged_buckets"] = sum(1 for r in self.state.values() if r.get("coll", 0) > 0)
            out["net_sweep_buckets"] = len(buckets)
        else:
            out["net_sweep_merged_buckets"] = sum(1 for i in select if self.state.get(i, {}).get("coll", 0) > 0)
            out["net_sweep_buckets"] = sum(1 for i in buckets if i in select)
        out["net_sweep_seq"] = sweep.get("seq", -1)
        out["net_sweep_span_us"] = round(sweep.get("span_ns", 0) / 1e3, 3)
        return out


def windows_from_sweeps(sweeps, window_sec=0.5, header=ETHERNET_HEADER_BYTES):
    sw = SweepWindows(window_sec, header)
    rows = []
    for s in sweeps:
        f = sw.add(s)
        if f is not None:
            rows.append(dict(window=len(rows), **f))
    return rows


def summarize(windows):
    """The release's row: mean, max, sum, std (population), active_windows of each feature over the windows."""
    out = {}
    n = len(windows)
    for f in FEATURES:
        v = [float(w[f]) for w in windows]
        mean = sum(v) / n if n else 0.0
        var = sum((x - mean) ** 2 for x in v) / n if n else 0.0
        st = {"mean": mean, "max": max(v) if v else 0.0, "sum": sum(v), "std": var ** 0.5,
              "active_windows": float(sum(1 for x in v if x != 0))}
        for s in STATS:
            out["%s__%s" % (f, s)] = float(st[s])
    return out


# ---------------------------------------------------------------------------------------------- the program
def parse_p4(frame):
    """What the bucket table's parser takes (switch/variants/gtot, sweep): EtherType 0x0800 at byte 12, a fixed 20-byte
    IPv4 header, TCP or UDP right after it. (sip, dip, proto, sport, dport, tcp_flags, totalLen) as ints, or None."""
    if len(frame) < 34 or frame[12] != 0x08 or frame[13] != 0x00:
        return None
    proto = frame[23]
    if proto not in (6, 17) or len(frame) < 34 + (20 if proto == 6 else 8):
        return None
    sp, dp = (frame[34] << 8) | frame[35], (frame[36] << 8) | frame[37]
    flags = (((frame[46] & 0x01) << 8) | frame[47]) if proto == 6 else 0
    total = (frame[16] << 8) | frame[17]
    sip = int.from_bytes(frame[26:30], "big")
    dip = int.from_bytes(frame[30:34], "big")
    return sip, dip, proto, sp, dp, flags, total


def _flow_index():
    here = Path(__file__).resolve().parent
    if str(here) not in sys.path:
        sys.path.insert(0, str(here))
    from flow_index import compute_flow_index
    return compute_flow_index


def ip_to_int(text):
    return int.from_bytes(bytes(int(x) for x in text.split(".")), "big")


def prefix_match(prefixes):
    """['10.0.0.10/32', ...] -> a function dip -> bool (frame_len's entries)."""
    nets = []
    for spec in prefixes or ():
        addr, _, plen = spec.partition("/")
        plen = int(plen or 32)
        mask = (M32 << (32 - plen)) & M32
        nets.append((ip_to_int(addr) & mask, mask))
    return lambda dip: any((dip & m) == a for a, m in nets)


class SweepModel:
    """The registers and per-packet logic of switch/variants/sweep's ingress.p4: data packets as basic_gtot_ba counts
    them (frame_len toward `frame_min`), probes as the program reads and exports. Timestamps are the low 32 bits of
    the arrival time in ns."""

    def __init__(self, frame_min=("10.0.0.10/32",)):
        self.flow_index = _flow_index()
        self.pad = prefix_match(frame_min)
        self.b = {}
        self.g = dict.fromkeys(TOTALS, 0)
        self.seq = 0
        self.probes = self.exported = 0

    def bucket_of(self, frame):
        p = parse_p4(frame)
        if p is None:
            return None
        sip, dip, proto, sp, dp, _, _ = p
        return self.flow_index(sip, dip, sp, dp, proto)

    def packet(self, frame, ts_ns):
        p = parse_p4(frame)
        if p is None:
            return None
        sip, dip, proto, sp, dp, flags, total = p
        L = 46 if (total <= 45 and self.pad(dip)) else total
        idx = self.flow_index(sip, dip, sp, dp, proto)
        r = self.b.get(idx)
        if r is None:
            r = self.b[idx] = dict.fromkeys(BUCKET_REGS, 0)
        if r["dir_valid"] == 0:
            r["dir_valid"] = 1
            r["ref_sp"], r["ref_dp"] = sp, dp
            ab = 1
        elif sp == r["ref_sp"] and dp == r["ref_dp"]:
            ab = 1
        elif sp == r["ref_dp"] and dp == r["ref_sp"]:
            ab = 0
        else:
            ab = 1          # collision / ambiguity fallback
            if r["coll"] < COLL_MAX:
                r["coll"] += 1
        ts = ts_ns & M32
        r["pkts"] = (r["pkts"] + 1) & M32
        r["bytes"] = (r["bytes"] + L) & M32
        if ab:
            r["pkts_ab"] = (r["pkts_ab"] + 1) & M32
            r["bytes_ab"] = (r["bytes_ab"] + L) & M32
            self.g["g_pkts_ab"] = (self.g["g_pkts_ab"] + 1) & M32
            self.g["g_bytes_ab"] = (self.g["g_bytes_ab"] + L) & M32
        else:
            self.g["g_pkts_ba"] = (self.g["g_pkts_ba"] + 1) & M32
            self.g["g_bytes_ba"] = (self.g["g_bytes_ba"] + L) & M32
        if r["min_len"] == 0 or L < r["min_len"]:
            r["min_len"] = L
        if L > r["max_len"]:
            r["max_len"] = L
        if r["first_ts"] == 0:
            r["first_ts"] = ts
        r["last_ts"] = ts
        if proto == 6:
            if flags & 0x002:
                r["syn"] = (r["syn"] + 1) & M32
                self.g["g_syn"] = (self.g["g_syn"] + 1) & M32
            if flags & 0x004:
                r["rst"] = (r["rst"] + 1) & M32
                self.g["g_rst"] = (self.g["g_rst"] + 1) & M32
            if flags & 0x010:
                r["ack"] = (r["ack"] + 1) & M32
                self.g["g_ack"] = (self.g["g_ack"] + 1) & M32
        return idx

    def probe(self, idx, t_ns=0, gen=0x0200, batch=0):
        """The record the program exports for a probe of bucket idx, or None (dropped: an empty bucket other than 0)."""
        self.probes += 1
        rec = dict.fromkeys(FIELDS, 0)
        rec.update(magic=SWEEP_MAGIC, idx=idx, gen=gen, batch=batch, t=t_ns & M32)
        if idx == 0:
            self.seq = (self.seq + 1) & M32
            rec.update(self.g)
        rec["seq"] = self.seq
        r = self.b.get(idx)
        if r is not None:
            rec.update(r)
        if rec["dir_valid"] == 0 and idx != 0:
            return None
        self.exported += 1
        return rec


def probe_plan(frames_us, anchor_us, window_us, windows, mode="changed", bucket_of=None):
    """The probes an in-band replay sends: [(boundary_us, [bucket, ...])] for boundaries k = 0..windows at
    anchor_us + k * window_us, bucket 0 first at each. mode "changed": the buckets of the frames since the previous
    boundary (at boundary 0: before it); "all": every bucket used so far. frames_us: [(us, frame)] in order."""
    if bucket_of is None:
        model = SweepModel(frame_min=())
        bucket_of = model.bucket_of
    plan, used, since = [], set(), set()
    i = 0
    for k in range(windows + 1):
        boundary = anchor_us + k * window_us
        while i < len(frames_us) and frames_us[i][0] < boundary:
            b = bucket_of(frames_us[i][1])
            if b is not None:
                used.add(b)
                since.add(b)
            i += 1
        chosen = since if mode == "changed" else used
        plan.append((boundary, [0] + sorted(x for x in chosen if x != 0)))
        since = set()
    return plan


def simulate_inband(frames_us, anchor_us, window_us=500000, windows=40, mode="changed", frame_min=("10.0.0.10/32",)):
    """The switch's exports for an in-band replay of a capture (perfect cuts: every probe of a boundary before the next
    frame), from the software model: [(us, record)]."""
    model = SweepModel(frame_min=frame_min)
    plan = probe_plan(frames_us, anchor_us, window_us, windows, mode, model.bucket_of)
    exports, i = [], 0
    for boundary, buckets in plan:
        while i < len(frames_us) and frames_us[i][0] < boundary:
            model.packet(frames_us[i][1], frames_us[i][0] * 1000)
            i += 1
        for b in buckets:
            rec = model.probe(b, boundary * 1000)
            if rec is not None:
                exports.append((boundary, rec))
    return exports, model


def ipv4_frame(sip, dip, proto, sp, dp, flags=0, payload=0, src_mac=b"\x02\x00\x00\x00\x0a\x0a",
               dst_mac=b"\x02\x00\x00\x00\x0a\x01"):
    """An Ethernet + IPv4 (20 B) + TCP (20 B, `flags`) or UDP (8 B) frame with `payload` zero bytes."""
    l4 = (struct.pack("!HHIIBBHHH", sp, dp, 0, 0, 0x50 | ((flags >> 8) & 1), flags & 0xFF, 65535, 0, 0) if proto == 6
          else struct.pack("!HHHH", sp, dp, 8 + payload, 0))
    total = 20 + len(l4) + payload
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0, 0, 64, proto, 0, sip.to_bytes(4, "big"), dip.to_bytes(4, "big"))
    words = struct.unpack("!10H", ip)
    c = sum(words)
    while c >> 16:
        c = (c & 0xFFFF) + (c >> 16)
    ip = ip[:10] + struct.pack("!H", (~c) & 0xFFFF) + ip[12:]
    return mac_bytes(dst_mac) + mac_bytes(src_mac) + b"\x08\x00" + ip + l4 + b"\x00" * payload


def test_traffic(n_flows=200, seed=1, start=0.0, spread_s=1.0):
    """Known-answer traffic: [(seconds, frame)] in time order, `n_flows` flows spread over `spread_s` from `start`.
    TCP flows between 10.0.0.10 and 10.0.0.1:80 (SYN, SYN+ACK back, ACK, data both ways, some RST), UDP flows to
    10.0.0.53:53 with a reply. Replies toward 10.0.0.10 without payload are under 46 B of IPv4 (frame_len).
    Beyond 15,000 flows the ports repeat and each further 15,000 come from guest 10.0.k.10 (k = 1, 2, ...), so the
    5-tuples stay distinct; the first 15,000 are the same for any n_flows."""
    import random
    rnd = random.Random(seed)
    guest, server, dns = ip_to_int("10.0.0.10"), ip_to_int("10.0.0.1"), ip_to_int("10.0.0.53")
    out = []
    base_guest = guest
    for i in range(n_flows):
        t = start + rnd.random() * spread_s
        gap = lambda: rnd.uniform(1e-4, 5e-3)       # noqa: E731
        k, j = divmod(i, 15000)
        guest = base_guest + (k << 8)               # 10.0.k.10
        if i % 3 == 2:
            sp = 50000 + j
            out.append((t, ipv4_frame(guest, dns, 17, sp, 53, payload=rnd.randint(20, 60))))
            t += gap()
            out.append((t, ipv4_frame(dns, guest, 17, 53, sp, payload=rnd.randint(40, 300))))
            continue
        sp = 40000 + j
        pkts = [(guest, server, sp, 80, 0x002, 0), (server, guest, 80, sp, 0x012, 0), (guest, server, sp, 80, 0x010, 0)]
        for _ in range(rnd.randint(1, 4)):
            pkts.append((guest, server, sp, 80, 0x018, rnd.randint(1, 1400)))
            pkts.append((server, guest, 80, sp, 0x010, 0))
            pkts.append((server, guest, 80, sp, 0x018, rnd.randint(1, 1400)))
        if i % 7 == 0:
            pkts.append((guest, server, sp, 80, 0x004, 0))
        for s, d, a, b, fl, pl in pkts:
            out.append((t, ipv4_frame(s, d, 6, a, b, fl, pl)))
            t += gap()
    out.sort(key=lambda x: x[0])
    return out


def exact(a, b):
    a, b = float(a), float(b)
    return abs(a - b) <= 1e-9 * max(1.0, abs(a), abs(b))


def compare_row(row, published):
    """(mismatched columns, mismatched non-duration columns) of a row against a published row."""
    bad = [c for c in row if c in published and not exact(row[c], published[c])]
    return bad, [c for c in bad if c.split("__")[0] not in DURATION_FEATURES]
