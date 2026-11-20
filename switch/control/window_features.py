"""The 29 window features of features/switch_model.py from the window registers of switch/variants/exact.

window_reader.py --follow prints, per finished window e, the window registers of bank e & 1: the
additive ones as they are (they are never cleared), the extremes as the window left them (the reader
clears them after the read). WindowFeatures.add() takes these lines in epoch order and returns the
window's features (the model's names), plus
    net_untracked_pkts    packets of flows that found no slot in the flow table (the window's flow
                          features are then not exact);
    net_window_lost       this window's numbers may be wrong, or those of one of the TTL windows before it,
                          which its flow features are rebuilt from: the reader marked that window lost (its
                          read came after the bank's next window had started, a late clear may have wiped
                          its extremes, or its bank was last read with other clocked pipes);
    net_unclocked_pkts    packets counted by a pipe whose clock lags (they belong to no window);
    net_rejected_markers  window markers from ports outside marker_ports since the window before.

The rebuild (ingress.p4's header comment): a flow is active in window e if its last packet is in
e-3..e. For a per-flow value v (min length, max length, duration; 1 for the count; has-B->A for
flows_with_ba) the sum over the active flows is
    S(e) = sum_{j=e-3..e} (In_j - sum_{k=j+1..e} Out_k[k-j])
with In_j = sum_cls Carry_j[cls] + Change_j and Out_k[d] = Carry_k[d]; for the counts In_j is the
number of flows of window j (touches) and Out_k[d] the touches of class d. The minimum length over
the active flows is 0xFFFF minus the maximum of reg_w_pa.lo and reg_w_pb.lo over windows e-3..e,
the maximum length the maximum of their .hi, the maximum duration that of reg_w_pd.

Lengths: the switch counts L (IPv4 totalLen, or the frame_len minimum); header (14) is added per
packet for the frame bytes of the dataset. Durations: units of 65.536 us (ingress_mac_tstamp[47:16]).
"""
from typing import Any, Dict, List, Optional

M32 = (1 << 32) - 1
TTL = 3
HEADER = 14
TIME_UNIT_S = 65536e-9

FEATURES = [
    "net_flow_count_seen", "net_pkts_total_delta", "net_bytes_total_delta", "net_pkts_ab_delta",
    "net_bytes_ab_delta", "net_pkts_ba_delta", "net_bytes_ba_delta", "net_min_len_mean", "net_max_len_mean",
    "net_min_len_min", "net_max_len_max", "net_avg_pkt_size_delta", "net_avg_pkt_size_ab_delta",
    "net_avg_pkt_size_ba_delta", "net_flow_duration_mean", "net_flow_duration_max", "net_bytes_per_sec_delta",
    "net_pkts_per_sec_delta", "net_down_up_ratio_delta", "net_ab_ratio_pkt_delta", "net_ba_ratio_pkt_delta",
    "net_ab_ratio_byte_delta", "net_ba_ratio_byte_delta", "net_syn_delta", "net_ack_delta", "net_rst_delta",
    "net_flows_with_ab", "net_flows_with_ba", "net_dir_valid_count",
]
ADDITIVE = ["reg_w_tot", "reg_w_flags", "reg_w_rst", "reg_w_cnt", "reg_w_chg_len", "reg_w_chg_dur",
            "reg_w_carry_len", "reg_w_carry_dur"]
EXTREMES = ["reg_w_pa", "reg_w_pb", "reg_w_pd"]


def _sub(a: Any, b: Any) -> Any:
    if isinstance(a, list):
        return [(x - y) & M32 for x, y in zip(a, b)]
    return (a - b) & M32


class WindowFeatures:
    def __init__(self, window_sec: float = 0.5, header: int = HEADER, time_unit_s: float = TIME_UNIT_S):
        self.window_sec = window_sec
        self.header = header
        self.unit_s = time_unit_s
        self.prev: Dict[Any, Any] = {}         # (register, index) -> value at the bank's previous read
        self.hist: Dict[int, Dict[str, Any]] = {}
        self.last_epoch: Optional[int] = None
        self.prev_rejected: Optional[int] = None
        self.lost: set = set()                 # windows the reader marked lost (the last TTL of them)

    def window_registers(self, line: Dict[str, Any]) -> Dict[str, Any]:
        """The window's own values: differences of the additive registers, the extremes as read."""
        e = int(line["epoch"])
        if self.last_epoch is not None and e != self.last_epoch + 1:
            raise ValueError("window %d after window %d: the reads must come in order" % (e, self.last_epoch))
        self.last_epoch = e
        regs = line["regs"]
        w: Dict[str, Dict[int, Any]] = {}
        for name in ADDITIVE:
            w[name] = {}
            for idx, v in regs[name].items():
                k = (name, int(idx))
                zero = [0, 0] if isinstance(v, list) else 0
                w[name][int(idx)] = _sub(v, self.prev.get(k, zero))
                self.prev[k] = v
        for name in EXTREMES:
            w[name] = {int(i): v for i, v in regs[name].items()}
        return w

    def add(self, line: Dict[str, Any]) -> Dict[str, Any]:
        e = int(line["epoch"])
        b = e & 1
        w = self.window_registers(line)
        tot = {i & 3: v for i, v in w["reg_w_tot"].items()}            # (found << 1) | dir
        cnt = {}
        for i, v in w["reg_w_cnt"].items():
            x = i & 31
            cnt[((x >> 2) & 7, (x >> 1) & 1, x & 1)] = v              # (code, ba_old, dir_ab)
        carry_len = {i & 3: v for i, v in w["reg_w_carry_len"].items()}
        carry_dur = {i & 3: v for i, v in w["reg_w_carry_dur"].items()}
        h = dict(cnt=cnt, chg_len=w["reg_w_chg_len"][b], chg_dur=w["reg_w_chg_dur"][b],
                 carry_len=carry_len, carry_dur=carry_dur, pa=w["reg_w_pa"][b], pb=w["reg_w_pb"][b],
                 pd=w["reg_w_pd"][b])
        self.hist[e] = h
        for old in [k for k in self.hist if k < e - TTL]:
            del self.hist[old]
        H = self.hist
        js = [j for j in range(e - TTL, e + 1) if j in H]

        def live(in_of, out_of) -> int:
            s = 0
            for j in js:
                s += in_of(H[j])
                for k in range(j + 1, e + 1):
                    if k in H:
                        s -= out_of(H[k], k - j)
            return s

        def touches(x, pred) -> int:
            return sum(v for (code, ba, d), v in x["cnt"].items() if code != 0 and pred(code & 3, ba, d))

        n = live(lambda x: touches(x, lambda c, a, d: True), lambda x, k: touches(x, lambda c, a, d: c == k))
        nba = live(lambda x: touches(x, lambda c, a, d: a == 1 or d == 0) + x["cnt"].get((0, 0, 0), 0),
                   lambda x, k: touches(x, lambda c, a, d: a == 1 and c == k))
        s_min = live(lambda x: sum(v[0] for v in x["carry_len"].values()) + x["chg_len"][0],
                     lambda x, k: x["carry_len"].get(k, [0, 0])[0]) & M32
        s_max = live(lambda x: sum(v[1] for v in x["carry_len"].values()) + x["chg_len"][1],
                     lambda x, k: x["carry_len"].get(k, [0, 0])[1]) & M32
        s_dur = live(lambda x: sum(x["carry_dur"].values()) + x["chg_dur"],
                     lambda x, k: x["carry_dur"].get(k, 0)) & M32
        pmin = 0xFFFF - max((max(H[j]["pa"][0], H[j]["pb"][0]) for j in js), default=0)
        pmax = max((max(H[j]["pa"][1], H[j]["pb"][1]) for j in js), default=0)
        pdur = max((H[j]["pd"] for j in js), default=0)

        hdr = self.header
        ab_p = tot.get(3, [0, 0])[0] + tot.get(1, [0, 0])[0]
        ba_p = tot.get(2, [0, 0])[0] + tot.get(0, [0, 0])[0]
        ab_b = tot.get(3, [0, 0])[1] + tot.get(1, [0, 0])[1] + hdr * ab_p
        ba_b = tot.get(2, [0, 0])[1] + tot.get(0, [0, 0])[1] + hdr * ba_p
        flags = w["reg_w_flags"][b]
        out: Dict[str, Any] = dict.fromkeys(FEATURES, 0)
        packets, size = ab_p + ba_p, ab_b + ba_b
        out.update({
            "net_pkts_total_delta": packets, "net_bytes_total_delta": size,
            "net_pkts_ab_delta": ab_p, "net_bytes_ab_delta": ab_b,
            "net_pkts_ba_delta": ba_p, "net_bytes_ba_delta": ba_b,
            "net_syn_delta": flags[0], "net_ack_delta": flags[1], "net_rst_delta": w["reg_w_rst"][b],
            "net_flow_count_seen": n, "net_dir_valid_count": n, "net_flows_with_ab": n, "net_flows_with_ba": nba,
            "net_min_len_mean": (s_min + hdr * n) / n if n else 0.0,
            "net_max_len_mean": (s_max + hdr * n) / n if n else 0.0,
            "net_min_len_min": pmin + hdr if n else 0, "net_max_len_max": pmax + hdr if n else 0,
            "net_avg_pkt_size_delta": size / packets if packets else 0.0,
            "net_avg_pkt_size_ab_delta": ab_b / ab_p if ab_p else 0.0,
            "net_avg_pkt_size_ba_delta": ba_b / ba_p if ba_p else 0.0,
            "net_flow_duration_mean": s_dur * self.unit_s / n if n else 0.0,
            "net_flow_duration_max": pdur * self.unit_s if n else 0.0,
            "net_bytes_per_sec_delta": size / self.window_sec, "net_pkts_per_sec_delta": packets / self.window_sec,
            "net_down_up_ratio_delta": ba_b / ab_b if ab_b else 0.0,
            "net_ab_ratio_pkt_delta": ab_p / packets if packets else 0.0,
            "net_ba_ratio_pkt_delta": ba_p / packets if packets else 0.0,
            "net_ab_ratio_byte_delta": ab_b / size if size else 0.0,
            "net_ba_ratio_byte_delta": ba_b / size if size else 0.0,
        })
        out["net_untracked_pkts"] = tot.get(0, [0, 0])[0] + tot.get(1, [0, 0])[0]
        if line.get("lost"):
            self.lost.add(e)
        self.lost = {j for j in self.lost if j >= e - TTL}
        out["net_window_lost"] = int(bool(self.lost))
        out["net_unclocked_pkts"] = int(line.get("unclocked_pkts") or 0)
        rejected = line.get("rejected_markers")
        out["net_rejected_markers"] = 0 if rejected is None or self.prev_rejected is None else \
            (int(rejected) - self.prev_rejected) & M32
        if rejected is not None:
            self.prev_rejected = int(rejected)
        return out


def window_rows(lines: List[Dict[str, Any]], **kw) -> Dict[int, Dict[str, Any]]:
    """epoch -> features, for reader lines in epoch order (lines without "epoch" are skipped)."""
    wf = WindowFeatures(**kw)
    return {int(l["epoch"]): wf.add(l) for l in lines if "epoch" in l and "regs" in l}
