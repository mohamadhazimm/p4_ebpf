"""Software model of perf/variants/exact: its registers and per-packet logic, for the unit tests and
for offline checks (it gives window_reader.py's lines, which window_features.py turns into features).

The flow table's hashes are stand-ins (CRC-32 of the ordered key with different seeds), not the
compiled ones, so which flows collide differs from the switch; everything else follows ingress.p4:
register names, index layout, the per-packet updates, the reader's clears of the extremes.

    m = ExactModel(frame_min={"10.0.0.10"})
    m.marker(1); m.packet(src, dst, proto, sport, dport, flags, total_len, t_ns); ...; m.marker(2)
    line = m.read(1)       # what window_reader.py --follow prints for window 1
"""
import socket
import zlib
from typing import Dict, Iterable, Optional

from window_reader import EXTREMES, WINDOW_REGS

M32 = (1 << 32) - 1
TTL = 3


def ordered_key(src: bytes, dst: bytes, proto: int, sport: int, dport: int):
    """The flow key with the lower (address, port) endpoint first, and whether the source is it."""
    a, b = (src, sport), (dst, dport)
    lo, hi = (a, b) if a <= b else (b, a)
    key = bytes([proto]) + lo[0] + lo[1].to_bytes(2, "big") + hi[0] + hi[1].to_bytes(2, "big")
    return key, a < b


class ExactModel:
    def __init__(self, ways: int = 4, way_bits: int = 14, frame_min: Iterable[str] = (), time_shift: int = 16):
        self.ways, self.wslots, self.shift = ways, 1 << way_bits, time_shift
        self.frame_min = {socket.inet_aton(a) for a in frame_min}
        self.way = [dict() for _ in range(ways)]
        self.ref: Dict[int, bool] = {}
        self.seen: Dict[int, int] = {}
        self.ba: Dict[int, int] = {}
        self.minl: Dict[int, int] = {}
        self.maxl: Dict[int, int] = {}
        self.first: Dict[int, int] = {}
        self.last: Dict[int, int] = {}
        self.r: Dict[tuple, object] = {}
        self.epoch = 0
        self.untracked_flows = set()

    # ------------------------------------------------------------ registers
    def _add(self, reg, idx, lo, hi=None):
        k = (reg, idx)
        if hi is None:
            self.r[k] = (self.r.get(k, 0) + lo) & M32
        else:
            v = self.r.setdefault(k, [0, 0])
            v[0], v[1] = (v[0] + lo) & M32, (v[1] + hi) & M32

    def _max(self, reg, idx, lo, hi=None):
        k = (reg, idx)
        if hi is None:
            self.r[k] = max(self.r.get(k, 0), lo)
        else:
            v = self.r.setdefault(k, [0, 0])
            v[0], v[1] = max(v[0], lo), max(v[1], hi)

    # ------------------------------------------------------------ packets
    def marker(self, epoch: int) -> None:
        self.epoch = epoch

    def _slot(self, key: bytes):
        sig = zlib.crc32(key, 0x5A5A5A5A) or 1
        for w in range(self.ways):
            i = zlib.crc32(key, 0x1000193 * (w + 1)) % self.wslots
            v = self.way[w].get(i, 0)
            if v == 0:
                self.way[w][i] = sig
                return w * self.wslots + i, True
            if v == sig:
                return w * self.wslots + i, False
        return None, False

    def packet(self, src: str, dst: str, proto: int, sport: int, dport: int, flags: int, total_len: int,
               t_ns: int) -> None:
        """One IPv4 TCP/UDP packet (flags: the 9-bit TCP flags, 0 for UDP)."""
        e = self.epoch
        b = e & 1
        e16 = e & 0xFFFF
        t = (t_ns >> self.shift) & M32
        s_ip, d_ip = socket.inet_aton(src), socket.inet_aton(dst)
        L = max(total_len, 46) if d_ip in self.frame_min else total_len
        self._max("reg_w_pb", b, 0xFFFF - L, L)
        self._add("reg_w_flags", b, int(bool(flags & 0x02)), int(bool(flags & 0x10)))
        if flags & 0x04:
            self._add("reg_w_rst", b, 1)
        key, smaller = ordered_key(s_ip, d_ip, proto, sport, dport)
        s, new = self._slot(key)
        found = int(s is not None)
        dir_ab = 1
        if found:
            if new:
                self.ref[s] = smaller
                self.seen[s] = e16
                self.minl[s] = self.maxl[s] = L
                old_min = old_max = L
                self.first[s] = first = t
                self.last[s] = old_last = t
                code = 4
            else:
                dir_ab = int(self.ref[s] == smaller)
                d = (e16 - self.seen[s]) & 0xFFFF
                code = 4 if d > TTL else d
                self.seen[s] = e16
                old_min, old_max = self.minl[s], self.maxl[s]
                self.minl[s], self.maxl[s] = min(old_min, L), max(old_max, L)
                first = self.first[s]
                old_last = self.last[s]
                self.last[s] = t
            ba_old = self.ba.get(s, 0)
            if dir_ab == 0:
                self.ba[s] = 1
            dec, inc = max(old_min - L, 0), max(L - old_max, 0)
            gap, dur_old, dur_new = (t - old_last) & M32, (old_last - first) & M32, (t - first) & M32
            self._add("reg_w_chg_len", b, -dec, inc)
            self._add("reg_w_chg_dur", b, gap)
            if code:
                self._add("reg_w_carry_len", (b << 2) | (code & 3), old_min, old_max)
                self._add("reg_w_carry_dur", (b << 2) | (code & 3), dur_old)
                self._add("reg_w_cnt", (b << 5) | (code << 2) | (ba_old << 1) | dir_ab, 1)
            elif ba_old == 0 and dir_ab == 0:
                self._add("reg_w_cnt", b << 5, 1)
            self._max("reg_w_pa", b, 0xFFFF - old_min, old_max)
            self._max("reg_w_pd", b, dur_new)
        else:
            self.untracked_flows.add(key)
        self._add("reg_w_tot", (b << 2) | (found << 1) | dir_ab, 1, L)

    # ------------------------------------------------------------ the reader
    def read(self, epoch: Optional[int] = None) -> dict:
        """window_reader.py's line for a finished window (default: the one before the current), then the
        clear of its bank's extremes."""
        e = self.epoch - 1 if epoch is None else epoch
        b = e & 1
        regs = {}
        for name, pair, how, idx in WINDOW_REGS:
            regs[name] = {str(i): (list(self.r.get((name, i), [0, 0])) if pair else self.r.get((name, i), 0))
                          for i in idx(b)}
        for name, pair, how, idx in WINDOW_REGS:
            if name in EXTREMES:
                for i in idx(b):
                    self.r.pop((name, i), None)
        return {"epoch": e, "bank": b, "regs": regs, "lost": False}
