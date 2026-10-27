#!/usr/bin/env python3
"""Receive the first-seen flow reports that the data plane mirrors to the CPU.

Reports start with cpu_report_t (headers.p4), followed by the first bytes of
the original packet:

    magic 0xBEF1 (18 B): magic, src_ip, dst_ip, src_port, dst_port, proto,
                         reason, flow_index  -- the bucket the data plane chose
    magic 0xBEEF (16 B): the same without flow_index (earlier builds); the
                         index is then computed with flow_index.py

Reports can be captured on a local interface (scapy; e.g. the model's veth5)
or, with --ssh, on the switch's CPU interface (enp5s0 for the PCIe CPU port on
a hardware Tofino) by streaming `tcpdump -w -` over SSH; that needs no Python
packages on the switch.
"""
from __future__ import annotations

import argparse
import shlex
import socket
import struct
import subprocess
import threading
import time
from typing import Callable, Dict, Iterator, List, Optional, Tuple

from flow_index import compute_flow_index

MAGIC = 0xBEF1          # cpu_report_t with flow_index
LEGACY_MAGIC = 0xBEEF   # cpu_report_t without flow_index
REPORT_LEN = 18
LEGACY_REPORT_LEN = 16
TCPDUMP_FILTER = "ether[0:2] = 0xbef1 or ether[0:2] = 0xbeef"

# Kept for callers of the earlier API.
compute_flow_index_symmetric = compute_flow_index


def parse_cpu_report(raw: bytes) -> Optional[Dict[str, object]]:
    if len(raw) < LEGACY_REPORT_LEN:
        return None
    magic, src_ip_raw, dst_ip_raw, sport, dport, proto, reason = struct.unpack("!HIIHHBB", raw[:16])
    if magic not in (MAGIC, LEGACY_MAGIC):
        return None
    computed = compute_flow_index(src_ip_raw, dst_ip_raw, sport, dport, proto)
    if magic == MAGIC:
        if len(raw) < REPORT_LEN:
            return None
        idx = struct.unpack("!H", raw[16:18])[0]
        source = "report"
    else:
        idx = computed
        source = "computed"
    return {
        "src_ip": socket.inet_ntoa(struct.pack("!I", src_ip_raw)),
        "dst_ip": socket.inet_ntoa(struct.pack("!I", dst_ip_raw)),
        "sport": sport,
        "dport": dport,
        "proto": proto,
        "reason": reason,
        "idx": idx,
        "idx_source": source,
        "idx_computed": computed,
    }


def iter_pcap_stream(stream) -> Iterator[Tuple[float, bytes]]:
    """Yield (timestamp, frame) from a pcap byte stream (tcpdump -w -)."""
    header = stream.read(24)
    if len(header) < 24:
        return
    magic = struct.unpack("<I", header[:4])[0]
    if magic in (0xA1B2C3D4, 0xA1B23C4D):
        endian, nano = "<", magic == 0xA1B23C4D
    elif magic in (0xD4C3B2A1, 0x4D3CB2A1):
        endian, nano = ">", magic == 0x4D3CB2A1
    else:
        raise ValueError("not a pcap stream (magic 0x%08x)" % magic)
    while True:
        rec = stream.read(16)
        if len(rec) < 16:
            return
        sec, frac, incl, _orig = struct.unpack(endian + "IIII", rec)
        data = stream.read(incl)
        if len(data) < incl:
            return
        yield sec + frac / (1e9 if nano else 1e6), data


class ReportCollector:
    """Collect CPU reports in the background, stamped with this host's clock.

    take(start, end) returns the reports received in [start, end), so register
    reads can run at window boundaries without losing reports meanwhile.
    """

    def __init__(self, iface: str, ssh_host: Optional[str] = None,
                 on_report: Optional[Callable[[Dict[str, object]], None]] = None):
        self.iface = iface
        self.ssh_host = ssh_host
        self.on_report = on_report
        self._reports: List[Tuple[float, Dict[str, object]]] = []
        self._lock = threading.Lock()
        self._sniffer = None
        self._proc = None
        self._thread = None
        self.frames_seen = 0

    def _add(self, raw: bytes) -> None:
        self.frames_seen += 1
        parsed = parse_cpu_report(raw)
        if not parsed:
            return
        with self._lock:
            self._reports.append((time.time(), parsed))
        if self.on_report:
            self.on_report(parsed)

    def start(self) -> "ReportCollector":
        if self.ssh_host:
            cmd = "tcpdump -i %s -U -s 128 -w - %s" % (shlex.quote(self.iface), shlex.quote(TCPDUMP_FILTER))
            self._proc = subprocess.Popen(["ssh", "-o", "BatchMode=yes", self.ssh_host, cmd],
                                          stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                          stderr=subprocess.DEVNULL)

            def pump():
                for _ts, frame in iter_pcap_stream(self._proc.stdout):
                    self._add(frame)
            self._thread = threading.Thread(target=pump, daemon=True)
            self._thread.start()
        else:
            from scapy.all import AsyncSniffer
            self._sniffer = AsyncSniffer(iface=self.iface, store=False,
                                         prn=lambda pkt: self._add(bytes(pkt)))
            self._sniffer.start()
        return self

    def stop(self) -> None:
        if self._sniffer is not None:
            self._sniffer.stop()
            self._sniffer = None
        if self._proc is not None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
            self._proc = None

    def take(self, start: float, end: float) -> List[Dict[str, object]]:
        with self._lock:
            return [r for t, r in self._reports if start <= t < end]


def collect_indexes_on_iface(iface: str, timeout: float, ssh_host: Optional[str] = None) -> List[int]:
    seen: List[int] = []

    def show(parsed):
        idx = parsed["idx"]
        if idx not in seen:
            seen.append(idx)
            print(
                f"[CPU-REPORT] {parsed['src_ip']}:{parsed['sport']} -> "
                f"{parsed['dst_ip']}:{parsed['dport']} proto={parsed['proto']} "
                f"reason={parsed['reason']} idx={idx} ({parsed['idx_source']})",
                flush=True,
            )

    collector = ReportCollector(iface, ssh_host=ssh_host, on_report=show).start()
    try:
        time.sleep(timeout)
    finally:
        collector.stop()
    return seen


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iface", default="veth5",
                    help="interface receiving the reports (veth5 on the model, enp5s0 on the switch)")
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--ssh", help="capture on this switch over SSH (e.g. root@172.168.1.2)")
    args = ap.parse_args()

    where = f"{args.ssh}:{args.iface}" if args.ssh else args.iface
    print(f"[INFO] Listening on {where} for mirrored CPU reports...", flush=True)
    collect_indexes_on_iface(args.iface, args.timeout, ssh_host=args.ssh)


if __name__ == "__main__":
    main()
