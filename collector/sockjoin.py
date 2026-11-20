"""Socket-level join of switch flows to processes, from sockowner's events (host/sockowner/).

The switch keeps state per 5-tuple and reports the 5-tuple of each new flow; sockowner reports, for
every 5-tuple a local socket sends or receives, the socket's cookie and cgroup, and for every socket
the process that created it. Joining the two on the 5-tuple says which execution each flow belongs
to, so the network features of an execution can be computed from its own flows only, instead of from
everything the host sent in the same windows (the window-level join of the dataset).

Flow keys are direction-independent and use the switch model's normalization:
(protocol, *sorted(((address, port), (address, port)))) with dotted-quad addresses.

Only the Python standard library is needed.
"""

import bisect
import csv
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

PROTOCOLS = {"tcp": 6, "udp": 17}

FlowKey = Tuple[int, Tuple[str, int], Tuple[str, int]]


def flow_key(protocol: int, address_a: str, port_a: int, address_b: str, port_b: int) -> FlowKey:
    """Direction-independent 5-tuple key, as in features/switch_model.py's FlowTable."""
    return (int(protocol), *sorted(((address_a, int(port_a)), (address_b, int(port_b)))))


@dataclass
class Socket:
    cookie: int
    tgid: int
    tid: int
    cgroup_id: int
    family: int
    type: int
    protocol: int
    comm: str
    created_ns: int
    released_ns: Optional[int] = None


@dataclass
class FlowSighting:
    ts_ns: int
    cookie: int
    cgroup_id: int
    direction: str
    key: FlowKey


@dataclass
class SockOwnerLog:
    sockets: Dict[int, Socket] = field(default_factory=dict)
    sightings: List[FlowSighting] = field(default_factory=list)
    ready_cgroup: Optional[int] = None
    health: Optional[Dict[str, int]] = None
    malformed: int = 0


def parse_lines(lines: Iterable[str]) -> SockOwnerLog:
    """Parse sockowner's output lines (see host/sockowner/sockowner.c)."""
    log = SockOwnerLog()
    for raw in lines:
        line = raw.strip()
        if not line:
            continue
        parts = line.split(",")
        kind = parts[0]
        try:
            if kind == "SOCKOWNER_READY":
                log.ready_cgroup = int(parts[1])
            elif kind == "SOCKOWNER_HEALTH":
                log.health = {"ringbuf_drops": int(parts[1]), "flow_map_errors": int(parts[2]),
                              "failed": int(parts[3])}
            elif kind == "SOCK" and len(parts) >= 10:
                cookie = int(parts[2])
                log.sockets[cookie] = Socket(cookie=cookie, tgid=int(parts[3]), tid=int(parts[4]),
                                             cgroup_id=int(parts[5]), family=int(parts[6]), type=int(parts[7]),
                                             protocol=int(parts[8]), comm=",".join(parts[9:]),
                                             created_ns=int(parts[1]))
            elif kind == "REL" and len(parts) >= 7:
                cookie = int(parts[2])
                if cookie in log.sockets and log.sockets[cookie].released_ns is None:
                    log.sockets[cookie].released_ns = int(parts[1])
            elif kind == "FLOW" and len(parts) == 10:
                protocol = PROTOCOLS[parts[5]]
                key = flow_key(protocol, parts[6], int(parts[7]), parts[8], int(parts[9]))
                log.sightings.append(FlowSighting(ts_ns=int(parts[1]), cookie=int(parts[2]),
                                                  cgroup_id=int(parts[3]), direction=parts[4], key=key))
            else:
                log.malformed += 1
        except (IndexError, KeyError, ValueError):
            log.malformed += 1
    log.sightings.sort(key=lambda s: s.ts_ns)
    return log


def read_log(path: str) -> SockOwnerLog:
    with open(path, encoding="utf-8", errors="replace") as stream:
        return parse_lines(stream)


class OwnerTable:
    """Who owned each 5-tuple, and since when. A 5-tuple can move to another socket (a port reused
    after a connection closed); owner() then answers for the given time."""

    def __init__(self, log: SockOwnerLog):
        self.log = log
        self.by_key: Dict[FlowKey, List[FlowSighting]] = {}
        for sighting in log.sightings:
            self.by_key.setdefault(sighting.key, []).append(sighting)
        self.times = {key: [s.ts_ns for s in items] for key, items in self.by_key.items()}

    def owner(self, key: FlowKey, at_ns: Optional[int] = None, slack_ns: int = 0) -> Optional[FlowSighting]:
        """The sighting that owned key at at_ns (the last one seen up to at_ns + slack_ns); without
        a time, the first sighting. None if no local socket carried the 5-tuple."""
        items = self.by_key.get(key)
        if not items:
            return None
        if at_ns is None:
            return items[0]
        position = bisect.bisect_right(self.times[key], at_ns + slack_ns) - 1
        return items[max(position, 0)]

    def process(self, sighting: Optional[FlowSighting]) -> Optional[Socket]:
        """The socket (with its creating process) behind a sighting, if its creation was seen."""
        return self.log.sockets.get(sighting.cookie) if sighting else None


@dataclass
class Selector:
    """Which flows belong to the monitored execution: by its cgroup (the collector puts each
    execution in its own cgroup), by its processes, or both (either matches)."""
    cgroup_ids: Set[int] = field(default_factory=set)
    tgids: Set[int] = field(default_factory=set)

    def owns(self, table: OwnerTable, sighting: Optional[FlowSighting]) -> bool:
        if sighting is None:
            return False
        if sighting.cgroup_id in self.cgroup_ids:
            return True
        socket = table.process(sighting)
        return socket is not None and socket.tgid in self.tgids


def owned_bucket_indexes(reports: Sequence[Dict[str, object]], table: OwnerTable, selector: Selector,
                         to_monotonic_ns=None) -> Set[int]:
    """Switch buckets whose reported 5-tuple belongs to the selected execution. reports are the
    collector's CPU reports (listen_cpu_reports.parse_cpu_report dicts: src_ip, dst_ip, sport, dport,
    proto, idx); to_monotonic_ns maps a report to its time on sockowner's clock (optional). A bucket
    shared by two flows (a hash collision) is attributed by the flow that was reported."""
    owned: Set[int] = set()
    for report in reports:
        try:
            key = flow_key(int(report["proto"]), str(report["src_ip"]), int(report["sport"]),
                           str(report["dst_ip"]), int(report["dport"]))
            index = int(report["idx"])
        except (KeyError, TypeError, ValueError):
            continue
        at = to_monotonic_ns(report) if to_monotonic_ns else None
        if selector.owns(table, table.owner(key, at)):
            owned.add(index)
    return owned


def packet_filter(table: OwnerTable, selector: Selector, realtime_to_monotonic_ns: Optional[int] = None):
    """A predicate for features/switch_model.py-style packets: f(key, time_us) is True when the
    packet's flow belongs to the selected execution. realtime_to_monotonic_ns converts the capture's
    epoch time to sockowner's monotonic clock (monotonic = realtime + offset); without it the
    first owner of each 5-tuple is used."""
    def owned(key: FlowKey, time_us: int) -> bool:
        at = time_us * 1000 + realtime_to_monotonic_ns if realtime_to_monotonic_ns is not None else None
        return selector.owns(table, table.owner(key, at, slack_ns=50_000_000))
    return owned


def window_features_selected(switch_model, pcap_path: str, start_us: int, keep, window_seconds: float = 0.5,
                             windows: int = 40, active_ttl_windows: int = 3) -> List[Dict[str, float]]:
    """switch_model.window_features, restricted to packets for which keep(key, time_us) is True.
    switch_model is the release's features/switch_model.py module (passed in, not imported here)."""
    window_us = int(round(window_seconds * 1_000_000))
    table = switch_model.FlowTable(window_seconds, active_ttl_windows)
    result, current = [], 0
    for time_us, timestamp, frame in switch_model.read_pcap(pcap_path):
        offset = time_us - start_us
        if offset < 0 or offset // window_us >= windows:
            continue
        window = offset // window_us
        if window < current:
            raise ValueError("packets are not in timestamp order")
        while current < window:
            result.append(table.read_window(current))
            current += 1
        packet = switch_model.parse_flow_packet(frame)
        if packet is None:
            continue
        source, destination, protocol, ports, flags = packet
        if keep(flow_key(protocol, source, ports[0], destination, ports[1]), time_us):
            table.update(window, timestamp, source, destination, protocol, ports, flags, len(frame))
    while current < windows:
        result.append(table.read_window(current))
        current += 1
    return result


def write_sightings_csv(log: SockOwnerLog, path: str) -> None:
    """One row per flow sighting with its owner, for inspection."""
    with open(path, "w", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(["ts_ns", "protocol", "a", "a_port", "b", "b_port", "direction", "cookie", "cgroup_id",
                         "tgid", "comm"])
        for s in log.sightings:
            socket = log.sockets.get(s.cookie)
            writer.writerow([s.ts_ns, s.key[0], s.key[1][0], s.key[1][1], s.key[2][0], s.key[2][1], s.direction,
                             s.cookie, s.cgroup_id, socket.tgid if socket else "", socket.comm if socket else ""])


def socket_join_windows(net_windows: Sequence[Dict[str, object]], table: OwnerTable, selector: Selector,
                        t0_wall: float, monotonic_minus_wall_ns: int) -> List[Dict[str, object]]:
    """Copies of the collector's windows with "owned_indexes": the buckets whose flow belongs to the
    selected execution. A bucket's flow is the 5-tuple of its latest CPU report ("report_keys" of the
    windows: [idx, proto, src, sport, dst, dport]); its owner is looked up as of the end of the window
    that carried the report, on sockowner's monotonic clock (wall time + monotonic_minus_wall_ns). A
    bucket cleared after a read loses its owner until it reports again."""
    owner_by_idx: Dict[int, bool] = {}
    out: List[Dict[str, object]] = []
    for win in net_windows:
        end_wall = t0_wall + float(win.get("net_window_end_sec", 0.0))
        at_ns = int(end_wall * 1e9) + monotonic_minus_wall_ns
        for item in win.get("report_keys", []) or []:
            idx, protocol, src, sport, dst, dport = item
            key = flow_key(int(protocol), str(src), int(sport), str(dst), int(dport))
            owner_by_idx[int(idx)] = selector.owns(table, table.owner(key, at_ns))
        copy = dict(win)
        copy["owned_indexes"] = sorted(idx for idx, own in owner_by_idx.items() if own)
        out.append(copy)
        for idx in win.get("cleared_indexes", []) or []:
            owner_by_idx.pop(int(idx), None)
    return out


LOOPBACK_PREFIX = "127."


class BucketOwners:
    """Owners of switch buckets when no CPU report names a bucket's flow (switch/variants/sweep, whose probes export
    the bucket table without addresses).

    A bucket's flow is the local 5-tuple that the switch hashes to it (bucket_of: the switch's symmetric flow hash,
    flow_index.compute_flow_index(address_a, address_b, port_a, port_b, protocol)) and that has the bucket's
    reference ports, the source and destination ports of the bucket's first packet since the reset (read with the
    bucket). That is the flow whose state the bucket holds, as a CPU report names it in the bucket program. Another
    local 5-tuple in the same bucket is a second flow merged into it (a hash collision: the switch counts its packets
    in the bucket and in reg_coll), and the bucket stays with the first. A 5-tuple that never crossed the switch
    (loopback, another interface) almost never has a used bucket's ports, so it owns nothing. Among the matching
    5-tuples (normally one) the owner at a time is OwnerTable.owner()'s sighting: a 5-tuple reused by another socket
    changes owner; a flow counted before its first sighting (the two clocks) keeps its first sighting's owner."""

    def __init__(self, table: OwnerTable, bucket_of):
        self.table = table
        self.keys: Dict[int, List[FlowKey]] = {}
        self.bucket_by_key: Dict[FlowKey, int] = {}
        for key in table.by_key:
            protocol, (address_a, port_a), (address_b, port_b) = key
            idx = int(bucket_of(address_a, address_b, port_a, port_b, protocol))
            self.bucket_by_key[key] = idx
            self.keys.setdefault(idx, []).append(key)

    @staticmethod
    def ports(key: FlowKey) -> Tuple[int, int]:
        return tuple(sorted((key[1][1], key[2][1])))  # type: ignore[return-value]

    def matching(self, idx: int, ref_sp: int, ref_dp: int) -> List[FlowKey]:
        """The local 5-tuples of bucket idx with its reference ports."""
        want = tuple(sorted((int(ref_sp), int(ref_dp))))
        return [k for k in self.keys.get(int(idx), ()) if self.ports(k) == want]

    def others(self, idx: int, ref_sp: int, ref_dp: int) -> List[FlowKey]:
        """The local 5-tuples hashed to bucket idx without its reference ports (merged into its flow if they crossed
        the switch)."""
        want = tuple(sorted((int(ref_sp), int(ref_dp))))
        return [k for k in self.keys.get(int(idx), ()) if self.ports(k) != want]

    def owner(self, idx: int, ref_sp: int, ref_dp: int, at_ns: Optional[int] = None,
              slack_ns: int = 0) -> Optional[FlowSighting]:
        """The sighting that owns bucket idx at at_ns (on sockowner's clock): of the matching 5-tuples' owners at
        that time, the one seen last up to at_ns + slack_ns, else the earliest; None if no local 5-tuple has the
        bucket's ports."""
        found = [self.table.owner(k, at_ns, slack_ns) for k in self.matching(idx, ref_sp, ref_dp)]
        found = [s for s in found if s is not None]
        if not found:
            return None
        if at_ns is not None:
            before = [s for s in found if s.ts_ns <= at_ns + slack_ns]
            if before:
                return max(before, key=lambda s: s.ts_ns)
        return min(found, key=lambda s: s.ts_ns)

    def first_seen_ns(self, key: FlowKey) -> int:
        return self.table.times[key][0]


def ip_scope_windows(net_windows: Sequence[Dict[str, object]], addresses: Iterable[str]) -> List[Dict[str, object]]:
    """Copies of the collector's windows with "owned_indexes": the buckets whose flow (the 5-tuple of the
    bucket's latest CPU report, "report_keys") has one of `addresses` as its source or destination. This is
    the host-level join for several hosts behind the switch: one host's network features are those of its
    own flows. A bucket cleared after a read loses its owner until it reports again; a flow between two of
    the given hosts counts for both."""
    want = {str(a) for a in addresses}
    owner_by_idx: Dict[int, bool] = {}
    out: List[Dict[str, object]] = []
    for win in net_windows:
        for item in win.get("report_keys", []) or []:
            idx, _protocol, src, _sport, dst, _dport = item
            owner_by_idx[int(idx)] = str(src) in want or str(dst) in want
        copy = dict(win)
        copy["owned_indexes"] = sorted(idx for idx, own in owner_by_idx.items() if own)
        out.append(copy)
        for idx in win.get("cleared_indexes", []) or []:
            owner_by_idx.pop(int(idx), None)
    return out
