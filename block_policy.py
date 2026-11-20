"""Block rules on a malicious verdict: the switch stops forwarding from the flagged host (perf/variants/exact_block).

hybrid_collector.py --block-on-alarm (with --switch-program exact and a build of perf/variants/exact_block) scores
the run after every window with the detectors of live_test/streaming/stream_verdicts.py. At the first window whose
probability reaches the threshold (the alarm) the switch is told to drop, from then on:

scope "host" (the default, --block-scope host): everything the flagged host sends. One entry per source address of
  the host (the local addresses of the monitored cgroup's flows, from sockowner's FLOW lines, and every --block-host
  address) and, with --block-host-port, one for everything entering that switch port (sources that are spoofed). The
  entries are written about 3-5 ms after the alarm; new connections are dropped from their first packet. The switch
  sees addresses and ports, not programs, so the host's other programs are blocked as well. After the alarm every
  window adds an address the program has used since, and retries a write that failed.

scope "flows" (--block-scope flows, PC1.md part 11): the program's own flows only:
- every 5-tuple a socket of the monitored cgroup has carried so far, one exact entry per direction; after the alarm,
  every new 5-tuple of the cgroup, once per window. A new connection therefore passes until the next window, so a
  program of short connections is never stopped (PC1.md 11F: every connection ended before its entry);
- its host, for a flood or a scan: when a window after the alarm, or the alarm's own window, has more active flows
  on the switch (net_flow_count_seen) than flood_flows. Default 500 active flows per 0.5-s window: about twice the
  busiest benign window of the dataset (231, a network-active benign client; every other benign run has at most 1),
  while the dataset's floods and scans have 1,000 to 98,000. The host is also blocked when the program's flow entries
  would no longer fit in the table (max_entries);
- without --sockowner (a replay: no local sockets) the switch cannot name the program's flows: the alarm blocks the
  host.

Blocked packets are still counted by the window registers, so the windows (and later verdicts) still show the
attack. At the end the entries are listed with their dropped packets and deleted (unless keep).

Only the Python standard library is needed here; the scoring function is passed in.
"""

import json
import os
import time
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple

import sockjoin

FLOOD_FLOWS_PER_HALF_SECOND = 500
# the entries the table holds: perf/variants/exact_block's 1,024 (-DBLOCK_ENTRIES) less one with the per-entry direct
# counter (the default): on the Wedge the 1,024th add fails with RESOURCE_EXHAUSTED (PC1.md part 11b)
BLOCK_ENTRIES = 1023
SCORE_WINDOWS = 40          # a run's windows at 0.5 s; a scorer of another table says its own (score.windows)
SCOPES = ("host", "flows")  # what an alarm blocks: everything from the host, or the program's flows

Entry = Dict[str, Any]


def flow_entries(key: sockjoin.FlowKey) -> List[Entry]:
    """Both directions of a 5-tuple (sockjoin.flow_key) as block entries."""
    proto, (addr_a, port_a), (addr_b, port_b) = key
    return [{"src": addr_a, "sport": port_a, "dst": addr_b, "dport": port_b, "proto": proto},
            {"src": addr_b, "sport": port_b, "dst": addr_a, "dport": port_a, "proto": proto}]


def host_entries(addresses: Iterable[str], port: Optional[int] = None) -> List[Entry]:
    """Everything from these source addresses, and with port everything entering that switch port."""
    out = [{"src": a} for a in sorted(set(addresses))]
    if port is not None:
        out.append({"port": int(port)})
    return out


def flood_threshold(window_sec: float, per_half_second: float = FLOOD_FLOWS_PER_HALF_SECOND) -> float:
    """The flood threshold scaled to the window length (the active set grows with it)."""
    return per_half_second * window_sec / 0.5


class FlowTail:
    """sockowner's FLOW lines as the log grows: the 5-tuples each cgroup's sockets carried, and the local
    addresses they used (the source of an egress packet, the destination of an ingress one). Lines are split on
    "\\n" only (a process name may hold any other line break, which str.splitlines() would cut on)."""

    def __init__(self, path: str):
        self.path = path
        self.offset = 0
        self.partial = ""
        self.keys: Dict[int, List[sockjoin.FlowKey]] = {}     # cgroup id -> keys in the order first seen
        self.seen: Dict[int, Set[sockjoin.FlowKey]] = {}
        self.local: Dict[int, Set[str]] = {}
        self.malformed = 0

    def poll(self) -> int:
        """Read what was appended since the last poll; returns the number of new (cgroup, 5-tuple) pairs."""
        try:
            with open(self.path, "rb") as stream:
                stream.seek(self.offset)
                data = stream.read()
        except OSError:
            return 0
        if not data:
            return 0
        self.offset += len(data)
        text = self.partial + data.decode("utf-8", errors="replace")
        lines = text.split("\n")
        self.partial = lines.pop()
        new = 0
        for line in lines:
            if not line.startswith("FLOW,"):
                continue
            parts = line.strip().split(",")
            try:
                if len(parts) != 10:
                    raise ValueError(line)
                cgroup, direction = int(parts[3]), parts[4]
                proto = sockjoin.PROTOCOLS[parts[5]]
                key = sockjoin.flow_key(proto, parts[6], int(parts[7]), parts[8], int(parts[9]))
                local = parts[6] if direction == "egress" else parts[8]
            except (KeyError, ValueError):
                self.malformed += 1
                continue
            seen = self.seen.setdefault(cgroup, set())
            self.local.setdefault(cgroup, set()).add(local)
            if key not in seen:
                seen.add(key)
                self.keys.setdefault(cgroup, []).append(key)
                new += 1
        return new

    def flows_of(self, cgroups: Iterable[int]) -> List[sockjoin.FlowKey]:
        out: List[sockjoin.FlowKey] = []
        for c in cgroups:
            out.extend(self.keys.get(c, []))
        return out

    def local_addresses(self, cgroups: Iterable[int]) -> Set[str]:
        out: Set[str] = set()
        for c in cgroups:
            out |= self.local.get(c, set())
        return out


class Blocker:
    """The verdict-to-block loop. request(dict) -> dict is the window reader's (WindowReaderProcess.request);
    score(rows) -> probability scores the run's rows so far (dicts with the host_ and net_ columns).

    The collector calls on_net_window(w, features) when the switch's window w has been read (its network
    columns; flood check and new flows, without waiting for the host window), on_row(w, row) when the row of
    window w is written (host and network columns; the verdict), and finish() at the end, while the reader
    is still running. skip_windows: the collector windows before this one are not the run's (a replay anchored
    on collector window K, replay_capture.py --align-window K: the detectors were trained on prefixes that start
    at the run's first window), so they are neither scored nor checked for a flood. force_window: raise the
    alarm at that window whatever the probability (to test the
    mechanism with benign programs)."""

    def __init__(self, request: Callable[[Dict[str, Any]], Dict[str, Any]],
                 score: Callable[[List[Dict[str, Any]]], float], threshold: float = 0.5,
                 cgroup_ids: Sequence[int] = (), tail: Optional[FlowTail] = None,
                 host_addresses: Sequence[str] = (), host_port: Optional[int] = None,
                 flood_flows: float = FLOOD_FLOWS_PER_HALF_SECOND, log_path: Optional[str] = None,
                 force_window: Optional[int] = None, keep: bool = False, echo: bool = True,
                 clock: Any = time, max_entries: int = BLOCK_ENTRIES, skip_windows: int = 0,
                 scope: str = "host"):
        if scope not in SCOPES:
            raise ValueError("block scope %r: one of %s" % (scope, ", ".join(SCOPES)))
        self.request_fn, self.score, self.threshold = request, score, threshold
        # the detector was trained on prefixes of up to one run's windows: 40 at 0.5 s, 80 at 0.25 s (PC1.md part 13)
        self.score_windows = int(getattr(score, "windows", None) or SCORE_WINDOWS)
        self.scope = scope
        self.blocked_addresses: Set[str] = set()
        self.port_blocked = False
        self.skip_windows = int(skip_windows)
        self.cgroup_ids = set(int(c) for c in cgroup_ids)
        self.tail, self.host_addresses, self.host_port = tail, list(host_addresses), host_port
        self.flood_flows, self.force_window, self.keep, self.echo = flood_flows, force_window, keep, echo
        self.clock, self.max_entries = clock, max_entries
        self.flow_entry_count = 0
        self.log = open(log_path, "a") if log_path else None
        self.rows: List[Dict[str, Any]] = []
        self.alarm: Optional[Dict[str, Any]] = None
        self.blocked_flows: Set[sockjoin.FlowKey] = set()
        self.host_blocked = False
        self.pending_flood: Optional[Dict[str, Any]] = None    # a flood window seen before the alarm's row
        self.events: List[Dict[str, Any]] = []
        self.errors = 0
        self.finished = False

    # ------------------------------------------------------------------ logging and requests
    def _record(self, rec: Dict[str, Any]) -> None:
        rec.setdefault("time", self.clock.time())
        self.events.append(rec)
        if self.log is not None:
            self.log.write(json.dumps(rec, sort_keys=True) + "\n")
            self.log.flush()

    def _say(self, msg: str) -> None:
        if self.echo:
            print(f"[BLOCK] {msg}", flush=True)

    def _request(self, req: Dict[str, Any]) -> Dict[str, Any]:
        try:
            reply = self.request_fn(req)
        except Exception as error:          # a dead reader must not end the collection
            reply = {"error": f"{type(error).__name__}: {error}"}
        if "error" in reply:
            self.errors += 1
            self._say(f"{req.get('op')} failed: {reply['error']}")
        return reply

    def _block(self, entries: List[Entry], reason: str, window: int, **extra: Any) -> Dict[str, Any]:
        t_request = self.clock.time()
        reply = self._request({"cmd": "block", "op": "add", "entries": entries})
        rec = {"event": "block", "reason": reason, "window": window, "entries": entries,
               "t_request": t_request, "t_reply": self.clock.time(),
               "reply": {k: v for k, v in reply.items() if k not in ("regs",)}}
        rec.update(extra)
        self._record(rec)
        if "error" not in reply:
            self._say(f"window {window}: {reason}: {len(entries)} entries "
                      f"({reply.get('added', 0)} added, {reply.get('existing', 0)} there) in "
                      f"{(rec['t_reply'] - t_request) * 1e3:.1f} ms")
        return reply

    # ------------------------------------------------------------------ what to block
    def _block_flows(self, window: int, reason: str) -> None:
        if self.tail is None or not self.cgroup_ids:
            return
        self.tail.poll()
        keys = [k for k in self.tail.flows_of(self.cgroup_ids) if k not in self.blocked_flows]
        if not keys:
            return
        entries = [e for k in keys for e in flow_entries(k)]
        # the flows leave room for the host's entries, so that the host block always fits when they no longer do
        reserve = len(host_entries(self._host_addresses(), self.host_port))
        if self.flow_entry_count + len(entries) > self.max_entries - reserve:
            # more flows than the table holds: the host instead
            self._block_host(window, "table_full")
            return
        reply = self._block(entries, reason, window, flows=len(keys))
        if "error" not in reply:
            self.blocked_flows.update(keys)
            self.flow_entry_count += len(entries)

    def _host_addresses(self) -> List[str]:
        addrs = set(self.host_addresses)
        if self.tail is not None and self.cgroup_ids:
            self.tail.poll()
            addrs |= self.tail.local_addresses(self.cgroup_ids)
        return sorted(addrs)

    def _block_host(self, window: int, reason: str, active_flows: Optional[float] = None) -> None:
        """Everything from the host: each of its source addresses, and with host_port everything entering that
        port. Called again, it adds only what is not blocked yet (an address the program used since, or a write
        that failed)."""
        addrs = [a for a in self._host_addresses() if a not in self.blocked_addresses]
        port = self.host_port if not self.port_blocked else None
        entries = host_entries(addrs, port)
        if not entries:
            if not self.host_blocked and not self.blocked_addresses:
                self._record({"event": "block_skipped", "reason": reason, "window": window,
                              "why": "no host address (no --sockowner flows and no --block-host) and no "
                                     "--block-host-port"})
                self._say(f"window {window}: {reason}: nothing to block (no host address or port)")
            return
        reply = self._block(entries, reason, window, active_flows=active_flows)
        if "error" not in reply:
            self.blocked_addresses.update(addrs)
            if port is not None:
                self.port_blocked = True
            self.host_blocked = True

    def _is_flood(self, features: Dict[str, Any]) -> bool:
        return float(features.get("net_flow_count_seen", 0) or 0) > self.flood_flows

    # ------------------------------------------------------------------ the collector's hooks
    def on_net_window(self, window: int, features: Dict[str, Any]) -> None:
        """The switch's window `window` has been read: after the alarm, block the flows that appeared and, on a
        flood window, the host; before it, remember a flood window for the alarm."""
        if self.finished or window < self.skip_windows:
            return
        if self.scope == "host":
            if self.alarm is not None:
                # a write that failed, or an address the program has used since the alarm
                self._block_host(window, "alarm_host_update")
            return
        flood = self._is_flood(features)
        if self.alarm is None:
            if flood and self.pending_flood is None:
                self.pending_flood = {"window": window, "active_flows": features.get("net_flow_count_seen")}
            return
        if flood:
            self._block_host(window, "flood", active_flows=features.get("net_flow_count_seen"))
        if not self.host_blocked:
            self._block_flows(window, "new_flows")

    def on_row(self, window: int, row: Dict[str, Any]) -> None:
        """The row of window `window` (host and network columns) is written: score the run so far."""
        if window < self.skip_windows:
            self._record({"event": "skipped", "window": window, "why": "before the run's first window"})
            return
        self.rows.append(row)
        rows = self.rows[-self.score_windows:]
        t0 = self.clock.time()
        p = float(self.score(rows))
        rec = {"event": "score", "window": window, "probability": round(p, 4), "windows_scored": len(rows),
               "score_ms": round((self.clock.time() - t0) * 1e3, 2)}
        if self.finished:
            rec["after_finish"] = True      # the run's last rows, written after the reader stopped
        self._record(rec)
        if self.alarm is not None or self.finished:
            return
        forced = self.force_window is not None and window >= self.force_window
        if p < self.threshold and not forced:
            return
        self.alarm = {"event": "alarm", "window": window, "probability": round(p, 4), "forced": bool(forced),
                      "threshold": self.threshold}
        self._record(dict(self.alarm))
        self._say(f"window {window}: ALARM p={p:.3f}" + (" (forced)" if forced else ""))
        if self.scope == "host":
            # the switch forwards nothing more from the flagged host
            self._block_host(window, "alarm")
            return
        flood_row = self._is_flood(row)
        if flood_row or self.pending_flood is not None:
            info = self.pending_flood or {"window": window, "active_flows": row.get("net_flow_count_seen")}
            self._block_host(window, "flood", active_flows=info.get("active_flows"))
        if self.tail is None:
            # no local sockets: the switch cannot name the program's flows, so the host
            self._block_host(window, "no_flow_identities")
        elif not self.host_blocked:
            self._block_flows(window, "flows")

    def finish(self) -> Dict[str, Any]:
        """The entries with their dropped packets, then (unless keep) delete them all."""
        listed = self._request({"cmd": "block", "op": "list"}) if (self.blocked_flows or self.host_blocked) else {}
        summary = {"event": "summary", "scope": self.scope, "alarm": self.alarm,
                   "flows_blocked": len(self.blocked_flows), "host_blocked": self.host_blocked,
                   "addresses_blocked": sorted(self.blocked_addresses), "port_blocked": self.port_blocked,
                   "errors": self.errors,
                   "entries": listed.get("entries"), "blocked_pkts": listed.get("blocked_pkts")}
        if not self.keep and (self.blocked_flows or self.host_blocked):
            cleared = self._request({"cmd": "block", "op": "clear"})
            summary["cleared"] = "error" not in cleared
        self._record(summary)
        if self.alarm is None:
            self._say("no alarm")
        else:
            what = (f"host {', '.join(sorted(self.blocked_addresses)) or '(no address)'}"
                    + (f" and port {self.host_port}" if self.port_blocked else "")
                    if self.scope == "host" else
                    f"{len(self.blocked_flows)} flow(s)" + (", host" if self.host_blocked else ""))
            self._say(f"alarm at window {self.alarm['window']}; {what} blocked; {listed.get('blocked_pkts')} packets "
                      "dropped" + ("" if self.keep else "; entries deleted"))
        self.finished = True
        return summary


    def close(self) -> None:
        if self.log is not None:
            self.log.close()
            self.log = None


def row_scorer(host_signals: Sequence[str], net_signals: Sequence[str],
               score: Callable[[Any, Any], float]) -> Callable[[List[Dict[str, Any]]], float]:
    """stream_verdicts.train()'s score(wh, wn) on a list of collector rows."""
    import numpy as np

    def f(rows: List[Dict[str, Any]]) -> float:
        wh = np.asarray([[float(r.get(s, 0) or 0) for s in host_signals] for r in rows])
        wn = np.asarray([[float(r.get(s, 0) or 0) for s in net_signals] for r in rows])
        return score(wh, wn)
    for name in ("windows", "window_sec", "prefixes"):
        if hasattr(score, name):
            setattr(f, name, getattr(score, name))
    return f


def default_table(window_sec: float, detector: str, base: Optional[str] = None) -> str:
    """The window table a detector trains on at window_sec (PC1.md part 13): the dataset's at 0.5 s; otherwise
    dataset_windows_<w>s.csv.gz (both halves), or for the network detector its network half net_windows_<w>s.csv.gz
    until the host half is there."""
    here = Path(base) if base else Path(__file__).resolve().parent / "live_test" / "streaming"
    if abs(window_sec - 0.5) < 1e-9:
        return str(here / "dataset_windows.csv.gz")
    tag = "%gs" % window_sec
    full, net = here / ("dataset_windows_%s.csv.gz" % tag), here / ("net_windows_%s.csv.gz" % tag)
    if full.exists():
        return str(full)
    if detector == "network" and net.exists():
        return str(net)
    raise FileNotFoundError("no training table for windows of %s: %s (the host half comes from "
                            "live_test/streaming/host_windows.py on the lab workstation)%s"
                            % (tag, full.name, "" if detector == "network" else
                               "; the network detector can use %s" % net.name))


def load_scorer(detector: str, hold_out: Sequence[str] = (), release: Optional[str] = None,
                windows_path: Optional[str] = None,
                extra_windows: Sequence[str] = (),
                window_sec: Optional[float] = None) -> Callable[[List[Dict[str, Any]]], float]:
    """The detector of stream_verdicts.py, trained now (about 1 s for network, 15 s for stacked; 6 and 45 s on
    PC1), on the dataset's window table and any extra_windows tables (live runs, PC1.md part 12). window_sec: the
    collector's window; the table defaults to default_table()'s, and one of another window length is refused."""
    import sys
    from pathlib import Path
    here = Path(__file__).resolve().parent / "live_test" / "streaming"
    if str(here) not in sys.path:
        sys.path.insert(0, str(here))
    import stream_verdicts
    release = release or str(here.parents[2] / "p4-ebpf-malware-detection")
    windows_path = windows_path or default_table(0.5 if window_sec is None else window_sec, detector, str(here))
    if not os.path.isdir(os.path.join(release, "evaluation")):
        raise FileNotFoundError(f"the release's evaluation/ (for the detectors' forests) not found under {release}: "
                                "give --block-release")
    host_sig, net_sig, score = stream_verdicts.train(release, windows_path, detector, list(hold_out),
                                                     list(extra_windows))
    if window_sec is not None and abs(score.window_sec - window_sec) > 1e-9:
        raise ValueError("%s has windows of %g s, the collector's are %g s: a detector scores only windows of the "
                         "length it was trained on" % (windows_path, score.window_sec, window_sec))
    f = row_scorer(host_sig, net_sig, score)
    f.table = windows_path
    return f
