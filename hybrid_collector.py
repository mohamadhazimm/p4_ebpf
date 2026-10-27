#!/usr/bin/env python3

import argparse
import csv
import json
import signal
import subprocess
import sys
import time
import re
from pathlib import Path
from typing import Dict, List, Optional, Any


# ============================================================
# IMPORT CPU REPORT LISTENER
# ============================================================

sys.path.insert(0, str(Path(__file__).resolve().parent / "thesis-hybrid-ebpf-p4" / "python"))
sys.path.append("/home/ubuntu/Desktop/p4_ebpf/thesis-hybrid-ebpf-p4/python")
from listen_cpu_reports import ReportCollector


# ============================================================
# DEFAULT PATHS
# ============================================================

DEFAULT_HOSTMON = "/home/ubuntu/Desktop/p4_ebpf/libbpf-bootstrap/examples/c/hostmon"
DEFAULT_P4_READER = "/home/ubuntu/Desktop/p4_ebpf/thesis-hybrid-ebpf-p4/python/read_registers_with_index.py"
DEFAULT_REPLAY = "/home/ubuntu/Desktop/p4_ebpf/thesis-hybrid-ebpf-p4/python/replay_pcaps_with_index.py"
DEFAULT_P4_FORWARDER = "/home/ubuntu/Desktop/p4_ebpf/thesis-hybrid-ebpf-p4/python/program_forwarding.py"

DEFAULT_OUT_CSV = "hybrid_windows.csv"


# ============================================================
# HOSTMON PARSING
# ============================================================

HOST_HEADER = [
    "COMM", "PID", "EXEC", "OPEN", "REN", "DEL", "CONN", "UNIQIP", "UNIQPRT",
    "TOTAL_SYSCALLS", "UNIQUE_SYSCALLS", "ENTROPY", "TOP_SYSCALL_FREQ",
    "AVG_RUN_LENGTH", "MAX_RUN_LENGTH", "TRANSITION_COUNT",
    "RARE_SYSCALL_RATIO", "FIRST50_UNIQUE", "FIRST100_UNIQUE"
]

HOST_WINDOW_RE = re.compile(
    r"^==== HOST WINDOW\s+(\d+)\s+START=([0-9.]+)\s+END=([0-9.]+)\s+DUR=([0-9.]+)\s+====$"
)


# ============================================================
# FINAL HOST FEATURES
# ============================================================

HOST_ZERO = {
    "host_active_processes": 0,

    "host_exec_total": 0,
    "host_open_total": 0,
    "host_rename_total": 0,
    "host_unlink_total": 0,
    "host_connect_total": 0,

    "host_unique_ip_total": 0,
    "host_unique_port_total": 0,

    "host_total_syscalls_total": 0,

    "host_unique_syscalls_mean": 0.0,
    "host_unique_syscalls_max": 0,

    "host_entropy_mean": 0.0,
    "host_entropy_max": 0.0,

    "host_top_syscall_freq_mean": 0.0,
    "host_top_syscall_freq_max": 0.0,

    "host_avg_run_length_mean": 0.0,
    "host_avg_run_length_max": 0.0,

    "host_max_run_length_mean": 0.0,
    "host_max_run_length_max": 0,

    "host_transition_count_total": 0,

    "host_rare_syscall_ratio_mean": 0.0,
    "host_rare_syscall_ratio_max": 0.0,

    "host_first50_unique_mean": 0.0,
    "host_first50_unique_max": 0,

    "host_first100_unique_mean": 0.0,
    "host_first100_unique_max": 0,
}


# ============================================================
# FINAL P4 NETWORK FEATURES
# Based on your P4 ingress registers:
# pkts, bytes, pkts_ab, bytes_ab, min_len, max_len,
# first_ts, last_ts, syn, ack, rst
# ============================================================

NET_ZERO = {
    "net_flow_count_seen": 0,

    # Window deltas
    "net_pkts_total_delta": 0,
    "net_bytes_total_delta": 0,

    "net_pkts_ab_delta": 0,
    "net_bytes_ab_delta": 0,

    "net_pkts_ba_delta": 0,
    "net_bytes_ba_delta": 0,

    # Size
    "net_min_len_mean": 0.0,
    "net_max_len_mean": 0.0,
    "net_min_len_min": 0,
    "net_max_len_max": 0,

    "net_avg_pkt_size_delta": 0.0,
    "net_avg_pkt_size_ab_delta": 0.0,
    "net_avg_pkt_size_ba_delta": 0.0,

    # Timing / rate
    "net_flow_duration_mean": 0.0,
    "net_flow_duration_max": 0.0,

    "net_bytes_per_sec_delta": 0.0,
    "net_pkts_per_sec_delta": 0.0,

    # Direction ratios
    "net_down_up_ratio_delta": 0.0,
    "net_ab_ratio_pkt_delta": 0.0,
    "net_ba_ratio_pkt_delta": 0.0,
    "net_ab_ratio_byte_delta": 0.0,
    "net_ba_ratio_byte_delta": 0.0,

    # TCP behavior
    "net_syn_delta": 0,
    "net_ack_delta": 0,
    "net_rst_delta": 0,

    # Flow direction activity
    "net_flows_with_ab": 0,
    "net_flows_with_ba": 0,
    "net_dir_valid_count": 0,
}


# ============================================================
# BASIC HELPERS
# ============================================================

def safe_float(x: object, default: float = 0.0) -> float:
    try:
        return float(x)
    except Exception:
        return default


def safe_int(x: object, default: int = 0) -> int:
    try:
        return int(float(x))
    except Exception:
        return default


def mean_or_zero(values: List[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def max_or_zero(values: List[float]) -> float:
    return max(values) if values else 0.0


def min_positive_or_zero(values: List[int]) -> int:
    vals = [v for v in values if v > 0]
    return min(vals) if vals else 0


def safe_div(a: float, b: float) -> float:
    return a / b if b else 0.0


def get_row_int(row: Dict[str, Any], key: str, default: int = 0) -> int:
    return safe_int(row.get(key, default), default)


def get_row_float(row: Dict[str, Any], key: str, default: float = 0.0) -> float:
    return safe_float(row.get(key, default), default)


# ============================================================
# HOSTMON PARSER
# ============================================================

def parse_host_windows(text: str) -> List[Dict[str, object]]:
    windows: List[Dict[str, object]] = []
    current_meta: Optional[Dict[str, object]] = None
    current_rows: List[Dict[str, object]] = []

    for raw in text.splitlines():
        line = raw.strip()

        if not line:
            continue

        m = HOST_WINDOW_RE.match(line)

        if m:
            if current_meta is not None:
                current_meta["rows"] = current_rows
                windows.append(current_meta)
                current_rows = []

            current_meta = {
                "host_window_id": safe_int(m.group(1)),
                "host_window_start_sec": safe_float(m.group(2)),
                "host_window_end_sec": safe_float(m.group(3)),
                "host_window_duration_sec": safe_float(m.group(4)),
            }
            continue

        if line == ",".join(HOST_HEADER):
            continue

        parts = [x.strip() for x in line.split(",")]

        if len(parts) != len(HOST_HEADER):
            continue

        row = {
            "comm": parts[0],
            "pid": safe_int(parts[1]),

            "exec": safe_int(parts[2]),
            "open": safe_int(parts[3]),
            "ren": safe_int(parts[4]),
            "del": safe_int(parts[5]),
            "conn": safe_int(parts[6]),

            "uniqip": safe_int(parts[7]),
            "uniqprt": safe_int(parts[8]),

            "total_syscalls": safe_int(parts[9]),
            "unique_syscalls": safe_int(parts[10]),

            "entropy": safe_float(parts[11]),
            "top_syscall_freq": safe_float(parts[12]),

            "avg_run_length": safe_float(parts[13]),
            "max_run_length": safe_int(parts[14]),

            "transition_count": safe_int(parts[15]),
            "rare_syscall_ratio": safe_float(parts[16]),

            "first50_unique": safe_int(parts[17]),
            "first100_unique": safe_int(parts[18]),
        }

        current_rows.append(row)

    if current_meta is not None:
        current_meta["rows"] = current_rows
        windows.append(current_meta)

    return windows


def summarize_host_window(win: Optional[List[Dict[str, object]]]) -> Dict[str, object]:
    if not win:
        return dict(HOST_ZERO)

    unique_syscalls = [safe_int(r["unique_syscalls"]) for r in win]
    entropy = [safe_float(r["entropy"]) for r in win]
    top_freq = [safe_float(r["top_syscall_freq"]) for r in win]
    avg_run = [safe_float(r["avg_run_length"]) for r in win]
    max_run = [safe_int(r["max_run_length"]) for r in win]
    rare_ratio = [safe_float(r["rare_syscall_ratio"]) for r in win]
    first50 = [safe_int(r["first50_unique"]) for r in win]
    first100 = [safe_int(r["first100_unique"]) for r in win]

    return {
        "host_active_processes": len(win),

        "host_exec_total": sum(safe_int(r["exec"]) for r in win),
        "host_open_total": sum(safe_int(r["open"]) for r in win),
        "host_rename_total": sum(safe_int(r["ren"]) for r in win),
        "host_unlink_total": sum(safe_int(r["del"]) for r in win),
        "host_connect_total": sum(safe_int(r["conn"]) for r in win),

        "host_unique_ip_total": sum(safe_int(r["uniqip"]) for r in win),
        "host_unique_port_total": sum(safe_int(r["uniqprt"]) for r in win),

        "host_total_syscalls_total": sum(safe_int(r["total_syscalls"]) for r in win),

        "host_unique_syscalls_mean": mean_or_zero(unique_syscalls),
        "host_unique_syscalls_max": max_or_zero(unique_syscalls),

        "host_entropy_mean": mean_or_zero(entropy),
        "host_entropy_max": max_or_zero(entropy),

        "host_top_syscall_freq_mean": mean_or_zero(top_freq),
        "host_top_syscall_freq_max": max_or_zero(top_freq),

        "host_avg_run_length_mean": mean_or_zero(avg_run),
        "host_avg_run_length_max": max_or_zero(avg_run),

        "host_max_run_length_mean": mean_or_zero(max_run),
        "host_max_run_length_max": max_or_zero(max_run),

        "host_transition_count_total": sum(safe_int(r["transition_count"]) for r in win),

        "host_rare_syscall_ratio_mean": mean_or_zero(rare_ratio),
        "host_rare_syscall_ratio_max": max_or_zero(rare_ratio),

        "host_first50_unique_mean": mean_or_zero(first50),
        "host_first50_unique_max": max_or_zero(first50),

        "host_first100_unique_mean": mean_or_zero(first100),
        "host_first100_unique_max": max_or_zero(first100),
    }


# ============================================================
# PROCESS MANAGEMENT
# ============================================================

def start_hostmon(hostmon_path: str, output_path: str, window_sec: float) -> subprocess.Popen:
    fout = open(output_path, "w")

    proc = subprocess.Popen(
        ["sudo", hostmon_path, str(window_sec)],
        stdout=fout,
        stderr=subprocess.STDOUT,
        text=True,
    )

    proc._collector_file = fout
    return proc


def stop_hostmon(proc: subprocess.Popen, grace: float = 2.0) -> None:
    if proc.poll() is None:
        proc.send_signal(signal.SIGINT)

        try:
            proc.wait(timeout=grace)
        except subprocess.TimeoutExpired:
            proc.terminate()

            try:
                proc.wait(timeout=grace)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=grace)

    fout = getattr(proc, "_collector_file", None)

    if fout:
        fout.close()


def run_scenario_command(cmd: str, shell: str = "/bin/bash") -> subprocess.Popen:
    return subprocess.Popen([shell, "-lc", cmd])


# ============================================================
# P4 HELPERS
# ============================================================

def run_p4_reader_json(
    reader_path: str,
    indexes: List[int],
    switch_ssh: Optional[str] = None,
    snapshot: str = "sync",
    clear_if_unchanged: Optional[Dict[int, int]] = None,
) -> Dict[str, Any]:
    if not indexes:
        return {"source": "empty", "flow_count": 0, "cleared": [], "rows": []}

    index_arg = ",".join(str(x) for x in indexes)

    cmd = [
        sys.executable,
        reader_path,
        "--index-mode", "cli",
        "--indexes", index_arg,
        "--format", "json",
        "--snapshot", snapshot,
    ]
    if switch_ssh:
        cmd += ["--ssh", switch_ssh]
    if clear_if_unchanged:
        cmd += ["--clear-if-unchanged", ",".join(f"{i}:{p}" for i, p in sorted(clear_if_unchanged.items()))]

    result = subprocess.run(
        cmd,
        check=True,
        capture_output=True,
        text=True,
    )

    raw = result.stdout or ""
    stripped = raw.strip()

    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        pass

    m = re.search(r'(\{"source":.*"rows":\s*\[.*\]\s*\})', raw, flags=re.DOTALL)

    if m:
        return json.loads(m.group(1))

    raise RuntimeError(
        "Failed to parse JSON from P4 reader output.\n\n"
        f"STDOUT:\n{result.stdout}\n\n"
        f"STDERR:\n{result.stderr}"
    )


def run_p4_forwarder(
    forwarder_path: str,
    int_port: int,
    ext_port: int,
    report_port: int,
    mirror_sid: int,
    switch_ssh: Optional[str] = None,
) -> None:
    cmd = [
        sys.executable,
        forwarder_path,
        "--int-port", str(int_port),
        "--ext-port", str(ext_port),
        "--report-port", str(report_port),
        "--mirror-sid", str(mirror_sid),
    ]
    if switch_ssh:
        cmd += ["--ssh", switch_ssh]
    subprocess.run(cmd, check=True)


def collect_windows_live(
    collector: ReportCollector,
    proc: subprocess.Popen,
    window_sec: float,
    drain_seconds: float,
    global_t0: float,
    reader_path: str,
    active_ttl_windows: int,
    switch_ssh: Optional[str] = None,
    snapshot: str = "sync",
    clear_idle_windows: int = 3,
) -> List[Dict[str, object]]:
    """Per window: the CPU-reported bucket indexes, and the P4 registers of all
    active indexes read at the end of that window.

    The collector keeps capturing reports in the background while the
    registers are read, so a read does not open a gap in the report capture.
    A bucket reports only once, when it is first used, so an index stays
    active while its packet counter keeps changing, and for active_ttl_windows
    windows after its last report or change.

    With clear_idle_windows > 0, a bucket whose counter has not changed for
    that many consecutive reads is cleared right after the read (only if it is
    still unchanged then). It is empty again, so the next flow that lands in it
    sends a new report instead of being merged silently into the old counters.
    """
    windows: List[Dict[str, object]] = []
    active_idx_last_seen: Dict[int, int] = {}
    last_pkts: Dict[int, int] = {}
    idle_reads: Dict[int, int] = {}

    w = 0
    proc_done = False
    proc_end_rel: Optional[float] = None

    while True:
        win_start_rel = w * window_sec
        win_end_rel = (w + 1) * window_sec

        win_start_abs = global_t0 + win_start_rel
        win_end_abs = global_t0 + win_end_rel

        now = time.time()
        if now < win_end_abs:
            time.sleep(win_end_abs - now)
        elif now > win_end_abs + 1.0:
            print(f"[WARN] window {w}: register read of the previous window overran by "
                  f"{now - win_end_abs:.1f} s")

        reports = collector.take(win_start_abs, win_end_abs)
        idxs = sorted({safe_int(r["idx"]) for r in reports})
        mismatches = sum(1 for r in reports if r["idx_source"] == "report" and r["idx"] != r["idx_computed"])
        if mismatches:
            print(f"[WARN] window {w}: {mismatches} report(s) carry an index that flow_index.py "
                  f"does not reproduce; the data plane and flow_index.py disagree")

        for idx in idxs:
            active_idx_last_seen[idx] = w
        active_idxs = sorted(
            idx for idx, last_seen in active_idx_last_seen.items()
            if (w - last_seen) <= active_ttl_windows
        )
        active_idx_last_seen = {idx: active_idx_last_seen[idx] for idx in active_idxs}

        # Buckets that would complete clear_idle_windows idle reads with this read.
        clear_candidates = {}
        if clear_idle_windows > 0:
            clear_candidates = {
                idx: last_pkts[idx] for idx in active_idxs
                if idx in last_pkts and idle_reads.get(idx, 0) + 1 >= clear_idle_windows
            }

        read_start = time.time()
        payload = run_p4_reader_json(reader_path, active_idxs, switch_ssh=switch_ssh, snapshot=snapshot,
                                     clear_if_unchanged=clear_candidates)
        read_end = time.time()

        for row in payload.get("rows", []):
            idx = safe_int(row.get("idx"))
            pkts = safe_int(row.get("pkts"))
            if last_pkts.get(idx) != pkts:
                active_idx_last_seen[idx] = w
                idle_reads[idx] = 0
            else:
                idle_reads[idx] = idle_reads.get(idx, 0) + 1
            last_pkts[idx] = pkts

        cleared = sorted(safe_int(x) for x in payload.get("cleared", []))
        for idx in cleared:
            active_idx_last_seen.pop(idx, None)
            last_pkts.pop(idx, None)
            idle_reads.pop(idx, None)

        windows.append({
            "net_window_id": w,
            "net_window_start_sec": round(win_start_rel, 3),
            "net_window_end_sec": round(win_end_rel, 3),
            "net_window_duration_sec": round(window_sec, 3),
            "indexes": idxs,
            "active_indexes": active_idxs,
            "report_count": len(reports),
            "index_mismatches": mismatches,
            "rows": payload.get("rows", []),
            "cleared_indexes": cleared,
            "p4_snapshot": payload.get("snapshot"),
            "p4_read_start_sec": round(read_start - global_t0, 3),
            "p4_read_sec": round(read_end - read_start, 3),
        })

        if not proc_done and proc.poll() is not None:
            proc_done = True
            proc_end_rel = time.time() - global_t0

        if proc_done and proc_end_rel is not None:
            if win_end_rel >= proc_end_rel + drain_seconds:
                break

        w += 1

    return windows


# ============================================================
# P4 SUMMARY BUILDER
# ============================================================

def build_net_summaries(
    net_windows: List[Dict[str, object]],
    window_sec: float,
) -> List[Dict[str, object]]:
    """Window features from the register snapshots taken at each window end
    (collect_windows_live): deltas against the previous snapshot of the same
    bucket index."""

    out: List[Dict[str, object]] = []

    prev_by_idx: Dict[int, Dict[str, Any]] = {}

    for win in net_windows:
        rows = win.get("rows", [])

        if not rows:
            out.append(dict(NET_ZERO))
            continue

        cleared_after_read = [safe_int(x) for x in win.get("cleared_indexes", [])]

        summary = dict(NET_ZERO)
        summary["net_flow_count_seen"] = len(rows)

        min_lens: List[int] = []
        max_lens: List[int] = []
        durations: List[float] = []

        for row in rows:
            idx = get_row_int(row, "idx", 0)
            prev = prev_by_idx.get(idx, {})

            # Current cumulative values from P4 registers
            pkts = get_row_int(row, "pkts", 0)
            bytes_total = get_row_int(row, "bytes", 0)

            pkts_ab = get_row_int(row, "pkts_ab", 0)
            bytes_ab = get_row_int(row, "bytes_ab", 0)

            pkts_ba = max(0, pkts - pkts_ab)
            bytes_ba = max(0, bytes_total - bytes_ab)

            syn = get_row_int(row, "syn", 0)
            ack = get_row_int(row, "ack", 0)
            rst = get_row_int(row, "rst", 0)

            min_len = get_row_int(row, "min_len", 0)
            max_len = get_row_int(row, "max_len", 0)

            first_ts = get_row_float(row, "first_ts", 0.0)
            last_ts = get_row_float(row, "last_ts", 0.0)

            dir_valid = get_row_int(row, "dir_valid", 0)

            # Previous cumulative values
            prev_pkts = get_row_int(prev, "pkts", 0)
            prev_bytes = get_row_int(prev, "bytes", 0)

            prev_pkts_ab = get_row_int(prev, "pkts_ab", 0)
            prev_bytes_ab = get_row_int(prev, "bytes_ab", 0)

            prev_pkts_ba = get_row_int(prev, "pkts_ba", max(0, prev_pkts - prev_pkts_ab))
            prev_bytes_ba = get_row_int(prev, "bytes_ba", max(0, prev_bytes - prev_bytes_ab))

            prev_syn = get_row_int(prev, "syn", 0)
            prev_ack = get_row_int(prev, "ack", 0)
            prev_rst = get_row_int(prev, "rst", 0)

            # Deltas for the current window
            pkts_delta = max(0, pkts - prev_pkts)
            bytes_delta = max(0, bytes_total - prev_bytes)

            pkts_ab_delta = max(0, pkts_ab - prev_pkts_ab)
            bytes_ab_delta = max(0, bytes_ab - prev_bytes_ab)

            pkts_ba_delta = max(0, pkts_ba - prev_pkts_ba)
            bytes_ba_delta = max(0, bytes_ba - prev_bytes_ba)

            syn_delta = max(0, syn - prev_syn)
            ack_delta = max(0, ack - prev_ack)
            rst_delta = max(0, rst - prev_rst)

            summary["net_pkts_total_delta"] += pkts_delta
            summary["net_bytes_total_delta"] += bytes_delta

            summary["net_pkts_ab_delta"] += pkts_ab_delta
            summary["net_bytes_ab_delta"] += bytes_ab_delta

            summary["net_pkts_ba_delta"] += pkts_ba_delta
            summary["net_bytes_ba_delta"] += bytes_ba_delta

            summary["net_syn_delta"] += syn_delta
            summary["net_ack_delta"] += ack_delta
            summary["net_rst_delta"] += rst_delta

            if min_len > 0:
                min_lens.append(min_len)

            if max_len > 0:
                max_lens.append(max_len)

            # first_ts/last_ts are the low 32 bits of a ns clock (wrap every 4.295 s).
            if first_ts > 0 and last_ts > 0:
                durations.append(float((int(last_ts) - int(first_ts)) % (1 << 32)))

            if dir_valid != 0:
                summary["net_dir_valid_count"] += 1

            if pkts_ab > 0 or bytes_ab > 0:
                summary["net_flows_with_ab"] += 1

            if pkts_ba > 0 or bytes_ba > 0:
                summary["net_flows_with_ba"] += 1

            prev_by_idx[idx] = row

        # Buckets cleared after this read restart from zero.
        for idx in cleared_after_read:
            prev_by_idx.pop(idx, None)

        pkts_delta = summary["net_pkts_total_delta"]
        bytes_delta = summary["net_bytes_total_delta"]

        pkts_ab_delta = summary["net_pkts_ab_delta"]
        bytes_ab_delta = summary["net_bytes_ab_delta"]

        pkts_ba_delta = summary["net_pkts_ba_delta"]
        bytes_ba_delta = summary["net_bytes_ba_delta"]

        summary["net_min_len_mean"] = mean_or_zero([float(x) for x in min_lens])
        summary["net_max_len_mean"] = mean_or_zero([float(x) for x in max_lens])
        summary["net_min_len_min"] = min_positive_or_zero(min_lens)
        summary["net_max_len_max"] = max_or_zero(max_lens)

        summary["net_avg_pkt_size_delta"] = safe_div(bytes_delta, pkts_delta)
        summary["net_avg_pkt_size_ab_delta"] = safe_div(bytes_ab_delta, pkts_ab_delta)
        summary["net_avg_pkt_size_ba_delta"] = safe_div(bytes_ba_delta, pkts_ba_delta)

        summary["net_flow_duration_mean"] = mean_or_zero(durations)
        summary["net_flow_duration_max"] = max_or_zero(durations)

        summary["net_bytes_per_sec_delta"] = safe_div(bytes_delta, window_sec)
        summary["net_pkts_per_sec_delta"] = safe_div(pkts_delta, window_sec)

        summary["net_down_up_ratio_delta"] = safe_div(bytes_ba_delta, bytes_ab_delta)

        summary["net_ab_ratio_pkt_delta"] = safe_div(pkts_ab_delta, pkts_delta)
        summary["net_ba_ratio_pkt_delta"] = safe_div(pkts_ba_delta, pkts_delta)

        summary["net_ab_ratio_byte_delta"] = safe_div(bytes_ab_delta, bytes_delta)
        summary["net_ba_ratio_byte_delta"] = safe_div(bytes_ba_delta, bytes_delta)

        out.append(summary)

    return out


# ============================================================
# CSV WRITER
# ============================================================

def append_csv_rows(path: str, rows: List[Dict[str, object]]) -> None:
    if not rows:
        return

    p = Path(path)
    write_header = not p.exists() or p.stat().st_size == 0

    with open(path, "a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))

        if write_header:
            writer.writeheader()

        writer.writerows(rows)


# ============================================================
# FINAL ROW BUILDER
# ============================================================

def build_rows(
    args,
    run_id: str,
    host_windows: List[Dict[str, object]],
    net_windows: List[Dict[str, object]],
    net_summaries: List[Dict[str, object]],
) -> List[Dict[str, object]]:

    count = max(len(host_windows), len(net_windows))
    rows: List[Dict[str, object]] = []

    for i in range(count):
        host_meta = host_windows[i] if i < len(host_windows) else None
        net_meta = net_windows[i] if i < len(net_windows) else None
        net_summary = net_summaries[i] if i < len(net_summaries) else dict(NET_ZERO)

        host_rows = host_meta["rows"] if host_meta else None
        host_summary = summarize_host_window(host_rows)

        row = {
            "timestamp": int(time.time()),
            "run_id": run_id,
            "scenario_name": args.scenario_name,
            "label": args.label,
            "mode": args.mode,
            "window_id": i,

            "host_window_id": host_meta["host_window_id"] if host_meta else i,
            "host_window_start_sec": host_meta["host_window_start_sec"] if host_meta else i * args.window_sec,
            "host_window_end_sec": host_meta["host_window_end_sec"] if host_meta else (i + 1) * args.window_sec,
            "host_window_duration_sec": host_meta["host_window_duration_sec"] if host_meta else args.window_sec,

            "net_window_id": net_meta["net_window_id"] if net_meta else i,
            "net_window_start_sec": net_meta["net_window_start_sec"] if net_meta else i * args.window_sec,
            "net_window_end_sec": net_meta["net_window_end_sec"] if net_meta else (i + 1) * args.window_sec,
            "net_window_duration_sec": net_meta["net_window_duration_sec"] if net_meta else args.window_sec,

            "cpu_index_count": len(net_meta["indexes"]) if net_meta else 0,
            "cpu_indexes": json.dumps(net_meta["indexes"] if net_meta else []),
        }

        row.update(host_summary)
        row.update(net_summary)

        rows.append(row)

    return rows


# ============================================================
# MAIN
# ============================================================

def main() -> None:
    ap = argparse.ArgumentParser(description="Collect synchronized HostMon/eBPF + P4 features per time window")

    ap.add_argument("--mode", choices=["command", "pcap"], required=True)
    ap.add_argument("--scenario-name", required=True)
    ap.add_argument("--label", required=True)

    ap.add_argument("--window-sec", type=float, default=10.0)
    ap.add_argument("--drain-seconds", type=float, default=2.0)
    ap.add_argument("--out-csv", default=DEFAULT_OUT_CSV)

    ap.add_argument("--hostmon", default=DEFAULT_HOSTMON)
    ap.add_argument("--hostmon-log", default="hostmon_capture.log")

    ap.add_argument("--p4-reader", default=DEFAULT_P4_READER)
    ap.add_argument("--p4-forwarder", default=DEFAULT_P4_FORWARDER)
    ap.add_argument("--skip-p4-forwarding", action="store_true")
    ap.add_argument("--forward-int-port", type=int, default=0)
    ap.add_argument("--forward-ext-port", type=int, default=1)
    ap.add_argument("--forward-report-port", type=int, default=2,
                    help="mirror destination for CPU reports (2 on the model, 192 = PCIe CPU port on the switch)")
    ap.add_argument("--mirror-sid", type=int, default=1)
    ap.add_argument("--switch-ssh",
                    help="run BFRT and the CPU-report capture on this switch over SSH, e.g. root@172.168.1.2")
    ap.add_argument("--p4-snapshot", choices=["sync", "hw"], default="sync",
                    help="register snapshot method of the P4 reader")
    ap.add_argument("--active-ttl-windows", type=int, default=5,
                    help="windows an index stays active after its last CPU report or counter change")
    ap.add_argument("--clear-idle-windows", type=int, default=3,
                    help="clear a bucket after this many reads without new packets, so that the next "
                         "flow in it reports again (0 = never clear)")

    ap.add_argument("--command")
    ap.add_argument("--shell", default="/bin/bash")

    ap.add_argument("--replay-script", default=DEFAULT_REPLAY)
    ap.add_argument("--pcap")
    ap.add_argument("--internal-cidr", default="172.16.11.0/24")
    ap.add_argument("--int-iface", default="veth1")
    ap.add_argument("--ext-iface", default="veth3")
    ap.add_argument("--cpu-iface", default="veth5")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--interval", type=float, default=0.0)

    args = ap.parse_args()

    if args.mode == "command" and not args.command:
        ap.error("--command is required when --mode command")

    if args.mode == "pcap" and not args.pcap:
        ap.error("--pcap is required when --mode pcap")

    for needed in [args.hostmon, args.p4_reader]:
        if not Path(needed).exists():
            raise FileNotFoundError(f"Required file not found: {needed}")

    if not args.skip_p4_forwarding and not Path(args.p4_forwarder).exists():
        raise FileNotFoundError(f"Forwarding setup file not found: {args.p4_forwarder}")

    if args.mode == "pcap" and not Path(args.replay_script).exists():
        raise FileNotFoundError(f"Replay script not found: {args.replay_script}")

    host_proc = None
    workload_proc = None
    report_collector = None

    run_id = f"{args.scenario_name}_{int(time.time())}"

    try:
        if not args.skip_p4_forwarding:
            print(f"[INFO] Programming forwarding via: {args.p4_forwarder}")
            run_p4_forwarder(
                args.p4_forwarder,
                args.forward_int_port,
                args.forward_ext_port,
                args.forward_report_port,
                args.mirror_sid,
                switch_ssh=args.switch_ssh,
            )

        where = f"{args.switch_ssh}:{args.cpu_iface}" if args.switch_ssh else args.cpu_iface
        print(f"[INFO] Collecting CPU reports on {where}")
        report_collector = ReportCollector(args.cpu_iface, ssh_host=args.switch_ssh).start()

        print(f"[INFO] Starting HostMon with window_sec={args.window_sec}")
        host_proc = start_hostmon(args.hostmon, args.hostmon_log, args.window_sec)

        time.sleep(0.2)

        if args.mode == "pcap":
            print(f"[INFO] Replaying PCAP: {args.pcap}")
            global_t0 = time.time()

            workload_proc = subprocess.Popen(
                [
                    sys.executable,
                    args.replay_script,
                    "--pcap", args.pcap,
                    "--internal-cidr", args.internal_cidr,
                    "--int-iface", args.int_iface,
                    "--ext-iface", args.ext_iface,
                    "--limit", str(args.limit),
                    "--interval", str(args.interval),
                ],
                text=True,
            )

        else:
            print(f"[INFO] Running command scenario: {args.command}")
            global_t0 = time.time()
            workload_proc = run_scenario_command(args.command, shell=args.shell)

        print("[INFO] Reading P4 registers at the end of every window")
        net_windows = collect_windows_live(
            collector=report_collector,
            proc=workload_proc,
            window_sec=args.window_sec,
            drain_seconds=args.drain_seconds if args.mode == "pcap" else 0.0,
            global_t0=global_t0,
            reader_path=args.p4_reader,
            active_ttl_windows=args.active_ttl_windows,
            switch_ssh=args.switch_ssh,
            snapshot=args.p4_snapshot,
            clear_idle_windows=args.clear_idle_windows,
        )
        report_collector.stop()
        print(f"[INFO] CPU reports: {sum(w['report_count'] for w in net_windows)} in "
              f"{len(net_windows)} windows; index mismatches: "
              f"{sum(w['index_mismatches'] for w in net_windows)}; idle buckets cleared: "
              f"{sum(len(w['cleared_indexes']) for w in net_windows)}")

        workload_proc.wait()

        if workload_proc.returncode != 0:
            raise RuntimeError(f"Workload failed with code {workload_proc.returncode}")

        print("[INFO] Stopping HostMon")
        stop_hostmon(host_proc)
        host_proc = None

        host_text = Path(args.hostmon_log).read_text() if Path(args.hostmon_log).exists() else ""
        host_windows = parse_host_windows(host_text)

        if host_windows:
            print(
                f"[DEBUG] host first={host_windows[0]['host_window_start_sec']:.3f} "
                f"last={host_windows[-1]['host_window_end_sec']:.3f}"
            )

        if net_windows:
            print(
                f"[DEBUG] net first={net_windows[0]['net_window_start_sec']:.3f} "
                f"last={net_windows[-1]['net_window_end_sec']:.3f}"
            )

        if len(host_windows) != len(net_windows):
            print(f"[WARN] host_windows={len(host_windows)} net_windows={len(net_windows)}; pairing by index")

        print("[INFO] Building P4 window summaries")
        net_summaries = build_net_summaries(
            net_windows=net_windows,
            window_sec=args.window_sec,
        )

        rows = build_rows(
            args=args,
            run_id=run_id,
            host_windows=host_windows,
            net_windows=net_windows,
            net_summaries=net_summaries,
        )

        append_csv_rows(args.out_csv, rows)

        print(f"[OK] Added {len(rows)} rows to {args.out_csv}")
        print(f"[OK] run_id: {run_id}")
        print(f"[OK] host_windows={len(host_windows)}")
        print(f"[OK] net_windows={len(net_windows)}")
        print(f"[OK] net_summaries={len(net_summaries)}")

    finally:
        if workload_proc is not None and workload_proc.poll() is None:
            try:
                workload_proc.terminate()
                workload_proc.wait(timeout=2)
            except Exception:
                pass

        if host_proc is not None:
            stop_hostmon(host_proc)

        if report_collector is not None:
            report_collector.stop()


if __name__ == "__main__":
    main()

# sudo python3 hybrid_collector.py \
#     --mode command \
#     --scenario-name test_run \
#     --label benign \
#     --command "python3 hybrid_data_generator.py --duration 120" \
#     --window-sec 10 \
#     --cpu-iface veth5 \
#     --forward-int-port 0 \
#     --forward-ext-port 1 \
#     --p4-forwarder program_forwarding.py \
#     --p4-reader read_registers_with_index.py