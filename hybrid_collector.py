#!/usr/bin/env python3

import argparse
import collections
import csv
import json
import os
import queue
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import re
from pathlib import Path
from typing import Callable, Dict, List, Optional, Any


# ============================================================
# IMPORT CPU REPORT LISTENER
# ============================================================

sys.path.insert(0, str(Path(__file__).resolve().parent / "thesis-hybrid-ebpf-p4" / "python"))
sys.path.append("/home/ubuntu/Desktop/p4_ebpf/thesis-hybrid-ebpf-p4/python")
from listen_cpu_reports import ReportCollector
from flow_index import compute_newconn_dst_index
from bfshell_run import DEFAULT_REMOTE_SDE_INSTALL


# ============================================================
# DEFAULT PATHS
# ============================================================

DEFAULT_HOSTMON = "/home/ubuntu/Desktop/p4_ebpf/libbpf-bootstrap/examples/c/hostmon"
DEFAULT_P4_READER = "/home/ubuntu/Desktop/p4_ebpf/thesis-hybrid-ebpf-p4/python/read_registers_with_index.py"
DEFAULT_REPLAY = "/home/ubuntu/Desktop/p4_ebpf/thesis-hybrid-ebpf-p4/python/replay_pcaps_with_index.py"
DEFAULT_P4_FORWARDER = "/home/ubuntu/Desktop/p4_ebpf/thesis-hybrid-ebpf-p4/python/program_forwarding.py"
DEFAULT_P4_RESETTER = str(Path(__file__).resolve().parent / "thesis-hybrid-ebpf-p4" / "python" / "reset_registers.py")
DEFAULT_BATCHED_READER = str(Path(__file__).resolve().parent / "thesis-hybrid-ebpf-p4" / "python" / "batched_reader.py")
DEFAULT_WINDOW_READER = str(Path(__file__).resolve().parent / "thesis-hybrid-ebpf-p4" / "python" / "window_reader.py")
DEFAULT_SWEEP_READER = str(Path(__file__).resolve().parent / "thesis-hybrid-ebpf-p4" / "python" / "sweep_reader.py")
SWEEP_PYDIR = str(Path(__file__).resolve().parent / "thesis-hybrid-ebpf-p4" / "python")
DEFAULT_GRPC_ADDR = "127.0.0.1:50052"

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
# and, per destination bucket, newconn_dst
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
    "net_new_conn_dst_max": 0,

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

HOST_WINDOW_DONE = "HOSTMON_WINDOW_DONE,"   # hostmon_agg's last line of a window (since 2026-11-19)


def parse_host_row(line: str) -> Optional[Dict[str, object]]:
    """One process row of a window block, or None for any other line. The 18 numbers are taken from the right, so
    a process name with commas (or any other character) keeps its row; the name is the CSV-quoted field before."""
    parts = line.rsplit(",", len(HOST_HEADER) - 1)
    if len(parts) != len(HOST_HEADER):
        return None
    comm = parts[0].strip()
    if len(comm) >= 2 and comm[0] == '"' and comm[-1] == '"':
        comm = comm[1:-1].replace('""', '"')
    parts = [comm] + [x.strip() for x in parts[1:]]
    return {
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


class HostLogParser:
    """The host monitor's output, fed in pieces (HostLogTail) or at once (parse_host_windows). Lines are split on
    "\\n" only: hostmon_agg replaces \\n and \\r in a process name but nothing else, and str.splitlines() also
    cuts at a vertical tab, a form feed or a file separator, which would drop that process's row. `windows` holds
    every window seen so far, each with its rows and "complete": its HOSTMON_WINDOW_DONE line (hostmon_agg since
    2026-11-19) or the next window's header has been read."""

    def __init__(self) -> None:
        self.windows: List[Dict[str, object]] = []
        self.partial = ""

    def feed(self, text: str, final: bool = False) -> None:
        lines = (self.partial + text).split("\n")
        self.partial = "" if final else lines.pop()
        for raw in lines:
            self._line(raw.strip())

    def _line(self, line: str) -> None:
        if not line:
            return
        m = HOST_WINDOW_RE.match(line)
        if m:
            if self.windows:
                self.windows[-1]["complete"] = True
            self.windows.append({
                "host_window_id": safe_int(m.group(1)),
                "host_window_start_sec": safe_float(m.group(2)),
                "host_window_end_sec": safe_float(m.group(3)),
                "host_window_duration_sec": safe_float(m.group(4)),
                "rows": [],
                "complete": False,
            })
            return
        if line.startswith(HOST_WINDOW_DONE):
            if self.windows and str(self.windows[-1]["host_window_id"]) == line[len(HOST_WINDOW_DONE):].strip():
                self.windows[-1]["complete"] = True
            return
        if not self.windows or line == ",".join(HOST_HEADER):
            return
        row = parse_host_row(line)
        if row is not None:
            self.windows[-1]["rows"].append(row)


def parse_host_windows(text: str) -> List[Dict[str, object]]:
    parser = HostLogParser()
    parser.feed(text, final=True)
    return parser.windows


def complete_host_windows(windows: List[Dict[str, object]]) -> int:
    """How many windows, from the first, are complete."""
    n = 0
    for w in windows:
        if not w.get("complete"):
            break
        n += 1
    return n


def wait_host_windows(tail: "HostLogTail", needed: int, timeout_s: float, clock: Any = time,
                      poll_s: float = 0.005) -> List[Dict[str, object]]:
    """The tail's windows once `needed` of them are complete, or when timeout_s has passed."""
    windows = tail.poll()
    deadline = clock.monotonic() + timeout_s
    while complete_host_windows(windows) < needed and clock.monotonic() < deadline:
        clock.sleep(poll_s)
        windows = tail.poll()
    return windows


class HostLogTail:
    """The host monitor's log as it grows: poll() reads only what was appended (the collector used to parse the
    whole log after every window) and returns every window so far."""

    def __init__(self, path: str) -> None:
        import codecs
        self.path, self.offset = path, 0
        self.parser = HostLogParser()
        self.decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")

    def poll(self) -> List[Dict[str, object]]:
        try:
            with open(self.path, "rb") as stream:
                stream.seek(self.offset)
                data = stream.read()
        except OSError:
            return self.parser.windows
        if data:
            self.offset += len(data)
            self.parser.feed(self.decoder.decode(data))
        return self.parser.windows


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

def start_hostmon(hostmon_path: str, output_path: str, window_sec: float,
                  use_sudo: Optional[bool] = None) -> subprocess.Popen:
    """Start HostMon in its own process group.

    As root (how the collector runs) HostMon is started directly, so the stop
    signal reaches it. Otherwise it goes through sudo; sudo does not relay a
    signal sent from the command's own process group, which is why a HostMon
    started through sudo in the collector's group kept running after
    stop_hostmon(). In a group of its own the signal is relayed.
    """
    fout = open(output_path, "w")
    if use_sudo is None:
        use_sudo = os.geteuid() != 0
    cmd = (["sudo"] if use_sudo else []) + [hostmon_path, str(window_sec)]

    proc = subprocess.Popen(
        cmd,
        stdout=fout,
        stderr=subprocess.STDOUT,
        text=True,
        start_new_session=True,
    )

    proc._collector_file = fout
    return proc


def stop_hostmon(proc: subprocess.Popen, grace: float = 5.0) -> None:
    """SIGINT (HostMon prints its last, partial window and exits), then
    SIGTERM, then SIGKILL to HostMon's whole process group, so that nothing
    of it outlives the run."""
    for sig in (signal.SIGINT, signal.SIGTERM):
        if proc.poll() is not None:
            break
        try:
            proc.send_signal(sig)
            proc.wait(timeout=grace)
        except subprocess.TimeoutExpired:
            continue
        except ProcessLookupError:
            break
    if proc.poll() is None:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            proc.kill()
        proc.wait(timeout=grace)

    fout = getattr(proc, "_collector_file", None)

    if fout:
        fout.close()


def read_host_windows(path: str) -> List[Dict[str, object]]:
    p = Path(path)
    return parse_host_windows(p.read_bytes().decode("utf-8", errors="replace")) if p.exists() else []


# ------------------------------------------------------------
# In-kernel monitor (ebpf_perf/hostmon_agg): cgroup + shared start time
# ------------------------------------------------------------

def cgroup_wrapped_command(cmd: str, cgroup: str, shell: str = "/bin/bash") -> List[str]:
    """argv that moves the scenario's shell into `cgroup` before it runs the
    command, so every process of the scenario is in the cgroup from its first
    system call (hostmon_agg filters on it). `$0` is the cgroup, `$1` the shell,
    `$2` the command."""
    return ["/bin/bash", "-c", 'echo $$ > "$0/cgroup.procs" && exec "$1" -c "$2"', cgroup, shell, cmd]


# The dataset's launcher (RUNBOOK 19.5.6): bash execs the program with its arguments. Its startup
# before that exec (178 system calls in the dataset's guest) is part of every dataset row's host
# features, so a run that is to be scored by the dataset's detectors starts the same way.
DATASET_LAUNCHER = ["/bin/bash", "-c", 'exec "$@"', "sample-launch"]


def dataset_launch_command(argv: List[str], cgroup: Optional[str] = None) -> List[str]:
    """argv that runs the program as the dataset's collector did:
    `/bin/bash -c 'exec "$@"' sample-launch PROGRAM ARGS...`. With `cgroup`, a
    shell joins the cgroup first and execs that launcher, so that the monitor
    sees the launcher's execve and startup, then the program (RUNBOOK 19.9.2).
    `$0` is the cgroup, `$@` the program and its arguments."""
    if not argv:
        raise ValueError("the dataset launcher needs a program to run")
    if cgroup is None:
        return DATASET_LAUNCHER + list(argv)
    return ["/bin/bash", "-c", 'echo $$ > "$0/cgroup.procs" && exec /bin/bash -c \'exec "$@"\' sample-launch "$@"',
            cgroup, *argv]


def stop_scenario(proc: subprocess.Popen, grace: float = 2.0, own_session: bool = False) -> None:
    """Stop the scenario as the dataset's runner stopped a program at its
    timeout: SIGTERM, then SIGKILL after `grace` seconds. With own_session the
    signal goes to the scenario's process group (it was started with
    start_new_session), so its children stop too."""
    if proc.poll() is not None:
        return
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            if own_session:
                os.killpg(os.getpgid(proc.pid), sig)
            else:
                proc.send_signal(sig)
        except (ProcessLookupError, PermissionError):
            return
        try:
            proc.wait(timeout=grace)
            return
        except subprocess.TimeoutExpired:
            continue


def ensure_cgroup(path: str) -> "tuple[Path, bool]":
    """(cgroup directory, created now). A cgroup-v2 directory is created by mkdir."""
    p = Path(path)
    created = False
    if not p.exists():
        p.mkdir(parents=True)
        created = True
    if not (p / "cgroup.procs").exists():
        raise RuntimeError(f"{p} is not a cgroup-v2 directory (no cgroup.procs)")
    return p, created


def cleanup_cgroup(p: Path, created: bool) -> None:
    """Kill what the scenario left in the cgroup; remove it if this run made it."""
    try:
        if (p / "cgroup.procs").read_text().split():
            (p / "cgroup.kill").write_text("1")
            time.sleep(0.2)
        if created:
            p.rmdir()
    except OSError as error:
        print(f"[WARN] cgroup {p} not cleaned up: {error}")


def wait_for_line(path: str, token: str, timeout: float, proc: Optional[subprocess.Popen] = None) -> str:
    """The first line of `path` starting with `token`, within `timeout` seconds."""
    deadline = time.time() + timeout
    while True:
        p = Path(path)
        if p.exists():
            for line in p.read_text(errors="replace").splitlines():
                if line.startswith(token):
                    return line
        exited = proc is not None and proc.poll() is not None
        if exited or time.time() >= deadline:
            tail = p.read_text(errors="replace")[-400:] if p.exists() else ""
            raise RuntimeError(f"{token} not seen in {path} within {timeout:.0f} s"
                               + (f"; the monitor exited with {proc.returncode}" if exited else "")
                               + (f"; output: {tail!r}" if tail else ""))
        time.sleep(0.05)


def start_hostmon_agg(hostmon_path: str, output_path: str, window_sec: float, cgroup: Path,
                      use_sudo: Optional[bool] = None) -> subprocess.Popen:
    """Start the in-kernel monitor on `cgroup`. It prints HOSTMON_READY, then
    waits for the shared monotonic start time on stdin (send_hostmon_start);
    its windows are anchored at that instant, like the collector's."""
    fout = open(output_path, "w")
    if use_sudo is None:
        use_sudo = os.geteuid() != 0
    cmd = (["sudo"] if use_sudo else []) + [hostmon_path, repr(float(window_sec)), str(cgroup)]
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=fout, stderr=subprocess.STDOUT, text=True,
                            start_new_session=True)
    proc._collector_file = fout
    return proc


def start_sockowner(sockowner_path: str, output_path: str, attach_cgroup: str = "/sys/fs/cgroup",
                    use_sudo: Optional[bool] = None) -> subprocess.Popen:
    """Start ebpf_perf/sockowner on attach_cgroup (the root: every process). It prints
    SOCKOWNER_READY, then one line per socket and per new 5-tuple, and SOCKOWNER_HEALTH when it
    is stopped (stop_hostmon: SIGINT first)."""
    fout = open(output_path, "w")
    if use_sudo is None:
        use_sudo = os.geteuid() != 0
    cmd = (["sudo"] if use_sudo else []) + [sockowner_path, str(attach_cgroup)]
    proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=fout, stderr=subprocess.STDOUT, text=True,
                            start_new_session=True)
    proc._collector_file = fout
    return proc


def sockowner_health(path: str) -> Optional[Dict[str, int]]:
    """The SOCKOWNER_HEALTH line: ring-buffer drops, flow-map errors, failed."""
    try:
        lines = Path(path).read_text(errors="replace").splitlines()
    except OSError:
        return None
    for line in reversed(lines):
        if line.startswith("SOCKOWNER_HEALTH,"):
            parts = line.split(",")
            try:
                return {"ringbuf_drops": int(parts[1]), "flow_map_errors": int(parts[2]), "failed": int(parts[3])}
            except (IndexError, ValueError):
                return None
    return None


def send_hostmon_start(proc: subprocess.Popen, start_monotonic: float) -> None:
    assert proc.stdin is not None
    proc.stdin.write(repr(float(start_monotonic)) + "\n")
    proc.stdin.flush()
    proc.stdin.close()


def hostmon_health(path: str) -> Optional[Dict[str, int]]:
    """The monitor's HOSTMON_HEALTH,<lost>,<capacity errors>,<late>,<failed> line, if printed."""
    p = Path(path)
    if not p.exists():
        return None
    for line in reversed(p.read_text(errors="replace").splitlines()):
        if line.startswith("HOSTMON_HEALTH,"):
            values = [safe_int(x) for x in line.split(",")[1:5]]
            return dict(zip(("lost", "capacity_errors", "late_events", "failed"), values))
    return None


def run_scenario_command(cmd: str, shell: str = "/bin/bash", cgroup: Optional[str] = None,
                         launcher: str = "shell", workspace: Optional[str] = None) -> subprocess.Popen:
    """launcher 'shell': the command string runs in `shell -c` (in the cgroup
    when given). launcher 'dataset': the command is split into words (no shell
    syntax) and runs as the dataset's launcher ran its programs: stdin
    /dev/null, a new session, cwd `workspace` (RUNBOOK 19.5.6, 19.9.2)."""
    if launcher == "dataset":
        argv = shlex.split(cmd)
        return subprocess.Popen(dataset_launch_command(argv, cgroup), stdin=subprocess.DEVNULL, cwd=workspace,
                                start_new_session=True)
    if cgroup is not None:
        return subprocess.Popen(cgroup_wrapped_command(cmd, cgroup, shell), text=True)
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
    dst_indexes: Optional[List[int]] = None,
    timeout: Optional[float] = None,
    clear_indexes: Optional[List[int]] = None,
) -> Dict[str, Any]:
    if not indexes and not dst_indexes and not clear_indexes:
        return {"source": "empty", "flow_count": 0, "dst_rows": [], "cleared": [], "rows": []}

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
    if clear_indexes:
        cmd += ["--clear-indexes", ",".join(str(x) for x in clear_indexes)]
    if dst_indexes:
        cmd += ["--dst-indexes", ",".join(str(x) for x in dst_indexes)]
    if timeout is not None:
        cmd += ["--timeout", str(timeout)]   # the reader's bfshell session

    result = subprocess.run(
        cmd,
        check=True,
        capture_output=True,
        text=True,
        timeout=None if timeout is None else timeout + 30,
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


class P4ReadError(RuntimeError):
    """A register read failed on every attempt."""


BUSY_SHELL = "Only one Python shell instance allowed"


def describe_failure(error: BaseException) -> str:
    if isinstance(error, subprocess.CalledProcessError):
        text = "\n".join(t for t in (error.stderr, error.stdout) if t)
        lines = [l.strip() for l in text.splitlines() if l.strip() and not l.strip().startswith("bfshell>")]
        busy = [l for l in lines if BUSY_SHELL in l]
        tail = busy[-1:] or lines[-1:]   # the busy-shell message, or the exception line of a traceback
        return f"exit status {error.returncode}" + (": " + tail[0] if tail else "")
    if isinstance(error, subprocess.TimeoutExpired):
        return f"no answer within {error.timeout:.0f} s"
    return f"{type(error).__name__}: {error}"


def read_p4_with_retries(
    reader_path: str,
    indexes: List[int],
    window: int,
    retries: int = 0,
    timeout: Optional[float] = None,
    **kwargs: Any,
) -> Dict[str, Any]:
    """run_p4_reader_json, tried retries + 1 times. A bfshell session can fail
    to start or hang; one such read must not end the run.

    A retried read repeats the same clear_if_unchanged request; a bucket that
    an interrupted attempt has already cleared no longer has the expected
    packet count, so it is not cleared again, and its next delta starts from
    the zero it now reads.

    Killing a bfshell client that timed out does not stop its script on the
    switch, and bf_switchd refuses a second Python shell meanwhile ("Only one
    Python shell instance allowed"); that refusal waits longer before the
    next attempt."""
    if timeout is not None:
        kwargs["timeout"] = timeout
    for attempt in range(retries + 1):
        try:
            return run_p4_reader_json(reader_path, indexes, **kwargs)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, RuntimeError, ValueError) as error:
            reason = describe_failure(error)
            if attempt == retries:
                raise P4ReadError(f"register read of window {window} failed after {retries + 1} attempt(s): "
                                  f"{reason}") from error
            wait = 15.0 if BUSY_SHELL in reason else 2.0
            print(f"[WARN] window {window}: register read attempt {attempt + 1} failed ({reason}); "
                  f"retrying in {wait:.0f} s")
            time.sleep(wait)
    raise AssertionError("unreachable")


class BatchedReaderProcess:
    """One long-lived `batched_reader.py --serve` process: a BF Runtime gRPC
    client that stays connected for the whole run and answers one JSON request
    per window (read_registers_with_index.py starts a bfshell session per
    window instead).

    Locally the process runs on this host against --grpc-addr. With switch_ssh
    the script is copied to the switch and runs there with the SDE's own
    Python client (the interpreter whose site-packages hold bfrt_grpc, e.g.
    python2.7 for SDE 9.6), talking to the switch's local gRPC server; SSH
    carries the request and payload lines.

    read_with_retries() has the semantics of read_p4_with_retries(): a failed
    or hung request is retried after the process is stopped, and the next
    request starts a new process (and gRPC connection)."""

    def __init__(self, script: str = DEFAULT_BATCHED_READER, grpc_addr: str = DEFAULT_GRPC_ADDR,
                 client_id: int = 7, p4_name: str = "basic", switch_ssh: Optional[str] = None,
                 remote_sde_install: str = DEFAULT_REMOTE_SDE_INSTALL, chunk: int = 4096,
                 safe_parse: bool = False, strict: bool = False, sync_batched: bool = False,
                 raw_wire: bool = False, start_timeout: float = 90.0, extra_args: Optional[List[str]] = None,
                 echo: bool = True):
        self.script = script
        self.grpc_addr = grpc_addr
        self.client_id = client_id
        self.p4_name = p4_name
        self.switch_ssh = switch_ssh
        self.remote_sde_install = remote_sde_install
        self.chunk = chunk
        self.safe_parse = safe_parse
        self.strict = strict
        self.sync_batched = sync_batched
        self.raw_wire = raw_wire
        self.start_timeout = start_timeout
        self.extra_args = list(extra_args or [])
        self.echo = echo
        self.remote_name = "batched_reader"
        self.ready: Optional[Dict[str, Any]] = None
        self.starts = 0
        self._proc: Optional[subprocess.Popen] = None
        self._lines: "queue.Queue[str]" = queue.Queue()
        self._stderr: "collections.deque[str]" = collections.deque(maxlen=60)

    def _args(self) -> List[str]:
        args = ["--serve", "--grpc-addr", self.grpc_addr, "--client-id", str(self.client_id),
                "--p4-name", self.p4_name, "--chunk", str(self.chunk)]
        if self.safe_parse:
            args.append("--safe-parse")
        if self.sync_batched:
            args.append("--sync-batched")
        if self.raw_wire:
            args.append("--raw-wire")
        if self.strict:
            args.append("--strict-core-registers")
        return args + self.extra_args

    def _spawn(self) -> subprocess.Popen:
        if self.switch_ssh is None:
            cmd = [sys.executable, self.script] + self._args()
        else:
            remote_path = f"/tmp/{self.remote_name}_{os.getpid()}.py"
            copy = subprocess.run(["ssh", "-o", "BatchMode=yes", self.switch_ssh, f"cat > {remote_path}"],
                                  input=Path(self.script).read_bytes(), stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT, timeout=60)
            if copy.returncode != 0:
                raise RuntimeError(f"could not copy {self.script} to {self.switch_ssh}: {copy.stdout.decode()}")
            sde = shlex.quote(self.remote_sde_install)
            script_args = " ".join(shlex.quote(a) for a in self._args() + ["--sde-install", self.remote_sde_install])
            remote = (f"SDE_INSTALL={sde}; export SDE_INSTALL; export LD_LIBRARY_PATH=/usr/local/lib:$SDE_INSTALL/lib; "
                      "py=; for d in \"$SDE_INSTALL\"/lib/python*/site-packages/tofino/bfrt_grpc; do "
                      "[ -d \"$d\" ] && py=$(basename \"$(dirname \"$(dirname \"$(dirname \"$d\")\")\")\"); done; "
                      "[ -n \"$py\" ] || py=python3; "
                      f"$py {remote_path} {script_args}; rc=$?; rm -f {remote_path}; exit $rc")
            cmd = ["ssh", "-o", "BatchMode=yes", "-T", self.switch_ssh, "bash -c %s" % shlex.quote(remote)]
        return subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, bufsize=1)

    def start(self) -> Dict[str, Any]:
        self.stop()
        self._lines = queue.Queue()
        proc = self._spawn()
        self._proc = proc

        def pump_stdout():
            for line in proc.stdout:
                self._lines.put(line)

        def pump_stderr():
            for line in proc.stderr:
                self._stderr.append(line.rstrip())
                if self.echo:
                    print(f"[reader] {line.rstrip()}", flush=True)

        threading.Thread(target=pump_stdout, daemon=True).start()
        threading.Thread(target=pump_stderr, daemon=True).start()
        ready = json.loads(self._get_line(self.start_timeout))
        if not ready.get("ready"):
            self.stop()
            raise RuntimeError(f"batched reader did not start: {ready}")
        self.ready = ready
        self.starts += 1
        return ready

    def _get_line(self, timeout: Optional[float]) -> str:
        deadline = None if timeout is None else time.time() + timeout
        while True:
            try:
                return self._lines.get(timeout=0.5 if deadline is None else max(0.0, min(0.5, deadline - time.time())))
            except queue.Empty:
                pass
            proc = self._proc
            if proc is not None and proc.poll() is not None:
                try:  # output that arrived just before the exit
                    return self._lines.get_nowait()
                except queue.Empty:
                    tail = "\n".join(list(self._stderr)[-8:])
                    raise RuntimeError(f"batched reader exited with {proc.returncode}: {tail}")
            if deadline is not None and time.time() >= deadline:
                raise subprocess.TimeoutExpired(["batched_reader"], timeout)

    def read(self, indexes: List[int], dst_indexes: Optional[List[int]] = None,
             clear_if_unchanged: Optional[Dict[int, int]] = None, snapshot: str = "sync",
             timeout: Optional[float] = None, source: str = "batched gRPC",
             clear_indexes: Optional[List[int]] = None, probe: Optional[Dict[int, int]] = None,
             probe_max_full: Optional[int] = None, totals: Any = False) -> Dict[str, Any]:
        if self._proc is None or self._proc.poll() is not None:
            self.start()
        assert self._proc is not None and self._proc.stdin is not None
        request = {"indexes": [int(i) for i in indexes], "dst_indexes": [int(i) for i in (dst_indexes or [])],
                   "clear_if_unchanged": {str(int(k)): int(v) for k, v in (clear_if_unchanged or {}).items()},
                   "clear_indexes": [int(i) for i in (clear_indexes or [])],
                   "snapshot": snapshot, "source": source}
        if probe:
            # dormant buckets: reg_pkts only, the changed ones in full (batched_reader.read_window)
            request["probe"] = {str(int(k)): int(v) for k, v in probe.items()}
            if probe_max_full is not None:
                request["probe_max_full"] = int(probe_max_full)
        if totals:
            # the gtot build's one-entry totals (batched_reader.read_window): from hardware before the flow
            # registers' sync, or "snapshot": synced with them (PC1.md part 4d's cut)
            request["totals"] = "snapshot" if totals == "snapshot" else True
        t_sent = time.time()
        self._proc.stdin.write(json.dumps(request) + "\n")
        self._proc.stdin.flush()
        line = self._get_line(timeout)
        t_reply = time.time()
        reply = json.loads(line)
        if "error" in reply:
            raise RuntimeError(f"batched reader: {reply['error']}")
        if isinstance(reply.get("timing"), dict):
            # This host's clock around the request; with the reader's reader_t_recv/reader_t_send they
            # map the reader's snapshot times (reader_t_sync_start/end) onto this clock (RUNBOOK 19.6).
            reply["timing"]["collector_t_sent"] = t_sent
            reply["timing"]["collector_t_reply"] = t_reply
        return reply

    def read_with_retries(self, indexes: List[int], window: int, retries: int = 0,
                          timeout: Optional[float] = None, **kwargs: Any) -> Dict[str, Any]:
        for attempt in range(retries + 1):
            try:
                return self.read(indexes, timeout=timeout, **kwargs)
            except (subprocess.TimeoutExpired, RuntimeError, ValueError, OSError) as error:
                reason = describe_failure(error)
                self.stop()
                if attempt == retries:
                    raise P4ReadError(f"register read of window {window} failed after {retries + 1} attempt(s): "
                                      f"{reason}") from error
                print(f"[WARN] window {window}: register read attempt {attempt + 1} failed ({reason}); "
                      f"restarting the batched reader and retrying in 2 s")
                time.sleep(2.0)
        raise AssertionError("unreachable")

    def stop(self) -> None:
        proc = self._proc
        self._proc = None
        if proc is None:
            return
        try:
            if proc.poll() is None and proc.stdin is not None:
                proc.stdin.write(json.dumps({"cmd": "quit"}) + "\n")
                proc.stdin.flush()
                proc.wait(timeout=3)
        except (OSError, ValueError, subprocess.TimeoutExpired):
            pass
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
        for pipe in (proc.stdin, proc.stdout, proc.stderr):
            try:
                if pipe is not None:
                    pipe.close()
            except OSError:
                pass


class WindowReaderProcess(BatchedReaderProcess):
    """`window_reader.py --serve` for perf/variants/exact (--switch-program exact): one request per command
    (setup, mark, read), one JSON reply each. On the switch, as the batched reader runs."""

    def __init__(self, script: str = DEFAULT_WINDOW_READER, grpc_addr: str = DEFAULT_GRPC_ADDR,
                 client_id: int = 9, p4_name: str = "basic", switch_ssh: Optional[str] = None,
                 remote_sde_install: str = DEFAULT_REMOTE_SDE_INSTALL, cpu_iface: str = "enp5s0",
                 start_timeout: float = 90.0, echo: bool = True):
        super().__init__(script, grpc_addr=grpc_addr, client_id=client_id, p4_name=p4_name, switch_ssh=switch_ssh,
                         remote_sde_install=remote_sde_install, start_timeout=start_timeout, echo=echo)
        self.cpu_iface = cpu_iface
        self.remote_name = "window_reader"

    def _args(self) -> List[str]:
        return ["--serve", "--grpc-addr", self.grpc_addr, "--client-id", str(self.client_id),
                "--p4-name", self.p4_name, "--cpu-iface", self.cpu_iface]

    def request(self, req: Dict[str, Any], timeout: Optional[float] = None) -> Dict[str, Any]:
        """One command; the reply with this host's clock around it (collector_t_sent / collector_t_reply)."""
        if self._proc is None or self._proc.poll() is not None:
            self.start()
        assert self._proc is not None and self._proc.stdin is not None
        t_sent = time.time()
        self._proc.stdin.write(json.dumps(req) + "\n")
        self._proc.stdin.flush()
        reply = json.loads(self._get_line(timeout))
        reply["collector_t_sent"], reply["collector_t_reply"] = t_sent, time.time()
        return reply


class SweepReaderProcess(WindowReaderProcess):
    """`sweep_reader.py --serve` for perf/variants/sweep (--switch-program sweep): setup, the packet generator
    (prepare, enable, stop) and the switch's state, one JSON reply per command. On the switch, as the batched
    reader runs. stop() stops the generator first (between two sweeps: a stop in a batch leaves the pipe's
    generator dead until switchd is restarted, PC1.md Results, part 9b)."""

    def __init__(self, script: str = DEFAULT_SWEEP_READER, grpc_addr: str = DEFAULT_GRPC_ADDR,
                 client_id: int = 9, p4_name: str = "basic", switch_ssh: Optional[str] = None,
                 remote_sde_install: str = DEFAULT_REMOTE_SDE_INSTALL, pipes: Optional[List[int]] = None,
                 local_port: int = 68, start_timeout: float = 90.0, echo: bool = True):
        super().__init__(script, grpc_addr=grpc_addr, client_id=client_id, p4_name=p4_name, switch_ssh=switch_ssh,
                         remote_sde_install=remote_sde_install, start_timeout=start_timeout, echo=echo)
        self.pipes = list(pipes or [1])
        self.local_port = int(local_port)
        self.remote_name = "sweep_reader"
        self.generator_running = False

    def _args(self) -> List[str]:
        return ["--serve", "--grpc-addr", self.grpc_addr, "--client-id", str(self.client_id),
                "--p4-name", self.p4_name, "--pipes", ",".join(str(p) for p in self.pipes),
                "--local-port", str(self.local_port)]

    def request(self, req: Dict[str, Any], timeout: Optional[float] = None) -> Dict[str, Any]:
        reply = super().request(req, timeout)
        if req.get("cmd") == "generator" and "error" not in reply:
            if req.get("stop"):
                self.generator_running = False
            elif req.get("enable"):
                self.generator_running = True
        return reply

    def stop(self) -> None:
        if self.generator_running and self._proc is not None and self._proc.poll() is None:
            try:
                r = self.request({"cmd": "generator", "stop": True}, timeout=15)
                print(f"[INFO] sweep build: generator stopped {json.dumps(r)}")
            except Exception as error:
                print(f"[WARN] sweep build: stopping the generator: {error}")
        super().stop()


class ExportCapture:
    """The sweep build's export records (EtherType 0x88B6) as they arrive on this host's interface, kept per sweep
    number with their arrival times. Both backends need root, capture promiscuously (an export keeps its probe's
    destination MAC) and take incoming frames only (an in-band replay's own probes leave through the same interface).
    "tcpdump" (the collector's default): tcpdump writes the records into a pcap file in /dev/shm and a thread reads
    and parses the file behind it, so a slow window delays the windows but loses no record. On PC1 (2 cores) while
    it replayed a flood, the "socket" backend (an AF_PACKET socket read by a Python thread) fell 5 s behind and
    dropped 129,000 records (syn_fan_40k, generator probes 0.5 us apart; PC1.md part 9g). Arrival times are then
    tcpdump's (--immediate-mode: per record, not in blocks up to 1 s late). With tcpdump a sweep counts as complete
    only once a later sweep has begun, or once the file is read to its end and no record of the sweep has come in for
    quiet_wall_s of this host's time: a record's own timestamp says when it reached the interface, not when tcpdump
    wrote it (a sweep taken by its timestamps alone missed records: bulk2000 lost 612 packets, PC1.md part 9g).
    add() takes a frame directly (tests)."""

    ETH_P_SWEEP = 0x88B6

    def __init__(self, iface: str, rcvbuf: int = 64 << 20, backend: str = "socket", pcap_path: Optional[str] = None,
                 buffer_kib: int = 131072):
        sys.path.insert(0, SWEEP_PYDIR)
        from sweep_features import parse_export
        self.parse_export = parse_export
        self.iface, self.rcvbuf = iface, rcvbuf
        if backend not in ("socket", "tcpdump"):
            raise ValueError(f"unknown export capture backend {backend!r}")
        self.backend, self.pcap_path, self.keep_pcap, self.buffer_kib = backend, pcap_path, pcap_path is not None, \
            buffer_kib
        self._tcpdump: Optional[subprocess.Popen] = None
        self._tcpdump_err: List[str] = []
        self._eof = True            # everything written so far is read (always so for the socket backend)
        self._final = threading.Event()
        self.last_add: Dict[int, float] = {}
        self.quiet_wall_s = 0.25
        self.lock = threading.Lock()
        self.by_seq: Dict[int, List[Any]] = {}
        self.first_t: Dict[int, float] = {}
        self.last_t: Dict[int, float] = {}
        self.max_seq = 0
        self.frames = self.records = self.other = 0
        self.kernel_drops = 0
        self._stop = threading.Event()
        self._sock = None
        self._thread: Optional[threading.Thread] = None

    def start(self) -> "ExportCapture":
        if self.backend == "tcpdump":
            return self._start_tcpdump()
        import socket
        import struct
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(self.ETH_P_SWEEP))
        try:
            s.setsockopt(socket.SOL_SOCKET, 33, self.rcvbuf)        # SO_RCVBUFFORCE (root)
        except OSError:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, self.rcvbuf)
        s.bind((self.iface, self.ETH_P_SWEEP))
        mreq = struct.pack("iHH8s", socket.if_nametoindex(self.iface), 1, 0, b"")   # PACKET_MR_PROMISC
        s.setsockopt(263, 1, mreq)                                   # SOL_PACKET, PACKET_ADD_MEMBERSHIP
        s.settimeout(0.2)
        self._sock = s
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        return self

    def _run(self) -> None:
        import socket
        while not self._stop.is_set():
            try:
                frame, addr = self._sock.recvfrom(2048)
            except socket.timeout:
                continue
            except OSError:
                break
            if addr[2] == 4:                                         # PACKET_OUTGOING
                continue
            self.add(time.time(), frame)

    def _start_tcpdump(self) -> "ExportCapture":
        if self.pcap_path is None:
            self.pcap_path = f"/dev/shm/hybrid_sweep_exports_{os.getpid()}.pcap"
        if os.path.exists(self.pcap_path):
            if self.keep_pcap:
                raise P4ReadError(f"--sweep-export-pcap {self.pcap_path} exists")
            os.unlink(self.pcap_path)
        cmd = ["tcpdump", "-i", self.iface, "-Q", "in", "-n", "-U", "--immediate-mode", "-s", "256",
               "-B", str(self.buffer_kib), "-w", self.pcap_path, "ether proto 0x88b6"]
        self._tcpdump = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                         stderr=subprocess.PIPE, text=True)
        listening = threading.Event()

        def err_reader() -> None:
            for line in self._tcpdump.stderr:
                self._tcpdump_err.append(line.rstrip())
                if "listening on" in line:
                    listening.set()
            listening.set()

        threading.Thread(target=err_reader, daemon=True).start()
        listening.wait(15)
        if self._tcpdump.poll() is not None or not any("listening on" in l for l in self._tcpdump_err):
            raise P4ReadError("the export capture (tcpdump) did not start: " + "; ".join(self._tcpdump_err[-3:]))
        self._eof = False
        self._thread = threading.Thread(target=self._run_pcap, daemon=True)
        self._thread.start()
        return self

    def _run_pcap(self) -> None:
        """Read tcpdump's file as it grows: one record at a time, a partial record left for the next read. _eof
        is set once a read finds nothing new; after stop() has ended tcpdump, the file is read to its end."""
        import struct
        f = None
        while f is None:
            try:
                f = open(self.pcap_path, "rb")
            except FileNotFoundError:
                if self._final.is_set():
                    return
                time.sleep(0.01)
        try:
            head = b""
            while len(head) < 24:
                more = f.read(24 - len(head))
                if not more:
                    if self._final.is_set():
                        return
                    time.sleep(0.005)
                head += more
            endian, frac = {b"\xd4\xc3\xb2\xa1": ("<", 1e-6), b"\xa1\xb2\xc3\xd4": (">", 1e-6),
                            b"\x4d\x3c\xb2\xa1": ("<", 1e-9), b"\xa1\xb2\x3c\x4d": (">", 1e-9)}[head[:4]]
            rec = struct.Struct(endian + "IIII")
            buf = b""
            while True:
                chunk = f.read(1 << 20)
                if not chunk:
                    self._eof = True
                    if self._final.is_set():
                        break
                    time.sleep(0.002)
                    continue
                self._eof = False
                buf += chunk
                pos = 0
                while len(buf) - pos >= 16:
                    sec, sub, incl, _orig = rec.unpack_from(buf, pos)
                    if len(buf) - pos - 16 < incl:
                        break
                    self.add(sec + sub * frac, buf[pos + 16:pos + 16 + incl])
                    pos += 16 + incl
                buf = buf[pos:]
        finally:
            self._eof = True
            f.close()

    def add(self, host_t: float, frame: bytes) -> None:
        rec = self.parse_export(frame)
        with self.lock:
            self.frames += 1
            if rec is None:
                self.other += 1
                return
            self.records += 1
            seq = rec["seq"]
            self.by_seq.setdefault(seq, []).append((host_t, rec))
            self.first_t.setdefault(seq, host_t)
            self.last_t[seq] = host_t
            self.last_add[seq] = time.time()
            self.max_seq = max(self.max_seq, seq)

    def read_drops(self) -> int:
        """The socket's drops so far (PACKET_STATISTICS counts since its last read); tcpdump's are known once it
        has stopped."""
        if self._sock is not None:
            import struct
            try:
                _packets, drops = struct.unpack("II", self._sock.getsockopt(263, 6, 8))
                self.kernel_drops += drops
            except OSError:
                pass
        return self.kernel_drops

    def complete(self, k: int, now: float, span_s: float, quiet_s: float) -> bool:
        """Sweep k is complete once a later sweep has begun, or span_s after its first record and quiet_s after
        its last."""
        with self.lock:
            if k not in self.by_seq:
                return False
            if self.max_seq > k:
                return True
            if self.backend == "tcpdump":
                return self._eof and now - self.first_t[k] >= span_s and \
                    now - self.last_add[k] >= max(quiet_s, self.quiet_wall_s)
            return now - self.first_t[k] >= span_s and now - self.last_t[k] >= quiet_s

    def take(self, k: int) -> List[Any]:
        with self.lock:
            self.first_t.pop(k, None)
            self.last_t.pop(k, None)
            self.last_add.pop(k, None)
            return self.by_seq.pop(k, [])

    def stop(self) -> None:
        if self._tcpdump is not None:
            if self._tcpdump.poll() is None:
                self._tcpdump.send_signal(signal.SIGINT)
                try:
                    self._tcpdump.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    self._tcpdump.kill()
                    self._tcpdump.wait()
            time.sleep(0.2)                 # the stderr thread takes tcpdump's last lines
            for line in self._tcpdump_err:
                m = re.match(r"(\d+) packets dropped by kernel", line)
                if m:
                    self.kernel_drops = int(m.group(1))
            self._tcpdump = None
            self._final.set()
            if self._thread is not None:
                self._thread.join(timeout=60)
            if not self.keep_pcap and self.pcap_path and os.path.exists(self.pcap_path):
                os.unlink(self.pcap_path)
            return
        self._final.set()
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2)
        if self._sock is not None:
            self.read_drops()
            self._sock.close()
            self._sock = None


# Absolute times a batched read reports (RUNBOOK 19.6); the timing log keeps them per window.
CLOCK_KEYS = ("collector_t_sent", "collector_t_reply", "reader_t_recv", "reader_t_sync_start",
              "reader_t_sync_end", "reader_t_send")
# --global-totals: the reader's clock around the totals' read, i.e. their cut (PC1.md part 4e)
TOTALS_CLOCK_KEYS = ("reader_t_totals_start", "reader_t_totals_end")


def make_timing_logger(reader_name: str, path: Optional[str] = None) -> Callable[..., None]:
    """Per window: active-set size and the time spent in the register sync, the
    reads and the clears (from the reader's payload) next to the wall time of
    the whole read; the difference is the session/IPC overhead. With path, one
    JSON object per window is appended to that file."""

    def log(window: int, payload: Dict[str, Any], read_start: float, read_end: float,
            n_active: int, n_dst: int, window_end: Optional[float] = None,
            extra: Optional[Dict[str, Any]] = None) -> None:
        wall_ms = (read_end - read_start) * 1000.0
        timing = payload.get("timing") or {}
        sync_s = payload.get("sync_s") or 0.0
        read_s = payload.get("read_s") or 0.0
        clear_s = payload.get("clear_s") or 0.0
        sync_ms = float(timing.get("sync_ms", sync_s * 1000.0))
        read_ms = float(timing.get("read_ms", max(0.0, read_s - sync_s) * 1000.0))
        clear_ms = float(timing.get("clear_ms", clear_s * 1000.0))
        overhead_ms = wall_ms - sync_ms - read_ms - clear_ms
        rpcs = {k: timing[k] for k in ("sync_rpcs", "read_rpcs", "read_entities", "clear_rpcs") if k in timing}
        parser = timing.get("parser")   # batched reader: raw / fast / safe
        record = {"window": window, "reader": reader_name, "parser": parser, "active": n_active, "dst": n_dst,
                  "snapshot": payload.get("snapshot"), "sync_ms": round(sync_ms, 3), "read_ms": round(read_ms, 3),
                  "clear_ms": round(clear_ms, 3), "wall_ms": round(wall_ms, 3), "overhead_ms": round(overhead_ms, 3),
                  "us_per_bucket": round(wall_ms * 1000.0 / n_active, 1) if n_active else None,
                  "cleared": len(payload.get("cleared") or []), "errors": len(payload.get("errors") or []),
                  "rpcs": rpcs,
                  # absolute times (RUNBOOK 19.6): the window's end and the read on the collector's clock,
                  # and the batched reader's request, snapshot and reply times on the reader's clock
                  "t_window_end": window_end, "t_read_start": read_start, "t_read_end": read_end,
                  "clock": {k: timing[k] for k in CLOCK_KEYS + TOTALS_CLOCK_KEYS if k in timing}}
        if extra:
            record.update(extra)
        print(f"[TIMING] window {window}: reader={reader_name}{'/' + parser if parser else ''} "
              f"active={n_active} dst={n_dst} "
              f"sync={sync_ms:.1f} ms read={read_ms:.1f} ms clear={clear_ms:.1f} ms wall={wall_ms:.1f} ms "
              f"overhead={overhead_ms:.1f} ms cleared={record['cleared']}"
              + (f" rpcs={rpcs}" if rpcs else ""), flush=True)
        if path:
            with open(path, "a") as f:
                f.write(json.dumps(record) + "\n")

    return log


# ============================================================
# READ CADENCE: cost model, read budget, report-only aggregates
# ============================================================

# Columns computed from the CPU reports alone, with no register read. They are
# the flood-path signal (new flows per second, destination fan-out, protocol
# mix) and stay available when the active set is too large to read.
REPORT_ZERO = {
    "rep_new_flows": 0,
    "rep_new_flows_per_sec": 0.0,
    "rep_distinct_src_ips": 0,
    "rep_distinct_dst_ips": 0,
    "rep_distinct_dst_ports": 0,
    "rep_tcp_share": 0.0,
    "rep_max_flows_to_one_dst": 0,
    "rep_max_flows_to_one_dst_port": 0,
    "net_overload": 0,
    "net_buckets_active": 0,
    "net_buckets_read": 0,
    "net_buckets_skipped": 0,
    "net_dst_buckets_skipped": 0,
    "net_read_budget_ms": 0.0,
    "net_read_allow_ms": 0.0,      # this window's allowance: the budget, or less when the read starts late
    "net_read_late_ms": 0.0,       # how long after the window boundary the read was decided
    "net_read_overrun": 0,
    "net_buckets_cleared": 0,      # idle (compare-and-clear) + expired (unconditional) clears in this read
    "net_clear_backlog": 0,        # expired buckets still waiting for their clear after this read
}

# A read may use the time left until the next window boundary minus this margin.
DEADLINE_SAFETY_MS = 5.0
# CPU reports that reach the collector after its last window took its reports: at the end of a run
# it waits until none has arrived for LATE_REPORT_QUIET_S (at most LATE_REPORT_MAX_S) and clears
# their buckets with the end-of-run clear (RUNBOOK 16).
LATE_REPORT_QUIET_S = 0.3
LATE_REPORT_MAX_S = 1.0
# The workload starts once the CPU-report capture is listening, or after this many seconds with a
# warning: reports sent before the capture listens are lost, and their buckets stay occupied and
# unknown to the collector (RUNBOOK 18: the first 20 ms of a replay left 33 buckets occupied).
REPORT_CAPTURE_READY_S = 10.0
# An expired bucket whose unconditional clear fails this many times is given up.
CLEAR_ATTEMPTS = 3

# Recommended option bundles. "switch": the Wedge100BF-32X with the batched
# reader on its wire-format route (RUNBOOK sections 9-10): 1 s windows, the
# dataset's 3-window idle TTL, syncs in one RPC, and a read budget of 70% of the
# window (RUNBOOK 14.2: at 80% the budget nearly equalled the deadline in a flood,
# where the reports, the selection and the post-read work take ~175 ms, so a
# read 15-25% slower than predicted ended after the next boundary).
# "model": the Tofino software model. With the batched reader its 15
# register syncs take 45-140 s and the shadow reads after them 7-121 s, 52-232 s
# per window in all; its hardware reads take ~0.47 s per register entry (18
# buckets = 118 s, growing with the active set). Measured 2026-11-07
# (live_test/RESULTS.md). Hence sync snapshots, a 600 s read timeout (the default
# 120 s cut off reads that would have finished), long windows, no idle clearing,
# and no budget (the syncs alone take most or all of a 60 s window, so a budget
# leaves no room for bucket reads).
# The reads still end after the next window boundary; that is expected on the
# model. Explicit options override the profile.
PROFILES: Dict[str, Dict[str, Any]] = {
    "switch": {"window_sec": 1.0, "active_ttl_windows": 3, "clear_idle_windows": 3, "reader": "batched",
               "reader_raw_wire": True, "reader_sync_batched": True, "p4_snapshot": "sync",
               "read_budget_frac": 0.7, "max_dst_reads": 256, "forward_report_port": 192,
               "clear_expired": 1, "clear_budget_frac": 0.5},
    "model": {"window_sec": 60.0, "active_ttl_windows": 3, "clear_idle_windows": 0, "reader": "batched",
              "p4_snapshot": "sync", "p4_read_timeout": 600.0, "read_budget_frac": 0.0, "max_dst_reads": 0,
              "forward_report_port": 2, "clear_expired": 0},
    # "dataset": the Wedge100BF-32X producing rows by the dataset's definitions (RUNBOOK 19.9), so that
    # the detectors trained on dataset/features.csv score them unchanged: 40 windows of 0.5 s from the
    # launch, the program stopped at 20 s as the dataset's runner did, the dataset's launcher (its
    # startup is part of every dataset row), Ethernet frame bytes (+14 B per packet on the IPv4
    # lengths the switch counts), durations in seconds (the 32-bit timestamps unwrapped), and no
    # bucket cleared during the run: a flow never ends in the dataset's extractor, so buckets that
    # leave the active set stay dormant, are re-read with the allowance left after the active set,
    # and are all cleared at the end of the run.
    "dataset": {"window_sec": 0.5, "active_ttl_windows": 3, "clear_idle_windows": 0, "reader": "batched",
                "reader_raw_wire": True, "reader_sync_batched": True, "p4_snapshot": "sync",
                "read_budget_frac": 0.7, "max_dst_reads": 256, "forward_report_port": 192,
                "clear_expired": 0, "clear_budget_frac": 0.5,
                "dormant_reads": 1, "dormant_probe": 1, "byte_layer": "frame", "duration_unit": "s", "windows": 40,
                "launcher": "dataset", "frame_min_default": ["10.0.0.10/32"]},
    # "exact": perf/variants/exact (or exact_block, for --block-on-alarm) on the Wedge: every window computed in
    # the data plane, 0.5-s windows cut by markers from the switch's CPU port, the dataset's launcher and frame
    # bytes, so that the detectors trained on dataset/features.csv score the rows unchanged.
    "exact": {"switch_program": "exact", "window_sec": 0.5, "window_markers": "cpu", "forward_report_port": 192,
              "byte_layer": "frame", "duration_unit": "s", "launcher": "dataset"},
}

# --block-on-alarm: active flows per 0.5-s window over which a flagged program's host is blocked (block_policy.py)
FLOOD_FLOWS_DEFAULT = 500

# Ethernet header bytes: the dataset counted frame bytes, the switch counts IPv4 totalLen.
ETHERNET_HEADER_BYTES = 14
# Dormant probes leave room for this many full bucket reads: the dormant buckets found changed.
DORMANT_RESUME_RESERVE = 8
# The one-entry global totals of the test build perf/variants/gtot (reg_g_<key>), per window as the reader sums
# them over the pipes; --global-totals takes the window totals from them (PC1.md part 4d).
GTOT_KEYS = ["pkts", "bytes", "pkts_ab", "bytes_ab", "syn", "ack", "rst"]
# The same build with -DP4_GLOBAL_TOTALS_SPLIT=1 (basic_gtot_ba, PC1.md part 4f): B->A counted in place of the
# packet and byte totals, so that B->A grows only with B->A packets; the totals are A->B + B->A.
GTOT_KEYS_SPLIT = ["pkts_ab", "bytes_ab", "pkts_ba", "bytes_ba", "syn", "ack", "rst"]


def gtot_keys(totals: Any) -> Optional[List[str]]:
    """The keys of a complete read of the global totals (GTOT_KEYS or GTOT_KEYS_SPLIT), else None."""
    if isinstance(totals, dict):
        for keys in (GTOT_KEYS, GTOT_KEYS_SPLIT):
            if all(totals.get(k) is not None for k in keys):
                return keys
    return None

# The flow timestamps are the low 32 bits of a ns clock.
TS_WRAP_S = (1 << 32) / 1e9

# Starting costs of one register read per reader route, in milliseconds. From
# the Wedge100BF-32X (RUNBOOK sections 9, 10 and 12.1) and the Tofino model
# (live_test/RESULTS.md, 2026-11-07). A run's model keeps learning from every
# window, so these only decide how well the first windows fit the budget.
ROUTE_COSTS: Dict[str, Dict[str, float]] = {
    # --reader batched --reader-raw-wire: the 14 syncs in one RPC 30-31 ms plus client/IPC overhead.
    # A read costs ~23 ms for its 14 (+1) Read RPCs plus 0.51-0.56 ms per bucket (RUNBOOK 16: 1 bucket
    # 21 ms, 101 buckets 74 ms, 1,054 units 612 ms); a clear ~3 ms for its Write plus 0.105 ms per
    # bucket (bucket by bucket, RUNBOOK 18: 1,000 buckets 116 ms, 5,000 532 ms, 16,000 1,708 ms; ordered
    # register by register it was 0.083-0.095 ms, but a packet in the middle of it tore the bucket).
    # Reads and clears smaller than min_rate_units do not move the per-bucket costs: one read
    # of a single bucket (the collector's connection probe, all request overhead) had taught the model
    # 18.6 ms per bucket, and five benign windows were then overloaded with reads that used 20-45% of
    # their allowance (RUNBOOK 16, bulk2000).
    "raw": {"fixed_ms": 65.0, "read_fixed_ms": 23.0, "read_ms_per_bucket": 0.56, "clear_fixed_ms": 3.0,
            "clear_ms_per_bucket": 0.105, "min_rate_units": 20.0},
    # --reader batched with the protobuf classes: syncs 58-70 ms, reads 1.1-1.55 ms, clears 0.55-0.75 ms
    # (per-request parts not measured on this route).
    "fast": {"fixed_ms": 70.0, "read_ms_per_bucket": 1.3, "clear_ms_per_bucket": 0.7, "min_rate_units": 20.0},
    # --reader legacy: one bfshell session per window (1.4-1.5 s) and 14 reg.get() calls per bucket
    # (4.5-5.1 s at ~915 active buckets).
    "legacy": {"fixed_ms": 1500.0, "read_ms_per_bucket": 3.6, "clear_ms_per_bucket": 1.5},
    # the Tofino software model with the batched reader: 15 syncs 45-140 s, ~2.1 s per bucket, a clear ~3 s.
    "model": {"fixed_ms": 99000.0, "read_ms_per_bucket": 2100.0, "clear_ms_per_bucket": 3000.0},
}


def payload_timing_ms(payload: Dict[str, Any], wall_ms: float) -> Dict[str, float]:
    """sync / read / clear / overhead milliseconds of one register read, from
    the reader's payload (the same fields make_timing_logger prints)."""
    timing = payload.get("timing") or {}
    sync_s = payload.get("sync_s") or 0.0
    read_s = payload.get("read_s") or 0.0
    clear_s = payload.get("clear_s") or 0.0
    sync_ms = float(timing.get("sync_ms", sync_s * 1000.0))
    read_ms = float(timing.get("read_ms", max(0.0, read_s - sync_s) * 1000.0))
    clear_ms = float(timing.get("clear_ms", clear_s * 1000.0))
    probe_ms = float(timing.get("probe_ms", 0.0))
    return {"sync_ms": sync_ms, "read_ms": read_ms, "clear_ms": clear_ms, "probe_ms": probe_ms,
            "overhead_ms": max(0.0, wall_ms - sync_ms - read_ms - clear_ms - probe_ms)}


class ReadCostModel:
    """What one register read costs on this control plane: a fixed part per
    window (the register syncs and the RPC/IPC overhead), a part per flow bucket
    read, a part per reg_newconn_dst bucket read (DST_WEIGHT of a flow bucket:
    one register entity instead of fourteen) and a part per bucket cleared.
    It also tracks the collector's own work around the read (prep_ms before the
    decision: taking the reports and computing the indexes; select_ms between
    the decision and the read: ranking the buckets, the clear lists; post_ms
    after the read: the rows, the state and the CSV), the last two of which the
    deadline rule of collect_windows_live subtracts from the time left in the
    window, and margin_ms, a running average of how much the reads have taken
    longer than predicted, which buckets_within() keeps free.

    The starting values are ROUTE_COSTS[route] (for_route()). Every measured
    window moves them with an exponential average, so the budget follows the
    reader route and the control plane actually in use. A read with at least one
    bucket also pays read_fixed_ms (its Read RPCs), one with a clear
    clear_fixed_ms (its Write RPC); these per-request parts are taken off before
    the per-bucket costs are learned, and reads or clears of fewer than
    min_rate_units buckets do not move the per-bucket costs at all (their time is
    almost all request overhead).

    A dormant probe (collect_windows_live's dormant_probe) reads one register
    entity per bucket, reg_pkts, like a reg_newconn_dst read: probe_ms_per_bucket
    starts at DST_WEIGHT of a flow bucket and is learned from the reader's
    probe_ms."""

    DST_WEIGHT = 0.15

    def __init__(self, fixed_ms: float = 70.0, read_ms_per_bucket: float = 1.3,
                 clear_ms_per_bucket: float = 0.7, alpha: float = 0.3, route: str = "fast",
                 read_fixed_ms: float = 0.0, clear_fixed_ms: float = 0.0, min_rate_units: float = 0.0,
                 probe_ms_per_bucket: Optional[float] = None):
        self.fixed_ms = fixed_ms
        self.read_ms_per_bucket = read_ms_per_bucket
        self.probe_ms_per_bucket = (self.DST_WEIGHT * read_ms_per_bucket if probe_ms_per_bucket is None
                                    else probe_ms_per_bucket)
        self.clear_ms_per_bucket = clear_ms_per_bucket
        self.read_fixed_ms = read_fixed_ms        # per read with at least one bucket: its Read RPCs
        self.clear_fixed_ms = clear_fixed_ms      # per read with at least one clear: its Write RPC
        self.min_rate_units = min_rate_units      # smaller reads / clears leave the per-bucket costs alone
        self.alpha = alpha
        self.route = route
        self.prep_ms = 0.0
        self.select_ms = 0.0
        self.post_ms = 0.0
        self.margin_ms = 0.0
        self.windows_seen = 0

    @classmethod
    def for_route(cls, route: str, alpha: float = 0.3) -> "ReadCostModel":
        return cls(alpha=alpha, route=route, **ROUTE_COSTS[route])

    def _ema(self, old: float, new: float, alpha: Optional[float] = None) -> float:
        a = self.alpha if alpha is None else alpha
        return old + a * (new - old)

    def update(self, n_read: int, n_cleared: int, timing: Dict[str, float], n_dst: int = 0,
               n_probe: int = 0) -> None:
        # How much longer than predicted (with the estimates the read was planned
        # with) this read took; only overshoots count, so the margin decays to 0
        # while the predictions hold.
        probe_ms = timing.get("probe_ms", 0.0)
        observed = timing["sync_ms"] + timing["read_ms"] + timing["clear_ms"] + timing["overhead_ms"] + probe_ms
        overshoot = observed - self.predict_ms(n_read, n_cleared, n_dst, n_probe)
        self.margin_ms = self._ema(self.margin_ms, max(0.0, overshoot))
        self.windows_seen += 1
        self.fixed_ms = self._ema(self.fixed_ms, timing["sync_ms"] + timing["overhead_ms"])
        units = n_read + self.DST_WEIGHT * n_dst
        if units > 0 and units >= self.min_rate_units:
            self.read_ms_per_bucket = self._ema(self.read_ms_per_bucket,
                                                max(0.0, timing["read_ms"] - self.read_fixed_ms) / units)
        if n_cleared > 0 and n_cleared >= self.min_rate_units:
            self.clear_ms_per_bucket = self._ema(self.clear_ms_per_bucket,
                                                 max(0.0, timing["clear_ms"] - self.clear_fixed_ms) / n_cleared)
        if n_probe > 0 and n_probe >= self.min_rate_units:
            self.probe_ms_per_bucket = self._ema(self.probe_ms_per_bucket, max(0.0, probe_ms) / n_probe)

    def update_processing(self, prep_ms: float, post_ms: float, select_ms: float = 0.0) -> None:
        """The collector's own time before, around and after the read (faster
        average: it changes with the report rate, not with the switch)."""
        self.prep_ms = self._ema(self.prep_ms, max(0.0, prep_ms), alpha=0.5)
        self.select_ms = self._ema(self.select_ms, max(0.0, select_ms), alpha=0.5)
        self.post_ms = self._ema(self.post_ms, max(0.0, post_ms), alpha=0.5)

    def predict_ms(self, n_read: int, n_cleared: int = 0, n_dst: int = 0, n_probe: int = 0) -> float:
        units = n_read + self.DST_WEIGHT * n_dst
        return (self.fixed_ms + (self.read_fixed_ms if units > 0 else 0.0) + units * self.read_ms_per_bucket
                + (self.clear_fixed_ms if n_cleared > 0 else 0.0) + n_cleared * self.clear_ms_per_bucket
                + n_probe * self.probe_ms_per_bucket)

    def probes_within(self, ms: float) -> int:
        """How many dormant buckets can be probed (reg_pkts only) in ms."""
        if ms <= 0 or self.probe_ms_per_bucket <= 0:
            return 0
        return int(ms // self.probe_ms_per_bucket)

    def buckets_within(self, budget_ms: float, n_cleared: int = 0, n_dst: int = 0) -> int:
        """How many flow buckets a read can cover inside budget_ms, next to
        n_cleared clears and n_dst reg_newconn_dst reads, keeping margin_ms free."""
        available = (budget_ms - self.fixed_ms - self.margin_ms - self.read_fixed_ms
                     - (self.clear_fixed_ms if n_cleared > 0 else 0.0) - n_cleared * self.clear_ms_per_bucket
                     - n_dst * self.DST_WEIGHT * self.read_ms_per_bucket)
        if available <= 0 or self.read_ms_per_bucket <= 0:
            return 0
        return int(available // self.read_ms_per_bucket)

    def clears_within(self, ms: float) -> int:
        """How many buckets can be cleared in ms (no fixed part: the clears travel
        in the window's read)."""
        if ms <= 0 or self.clear_ms_per_bucket <= 0:
            return 0
        return int(ms // self.clear_ms_per_bucket)

    def as_dict(self) -> Dict[str, float]:
        return {"route": self.route, "fixed_ms": round(self.fixed_ms, 2),
                "read_fixed_ms": round(self.read_fixed_ms, 2),
                "read_ms_per_bucket": round(self.read_ms_per_bucket, 4),
                "clear_fixed_ms": round(self.clear_fixed_ms, 2),
                "clear_ms_per_bucket": round(self.clear_ms_per_bucket, 4),
                "probe_ms_per_bucket": round(self.probe_ms_per_bucket, 4),
                "prep_ms": round(self.prep_ms, 2), "select_ms": round(self.select_ms, 2),
                "post_ms": round(self.post_ms, 2), "margin_ms": round(self.margin_ms, 2),
                "windows_seen": self.windows_seen}


def report_aggregates(reports: List[Dict[str, object]], window_sec: float) -> Dict[str, object]:
    """The REPORT_ZERO columns of one window from its CPU reports (one report per
    new bucket, carrying the 5-tuple). No register is read for these."""
    agg: Dict[str, object] = dict(REPORT_ZERO)
    n = len(reports)
    agg["rep_new_flows"] = n
    agg["rep_new_flows_per_sec"] = safe_div(n, window_sec)
    if n == 0:
        return agg
    src_ips = collections.Counter(str(r.get("src_ip")) for r in reports)
    dst_ips = collections.Counter(str(r.get("dst_ip")) for r in reports)
    dst_ports = collections.Counter(safe_int(r.get("dport")) for r in reports)
    dst_ip_ports = collections.Counter((str(r.get("dst_ip")), safe_int(r.get("dport"))) for r in reports)
    agg["rep_distinct_src_ips"] = len(src_ips)
    agg["rep_distinct_dst_ips"] = len(dst_ips)
    agg["rep_distinct_dst_ports"] = len(dst_ports)
    agg["rep_tcp_share"] = safe_div(sum(1 for r in reports if safe_int(r.get("proto")) == 6), n)
    agg["rep_max_flows_to_one_dst"] = max(dst_ips.values())
    agg["rep_max_flows_to_one_dst_port"] = max(dst_ip_ports.values())
    return agg


def select_within_budget(active: List[int], last_seen: Dict[int, int], allowed: int) -> "tuple[List[int], List[int]]":
    """The buckets to read when only `allowed` of the active ones fit: the most
    recently reported or changed first (their deltas describe the current
    window), ties by index. Returns (read, skipped), both sorted by index."""
    if allowed >= len(active):
        return sorted(active), []
    if allowed <= 0:
        return [], sorted(active)
    ranked = sorted(active, key=lambda idx: (-last_seen.get(idx, -1), idx))
    chosen = set(ranked[:allowed])
    return sorted(chosen), sorted(idx for idx in active if idx not in chosen)


def run_p4_forwarder(
    forwarder_path: str,
    int_port: int,
    ext_port: int,
    report_port: int,
    mirror_sid: int,
    switch_ssh: Optional[str] = None,
    attempts: int = 3,
) -> None:
    """Retried: the first bfshell session right after BFRT starts listening can
    fail ("Can't startup clish")."""
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
    for attempt in range(1, attempts + 1):
        try:
            subprocess.run(cmd, check=True)
            return
        except subprocess.CalledProcessError:
            if attempt == attempts:
                raise
            print(f"[WARN] programming forwarding failed (attempt {attempt} of {attempts}); retrying")
            time.sleep(5.0)


def run_p4_register_reset(resetter_path: str, switch_ssh: Optional[str] = None) -> None:
    """Clear all detector registers (reset_registers.py) before the run.

    A bucket left from an earlier run keeps dir_valid = 1, so a new flow that
    lands in it sends no CPU report and is never read; reg_newconn_dst would
    return its count since the switch started."""
    cmd = [sys.executable, resetter_path]
    if switch_ssh:
        cmd += ["--ssh", switch_ssh]
    started = time.time()
    subprocess.run(cmd, check=True)
    print(f"[INFO] P4 registers cleared in {time.time() - started:.1f} s")


def wait_for_late_reports(take_after: Callable[[float], List[Dict[str, object]]], since: float, clk: Any,
                          quiet_s: float = LATE_REPORT_QUIET_S,
                          max_s: float = LATE_REPORT_MAX_S) -> List[Dict[str, object]]:
    """The CPU reports received at or after `since` (the end of the last window),
    once none has arrived for quiet_s seconds, or after max_s seconds."""
    start = clk.time()
    count, changed = -1, start
    while True:
        late = take_after(since)
        now = clk.time()
        if len(late) != count:
            count, changed = len(late), now
        if now - changed >= quiet_s or now - start >= max_s:
            return late
        clk.sleep(0.05)


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
    read_timeout: Optional[float] = None,
    read_retries: int = 0,
    on_window: Optional[Callable[[Dict[str, object]], None]] = None,
    read_fn: Optional[Callable[..., Dict[str, Any]]] = None,
    timing_log: Optional[Callable[..., None]] = None,
    read_budget_frac: float = 0.0,
    max_read_buckets: int = 0,
    max_dst_reads: int = 0,
    cost_model: Optional[ReadCostModel] = None,
    clear_expired: bool = False,
    clear_budget_frac: float = 0.5,
    clock: Any = None,
    dormant_reads: bool = False,
    dormant_probe: bool = False,
    global_totals: bool = False,
    totals_cut: str = "boundary",
    max_windows: int = 0,
    stop_fn: Optional[Callable[[], None]] = None,
) -> List[Dict[str, object]]:
    """Per window: the CPU-reported bucket indexes, and the P4 registers of all
    active indexes read at the end of that window.

    Read budget (read_budget_frac > 0): a read may take at most that fraction of
    the window, and never more than the time left until the next window
    boundary minus the collector's measured post-read work (so a read that
    started late shrinks instead of pushing every later window; the deadline
    rule). From the cost model's running estimate (ReadCostModel, updated from
    every window's measured timing; it counts the flow bucket reads, the
    reg_newconn_dst reads and the clears) the collector computes how many
    buckets fit and, when the active set is larger, reads only the most
    recently reported or changed ones (select_within_budget); the rest are
    skipped and counted (window["net_buckets_skipped"], window["overload"]).
    max_read_buckets caps the buckets read per window regardless of the budget;
    max_dst_reads caps the reg_newconn_dst buckets read (the most reported
    destinations first). Every window also carries report_aggregates(): the
    new-flow rate, destination fan-out and protocol mix from the reports alone,
    which need no register read and so survive an overload. With the budget
    off (the default) the behaviour is unchanged.

    clear_expired: a bucket that leaves the active set (active_ttl_windows after
    its last report or change) without having been cleared is still occupied on
    the switch, and an occupied bucket sends no CPU report for the next flow
    that lands in it (RUNBOOK section 12.2: a flood left 46% of the table
    occupied and the next capture lost half of its flows). With clear_expired
    those buckets are cleared unconditionally in a later read, oldest first, at
    most clear_budget_frac of the window's allowance (after the fixed cost) per
    window; the rest wait (window["report_aggregates"]["net_clear_backlog"]).
    A bucket whose clear fails CLEAR_ATTEMPTS times is given up; one that
    reports again meanwhile is live and leaves the queue.

    dormant_reads (RUNBOOK 19.9, the dataset profile): in the dataset's
    extractor a flow never ends, so a bucket that leaves the active set is not
    cleared but kept dormant, and read again, round robin, with whatever the
    allowance leaves after the active set (never counted as overload). A
    dormant bucket whose packet count changed is active again from that window,
    with its registers intact, as the dataset's flow would be. clear_expired is
    not applied during the run; every bucket still tracked is cleared at the
    end of the run. Each window records "active_after_read_indexes" (the active
    set once this read's changes are known; NetSummarizer counts those rows),
    "dormant_count" and "dormant_read_indexes".

    dormant_probe (with dormant_reads and a read_fn that takes probe=, the
    batched reader): instead of reading a few dormant buckets in full, round
    robin, every window probes as many as the allowance fits, oldest probed
    first (usually all of them): only reg_pkts, one register entity per bucket,
    from the window's snapshot, and the reader reads in full, in the same window,
    those whose count changed. A reused 5-tuple lands in its occupied dormant
    bucket and sends no CPU report; with round-robin reads its packets counted
    only when the bucket's turn came, windows later (PC1.md part 4b). A few
    buckets' full reads (DORMANT_RESUME_RESERVE) are kept free for the resumed
    ones, and the reader reads in full only as many changed buckets as the
    allowance left after the probes fits (probe_max_full); the others are
    active again and read with the active set from the next window, under its
    budget (a fan-out flood changes thousands of occupied dormant buckets at
    once: read all in full, the reads overran the window, PC1.md part 4c). Each
    window also records "dormant_probed_count", "dormant_resumed_indexes" and
    "dormant_deferred_indexes".

    global_totals (the test build perf/variants/gtot and the batched reader):
    every read also returns the seven one-entry totals (window["totals"]);
    NetSummarizer(global_totals=True) takes the window's packet, byte and flag
    totals from their differences. totals_cut "boundary": a request of their
    own right after the boundary, before the reports are taken and the read is
    planned (the reader reads them from hardware, no sync: their cut ~2 ms after
    the boundary, PC1.md part 4e); if it fails, the window's read takes them.
    "read": in the window's read, from hardware before the flow registers'
    sync (cut after the reports' processing: ~2 ms calm, ~35 ms under a flood).
    "snapshot": synced with the flow registers, last in the ~31 ms sync (part
    4d), so a window's first ~30 ms or more counted in the window before.

    A program without reg_newconn_dst (the deployed basic_fix) answers its reads
    with an error and no rows: from then on no destination bucket is requested
    (nor counted as skipped), and the cost model learns only from the rows read.

    max_windows: the run has exactly that many windows whether or not the
    scenario has ended (the dataset's observation was fixed: 40 windows of
    0.5 s). After the last window's read, stop_fn() stops the scenario, as the
    runner stopped a program at its timeout; the teardown packets of the dying
    program then fall outside the run, as they did in the dataset.

    The registers are read by read_fn(active_indexes, window, snapshot=...,
    clear_if_unchanged=..., dst_indexes=..., [clear_indexes=...]) -> payload,
    if given (the batched gRPC reader), else by the legacy reader script at
    reader_path; clear_indexes is passed only when there is something to clear
    unconditionally. timing_log, if given, receives every window's payload and
    read times (make_timing_logger). clock (tests) replaces the time module.

    A failed register read is retried read_retries times (each attempt
    limited to read_timeout seconds) before P4ReadError ends the collection.
    on_window, if given, receives every window as soon as it is read.

    The collector keeps capturing reports in the background while the
    registers are read, so a read does not open a gap in the report capture.
    A bucket reports only once, when it is first used, so an index stays
    active while its packet counter keeps changing, and for active_ttl_windows
    windows after its last report or change.

    With clear_idle_windows > 0, a bucket whose counter has not changed for
    that many consecutive reads is cleared right after the read (only if it is
    still unchanged then). It is empty again, so the next flow that lands in it
    sends a new report instead of being merged silently into the old counters.

    Each TCP report also names the reg_newconn_dst bucket of its (src, dst,
    dport) key. Those buckets stay active the same way, while their count
    changes; they are never cleared.
    """
    windows: List[Dict[str, object]] = []
    active_idx_last_seen: Dict[int, int] = {}
    last_pkts: Dict[int, int] = {}
    idle_reads: Dict[int, int] = {}
    active_dst_last_seen: Dict[int, int] = {}
    last_new_conn: Dict[int, int] = {}
    dst_report_counts: Dict[int, int] = {}
    cost = cost_model if cost_model is not None else ReadCostModel()
    budget_ms = read_budget_frac * window_sec * 1000.0 if read_budget_frac > 0 else None
    overruns = 0
    clk = clock if clock is not None else time
    # expired buckets waiting for an unconditional clear, oldest first -> failed attempts
    pending_clear: "collections.OrderedDict[int, int]" = collections.OrderedDict()
    expired_total = 0
    expired_cleared_total = 0
    dropped_clears = 0
    # dormant_reads: buckets that left the active set, in round-robin order (oldest read first)
    dormant: "collections.OrderedDict[int, None]" = collections.OrderedDict()
    dormant_resumed = 0
    dormant_reads_total = 0
    dormant_max = 0
    if dormant_probe and (not dormant_reads or read_fn is None):
        print("[WARN] --dormant-probe needs --dormant-reads and the batched reader; dormant buckets are read "
              "round robin")
        dormant_probe = False
    dormant_probes_total = 0
    dormant_probe_resumed_total = 0
    dormant_deferred_total = 0
    dst_missing = False
    if global_totals and read_fn is None:
        print("[WARN] --global-totals needs the batched reader; the window totals come from the buckets read")
        global_totals = False

    w = 0
    proc_done = False
    proc_end_rel: Optional[float] = None

    while True:
        win_start_rel = w * window_sec
        win_end_rel = (w + 1) * window_sec

        win_start_abs = global_t0 + win_start_rel
        win_end_abs = global_t0 + win_end_rel

        now = clk.time()
        if now < win_end_abs:
            clk.sleep(win_end_abs - now)
        elif now > win_end_abs + 1.0:
            print(f"[WARN] window {w}: register read of the previous window overran by "
                  f"{now - win_end_abs:.1f} s")
        t_iter_start = clk.time()

        boundary_totals: Optional[Dict[str, Any]] = None
        boundary_timing: Dict[str, Any] = {}
        if global_totals and totals_cut == "boundary":
            # The totals' cut right after the boundary (PC1.md part 4e): a totals-only request, before the reports
            # are taken. If it fails (after read_fn's retries), the window's read takes them.
            try:
                # (global_totals is off without the batched reader, so read_fn is set here)
                bp = read_fn([], w, snapshot=snapshot, clear_if_unchanged={}, dst_indexes=[], totals=True)
                if gtot_keys(bp.get("totals")) is not None:
                    boundary_totals = bp["totals"]
                    boundary_timing = {k: v for k, v in (bp.get("timing") or {}).items() if k in TOTALS_CLOCK_KEYS}
                else:
                    print(f"[WARN] window {w}: the boundary totals read returned no totals "
                          f"({bp.get('errors')}); the window's read takes them")
            except Exception as error:
                print(f"[WARN] window {w}: the boundary totals read failed ({describe_failure(error)}); "
                      f"the window's read takes them")

        reports = collector.take(win_start_abs, win_end_abs)
        idxs = sorted({safe_int(r["idx"]) for r in reports})
        # The reg_newconn_dst bucket of every TCP report. listen_cpu_reports computes it in the capture
        # thread as the report arrives ("dst_idx"); it is computed here only for reports without it
        # (RUNBOOK sections 12.2 and 13.3: up to ~3,000 reports per window under a flood).
        tcp_dst = []
        for r in reports:
            if safe_int(r["proto"]) == 6:
                d = r.get("dst_idx")
                if d is None:
                    d = compute_newconn_dst_index(r["src_ip"], r["dst_ip"], safe_int(r["dport"]), 6)
                tcp_dst.append(safe_int(d))
        dst_idxs = sorted(set(tcp_dst))
        mismatches = sum(1 for r in reports if r["idx_source"] == "report" and r["idx"] != r["idx_computed"])
        if mismatches:
            print(f"[WARN] window {w}: {mismatches} report(s) carry an index that flow_index.py "
                  f"does not reproduce; the data plane and flow_index.py disagree")

        for idx in idxs:
            active_idx_last_seen[idx] = w
            pending_clear.pop(idx, None)     # it reports again, so it is live: not to be cleared
            dormant.pop(idx, None)
        expired = sorted(
            idx for idx, last_seen in active_idx_last_seen.items()
            if (w - last_seen) > active_ttl_windows
        )
        active_idxs = sorted(
            idx for idx, last_seen in active_idx_last_seen.items()
            if (w - last_seen) <= active_ttl_windows
        )
        active_idx_last_seen = {idx: active_idx_last_seen[idx] for idx in active_idxs}
        # A bucket cleared by the idle rule left the active set at its clear; what
        # expires here was read too seldom (or never) to be cleared and is still
        # occupied on the switch.
        expired_total += len(expired)
        if dormant_reads:
            for idx in expired:
                dormant.setdefault(idx, None)
        elif clear_expired:
            for idx in expired:
                pending_clear.setdefault(idx, 0)

        for d in tcp_dst:
            dst_report_counts[d] = dst_report_counts.get(d, 0) + 1
        for idx in dst_idxs:
            active_dst_last_seen[idx] = w
        active_dst_idxs = sorted(
            idx for idx, last_seen in active_dst_last_seen.items()
            if (w - last_seen) <= active_ttl_windows
        )
        active_dst_last_seen = {idx: active_dst_last_seen[idx] for idx in active_dst_idxs}
        dst_report_counts = {idx: dst_report_counts[idx] for idx in active_dst_idxs if idx in dst_report_counts}

        # The allowance of this window's read: the budget, or the time left until
        # the next window boundary minus the measured post-read work when the
        # read is decided late (the previous read overran, or the reports took
        # long to process). A late window shrinks its own read; it does not
        # delay the next one.
        agg = report_aggregates(reports, window_sec)
        t_decide = clk.time()
        late_ms = max(0.0, (t_decide - win_end_abs) * 1000.0)
        allow_ms: Optional[float] = None
        if budget_ms is not None:
            # The time left until the next window boundary, minus the measured work between this
            # decision and the read (select_ms) and after the read (post_ms).
            time_left_ms = ((win_end_abs + window_sec - t_decide) * 1000.0 - cost.select_ms - cost.post_ms
                            - DEADLINE_SAFETY_MS)
            allow_ms = max(0.0, min(budget_ms, time_left_ms))
        if max_dst_reads > 0 and len(active_dst_idxs) > max_dst_reads:
            ranked_dst = sorted(active_dst_idxs, key=lambda idx: (-dst_report_counts.get(idx, 0),
                                                                  -active_dst_last_seen.get(idx, -1), idx))
            read_dst_idxs = sorted(ranked_dst[:max_dst_reads])
        else:
            read_dst_idxs = active_dst_idxs
        if dst_missing:
            read_dst_idxs = []   # the program has no reg_newconn_dst: nothing to read, and no overload
        # Expired buckets cleared in this read, oldest first, within their share
        # of the allowance that is left after the fixed cost.
        clear_now: List[int] = []
        if pending_clear:
            n_clear = len(pending_clear)
            if allow_ms is not None:
                n_clear = min(n_clear, cost.clears_within(max(0.0, allow_ms - cost.fixed_ms) * clear_budget_frac))
            clear_now = list(pending_clear)[:n_clear]
        idle_estimate = 0
        if clear_idle_windows > 0:
            idle_estimate = sum(1 for idx in active_idxs
                                if idx in last_pkts and idle_reads.get(idx, 0) + 1 >= clear_idle_windows)
        allowed = len(active_idxs)
        if allow_ms is not None:
            allowed = min(allowed, cost.buckets_within(allow_ms, n_cleared=len(clear_now) + idle_estimate,
                                                       n_dst=len(read_dst_idxs)))
        if max_read_buckets > 0:
            allowed = min(allowed, max_read_buckets)
        read_idxs, skipped_idxs = select_within_budget(active_idxs, active_idx_last_seen, allowed)
        if skipped_idxs and not windows:
            limit = f"read allowance {allow_ms:.0f} ms" if allow_ms is not None else f"cap of {max_read_buckets} reads"
            print(f"[WARN] window {w}: the {limit} fits {allowed} of {len(active_idxs)} active buckets "
                  f"(cost estimate {cost.as_dict()}); the rest are skipped and counted")

        # Dormant buckets read with what the allowance leaves after the active set, oldest read first.
        dormant_now: List[int] = []
        probe_now: Dict[int, int] = {}
        probe_max_full: Optional[int] = None
        if dormant_probe and dormant and not skipped_idxs:
            # Probe reg_pkts of as many dormant buckets as fit, oldest probed first; the reader reads the
            # changed ones in full, as many as the allowance still fits, so a resumed flow counts in this
            # window; the other changed ones are deferred.
            n_probe = len(dormant)
            if allow_ms is not None:
                # the allowance after the active reads (the Read RPCs' fixed part counted even without an
                # active bucket: the changed dormant ones are read the same way)
                avail_ms = (allow_ms - cost.margin_ms
                            - cost.predict_ms(len(read_idxs), len(clear_now) + idle_estimate, len(read_dst_idxs))
                            - (cost.read_fixed_ms if not read_idxs else 0.0))
                n_probe = max(0, min(n_probe, cost.probes_within(
                    avail_ms - DORMANT_RESUME_RESERVE * cost.read_ms_per_bucket)))
                left_ms = avail_ms - n_probe * cost.probe_ms_per_bucket
                probe_max_full = (max(0, int(left_ms // cost.read_ms_per_bucket)) if cost.read_ms_per_bucket > 0
                                  else DORMANT_RESUME_RESERVE)
            probe_list = list(dormant)[:n_probe]
            for idx in probe_list:
                dormant.move_to_end(idx)
            # a bucket never read has no known count: -1 differs from any, so it is read in full
            probe_now = {idx: last_pkts.get(idx, -1) for idx in probe_list}
            dormant_probes_total += len(probe_now)
        elif dormant_reads and dormant and not skipped_idxs:
            n_dormant = len(dormant)
            if allow_ms is not None:
                fit = cost.buckets_within(allow_ms, n_cleared=len(clear_now) + idle_estimate, n_dst=len(read_dst_idxs))
                n_dormant = max(0, min(n_dormant, fit - len(read_idxs)))
            if max_read_buckets > 0:
                n_dormant = max(0, min(n_dormant, max_read_buckets - len(read_idxs)))
            dormant_now = list(dormant)[:n_dormant]
            for idx in dormant_now:
                dormant.move_to_end(idx)
            dormant_reads_total += len(dormant_now)
        dormant_max = max(dormant_max, len(dormant))
        request_idxs = sorted(set(read_idxs) | set(dormant_now))

        # Buckets that would complete clear_idle_windows idle reads with this read.
        clear_candidates = {}
        if clear_idle_windows > 0:
            clear_candidates = {
                idx: last_pkts[idx] for idx in read_idxs
                if idx in last_pkts and idle_reads.get(idx, 0) + 1 >= clear_idle_windows
            }

        extra: Dict[str, Any] = {"clear_indexes": clear_now} if clear_now else {}
        if probe_now:
            extra["probe"] = probe_now
            if probe_max_full is not None:
                extra["probe_max_full"] = probe_max_full
        if global_totals and boundary_totals is None:
            extra["totals"] = "snapshot" if totals_cut == "snapshot" else True
        read_start = clk.time()
        if read_fn is None:
            payload = read_p4_with_retries(reader_path, request_idxs, w, retries=read_retries, timeout=read_timeout,
                                           switch_ssh=switch_ssh, snapshot=snapshot,
                                           clear_if_unchanged=clear_candidates, dst_indexes=read_dst_idxs, **extra)
        else:
            payload = read_fn(request_idxs, w, snapshot=snapshot, clear_if_unchanged=clear_candidates,
                              dst_indexes=read_dst_idxs, **extra)
        read_end = clk.time()
        if boundary_totals is not None and isinstance(payload.get("timing"), dict):
            payload["timing"].update(boundary_timing)     # the totals' cut, for the timing log
        resumed_now = sorted(safe_int(i) for i in (payload.get("resumed") or []))
        deferred_now = sorted(safe_int(i) for i in (payload.get("deferred") or []))
        dormant_probe_resumed_total += len(resumed_now)
        dormant_deferred_total += len(deferred_now)
        dst_rows_read = len(payload.get("dst_rows") or [])
        if (read_dst_idxs and not dst_rows_read
                and any("reg_newconn_dst" in str(e) and "missing" in str(e).lower() for e in (payload.get("errors") or []))):
            dst_missing = True
            print("[INFO] the program has no reg_newconn_dst: destination buckets are not read from now on")
        if timing_log is not None:
            if dormant_reads:
                fields = {"active_read": len(read_idxs), "dormant": len(dormant), "dormant_read": len(dormant_now)}
                if dormant_probe:
                    fields.update(dormant_probed=len(probe_now), dormant_probe_resumed=len(resumed_now),
                                  dormant_probe_deferred=len(deferred_now))
                timing_log(w, payload, read_start, read_end, len(request_idxs), len(read_dst_idxs),
                           window_end=win_end_abs, extra=fields)
            else:
                timing_log(w, payload, read_start, read_end, len(request_idxs), len(read_dst_idxs), window_end=win_end_abs)
        wall_ms = (read_end - read_start) * 1000.0
        cost.update(len(request_idxs) + len(resumed_now), len(payload.get("cleared") or []),
                    payload_timing_ms(payload, wall_ms), n_dst=dst_rows_read, n_probe=len(probe_now))
        overrun = read_end > win_end_abs + window_sec
        dst_skipped = 0 if dst_missing else len(active_dst_idxs) - len(read_dst_idxs)
        overruns += int(overrun)
        agg.update({
            "net_overload": int(bool(skipped_idxs) or dst_skipped > 0 or len(clear_now) < len(pending_clear)),
            "net_buckets_active": len(active_idxs),
            "net_buckets_read": len(read_idxs),
            "net_buckets_skipped": len(skipped_idxs),
            "net_dst_buckets_skipped": dst_skipped,
            "net_read_budget_ms": round(budget_ms, 1) if budget_ms is not None else 0.0,
            "net_read_allow_ms": round(allow_ms, 1) if allow_ms is not None else 0.0,
            "net_read_late_ms": round(late_ms, 1),
            "net_read_overrun": int(overrun),
        })

        for row in payload.get("rows", []):
            idx = safe_int(row.get("idx"))
            pkts = safe_int(row.get("pkts"))
            if last_pkts.get(idx) != pkts:
                active_idx_last_seen[idx] = w
                idle_reads[idx] = 0
                if idx in dormant:          # its flow resumed: active again, registers intact
                    del dormant[idx]
                    dormant_resumed += 1
            else:
                idle_reads[idx] = idle_reads.get(idx, 0) + 1
            last_pkts[idx] = pkts
        # Dormant buckets the probe found changed but could not read in full within the allowance: active
        # again (they are), read with the active set from the next window on, under its budget.
        for idx in deferred_now:
            active_idx_last_seen[idx] = w
            if idx in dormant:
                del dormant[idx]
                dormant_resumed += 1
        # The active set once this read's changes are known (before this read's clears take effect:
        # a bucket cleared after this read still counts in this window).
        active_after_read = sorted(active_idx_last_seen)

        for row in payload.get("dst_rows", []):
            idx = safe_int(row.get("idx"))
            new_conn = safe_int(row.get("new_conn"))
            if last_new_conn.get(idx) != new_conn:
                active_dst_last_seen[idx] = w
            last_new_conn[idx] = new_conn

        cleared = sorted(safe_int(x) for x in payload.get("cleared", []))
        cleared_set = set(cleared)
        for idx in cleared:
            active_idx_last_seen.pop(idx, None)
            last_pkts.pop(idx, None)
            idle_reads.pop(idx, None)
        expired_cleared = [idx for idx in clear_now if idx in cleared_set]
        expired_cleared_total += len(expired_cleared)
        for idx in clear_now:
            if idx in cleared_set:
                pending_clear.pop(idx, None)
            else:
                pending_clear[idx] = pending_clear.get(idx, 0) + 1
                if pending_clear[idx] >= CLEAR_ATTEMPTS:
                    pending_clear.pop(idx, None)
                    dropped_clears += 1
        agg["net_buckets_cleared"] = len(cleared)
        agg["net_clear_backlog"] = len(pending_clear)

        windows.append({
            "net_window_id": w,
            "net_window_start_sec": round(win_start_rel, 3),
            "net_window_end_sec": round(win_end_rel, 3),
            "net_window_duration_sec": round(window_sec, 3),
            "indexes": idxs,
            "active_indexes": active_idxs,
            "read_indexes": read_idxs,
            "skipped_count": len(skipped_idxs),
            "overload": bool(agg["net_overload"]),
            "report_count": len(reports),
            # [idx, proto, src, sport, dst, dport] of each report: the flow of each newly reported bucket,
            # for the socket-level join (--sockowner, sockjoin.socket_join_windows)
            "report_keys": [[safe_int(r.get("idx")), safe_int(r.get("proto")), str(r.get("src_ip")),
                             safe_int(r.get("sport")), str(r.get("dst_ip")), safe_int(r.get("dport"))]
                            for r in reports],
            "report_aggregates": agg,
            "index_mismatches": mismatches,
            "rows": payload.get("rows", []),
            "dst_indexes": dst_idxs,
            "active_dst_indexes": active_dst_idxs,
            "read_dst_indexes": read_dst_idxs,
            "dst_rows": payload.get("dst_rows", []),
            "cleared_indexes": cleared,
            "expired_indexes": expired,
            "expired_cleared_indexes": expired_cleared,
            "active_after_read_indexes": active_after_read,
            "dormant_count": len(dormant),
            "dormant_read_indexes": sorted(dormant_now),
            "dormant_probed_count": len(probe_now),
            "dormant_resumed_indexes": resumed_now,
            "dormant_deferred_indexes": deferred_now,
            "totals": (boundary_totals if boundary_totals is not None else payload.get("totals"))
                      if global_totals else None,
            "totals_cut": (("boundary" if boundary_totals is not None else
                            ("snapshot" if totals_cut == "snapshot" else "read")) if global_totals else None),
            "p4_snapshot": payload.get("snapshot"),
            "p4_read_start_sec": round(read_start - global_t0, 3),
            "p4_read_sec": round(read_end - read_start, 3),
            "p4_read_overrun": overrun,
        })
        if on_window is not None:
            on_window(windows[-1])

        if not proc_done and proc.poll() is not None:
            proc_done = True
            proc_end_rel = clk.time() - global_t0

        post_end = clk.time()
        cost.update_processing((t_decide - t_iter_start) * 1000.0, (post_end - read_end) * 1000.0,
                               select_ms=(read_start - t_decide) * 1000.0)

        if max_windows:
            if w + 1 >= max_windows:
                # The run has its windows. The program is stopped now, after the last read, as the
                # dataset's runner stopped it at its timeout; its teardown packets fall outside the run.
                if stop_fn is not None:
                    stop_fn()
                break
        elif proc_done and proc_end_rel is not None:
            if win_end_rel >= proc_end_rel + drain_seconds:
                break

        w += 1

    # End of the run: with clear_expired, clear what the collector still tracks as occupied on the
    # switch (the last windows' active set and the clear backlog), so that the next run, or traffic
    # after the collector stops, finds those buckets empty. RUNBOOK section 13.2: after the flood,
    # 5,429 buckets stayed occupied and the next capture without a register reset lost 8.6% of its
    # flows. The run's windows are complete at this point, so a failed clear only leaves them occupied.
    if (clear_expired or dormant_reads) and windows:
        # Reports that arrived after the last window took its reports: no window has seen their
        # buckets (RUNBOOK 16: the last 0.1 s of a 2,000 packets/s flood left 176 of them occupied).
        # A collector without take_after (the tests' fakes) skips this.
        late_reports: List[Dict[str, object]] = []
        take_after = getattr(collector, "take_after", None)
        if take_after is not None:
            late_reports = wait_for_late_reports(take_after, win_end_abs, clk)
        late_idxs = {safe_int(r["idx"]) for r in late_reports}
        leftover = sorted(set(active_idx_last_seen) | set(pending_clear) | set(dormant) | late_idxs)
        final_cleared: List[int] = []
        if leftover:
            t_clear = clk.time()
            try:
                if read_fn is None:
                    payload = read_p4_with_retries(reader_path, [], w + 1, retries=read_retries, timeout=read_timeout,
                                                   switch_ssh=switch_ssh, snapshot=snapshot, clear_if_unchanged={},
                                                   dst_indexes=[], clear_indexes=leftover)
                else:
                    payload = read_fn([], w + 1, snapshot=snapshot, clear_if_unchanged={}, dst_indexes=[],
                                      clear_indexes=leftover)
                final_cleared = sorted(safe_int(x) for x in payload.get("cleared", []))
                print(f"[INFO] end of run: cleared {len(final_cleared)} of the {len(leftover)} buckets still occupied "
                      f"(the last windows' active set, {len(dormant)} dormant, the clear backlog and {len(late_idxs)} "
                      f"bucket(s) of the {len(late_reports)} report(s) that arrived after the last window) in "
                      f"{(clk.time() - t_clear) * 1000.0:.0f} ms")
            except (P4ReadError, RuntimeError, OSError, ValueError) as error:
                print(f"[WARN] end of run: clearing the {len(leftover)} occupied buckets failed ({error}); they stay "
                      f"occupied until the next register reset")
        windows[-1]["final_cleared_indexes"] = final_cleared
        windows[-1]["late_report_indexes"] = sorted(late_idxs)

    if overruns:
        print(f"[WARN] {overruns} of {len(windows)} register reads ended after the next window boundary; "
              f"use a longer window or a read budget (--read-budget-frac)")
    skipped_total = sum(int(win["skipped_count"]) for win in windows)
    if skipped_total:
        print(f"[INFO] read budget: {skipped_total} bucket reads skipped over {sum(1 for win in windows if win['overload'])} "
              f"overloaded window(s); final cost estimate {cost.as_dict()}")
    if dormant_reads:
        how = (f"{dormant_probes_total} dormant probes (reg_pkts), {dormant_probe_resumed_total} of them changed and "
               f"read in full, {dormant_deferred_total} changed and deferred to the active set"
               if dormant_probe else f"{dormant_reads_total} dormant reads")
        print(f"[INFO] dormant buckets: {expired_total} left the active set and were kept, at most {dormant_max} at a "
              f"time; {how} over {len(windows)} windows; {dormant_resumed} resumed "
              f"and counted again with their registers intact; all cleared at the end of the run")
    elif expired_total:
        print(f"[INFO] {expired_total} bucket(s) left the active set without an idle clear; "
              + (f"{expired_cleared_total} cleared unconditionally, {len(pending_clear)} still waiting, "
                 f"{dropped_clears} given up after {CLEAR_ATTEMPTS} failed clears"
                 if clear_expired else "they stay occupied on the switch until the next register reset "
                 "(--clear-expired 1 clears them)"))
    return windows


# ============================================================
# P4 SUMMARY BUILDER
# ============================================================

# --switch-program exact: the columns a window gets besides the model's 29 features (window_features.py)
EXACT_EXTRA_KEYS = ["net_untracked_pkts", "net_window_lost", "net_unclocked_pkts", "net_rejected_markers"]


def exact_summary(feats: Dict[str, Any], duration_unit: str = "s") -> Dict[str, Any]:
    """A window's network columns from window_features.py: the collector's NET_ZERO columns with the
    switch's values, and the exact build's own checks."""
    out = dict(NET_ZERO)
    for k in NET_ZERO:
        if k in feats:
            out[k] = feats[k]
    if duration_unit == "ns":
        out["net_flow_duration_mean"] = feats["net_flow_duration_mean"] * 1e9
        out["net_flow_duration_max"] = feats["net_flow_duration_max"] * 1e9
    for k in EXACT_EXTRA_KEYS:
        out[k] = int(feats.get(k, 0))
    return out


def start_window_timer(reader: Any, first_tick_at: float, window_sec: float, clock: Any = None) -> Dict[str, Any]:
    """--window-markers timer: start the generators' timers one window before first_tick_at (this host's clock),
    so that their first tick, which starts the switch's epoch 1, falls on the start of the collector's window 0
    (as the first CPU marker does). The generators are configured first ("prepare", about 20 ms); at the start
    time only the enables go out, through the reader's pipe and one gRPC write per pipe, so the ticks come a few ms
    after the boundaries. They then drift with the switch's clock against this host's (15-40 ppm on the Wedge,
    PC1.md parts 6d-6e)."""
    clk = clock if clock is not None else time
    r = reader.request({"cmd": "timer", "prepare": True, "period_ns": int(round(window_sec * 1e9))})
    if "error" in r:
        raise P4ReadError(f"window timer: {r['error']}")
    delay = first_tick_at - window_sec - clk.time()
    if delay > 0:
        clk.sleep(delay)
    r = reader.request({"cmd": "timer", "enable": True})
    if "error" in r:
        raise P4ReadError(f"window timer: {r['error']}")
    return r


def collect_windows_exact(
    reader: Any,
    proc: subprocess.Popen,
    window_sec: float,
    global_t0: float,
    markers: str = "cpu",
    on_window: Optional[Callable[[Dict[str, object]], None]] = None,
    max_windows: int = 0,
    stop_fn: Optional[Callable[[], None]] = None,
    drain_seconds: float = 0.0,
    read_timeout: float = 5.0,
    header: int = ETHERNET_HEADER_BYTES,
    duration_unit: str = "s",
    timing_path: Optional[str] = None,
    clock: Any = None,
) -> List[Dict[str, object]]:
    """The windows of perf/variants/exact (--switch-program exact). Collector window w is the switch's
    epoch w + 1. markers "cpu": the reader sends the window markers from the switch's CPU port, epoch 1 at
    the start and epoch w + 2 at the end of window w, so the switch's windows are the collector's (cut
    when the marker enters the pipeline, ~1 ms after the boundary, the same for every register). markers
    "inband": the scenario sends them in order with its traffic (live_test/replay_absolute.py --markers in
    a replay); the collector only reads. "timer": every pipe's packet generator ticks the clock, started by
    start_window_timer() so that its first tick starts epoch 1 at the start of window 0; the collector only
    reads, as with in-band markers. After each boundary the reader waits until window w has ended on
    the switch (at most read_timeout s), reads it and clears it; window_features.py gives its features. With
    in-band markers the reader follows the switch's clock itself ("follow") and reads each window as soon as
    it ends, so a collector slowed down by its host (a flood replay on PC1's two CPUs) cannot read a window
    after the window after the next has started in its bank. No CPU report, no bucket and no read budget:
    every window is complete whatever the traffic.

    max_windows: exactly that many windows, then stop_fn() (as collect_windows_live). Otherwise windows
    continue until the scenario has ended and drain_seconds have passed. reader.request(dict) -> dict
    (WindowReaderProcess; tests pass a fake). timing_path: one JSON line per window (the reader's reply
    without its registers)."""
    sys.path.insert(0, str(Path(__file__).resolve().parent / "thesis-hybrid-ebpf-p4" / "python"))
    from window_features import WindowFeatures
    clk = clock if clock is not None else time
    wf = WindowFeatures(window_sec=window_sec, header=header)
    timing = open(timing_path, "a") if timing_path else None
    windows: List[Dict[str, object]] = []

    def mark(epoch: int) -> Dict[str, Any]:
        r = reader.request({"cmd": "mark", "epoch": epoch})
        if "error" in r:
            raise P4ReadError(f"window marker {epoch}: {r['error']}")
        return r

    first_mark = None
    if markers == "cpu":
        first_mark = mark(1)
    else:
        r = reader.request({"cmd": "follow"})
        if "error" in r:
            raise P4ReadError(f"window reader follow: {r['error']}")
    w = 0
    ended_at: Optional[float] = None
    try:
        while True:
            boundary = global_t0 + (w + 1) * window_sec
            delay = boundary - clk.time()
            if delay > 0:
                clk.sleep(delay)
            marked = mark(w + 2) if markers == "cpu" else None
            line = reader.request({"cmd": "read", "epoch": w + 1, "timeout": read_timeout})
            if "error" in line:
                hint = (" (no tick: is the program built with -DTIMER_LOCAL_PORT=68?)"
                        if markers == "timer" and w == 0 else "")
                raise P4ReadError(f"window {w}: {line['error']}{hint}")
            feats = wf.add(line)
            win: Dict[str, object] = {
                "net_window_id": w, "net_window_start_sec": w * window_sec,
                "net_window_end_sec": (w + 1) * window_sec, "net_window_duration_sec": window_sec,
                "indexes": [], "report_count": 0, "index_mismatches": 0, "cleared_indexes": [],
                "report_aggregates": dict(REPORT_ZERO), "exact_features": exact_summary(feats, duration_unit),
            }
            windows.append(win)
            if timing is not None:
                rec = {k: v for k, v in line.items() if k != "regs"}
                rec.update(window=w, t_window_end=boundary, marked=marked)
                if w == 0 and first_mark is not None:
                    rec["marked_first"] = first_mark
                timing.write(json.dumps(rec) + "\n")
                timing.flush()
            if on_window is not None:
                on_window(win)
            w += 1
            if max_windows:
                if w >= max_windows:
                    if stop_fn is not None:
                        stop_fn()
                    break
            elif proc.poll() is not None:
                ended_at = clk.time() if ended_at is None else ended_at
                if clk.time() - ended_at >= drain_seconds:
                    break
    finally:
        if timing is not None:
            timing.close()
    return windows


# --switch-program sweep: the columns a window gets besides the model's 29 features (sweep_features.py)
SWEEP_EXTRA_KEYS = ["net_sweep_totals_mismatch", "net_sweep_coll_pkts", "net_sweep_coll_saturated",
                    "net_sweep_merged_active", "net_sweep_merged_buckets", "net_sweep_buckets", "net_sweep_span_us"]


def sweep_summary(feats: Dict[str, Any], duration_unit: str = "s") -> Dict[str, Any]:
    """A window's network columns from sweep_features.SweepWindows: the collector's NET_ZERO columns with the
    sweep's values, and the sweep build's own checks (the totals check, the collision counts)."""
    out = dict(NET_ZERO)
    for k in NET_ZERO:
        if k in feats:
            out[k] = feats[k]
    if duration_unit == "ns":
        out["net_flow_duration_mean"] = feats["net_flow_duration_mean"] * 1e9
        out["net_flow_duration_max"] = feats["net_flow_duration_max"] * 1e9
    for k in SWEEP_EXTRA_KEYS:
        out[k] = feats.get(k, 0)
    return out


def start_sweep_generator(reader: Any, first_sweep_at: float, window_sec: float, ipg_ns: int = 2000,
                          buckets: int = 65536, clock: Any = None) -> Dict[str, Any]:
    """--sweep-probes generator: configure the generator ("prepare", about 20 ms), then enable it one window before
    first_sweep_at (this host's clock): its first sweep, one period after the enable, falls on the start of the
    collector's window 0 (as start_window_timer does for the exact build's timer)."""
    clk = clock if clock is not None else time
    r = reader.request({"cmd": "generator", "prepare": True, "period_ns": int(round(window_sec * 1e9)),
                        "buckets": int(buckets), "ipg_ns": int(ipg_ns)}, timeout=60)
    if "error" in r:
        raise P4ReadError(f"sweep generator: {r['error']}")
    delay = first_sweep_at - window_sec - clk.time()
    if delay > 0:
        clk.sleep(delay)
    e = reader.request({"cmd": "generator", "enable": True}, timeout=30)
    if "error" in e:
        raise P4ReadError(f"sweep generator: {e['error']}")
    r.update(e)
    return r


def collect_windows_sweep(
    capture: Any,
    proc: subprocess.Popen,
    window_sec: float,
    global_t0: float,
    probes: str = "generator",
    sweep_span_s: float = 0.0,
    on_window: Optional[Callable[[Dict[str, object]], None]] = None,
    max_windows: int = 0,
    stop_fn: Optional[Callable[[], None]] = None,
    drain_seconds: float = 0.0,
    sweep_timeout: float = 5.0,
    quiet_s: float = 0.05,
    header: int = ETHERNET_HEADER_BYTES,
    duration_unit: str = "s",
    timing_path: Optional[str] = None,
    clock: Any = None,
    start_timeout: float = 120.0,
    keep_records: bool = False,
) -> List[Dict[str, object]]:
    """The windows of perf/variants/sweep (--switch-program sweep). Sweep k is the switch's k-th sweep since the
    reset (its reg_sweep_seq): sweep 1 is the state at the start of window 0, sweep w + 2 the state at its end,
    and sweep_features.SweepWindows turns two consecutive sweeps into the window's features. probes "generator":
    the switch's packet generator sweeps every bucket every window, started by start_sweep_generator(); a sweep
    takes sweep_span_s (65,536 probes x the generator's gap), and a bucket is cut when its probe passes.
    "inband": the scenario sends the probes in order with its traffic (live_test/replay_absolute.py --probes);
    the cut is then exact. After each boundary the collector waits until the sweep is complete in `capture`
    (ExportCapture: a later sweep has begun, or sweep_span_s after its first record and quiet_s after its last),
    at most sweep_timeout s. No CPU report and no register read: every bucket is in every window. A bucket missing
    from a sweep (a lost export) shows in net_sweep_totals_mismatch. With "inband" the scenario may start late (a
    replay of a flood plans its probes first) and then shifts its whole schedule (replay_absolute.py): the first
    sweep gets start_timeout s, and the later ones are awaited from the collector's boundaries plus the lateness
    of the first (inband_shift_s in the timing file); the windows are the probes' either way.

    max_windows: exactly that many windows, then stop_fn() (as collect_windows_live). Otherwise windows continue
    until the scenario has ended and drain_seconds have passed. timing_path: one JSON line per window.
    keep_records (--sockowner): each window keeps the records of the buckets that changed in its sweep
    ("sweep_records", sweep_features.compact tuples) and the sweep's clock ("sweep_clock": the first record's
    arrival on this host and its switch time); window 0 also the first sweep's records ("sweep_base",
    "sweep_base_clock"). sweep_socket_join() computes the socket-level join from them after the run."""
    sys.path.insert(0, SWEEP_PYDIR)
    from sweep_features import SweepWindows, compact, group_sweeps
    clk = clock if clock is not None else time
    sw = SweepWindows(window_sec=window_sec, header=header)
    timing = open(timing_path, "a") if timing_path else None
    windows: List[Dict[str, object]] = []

    def wait_sweep(k: int, not_before: float, timeout: Optional[float] = None) -> Dict[str, Any]:
        timeout = sweep_timeout if timeout is None else timeout
        deadline = not_before + timeout
        while True:
            now = clk.time()
            if now >= not_before and capture.complete(k, now, sweep_span_s, quiet_s):
                break
            if now >= deadline:
                break
            clk.sleep(0.005)
        recs = capture.take(k)
        if not recs:
            hint = (" (is the generator running, and --sweep-export-iface the interface of --sweep-export-port?)"
                    if probes == "generator" else " (does the scenario send the probes?)")
            raise P4ReadError(f"sweep {k}: no export within {timeout:.1f} s of "
                              f"{not_before - global_t0:+.3f} s{hint}")
        sweeps = group_sweeps(recs)
        sweep = max(sweeps, key=lambda s: s["records"])      # one generator expected (one pipe)
        sweep["generators"] = len(sweeps)
        return sweep

    inband = probes == "inband"
    base = wait_sweep(1, global_t0, max(sweep_timeout, start_timeout) if inband else None)
    shift = max(0.0, base["host_first"] - global_t0) if inband else 0.0
    sw.add(base)
    base_kept = ([compact(rec) for rec in base["buckets"].values()], [base["host_first"], base["t_first"]]) \
        if keep_records else None
    w = 0
    ended_at: Optional[float] = None
    try:
        while True:
            boundary = global_t0 + (w + 1) * window_sec
            sweep = wait_sweep(w + 2, boundary + shift)
            feats = sw.add(sweep)
            win: Dict[str, object] = {
                "net_window_id": w, "net_window_start_sec": w * window_sec,
                "net_window_end_sec": (w + 1) * window_sec, "net_window_duration_sec": window_sec,
                "indexes": [], "report_count": 0, "index_mismatches": 0, "cleared_indexes": [],
                "report_aggregates": dict(REPORT_ZERO), "exact_features": sweep_summary(feats, duration_unit),
            }
            if keep_records:
                win["sweep_records"] = [compact(sweep["buckets"][i]) for i in sw.last_changed]
                win["sweep_clock"] = [sweep["host_first"], sweep["t_first"]]
                if w == 0:
                    win["sweep_base"], win["sweep_base_clock"] = base_kept
            windows.append(win)
            if timing is not None:
                rec = {"window": w, "t_window_end": boundary, "seq": sweep["seq"], "records": sweep["records"],
                       "buckets": len(sweep["buckets"]), "duplicates": sweep["duplicates"],
                       "generators": sweep["generators"], "span_ns": sweep["span_ns"],
                       "host_first": sweep["host_first"], "host_last": sweep["host_last"],
                       "lag_s": round(sweep["host_first"] - boundary, 6),
                       "totals_mismatch": feats.get("net_sweep_totals_mismatch"),
                       "coll_pkts": feats.get("net_sweep_coll_pkts"),
                       "capture_drops": capture.read_drops() if hasattr(capture, "read_drops") else None}
                if w == 0:
                    rec.update(base_seq=base["seq"], base_host_first=base["host_first"],
                               base_lag_s=round(base["host_first"] - global_t0, 6), inband_shift_s=round(shift, 6))
                timing.write(json.dumps(rec) + "\n")
                timing.flush()
            if on_window is not None:
                on_window(win)
            w += 1
            if max_windows:
                if w >= max_windows:
                    if stop_fn is not None:
                        stop_fn()
                    break
            elif proc.poll() is not None:
                ended_at = clk.time() if ended_at is None else ended_at
                if clk.time() - ended_at >= drain_seconds:
                    break
    finally:
        if timing is not None:
            timing.close()
    return windows


class NetSummarizer:
    """Window features from the register snapshots taken at each window end
    (collect_windows_live): deltas against the previous snapshot of the same
    bucket index. net_new_conn_dst_max is the largest increase of one
    reg_newconn_dst bucket since its previous read.

    add() takes the windows one at a time, in order, so that a window's row
    can be written as soon as the window is read.

    byte_layer "frame" (the dataset profile, RUNBOOK 19.9.1): the dataset
    counted Ethernet frame bytes, the switch counts IPv4 totalLen, so 14 B per
    packet are added to the byte deltas and to min_len/max_len before the
    derived features. duration_unit "s": net_flow_duration_* in seconds, as in
    the dataset, with the 32-bit wrap of the timestamps resolved from the
    windows in which the bucket first appeared and last changed (unique while
    the window is shorter than half the wrap, 2.147 s); "ns" keeps the register
    difference modulo 2^32. A window's "active_after_read_indexes", when
    present, names the rows that count in its features; the other rows read
    (dormant buckets) only update the bookkeeping."""

    def __init__(self, window_sec: float, byte_layer: str = "ipv4", duration_unit: str = "ns",
                 global_totals: bool = False):
        if byte_layer not in ("ipv4", "frame"):
            raise ValueError(f"byte_layer must be 'ipv4' or 'frame', not {byte_layer!r}")
        if duration_unit not in ("ns", "s"):
            raise ValueError(f"duration_unit must be 'ns' or 's', not {duration_unit!r}")
        self.window_sec = window_sec
        self.byte_layer = byte_layer
        self.duration_unit = duration_unit
        # global_totals (PC1.md part 4d): the window's packet, byte and flag totals from the differences of the
        # gtot build's one-entry totals (window["totals"]), not from the buckets read, so a flood that keeps
        # more buckets active than a window's read can cover does not shrink them. Every row then also has
        # net_gtot_used and the bucket sums net_gtot_bucket_pkts_delta / net_gtot_bucket_bytes_delta (equal to
        # the totals in a window without overload: a check). The registers are reset at the start of the run,
        # so the first baseline is zero; after a window without totals the next one only sets the baseline.
        self.global_totals = global_totals
        self.prev_totals: Optional[Dict[str, int]] = None
        self.totals_baseline_ok = True
        self.prev_by_idx: Dict[int, Dict[str, Any]] = {}
        self.prev_new_conn: Dict[int, int] = {}
        self.n_windows = 0
        # for the duration unwrap: the window a bucket first appeared in, the windows of the read
        # before and the read at its last packet-count change, and the window of its last read
        self.first_window: Dict[int, int] = {}
        self.last_change_span: Dict[int, "tuple[int, int]"] = {}
        self.last_read_window: Dict[int, int] = {}

    def unwrap_seconds(self, idx: int, d_mod_ns: int) -> float:
        """The flow's duration in seconds from the register difference modulo 2^32 (d_mod_ns)
        and the windows the collector saw: the first packet lies in the bucket's first window,
        the last one between the read before and the read at its last change."""
        d_mod = d_mod_ns / 1e9
        first_w = self.first_window.get(idx, 0)
        before_w, change_w = self.last_change_span.get(idx, (first_w - 1, first_w))
        # midpoints in window units (the read of window j is at time j + 1)
        estimate = ((before_w + change_w) / 2.0 + 1.0 - (first_w + 0.5)) * self.window_sec
        k = max(0, int(round((estimate - d_mod) / TS_WRAP_S)))
        return d_mod + k * TS_WRAP_S

    def _apply_totals(self, summary: Dict[str, Any], totals: Any, header: int, whole_switch: bool) -> None:
        """Replace the bucket sums of the window totals with the global totals' differences (global_totals)."""
        summary["net_gtot_bucket_pkts_delta"] = summary["net_pkts_total_delta"]
        summary["net_gtot_bucket_bytes_delta"] = summary["net_bytes_total_delta"]
        used = 0
        keys = gtot_keys(totals)
        if keys is None:
            self.totals_baseline_ok = False          # the next window's difference would span two windows
        else:
            now = {k: int(totals[k]) for k in keys}
            prev = self.prev_totals if self.prev_totals is not None else dict.fromkeys(keys, 0)
            if self.totals_baseline_ok and whole_switch and set(prev) == set(keys):
                # 32-bit registers: differences modulo 2^32
                d = {k: (now[k] - prev[k]) % (1 << 32) for k in keys}
                if "pkts_ba" in d:
                    # basic_gtot_ba: B->A as counted; read apart from A->B, it cannot hold A->B packets
                    pkts_ba, bytes_ba = d["pkts_ba"], d["bytes_ba"]
                    d["pkts"], d["bytes"] = d["pkts_ab"] + pkts_ba, d["bytes_ab"] + bytes_ba
                else:
                    pkts_ba, bytes_ba = max(0, d["pkts"] - d["pkts_ab"]), max(0, d["bytes"] - d["bytes_ab"])
                summary["net_pkts_total_delta"] = d["pkts"]
                summary["net_bytes_total_delta"] = d["bytes"] + header * d["pkts"]
                summary["net_pkts_ab_delta"] = d["pkts_ab"]
                summary["net_bytes_ab_delta"] = d["bytes_ab"] + header * d["pkts_ab"]
                summary["net_pkts_ba_delta"] = pkts_ba
                summary["net_bytes_ba_delta"] = bytes_ba + header * pkts_ba
                summary["net_syn_delta"] = d["syn"]
                summary["net_ack_delta"] = d["ack"]
                summary["net_rst_delta"] = d["rst"]
                used = 1
            self.prev_totals = now
            self.totals_baseline_ok = True
        summary["net_gtot_used"] = used

    def add(self, win: Dict[str, object]) -> Dict[str, object]:
        window_sec = self.window_sec
        prev_by_idx = self.prev_by_idx
        prev_new_conn = self.prev_new_conn
        w = self.n_windows
        self.n_windows += 1
        header = ETHERNET_HEADER_BYTES if self.byte_layer == "frame" else 0

        rows = win.get("rows", [])

        new_conn_max = 0
        for row in win.get("dst_rows", []):
            idx = get_row_int(row, "idx", 0)
            new_conn = get_row_int(row, "new_conn", 0)
            new_conn_max = max(new_conn_max, new_conn - prev_new_conn.get(idx, 0))
            prev_new_conn[idx] = new_conn

        if not rows and not self.global_totals:
            return dict(NET_ZERO, net_new_conn_dst_max=new_conn_max)

        cleared_after_read = [safe_int(x) for x in win.get("cleared_indexes", [])]
        # The rows that count in this window: the active set once the read's changes are known
        # (collect_windows_live with dormant reads). Without the key, every row read is active.
        active_filter = win.get("active_after_read_indexes")
        active_set = {safe_int(x) for x in active_filter} if active_filter is not None else None
        # The socket-level join (sockjoin.socket_join_windows): only the buckets whose flow belongs to the
        # monitored execution count. Without the key every bucket counts (the window-level join).
        owned_filter = win.get("owned_indexes")
        owned_set = {safe_int(x) for x in owned_filter} if owned_filter is not None else None

        summary = dict(NET_ZERO)
        summary["net_new_conn_dst_max"] = new_conn_max

        min_lens: List[int] = []
        max_lens: List[int] = []
        durations: List[float] = []
        n_active = 0

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

            if header:
                # the dataset's Ethernet frame bytes: 14 B per packet more than the IPv4 lengths
                bytes_delta += header * pkts_delta
                bytes_ab_delta += header * pkts_ab_delta
                bytes_ba_delta += header * pkts_ba_delta
                if min_len > 0:
                    min_len += header
                if max_len > 0:
                    max_len += header

            # Bookkeeping for the duration unwrap: first appearance, last change, last read.
            if pkts > 0 and idx not in self.first_window:
                self.first_window[idx] = w
            prev_read_w = self.last_read_window.get(idx, w - 1)
            if pkts != prev_pkts:
                self.last_change_span[idx] = (prev_read_w, w)
            self.last_read_window[idx] = w

            # A row counts in this window if its bucket is active once this read is known, or
            # if it changed in this window (a dormant flow that resumed).
            if active_set is not None and idx not in active_set and pkts_delta == 0:
                # Keep the old baseline. No new packet in reg_pkts, but a register synced later in
                # the same snapshot (reg_bytes, ~2 ms after reg_pkts) can already hold packets that
                # arrived between the two syncs; they count with their packets, in the window whose
                # reg_pkts sees them. Taking this row as the baseline lost their bytes (PC1.md
                # part 4: bulk1600 and bulk2000 320 B short).
                continue
            prev_by_idx[idx] = row
            if owned_set is not None and idx not in owned_set:
                continue
            n_active += 1

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
                d_mod_ns = (int(last_ts) - int(first_ts)) % (1 << 32)
                if self.duration_unit == "s":
                    durations.append(self.unwrap_seconds(idx, d_mod_ns))
                else:
                    durations.append(float(d_mod_ns))

            if dir_valid != 0:
                summary["net_dir_valid_count"] += 1

            if pkts_ab > 0 or bytes_ab > 0:
                summary["net_flows_with_ab"] += 1

            if pkts_ba > 0 or bytes_ba > 0:
                summary["net_flows_with_ba"] += 1

        summary["net_flow_count_seen"] = n_active

        # Buckets cleared after this read restart from zero.
        for idx in cleared_after_read:
            prev_by_idx.pop(idx, None)
            self.first_window.pop(idx, None)
            self.last_change_span.pop(idx, None)
            self.last_read_window.pop(idx, None)

        if self.global_totals:
            self._apply_totals(summary, win.get("totals"), header, owned_set is None)

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

        return summary


def build_net_summaries(
    net_windows: List[Dict[str, object]],
    window_sec: float,
    **kwargs: Any,
) -> List[Dict[str, object]]:
    """NetSummarizer over all windows of a run (kwargs: byte_layer, duration_unit)."""
    summarizer = NetSummarizer(window_sec, **kwargs)
    return [summarizer.add(win) for win in net_windows]


# ============================================================
# CSV WRITER
# ============================================================

def append_csv_rows(path: str, rows: List[Dict[str, object]]) -> None:
    if not rows:
        return

    p = Path(path)
    write_header = not p.exists() or p.stat().st_size == 0
    fieldnames = list(rows[0].keys())
    if not write_header:
        with open(path, newline="") as f:
            existing = next(csv.reader(f), [])
        if existing != fieldnames:
            raise ValueError(f"{path} has a different column set ({len(existing)} columns, this run has "
                             f"{len(fieldnames)}; the report-aggregate columns were added on 2026-11-07): write "
                             f"this run to a new --out-csv")

    with open(path, "a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)

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
    return [
        build_row(args, run_id, i,
                  host_windows[i] if i < len(host_windows) else None,
                  net_windows[i] if i < len(net_windows) else None,
                  net_summaries[i] if i < len(net_summaries) else dict(NET_ZERO))
        for i in range(count)
    ]


def build_row(
    args,
    run_id: str,
    i: int,
    host_meta: Optional[Dict[str, object]],
    net_meta: Optional[Dict[str, object]],
    net_summary: Dict[str, object],
) -> Dict[str, object]:
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
    row.update(net_meta.get("report_aggregates", REPORT_ZERO) if net_meta else REPORT_ZERO)
    return row


class RunWriter:
    """The rows of one run, written as soon as they are complete.

    While the run lasts, each row goes to PARTIAL next to the output CSV
    (OUT.<run_id>.partial.csv), so a collector that dies mid-run leaves its
    windows on disk. commit() appends the rows to the output CSV: only complete
    runs reach it, as before. abandon() renames PARTIAL to
    OUT.<run_id>.incomplete.csv for a run that failed.
    """

    def __init__(self, out_csv: str, run_id: str):
        out = Path(out_csv)
        tag = re.sub(r"[^A-Za-z0-9_.-]", "_", run_id)
        self.out_csv = out
        self.partial = out.with_name(f"{out.stem}.{tag}.partial.csv")
        self.incomplete = out.with_name(f"{out.stem}.{tag}.incomplete.csv")
        self.rows: List[Dict[str, object]] = []
        self._file = None
        self._writer = None

    @property
    def count(self) -> int:
        return len(self.rows)

    def write(self, row: Dict[str, object]) -> None:
        if self._writer is None:
            self._file = open(self.partial, "w", newline="")
            self._writer = csv.DictWriter(self._file, fieldnames=list(row.keys()))
            self._writer.writeheader()
        self._writer.writerow(row)
        self._file.flush()
        self.rows.append(row)

    def _close(self) -> None:
        if self._file is not None:
            self._file.close()
            self._file = None

    def commit(self) -> None:
        self._close()
        append_csv_rows(str(self.out_csv), self.rows)
        if self.partial.exists():
            self.partial.unlink()

    def abandon(self) -> Optional[Path]:
        self._close()
        if self.partial.exists():
            self.partial.replace(self.incomplete)
            return self.incomplete
        return None


def socket_join_rows(args, run_id: str, cgroup_path: Optional[Path], global_t0: float,
                     host_windows: List[Dict[str, object]], net_windows: List[Dict[str, object]],
                     monotonic_minus_wall_ns: Optional[int] = None) -> List[Dict[str, object]]:
    """The run's rows with the socket-level join's network features: only the buckets whose flow's
    socket is in the monitored cgroup count (sockjoin.py). The host columns are the same as in the
    window-level rows."""
    import sockjoin
    if monotonic_minus_wall_ns is None:
        monotonic_minus_wall_ns = time.monotonic_ns() - time.time_ns()
    log = sockjoin.read_log(args.sockowner_log)
    health = log.health
    print(f"[INFO] sockowner: {len(log.sightings)} flow sightings, {len(log.sockets)} sockets, health {health}")
    if health is None or health["ringbuf_drops"] or health["flow_map_errors"] or health["failed"]:
        print("[WARN] sockowner reported drops, map errors or a failure (or no health line): the socket-level "
              "join may miss flows")
    cgroup_id = os.stat(cgroup_path).st_ino if cgroup_path is not None else 0
    table = sockjoin.OwnerTable(log)
    selector = sockjoin.Selector(cgroup_ids={cgroup_id})
    if net_windows and "sweep_records" in net_windows[0]:
        summaries = sweep_socket_join(net_windows, table, selector, monotonic_minus_wall_ns, args.window_sec,
                                      header=ETHERNET_HEADER_BYTES if args.byte_layer == "frame" else 0,
                                      duration_unit=args.duration_unit)
        print(f"[INFO] socket-level join (sweep build): cgroup {cgroup_id}, "
              f"{summaries[-1]['net_sock_owned_buckets'] if summaries else 0} owned buckets, "
              f"{sum(1 for x in summaries if x['net_sock_shared_active'])} windows with a bucket shared with another "
              f"execution, {summaries[-1]['net_sock_hidden_flows'] if summaries else 0} of its flows in another "
              f"flow's bucket")
        return [dict(row, join="socket") for row in build_rows(args, run_id, host_windows, net_windows, summaries)]
    joined = sockjoin.socket_join_windows(net_windows, table, selector, global_t0, monotonic_minus_wall_ns)
    owned = sum(len(w["owned_indexes"]) for w in joined)
    print(f"[INFO] socket-level join: cgroup {cgroup_id}, {owned} owned bucket-windows over {len(joined)} windows")
    summaries = build_net_summaries(joined, args.window_sec, byte_layer=args.byte_layer,
                                    duration_unit=args.duration_unit)
    return [dict(row, join="socket") for row in build_rows(args, run_id, host_windows, joined, summaries)]


# --switch-program sweep with --sockowner: the socket-level join's own columns (sweep_socket_join)
SWEEP_SOCK_KEYS = ["net_sock_owned_buckets", "net_sock_shared_active", "net_sock_hidden_flows"]
# the sweep's own checks, taken from the window-level row (they describe the sweep, not a selection of it)
SWEEP_WINDOW_KEYS = ["net_sweep_totals_mismatch", "net_sweep_buckets", "net_sweep_span_us"]


def sweep_socket_join(net_windows: List[Dict[str, object]], table: Any, selector: Any, monotonic_minus_wall_ns: int,
                      window_sec: float, header: int = ETHERNET_HEADER_BYTES, duration_unit: str = "s",
                      slack_ns: int = 50_000_000, bucket_of: Optional[Callable[..., int]] = None,
                      ) -> List[Dict[str, object]]:
    """The socket-level join on perf/variants/sweep: each window's network columns from the buckets whose flow
    belongs to the selected execution only.

    The sweep build sends no CPU report, so the 5-tuple of a bucket comes from this host's sockets
    (sockjoin.BucketOwners): the local 5-tuple that the switch hashes to the bucket and that has the bucket's
    reference ports. Its owner is looked up as of the bucket's cut in that window, on sockowner's clock: the
    first record's arrival on this host (sweep_clock) plus the bucket's probe time after it (its switch time),
    plus monotonic_minus_wall_ns. Owners are decided again whenever a bucket changes (a new sighting comes with a
    packet). The features are sweep_features.SweepWindows(select=...) over the records the collector kept
    (collect_windows_sweep keep_records): the same as over whole sweeps, because a bucket without a packet adds
    nothing. With a selector that owns every bucket the rows are the window-level rows.

    Besides NET_ZERO and SWEEP_EXTRA_KEYS (the collision columns of the owned buckets only; the totals check, the
    records and the span of the whole sweep, as in the window-level row), each window has:
      net_sock_owned_buckets   buckets that belong to the execution so far
      net_sock_shared_active   active buckets whose local 5-tuples belong to the execution and to another (its
                               own flows mixed with another execution's in one bucket)
      net_sock_hidden_flows    the execution's 5-tuples seen so far whose bucket holds another flow (ports that
                               are not the bucket's): their packets count for that flow's owner, not for it
    Loopback 5-tuples are left out of the last two (they never cross the switch)."""
    sys.path.insert(0, SWEEP_PYDIR)
    import sockjoin
    from sweep_features import M32, SweepWindows, expand
    if bucket_of is None:
        from flow_index import compute_flow_index as bucket_of
    owners = sockjoin.BucketOwners(table, bucket_of)
    owns = lambda s: selector.owns(table, s)                                    # noqa: E731
    own_keys = [k for k in owners.bucket_by_key
                if not (k[1][0].startswith(sockjoin.LOOPBACK_PREFIX) or k[2][0].startswith(sockjoin.LOOPBACK_PREFIX))]
    own_keys = [(owners.first_seen_ns(k), k) for k in own_keys if owns(table.owner(k))]
    own_keys.sort()
    sw = SweepWindows(window_sec=window_sec, header=header)
    owned: Dict[int, bool] = {}

    def decide(records: List[Dict[str, Any]], clock: List[float]) -> None:
        host_first, t_first = float(clock[0]), int(clock[1])
        for rec in records:
            cut_wall = host_first + ((int(rec["t"]) - t_first) & M32) / 1e9
            at_ns = int(round(cut_wall * 1e9)) + monotonic_minus_wall_ns
            owned[rec["idx"]] = owns(owners.owner(rec["idx"], rec["ref_sp"], rec["ref_dp"], at_ns, slack_ns))

    if not net_windows:
        return []
    base = [expand(v) for v in net_windows[0].get("sweep_base", [])]
    decide(base, net_windows[0].get("sweep_base_clock", [0.0, 0]))
    sw.add({"buckets": {rec["idx"]: rec for rec in base}, "totals": None}, select=set())
    out: List[Dict[str, object]] = []
    for w, win in enumerate(net_windows):
        records = [expand(v) for v in win.get("sweep_records", [])]
        decide(records, win.get("sweep_clock", [0.0, 0]))
        select = {idx for idx, own in owned.items() if own}
        feats = sw.add({"buckets": {rec["idx"]: rec for rec in records}, "totals": None}, select=select)
        summary = sweep_summary(feats, duration_unit)
        whole = win.get("exact_features") or {}
        for k in SWEEP_WINDOW_KEYS:
            summary[k] = whole.get(k, summary[k])
        end_ns = int(round((float(win["sweep_clock"][0]) if win.get("sweep_clock") else 0.0) * 1e9)) \
            + monotonic_minus_wall_ns + slack_ns
        active = [i for i, seen in sw.seen.items() if 0 <= w - seen <= sw.ttl]
        shared = 0
        for idx in active:
            kinds = {owns(table.owner(k, end_ns)) for k in owners.keys.get(idx, ())
                     if owners.first_seen_ns(k) <= end_ns and not k[1][0].startswith(sockjoin.LOOPBACK_PREFIX)
                     and not k[2][0].startswith(sockjoin.LOOPBACK_PREFIX)}
            shared += int(len(kinds) == 2)
        hidden = 0
        for first_ns, key in own_keys:
            if first_ns > end_ns:
                break
            idx = owners.bucket_by_key[key]
            rec = sw.state.get(idx)
            if rec is not None and not owned.get(idx, False) and \
                    owners.ports(key) != tuple(sorted((rec["ref_sp"], rec["ref_dp"]))):
                hidden += 1
        summary.update(net_sock_owned_buckets=len(select), net_sock_shared_active=shared,
                       net_sock_hidden_flows=hidden)
        out.append(summary)
    return out


def ip_scope_rows(args, run_id: str, host_windows: List[Dict[str, object]],
                  net_windows: List[Dict[str, object]], address: str) -> List[Dict[str, object]]:
    """The run's rows with the host-level join's network features for one host: only the buckets whose flow
    has `address` as source or destination count (sockjoin.ip_scope_windows). The host columns are the same
    as in the window-level rows (they come from this machine's monitor)."""
    import sockjoin
    scoped = sockjoin.ip_scope_windows(net_windows, [address])
    owned = sum(len(w["owned_indexes"]) for w in scoped)
    print(f"[INFO] host-level join on {address}: {owned} owned bucket-windows over {len(scoped)} windows")
    summaries = build_net_summaries(scoped, args.window_sec, byte_layer=args.byte_layer,
                                    duration_unit=args.duration_unit)
    return [dict(row, join="ip:" + address) for row in build_rows(args, run_id, host_windows, scoped, summaries)]


def socket_csv_path(args) -> Path:
    """--socket-join-csv, or --out-csv with .socket before the suffix."""
    if args.socket_join_csv:
        return Path(args.socket_join_csv)
    out = Path(args.out_csv)
    return out.with_name(out.stem + ".socket" + out.suffix)


def extra_socket_csv_path(socket_csv: Path, name: str) -> Path:
    """The CSV of --socket-join-also's cgroup NAME: the socket-join CSV with .NAME before the suffix."""
    tag = re.sub(r"[^A-Za-z0-9_.-]", "_", name)
    return socket_csv.with_name(f"{socket_csv.stem}.{tag}{socket_csv.suffix}")


def scoped_csv_path(out_csv: str, address: str) -> Path:
    out = Path(out_csv)
    return out.with_name(f"{out.stem}.scoped-{address}{out.suffix}")


# ============================================================
# MAIN
# ============================================================

def profile_parser() -> argparse.ArgumentParser:
    pre = argparse.ArgumentParser(add_help=False)
    pre.add_argument("--profile", choices=sorted(PROFILES),
                     help="option bundle for the target: 'switch' (Wedge100BF-32X: 1 s windows, 3-window TTL, batched "
                          "reader on the wire-format route with the syncs in one RPC, read budget 70%% of the window) "
                          "or 'model' (Tofino software model: 60 s windows, batched reader with register syncs, "
                          "600 s read timeout, no idle clearing, no budget) or 'dataset' (the Wedge producing rows by "
                          "the dataset's definitions for its detectors: 40 windows of 0.5 s, the dataset's launcher, "
                          "frame bytes, durations in seconds, dormant reads instead of clears; RUNBOOK 19.9) or "
                          "'exact' (perf/variants/exact or exact_block: 0.5 s windows computed in the data plane, cut "
                          "by CPU-port markers, the dataset's launcher, frame bytes). Options "
                          "given explicitly override the profile")
    return pre


def build_arg_parser(profile: Optional[str] = None) -> argparse.ArgumentParser:
    """The collector's options; with `profile`, that bundle's values become the defaults."""
    ap = argparse.ArgumentParser(description="Collect synchronized HostMon/eBPF + P4 features per time window",
                                 parents=[profile_parser()])

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
    ap.add_argument("--p4-resetter", default=DEFAULT_P4_RESETTER)
    ap.add_argument("--no-register-reset", action="store_true",
                    help="do not clear the P4 registers before the run (a bucket left from an earlier run "
                         "then sends no CPU report for a new flow that lands in it)")
    ap.add_argument("--p4-read-timeout", type=float, default=120.0,
                    help="seconds one register read may take before it is retried: the legacy reader's bfshell "
                         "session (that process is stopped 30 s later) or the batched reader's answer (the reader "
                         "is restarted)")
    ap.add_argument("--p4-read-retries", type=int, default=2,
                    help="retries of a failed register read before the run stops")
    ap.add_argument("--reader", choices=["legacy", "batched"], default="legacy",
                    help="register reader: legacy = one bfshell/bfrt_python session per window with one get() per "
                         "register per bucket (read_registers_with_index.py); batched = one long-lived BF Runtime "
                         "gRPC client, one Sync and one batched Read per register table per window "
                         "(batched_reader.py)")
    ap.add_argument("--batched-reader", default=DEFAULT_BATCHED_READER)
    ap.add_argument("--switch-program", choices=["buckets", "exact", "sweep"], default="buckets",
                    help="the P4 program on the switch: 'buckets' (basic_fix and its test builds: per-bucket "
                         "registers read at each window end), 'exact' (perf/variants/exact: the window features "
                         "computed in the data plane, read by window_reader.py; p4_perf.md section 5.7) or 'sweep' "
                         "(perf/variants/sweep: the bucket table read by the data plane, its export records "
                         "captured on --sweep-export-iface; p4_perf.md section 5.8)")
    ap.add_argument("--sweep-probes", choices=["generator", "inband"], default="generator",
                    help="sweep: who sends the probes. 'generator': the switch's packet generator, every bucket every "
                         "--window-sec from the collector's window 0 on (the deployment); 'inband': the scenario, in "
                         "order with its traffic (a replay with replay_absolute.py --probes), from --sweep-probe-port")
    ap.add_argument("--sweep-reader", default=DEFAULT_SWEEP_READER)
    ap.add_argument("--sweep-export-iface", default="eth1",
                    help="sweep: this host's interface toward --sweep-export-port, where the exports arrive (root)")
    ap.add_argument("--sweep-export-port", type=int, default=None,
                    help="sweep: the dev_port the switch sends the export records to (default --forward-int-port)")
    ap.add_argument("--sweep-probe-port", type=int, default=None,
                    help="sweep, --sweep-probes inband: the dev_port the scenario's probes enter (default "
                         "--forward-int-port)")
    ap.add_argument("--sweep-ipg-ns", type=int, default=2000,
                    help="sweep, generator: the gap between two probes; a sweep takes 65,536 x this (default 2000: "
                         "131 ms, at most 500 k exports/s toward --sweep-export-iface)")
    ap.add_argument("--sweep-pipes", default="1", help="sweep, generator: the pipes whose generator sweeps (one)")
    ap.add_argument("--sweep-local-port", type=int, default=68, help="sweep, generator: its pipe-local port")
    ap.add_argument("--sweep-timeout", type=float, default=5.0,
                    help="sweep: how long after a boundary the collector waits for its sweep")
    ap.add_argument("--sweep-capture", choices=["tcpdump", "socket"], default="tcpdump",
                    help="sweep: how this host takes the exports: 'tcpdump' writes them into a file in /dev/shm that "
                         "the collector parses behind it (no loss when the collector falls behind), 'socket' an "
                         "AF_PACKET socket read by a thread (drops under a flood on a 2-core host)")
    ap.add_argument("--sweep-export-pcap", default=None,
                    help="sweep, --sweep-capture tcpdump: keep the exports' pcap at this new path (default: a file "
                         "in /dev/shm, deleted at the end)")
    ap.add_argument("--window-markers", choices=["cpu", "inband", "timer"], default="cpu",
                    help="exact: who starts the switch's windows. 'cpu': the reader, from the switch's CPU port "
                         "(--cpu-iface), at the collector's window boundaries; 'inband': the scenario, in order with "
                         "its traffic (a replay with replay_absolute.py --markers), from --marker-port; 'timer': "
                         "every pipe's packet generator, a tick every --window-sec from the collector's window 0 on "
                         "(a build with -DTIMER_LOCAL_PORT=68; no marker counts)")
    ap.add_argument("--marker-port", type=int, default=None,
                    help="exact, --window-markers inband: the dev_port the scenario's markers enter (default "
                         "--forward-int-port)")
    ap.add_argument("--frame-min", action="append", default=None,
                    help="exact: DST/PREFIX toward which packets count at least the 60-byte frame minimum, as the "
                         "monitored host's own capture saw them; repeatable, and replaces the profile's default "
                         "(dataset: 10.0.0.10/32, the dataset's guest). --frame-min none: no such address")
    ap.add_argument("--frame-min-default", action="append", default=[], help=argparse.SUPPRESS)  # the profile's
    ap.add_argument("--window-reader", default=DEFAULT_WINDOW_READER)
    ap.add_argument("--exact-read-timeout", type=float, default=5.0,
                    help="exact: how long a window's read waits for the window to end on the switch")
    ap.add_argument("--grpc-addr", default=DEFAULT_GRPC_ADDR,
                    help="BF Runtime gRPC server for --reader batched; with --switch-ssh the reader runs on the "
                         "switch, so this is the address as seen from there")
    ap.add_argument("--grpc-client-id", type=int, default=7)
    ap.add_argument("--reader-local", action="store_true",
                    help="with --switch-ssh: run the batched reader on this host against --grpc-addr (e.g. "
                         "172.168.1.2:50052 or an SSH tunnel) instead of on the switch; the reports are still "
                         "captured on the switch")
    ap.add_argument("--p4-name", default="basic")
    ap.add_argument("--reader-chunk", type=int, default=4096, help="batched reader: keys per Read request")
    ap.add_argument("--reader-safe-parse", action="store_true",
                    help="batched reader: parse responses with the client's to_dict() only (slower)")
    ap.add_argument("--reader-sync-batched", action="store_true",
                    help="batched reader: the 14 register Syncs in one Write RPC instead of one per table")
    ap.add_argument("--reader-raw-wire", action="store_true",
                    help="batched reader: byte templates and a wire-format parser instead of the protobuf classes "
                         "per entity (for a client without the C protobuf implementation, such as the SDE 9.6 "
                         "one on the switch; checked against the client's parser on the first read)")
    ap.add_argument("--remote-sde-install", default=DEFAULT_REMOTE_SDE_INSTALL,
                    help="SDE install on the switch (--switch-ssh)")
    ap.add_argument("--reader-timing", action="store_true",
                    help="print, per window, the active-set size and the time spent in the register sync, the reads "
                         "and the clears (also enabled by P4_READER_TIMING=1)")
    ap.add_argument("--reader-timing-file", help="append the per-window timing as JSON lines to this file")
    ap.add_argument("--read-budget-frac", type=float, default=0.0,
                    help="a register read may take at most this fraction of the window (0 = no limit). When the "
                         "active set does not fit, the most recently reported/changed buckets are read and the rest "
                         "skipped and counted (net_buckets_skipped, net_overload); the report-only columns rep_* "
                         "are always available. The cost estimate starts from the switch measurements and follows "
                         "the measured windows")
    ap.add_argument("--max-read-buckets", type=int, default=0,
                    help="hard cap on flow buckets read per window (0 = none)")
    ap.add_argument("--max-dst-reads", type=int, default=0,
                    help="cap on reg_newconn_dst buckets read per window, most reported destinations first (0 = none)")
    ap.add_argument("--clear-expired", type=int, default=0,
                    help="1: a bucket that leaves the active set without having been cleared (skipped under the read "
                         "budget, so never idle-read) is cleared unconditionally in a later read, oldest first, so a "
                         "flood does not leave the switch's table occupied (an occupied bucket sends no CPU report "
                         "for the next flow that lands in it). 0 = only the compare-and-clear of idle buckets")
    ap.add_argument("--clear-budget-frac", type=float, default=0.5,
                    help="share of a window's read allowance (after the fixed sync cost) that --clear-expired may "
                         "spend; the rest of the backlog waits for the next window")
    ap.add_argument("--hostmon-cgroup",
                    help="run the in-kernel monitor (ebpf_perf/hostmon_agg, given with --hostmon) on this cgroup-v2 "
                         "directory (created if missing): the scenario command is started inside it at a shared "
                         "start time one second ahead, so host and network windows share one origin. Without this "
                         "option --hostmon is the streaming monitor started as before")

    ap.add_argument("--sockowner",
                    help="socket-level join: run ebpf_perf/sockowner (path to its binary) during the run. It records "
                         "which socket, process and cgroup each 5-tuple belongs to; the flows whose socket is in the "
                         "--hostmon-cgroup give a second set of network features, written to --socket-join-csv. "
                         "Needs --hostmon-cgroup. With --switch-program sweep (no CPU reports) a bucket's 5-tuple is "
                         "the local one the switch hashes to it with the bucket's reference ports (sweep_socket_join)")
    ap.add_argument("--sockowner-log", default="sockowner.log")
    ap.add_argument("--scope-ip", action="append", default=[],
                    help="host-level join (several hosts behind the switch): also write, for this address, rows "
                         "whose network features count only the flows with it as source or destination, to the "
                         "--out-csv name with .scoped-ADDRESS before the suffix (repeatable: one file per address)")
    ap.add_argument("--sockowner-attach", default="/sys/fs/cgroup",
                    help="cgroup-v2 directory sockowner attaches to (default: the root, so every process is seen)")
    ap.add_argument("--socket-join-csv",
                    help="output CSV of the socket-level join (default: --out-csv with .socket before the suffix)")
    ap.add_argument("--socket-join-also", action="append", default=[], metavar="CGROUP_DIR",
                    help="with --sockowner: also write the socket-level join of this existing cgroup-v2 directory "
                         "(e.g. a background program's), from the same windows, to the socket-join CSV's name with "
                         ".<directory name> before the suffix; network columns only (its host columns are zero). "
                         "Repeatable. With the monitored cgroup's rows it lets a run check that the socket joins "
                         "partition the window-level rows")
    ap.add_argument("--block-on-alarm", action="store_true",
                    help="--switch-program exact with a build of perf/variants/exact_block: score the run after every "
                         "window (the detectors of live_test/streaming/stream_verdicts.py) and, at the first window "
                         "whose probability reaches --block-threshold, have the switch stop forwarding from the "
                         "flagged host: every source address of the monitored program (from --sockowner) and each "
                         "--block-host, and with --block-host-port everything entering that port (--block-scope "
                         "host, the default), or only the program's flows (--block-scope flows; block_policy.py). "
                         "At the end the entries are listed with their dropped packets and deleted")
    ap.add_argument("--block-scope", choices=["host", "flows"], default="host",
                    help="what an alarm blocks: host (default): everything the flagged host sends, from the alarm "
                         "on, new connections included; flows: the monitored program's 5-tuples, each new one "
                         "from the next window on, and its host only on a flood (PC1.md part 11: short "
                         "connections pass)")
    ap.add_argument("--block-detector", choices=["auto", "network", "host", "concat", "stacked"], default="auto",
                    help="the detector for --block-on-alarm (auto: stacked with --hostmon-cgroup, network without)")
    ap.add_argument("--block-threshold", type=float, default=0.5)
    ap.add_argument("--block-hold-out-group", action="append", default=[], metavar="CV_GROUP",
                    help="train the detector without the dataset runs of this group (features.csv cv_group; a replay "
                         "of a dataset run: its own group, or the verdict is in-sample); repeatable")
    ap.add_argument("--block-host", action="append", default=[], metavar="ADDRESS",
                    help="a host block also drops everything from this source address (repeatable); with --sockowner "
                         "the program's own local addresses are always included")
    ap.add_argument("--block-host-port", type=int, metavar="DEV_PORT",
                    help="a host block also drops everything entering this switch dev_port (sources spoofed)")
    ap.add_argument("--block-flood-flows", type=float,
                    help="active flows in a window over which a flagged program's host is blocked (default "
                         f"{FLOOD_FLOWS_DEFAULT} per 0.5 s, scaled to --window-sec)")
    ap.add_argument("--block-force-alarm-window", type=int, metavar="W",
                    help="raise the alarm at window W whatever the probability (to test the blocking with benign "
                         "programs)")
    ap.add_argument("--block-skip-windows", type=int, default=0, metavar="K",
                    help="--block-on-alarm: the collector windows before K are not the run's (a replay anchored on window K, replay_capture.py --align-window K): they are neither scored nor checked for a flood, so that the detectors, trained on prefixes from the run's first window, see the same windows")
    ap.add_argument("--block-keep", action="store_true", help="leave the block entries in the switch at the end")
    ap.add_argument("--block-entries", type=int, default=1023,
                    help="the entries the block table holds (the build's -DBLOCK_ENTRIES less one with the per-entry "
                         "direct counter: 1,023 for the default build on the Wedge, PC1.md part 11b): when a flagged "
                         "program's flow entries "
                         "would exceed it, its host is blocked instead")
    ap.add_argument("--block-log",
                    help="JSONL of the scores, the alarm and every block request (default: --out-csv with "
                         ".block.jsonl instead of the suffix)")
    ap.add_argument("--block-release",
                    help="the release checkout whose evaluation/ has the detectors' forest (default: "
                         "p4-ebpf-malware-detection next to this repository)")

    ap.add_argument("--dormant-reads", type=int, default=0, choices=[0, 1],
                    help="1: a bucket that leaves the active set is not cleared but read again, round robin, with the "
                         "allowance left after the active set, so a flow that pauses and resumes keeps its registers "
                         "(the dataset's extractor never ends a flow); every tracked bucket is cleared at the end of "
                         "the run, and --clear-expired is not applied during it (RUNBOOK 19.9.1)")
    ap.add_argument("--dormant-probe", type=int, default=0, choices=[0, 1],
                    help="with --dormant-reads and the batched reader: probe reg_pkts of every dormant bucket that "
                         "fits the allowance each window and read the changed ones in full, instead of a few full "
                         "reads round robin, so a flow that resumes in its dormant bucket counts in that window "
                         "(PC1.md part 4b); on in --profile dataset")
    ap.add_argument("--global-totals", type=int, default=0, choices=[0, 1],
                    help="test build perf/variants/gtot with the batched reader: read its seven one-entry totals "
                         "every window and take the window's packet, byte and TCP-flag totals from them, so that "
                         "an overloaded read does not shrink them (PC1.md part 4d); adds net_gtot_* check columns")
    ap.add_argument("--totals-cut", default="boundary", choices=["boundary", "read", "snapshot"],
                    help="with --global-totals 1: 'boundary' reads the totals in a request of their own right after "
                         "the window boundary (cut ~2 ms after it, PC1.md part 4e); 'read' in the window's read, "
                         "before the flow registers' sync (after the reports' processing); 'snapshot' synced with "
                         "the flow registers, last in the ~31 ms sync (part 4d)")
    ap.add_argument("--byte-layer", choices=["ipv4", "frame"], default="ipv4",
                    help="'frame' adds 14 B per packet to the byte counts and the packet lengths: the dataset counted "
                         "Ethernet frames, the switch counts IPv4 totalLen (RUNBOOK 19.9.1)")
    ap.add_argument("--duration-unit", choices=["ns", "s"], default="ns",
                    help="unit of net_flow_duration_mean/max: 'ns' (the register difference modulo 2^32) or 's' (the "
                         "dataset's seconds, the 32-bit wrap resolved from the windows of the flow's first packet and "
                         "last change; needs windows under 2.1 s)")
    ap.add_argument("--windows", type=int, default=0,
                    help="run exactly this many windows whether or not the command has ended, then stop the command "
                         "(SIGTERM, then SIGKILL) as the dataset's runner did at its timeout; 0: until the command ends")
    ap.add_argument("--launcher", choices=["shell", "dataset"], default="shell",
                    help="how --command starts: 'shell' runs it in --shell -c; 'dataset' splits it into words (no shell "
                         "syntax) and runs it as the dataset's launcher did (/bin/bash -c 'exec \"$@\"' sample-launch "
                         "PROGRAM ARGS; stdin /dev/null, a new session, a private working directory, so file paths in "
                         "the command must be absolute), whose startup is part of every dataset row's host features "
                         "(RUNBOOK 19.5.6, 19.9.2)")
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

    if profile:
        ap.set_defaults(**PROFILES[profile])
    return ap


def main() -> None:
    profile_args, _ = profile_parser().parse_known_args()
    ap = build_arg_parser(profile_args.profile)
    args = ap.parse_args()
    if args.profile:
        print(f"[INFO] profile {args.profile}: " + ", ".join(f"{k}={getattr(args, k)}" for k in sorted(PROFILES[args.profile])))

    if args.mode == "command" and not args.command:
        ap.error("--command is required when --mode command")
    if args.hostmon_cgroup and args.mode != "command":
        ap.error("--hostmon-cgroup applies to --mode command (the replayed packets have no local process to monitor)")

    exact = args.switch_program == "exact"
    if exact and args.sockowner and not args.block_on_alarm:
        ap.error("--sockowner needs the per-bucket registers of --switch-program buckets or sweep: perf/variants/exact "
                 "keeps no per-flow counters for the socket-level join (with --block-on-alarm, --sockowner names the "
                 "flagged program's flows for the block rules)")
    if exact and (args.socket_join_csv or args.socket_join_also):
        ap.error("--socket-join-csv and --socket-join-also need --switch-program buckets or sweep: perf/variants/exact "
                 "keeps no per-flow counters for the socket-level join")
    if args.block_on_alarm and not exact:
        ap.error("--block-on-alarm needs --switch-program exact (a build of perf/variants/exact_block)")
    if args.block_on_alarm and args.block_detector in ("host", "concat", "stacked") and not args.hostmon_cgroup:
        ap.error(f"--block-detector {args.block_detector} needs the host monitor's windows (--hostmon-cgroup); "
                 "without it use network")
    if args.block_on_alarm and not args.sockowner and not args.block_host and args.block_host_port is None:
        ap.error("--block-on-alarm without --sockowner can only block a host: give --block-host ADDRESS and/or "
                 "--block-host-port DEV_PORT")
    if exact and args.global_totals:
        ap.error("--global-totals is for the gtot test build; --switch-program exact computes the windows itself")
    if exact and args.scope_ip:
        ap.error("--scope-ip needs the CPU reports of --switch-program buckets (the 5-tuple that owns each bucket): "
                 "perf/variants/exact keeps no per-flow rows to split by host")
    timer_mode = exact and args.window_markers == "timer"
    sweep = args.switch_program == "sweep"
    if sweep and args.global_totals:
        ap.error("--global-totals is for the gtot test build: --switch-program sweep reads the totals with every sweep")
    if sweep and args.scope_ip:
        ap.error("--scope-ip needs the CPU reports of --switch-program buckets (the 5-tuple that owns each bucket): "
                 "the sweep build exports its buckets without addresses, and this host's sockets (--sockowner) name "
                 "only its own flows")
    sweep_gen = sweep and args.sweep_probes == "generator"
    if sweep and len([p for p in args.sweep_pipes.split(",") if p.strip()]) != 1:
        ap.error("--sweep-pipes: one pipe (the windows are built from one generator's sweeps)")
    computed = exact or sweep       # the switch program gives the windows: no CPU reports, no register reads
    if args.sockowner and not args.hostmon_cgroup:
        ap.error("--sockowner needs --hostmon-cgroup: the socket-level join selects the flows of that cgroup")
    if args.socket_join_also and not args.sockowner:
        ap.error("--socket-join-also needs --sockowner")
    if args.mode == "pcap" and not args.pcap:
        ap.error("--pcap is required when --mode pcap")
    if args.launcher == "dataset" and args.mode != "command":
        ap.error("--launcher dataset applies to --mode command")
    if args.duration_unit == "s" and args.window_sec > TS_WRAP_S / 2:
        print(f"[WARN] --duration-unit s resolves the 32-bit timestamp wrap from the windows; with {args.window_sec} s "
              f"windows (over {TS_WRAP_S / 2:.2f} s) a duration can be off by a multiple of {TS_WRAP_S:.3f} s")

    for needed in [args.hostmon, args.window_reader if exact else args.sweep_reader if sweep else
                   (args.p4_reader if args.reader == "legacy" else args.batched_reader)]:
        if not Path(needed).exists():
            raise FileNotFoundError(f"Required file not found: {needed}")

    if not args.skip_p4_forwarding and not Path(args.p4_forwarder).exists():
        raise FileNotFoundError(f"Forwarding setup file not found: {args.p4_forwarder}")

    if not computed and not args.no_register_reset and not Path(args.p4_resetter).exists():
        raise FileNotFoundError(f"Register reset script not found: {args.p4_resetter}")

    if args.mode == "pcap" and not Path(args.replay_script).exists():
        raise FileNotFoundError(f"Replay script not found: {args.replay_script}")

    host_proc = None
    sock_proc = None
    clock_offset_ns: Optional[int] = None
    workload_proc = None
    report_collector = None
    batched_reader = None
    window_reader = None
    export_capture = None
    cgroup_path: Optional[Path] = None
    cgroup_created = False

    run_id = f"{args.scenario_name}_{int(time.time())}"
    writer = RunWriter(args.out_csv, run_id)
    summarizer = NetSummarizer(args.window_sec, byte_layer=args.byte_layer, duration_unit=args.duration_unit,
                               global_totals=bool(args.global_totals))
    # the dataset launcher's private working directory (RUNBOOK 19.5.6)
    workspace = tempfile.mkdtemp(prefix="sample-launch-") if args.launcher == "dataset" else None
    net_windows: List[Dict[str, object]] = []
    net_summaries: List[Dict[str, object]] = []
    committed = False
    block_score = None          # --block-on-alarm: the detector, trained before the run
    blocker = None              # block_policy.Blocker, from the run's start

    def write_ready_rows(host_windows: List[Dict[str, object]], final: bool) -> None:
        # Row i pairs host window i with network window i; the network windows
        # define the rows. During the run a host window is used once it is
        # complete: its HOSTMON_WINDOW_DONE line (hostmon_agg) or the next
        # window's header (older monitors) has been read.
        ready = len(host_windows) if final else complete_host_windows(host_windows)
        while writer.count < len(net_windows):
            i = writer.count
            if not final and i >= ready:
                break
            host_meta = host_windows[i] if i < len(host_windows) else None
            row = build_row(args, run_id, i, host_meta, net_windows[i], net_summaries[i])
            writer.write(row)
            if blocker is not None and args.hostmon_cgroup:
                blocker.on_row(i, row)

    host_tail = HostLogTail(args.hostmon_log)
    # --block-on-alarm with the host monitor: after each switch window, wait this long at most for the monitor's
    # window (printed about 50 ms after it ends), so that the verdict on a window comes right after it
    host_wait_s = min(0.25, 0.5 * args.window_sec)

    def on_window(win: Dict[str, object]) -> None:
        net_windows.append(win)
        net_summaries.append(win["exact_features"] if "exact_features" in win else summarizer.add(win))
        if blocker is not None:
            blocker.on_net_window(len(net_windows) - 1, net_summaries[-1])
            if not args.hostmon_cgroup:
                # no host monitor (a replay): the row has only network columns and is complete now
                i = len(net_windows) - 1
                blocker.on_row(i, build_row(args, run_id, i, None, net_windows[i], net_summaries[i]))
        if blocker is not None and args.hostmon_cgroup:
            host_windows = wait_host_windows(host_tail, len(net_windows), host_wait_s)
        else:
            host_windows = host_tail.poll()
        write_ready_rows(host_windows, final=False)

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

        if exact:
            # perf/variants/exact: its reader clears the registers, installs frame_len and the marker ports
            window_reader = WindowReaderProcess(
                args.window_reader, grpc_addr=args.grpc_addr, p4_name=args.p4_name,
                switch_ssh=None if args.reader_local else args.switch_ssh,
                remote_sde_install=args.remote_sde_install, cpu_iface=args.cpu_iface)
            print(f"[INFO] window reader ready: {json.dumps(window_reader.start())}")
            if args.window_markers == "cpu":
                marker_ports = [int(args.forward_report_port)]
            elif args.window_markers == "inband":
                marker_ports = [args.marker_port if args.marker_port is not None else int(args.forward_int_port)]
            else:
                marker_ports = []          # the timer: no marker frame may move the clock
            frame_min = args.frame_min if args.frame_min is not None else args.frame_min_default
            frame_min = [f for f in frame_min if f != "none"]
            got = window_reader.request({"cmd": "setup", "reset": not args.no_register_reset,
                                         "frame_min": frame_min, "marker_ports": marker_ports},
                                        timeout=300)
            if "error" in got:
                raise P4ReadError(f"window reader setup: {got['error']}")
            print(f"[INFO] exact build: {json.dumps({k: v for k, v in got.items() if k != 'sizes'})}")
            if args.block_on_alarm:
                import block_policy
                probe = window_reader.request({"cmd": "block", "op": "list"})
                if "error" in probe:
                    raise P4ReadError(f"--block-on-alarm: the program has no usable block table ({probe['error']}); "
                                      "load a build of perf/variants/exact_block")
                detector = (args.block_detector if args.block_detector != "auto"
                            else "stacked" if args.hostmon_cgroup else "network")
                t_train = time.monotonic()
                block_score = block_policy.load_scorer(detector, args.block_hold_out_group, args.block_release)
                print(f"[INFO] block rules: {detector} detector trained in {time.monotonic() - t_train:.1f} s"
                      + (f" without {', '.join(args.block_hold_out_group)}" if args.block_hold_out_group else "")
                      + f"; alarm at p >= {args.block_threshold}")
        elif sweep:
            # perf/variants/sweep: its reader clears the registers, installs frame_len, the probe and export ports
            window_reader = SweepReaderProcess(
                args.sweep_reader, grpc_addr=args.grpc_addr, p4_name=args.p4_name,
                switch_ssh=None if args.reader_local else args.switch_ssh,
                remote_sde_install=args.remote_sde_install,
                pipes=[int(p) for p in args.sweep_pipes.split(",") if p.strip()], local_port=args.sweep_local_port)
            print(f"[INFO] sweep reader ready: {json.dumps(window_reader.start())}")
            frame_min = args.frame_min if args.frame_min is not None else args.frame_min_default
            frame_min = [f for f in frame_min if f != "none"]
            export_port = args.sweep_export_port if args.sweep_export_port is not None else int(args.forward_int_port)
            probe_ports = [] if sweep_gen else [args.sweep_probe_port if args.sweep_probe_port is not None
                                               else int(args.forward_int_port)]
            got = window_reader.request({"cmd": "setup", "reset": not args.no_register_reset,
                                         "frame_min": frame_min, "sweep_ports": probe_ports,
                                         "export_port": export_port}, timeout=300)
            if "error" in got:
                raise P4ReadError(f"sweep reader setup: {got['error']}")
            print(f"[INFO] sweep build: {json.dumps({k: v for k, v in got.items() if k != 'sizes'})}")
            export_capture = ExportCapture(args.sweep_export_iface, backend=args.sweep_capture,
                                           pcap_path=args.sweep_export_pcap).start()
            print(f"[INFO] sweep build: capturing the exports on {args.sweep_export_iface} ({args.sweep_capture}"
                  + (f", {export_capture.pcap_path}" if args.sweep_capture == "tcpdump" else "") + ")")
        elif args.no_register_reset:
            print("[WARN] P4 registers not cleared (--no-register-reset): a flow that lands in a bucket left "
                  "from an earlier run sends no CPU report and is not counted")
        else:
            print(f"[INFO] Clearing the P4 registers via: {args.p4_resetter}")
            run_p4_register_reset(args.p4_resetter, switch_ssh=args.switch_ssh)

        read_fn = None
        if args.reader == "batched" and not computed:
            batched_reader = BatchedReaderProcess(
                args.batched_reader, grpc_addr=args.grpc_addr, client_id=args.grpc_client_id, p4_name=args.p4_name,
                switch_ssh=None if args.reader_local else args.switch_ssh,
                remote_sde_install=args.remote_sde_install, chunk=args.reader_chunk,
                safe_parse=args.reader_safe_parse, sync_batched=args.reader_sync_batched,
                raw_wire=args.reader_raw_wire)
            ready = batched_reader.start()
            print(f"[INFO] batched gRPC reader ready: {json.dumps(ready)}")

            def read_fn(idxs, w, **kw):
                return batched_reader.read_with_retries(idxs, w, retries=args.p4_read_retries,
                                                        timeout=args.p4_read_timeout, **kw)
        timing_on = args.reader_timing or args.reader_timing_file or os.environ.get("P4_READER_TIMING") == "1"
        timing_log = make_timing_logger(args.reader, args.reader_timing_file) if timing_on else None

        where = f"{args.switch_ssh}:{args.cpu_iface}" if args.switch_ssh else args.cpu_iface
        if computed:
            pass   # no CPU reports: the windows come from the window registers or the sweeps
        else:
            print(f"[INFO] Collecting CPU reports on {where}")
            report_collector = ReportCollector(args.cpu_iface, ssh_host=args.switch_ssh).start()
        t_capture = time.time()
        if computed:
            pass
        elif report_collector.wait_ready(REPORT_CAPTURE_READY_S):
            print(f"[INFO] CPU-report capture listening after {time.time() - t_capture:.1f} s")
        else:
            said = "; ".join(report_collector.capture_messages[-3:]) or "no message"
            print(f"[WARN] the CPU-report capture did not say it is listening within {REPORT_CAPTURE_READY_S:.0f} s "
                  f"({said}); the reports of the first packets may be lost")

        def launch() -> subprocess.Popen:
            if args.mode == "pcap":
                print(f"[INFO] Replaying PCAP: {args.pcap}")
                return subprocess.Popen(
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
            print(f"[INFO] Running command scenario ({args.launcher} launcher): {args.command}")
            return run_scenario_command(args.command, shell=args.shell,
                                        cgroup=str(cgroup_path) if cgroup_path is not None else None,
                                        launcher=args.launcher, workspace=workspace)

        if args.hostmon_cgroup:
            # In-kernel monitor: READY, then a shared start time one second ahead;
            # the scenario starts inside the cgroup at that instant, and both the
            # host windows and the network windows are anchored there.
            cgroup_path, cgroup_created = ensure_cgroup(args.hostmon_cgroup)
            if args.sockowner:
                print(f"[INFO] Starting sockowner {args.sockowner} on {args.sockowner_attach}")
                sock_proc = start_sockowner(args.sockowner, args.sockowner_log, args.sockowner_attach)
                print("[INFO] " + wait_for_line(args.sockowner_log, "SOCKOWNER_READY", 30.0, sock_proc))
            print(f"[INFO] Starting the in-kernel monitor {args.hostmon} on {cgroup_path} with window_sec={args.window_sec}")
            host_proc = start_hostmon_agg(args.hostmon, args.hostmon_log, args.window_sec, cgroup_path)
            print("[INFO] " + wait_for_line(args.hostmon_log, "HOSTMON_READY", 30.0, host_proc))
            start_mono = time.monotonic() + (max(1.0, args.window_sec + 0.5) if (timer_mode or sweep_gen) else 1.0)
            send_hostmon_start(host_proc, start_mono)
            if timer_mode:
                started = start_window_timer(window_reader, time.time() + start_mono - time.monotonic(),
                                             args.window_sec)
                print(f"[INFO] exact build: window timer {json.dumps(started)}")
            if sweep_gen:
                started = start_sweep_generator(window_reader, time.time() + start_mono - time.monotonic(),
                                                args.window_sec, ipg_ns=args.sweep_ipg_ns)
                print(f"[INFO] sweep build: generator {json.dumps(started)}")
            time.sleep(max(0.0, start_mono - time.monotonic()))
            global_t0 = time.time()
            clock_offset_ns = time.monotonic_ns() - time.time_ns()   # sockowner's clock vs the windows' wall clock
            os.environ["HYBRID_T0"] = repr(global_t0)   # the window origin, for the scenario (RUNBOOK 19.6)
            workload_proc = launch()
        else:
            print(f"[INFO] Starting HostMon with window_sec={args.window_sec}")
            host_proc = start_hostmon(args.hostmon, args.hostmon_log, args.window_sec)
            time.sleep(0.2)
            if timer_mode:
                first_tick = time.time() + args.window_sec + 0.3
                started = start_window_timer(window_reader, first_tick, args.window_sec)
                print(f"[INFO] exact build: window timer {json.dumps(started)}")
                time.sleep(max(0.0, first_tick - time.time()))
            if sweep_gen:
                first_sweep = time.time() + args.window_sec + 0.3
                started = start_sweep_generator(window_reader, first_sweep, args.window_sec, ipg_ns=args.sweep_ipg_ns)
                print(f"[INFO] sweep build: generator {json.dumps(started)}")
                time.sleep(max(0.0, first_sweep - time.time()))
            global_t0 = time.time()
            os.environ["HYBRID_T0"] = repr(global_t0)   # the window origin, for the scenario (RUNBOOK 19.6)
            workload_proc = launch()

        if getattr(args, "profile", None) == "model":
            route = "model"
        elif args.reader == "batched":
            route = "raw" if args.reader_raw_wire else "fast"
        else:
            route = "legacy"
        cost_model = ReadCostModel.for_route(route)
        print(f"[INFO] Reading P4 registers at the end of every window ({args.reader} reader, cost model "
              f"{cost_model.as_dict()}"
              + (f", budget {args.read_budget_frac:.0%} of the window" if args.read_budget_frac > 0 else "")
              + (", expired buckets cleared unconditionally" if args.clear_expired and not args.dormant_reads else "")
              + (", dormant buckets re-read instead of cleared" if args.dormant_reads else "")
              + (f", exactly {args.windows} windows" if args.windows else "")
              + (f", {args.byte_layer} bytes, durations in {args.duration_unit}") + ")")

        def stop_fn() -> None:
            stop_scenario(workload_proc, own_session=args.launcher == "dataset")

        if exact and block_score is not None:
            import block_policy
            flood = (args.block_flood_flows if args.block_flood_flows is not None
                     else block_policy.flood_threshold(args.window_sec, FLOOD_FLOWS_DEFAULT))
            block_log = args.block_log or str(Path(args.out_csv).with_suffix("")) + ".block.jsonl"
            blocker = block_policy.Blocker(
                window_reader.request, block_score, threshold=args.block_threshold,
                cgroup_ids=[os.stat(cgroup_path).st_ino] if (args.sockowner and cgroup_path is not None) else [],
                tail=block_policy.FlowTail(args.sockowner_log) if args.sockowner else None,
                host_addresses=args.block_host, host_port=args.block_host_port, flood_flows=flood,
                log_path=block_log, force_window=args.block_force_alarm_window, keep=args.block_keep,
                max_entries=args.block_entries, skip_windows=args.block_skip_windows, scope=args.block_scope)
            if args.block_scope == "host":
                print("[INFO] block rules: at the alarm, everything from the host: "
                      + ", ".join((["the monitored program's source addresses"] if args.sockowner else [])
                                  + [f"src {a}" for a in args.block_host]
                                  + ([f"port {args.block_host_port}"] if args.block_host_port is not None else []))
                      + f"; log {block_log}")
            else:
                print(f"[INFO] block rules: flows of {'the monitored cgroup' if args.sockowner else 'no program (no --sockowner)'}"
                      f", host on more than {flood:g} active flows per window, log {block_log}")
        if exact:
            print(f"[INFO] exact build: window markers {args.window_markers}, {args.byte_layer} bytes, durations in "
                  f"{args.duration_unit}" + (f", exactly {args.windows} windows" if args.windows else ""))
            collect_windows_exact(
                window_reader, workload_proc, args.window_sec, global_t0, markers=args.window_markers,
                on_window=on_window, max_windows=args.windows, stop_fn=stop_fn if args.windows else None,
                drain_seconds=args.drain_seconds if args.mode == "pcap" else 0.0,
                read_timeout=args.exact_read_timeout,
                header=ETHERNET_HEADER_BYTES if args.byte_layer == "frame" else 0,
                duration_unit=args.duration_unit, timing_path=args.reader_timing_file)
            if blocker is not None:
                blocker.finish()
            window_reader.stop()
            window_reader = None
        elif sweep:
            span = 65536 * args.sweep_ipg_ns / 1e9 + 0.02 if sweep_gen else 0.0
            print(f"[INFO] sweep build: probes from the {args.sweep_probes}, {args.byte_layer} bytes, durations in "
                  f"{args.duration_unit}" + (f", a sweep in {span * 1e3:.0f} ms" if sweep_gen else "")
                  + (f", exactly {args.windows} windows" if args.windows else ""))
            collect_windows_sweep(
                export_capture, workload_proc, args.window_sec, global_t0, probes=args.sweep_probes,
                sweep_span_s=span, on_window=on_window, max_windows=args.windows,
                stop_fn=stop_fn if args.windows else None,
                drain_seconds=args.drain_seconds if args.mode == "pcap" else 0.0,
                sweep_timeout=args.sweep_timeout,
                header=ETHERNET_HEADER_BYTES if args.byte_layer == "frame" else 0,
                duration_unit=args.duration_unit, timing_path=args.reader_timing_file,
                keep_records=bool(args.sockowner))
            window_reader.stop()
            window_reader = None
            export_capture.stop()
        else:
            collect_windows_live(
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
                read_timeout=args.p4_read_timeout,
                read_retries=args.p4_read_retries,
                on_window=on_window,
                read_fn=read_fn,
                timing_log=timing_log,
                read_budget_frac=args.read_budget_frac,
                max_read_buckets=args.max_read_buckets,
                max_dst_reads=args.max_dst_reads,
                cost_model=cost_model,
                clear_expired=bool(args.clear_expired),
                clear_budget_frac=args.clear_budget_frac,
                dormant_reads=bool(args.dormant_reads),
                dormant_probe=bool(args.dormant_probe),
                global_totals=bool(args.global_totals),
                totals_cut=args.totals_cut,
                max_windows=args.windows,
                stop_fn=stop_fn if args.windows else None,
            )
        if report_collector is not None:
            report_collector.stop()
        if batched_reader is not None:
            batched_reader.stop()
        if sweep:
            print(f"[INFO] sweep build: {len(net_windows)} windows; exports captured {export_capture.records}, "
                  f"dropped by this host's capture ({args.sweep_capture}) {export_capture.kernel_drops}; windows whose totals disagree "
                  f"with the buckets' sum {sum(1 for x in net_summaries if x['net_sweep_totals_mismatch'] == 1)}; "
                  f"colliding packets {sum(x['net_sweep_coll_pkts'] for x in net_summaries)} "
                  f"(windows with merged buckets {sum(1 for x in net_summaries if x['net_sweep_merged_active'])})")
        elif exact:
            print(f"[INFO] exact build: {len(net_windows)} windows; packets without a slot "
                  f"{sum(x['net_untracked_pkts'] for x in net_summaries)}, windows lost "
                  f"{sum(x['net_window_lost'] for x in net_summaries)}, unclocked packets "
                  f"{sum(x['net_unclocked_pkts'] for x in net_summaries)}, rejected markers "
                  f"{sum(x['net_rejected_markers'] for x in net_summaries)}")
        else:
            print(f"[INFO] CPU reports: {sum(w['report_count'] for w in net_windows)} in "
                  f"{len(net_windows)} windows; index mismatches: "
                  f"{sum(w['index_mismatches'] for w in net_windows)}; buckets cleared: "
                  f"{sum(len(w['cleared_indexes']) for w in net_windows)} "
                  f"({sum(len(w.get('expired_cleared_indexes') or []) for w in net_windows)} of them expired, "
                  f"unconditionally); clear backlog after the last window: "
                  f"{net_windows[-1]['report_aggregates']['net_clear_backlog'] if net_windows else 0}; "
                  f"cleared at the end of the run: "
                  f"{len(net_windows[-1].get('final_cleared_indexes') or []) if net_windows else 0}")

        workload_proc.wait()
        workload_rc = workload_proc.returncode

        print("[INFO] Stopping HostMon")
        stop_hostmon(host_proc)
        host_proc = None
        health = hostmon_health(args.hostmon_log)
        if health is not None:
            print(f"[INFO] HOSTMON_HEALTH {health}")
            if health["lost"] or health["capacity_errors"] or health["failed"]:
                print("[WARN] the host monitor reported lost events, capacity errors or failures: "
                      "treat this run's host rows as incomplete")

        host_windows = read_host_windows(args.hostmon_log)

        socket_rows: Optional[List[Dict[str, object]]] = None
        extra_socket_rows: List[Any] = []
        if sock_proc is not None:
            print("[INFO] Stopping sockowner")
            stop_hostmon(sock_proc)
            sock_proc = None
        if exact and args.sockowner:
            print("[INFO] sockowner named the flagged program's flows for the block rules (no socket-level join with "
                  "--switch-program exact)")
        elif args.sockowner:
            socket_rows = socket_join_rows(args, run_id, cgroup_path, global_t0, host_windows, net_windows,
                                           clock_offset_ns)
            for extra in args.socket_join_also:
                extra_path = Path(extra)
                if not (extra_path / "cgroup.procs").exists():
                    print(f"[WARN] --socket-join-also {extra}: not a cgroup-v2 directory, skipped")
                    continue
                rows = socket_join_rows(args, run_id, extra_path, global_t0, [], net_windows, clock_offset_ns)
                extra_socket_rows.append((extra_path, [dict(r, join="socket:" + extra_path.name) for r in rows]))

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
        if len(host_windows) > len(net_windows):
            print(f"[INFO] {len(host_windows) - len(net_windows)} host window(s) after the last register read "
                  f"have no network data and get no row")

        write_ready_rows(host_windows, final=True)

        if workload_rc != 0:
            if args.windows:
                print(f"[INFO] the command ended with code {workload_rc} (negative: stopped by that signal); the run "
                      f"keeps its {args.windows} windows, as the dataset's runs did")
            else:
                raise RuntimeError(f"Workload failed with code {workload_rc}")

        writer.commit()
        committed = True
        if socket_rows is not None:
            out = socket_csv_path(args)
            append_csv_rows(str(out), socket_rows)
            print(f"[OK] Added {len(socket_rows)} socket-join rows to {out}")
        for extra_path, rows in extra_socket_rows:
            out = extra_socket_csv_path(socket_csv_path(args), extra_path.name)
            append_csv_rows(str(out), rows)
            print(f"[OK] Added {len(rows)} socket-join rows of {extra_path} to {out}")
        for address in args.scope_ip:
            scoped_rows = ip_scope_rows(args, run_id, host_windows, net_windows, address)
            out = scoped_csv_path(args.out_csv, address)
            append_csv_rows(str(out), scoped_rows)
            print(f"[OK] Added {len(scoped_rows)} host-level join rows to {out}")

        print(f"[OK] Added {writer.count} rows to {args.out_csv}")
        print(f"[OK] run_id: {run_id}")
        print(f"[OK] host_windows={len(host_windows)}")
        print(f"[OK] net_windows={len(net_windows)}")
        print(f"[OK] net_summaries={len(net_summaries)}")

    finally:
        if workload_proc is not None and workload_proc.poll() is None:
            try:
                stop_scenario(workload_proc, own_session=args.launcher == "dataset")
            except Exception:
                pass
        if workspace is not None:
            shutil.rmtree(workspace, ignore_errors=True)

        if host_proc is not None:
            stop_hostmon(host_proc)

        if sock_proc is not None:
            stop_hostmon(sock_proc)

        if report_collector is not None:
            report_collector.stop()

        if batched_reader is not None:
            batched_reader.stop()

        if blocker is not None and not blocker.finished and window_reader is not None:
            try:
                blocker.finish()
            except Exception as error:
                print(f"[WARN] block rules: could not list or delete the entries: {error}")
        if blocker is not None:
            blocker.close()
        if window_reader is not None:
            window_reader.stop()

        if export_capture is not None:
            export_capture.stop()

        if cgroup_path is not None:
            cleanup_cgroup(cgroup_path, cgroup_created)

        if not committed:
            # Keep what was collected; the output CSV only receives complete runs.
            try:
                if writer.count < len(net_windows):
                    write_ready_rows(read_host_windows(args.hostmon_log), final=True)
                kept = writer.abandon()
                if kept is not None:
                    print(f"[ERROR] the run did not complete; its {writer.count} window rows are in {kept} "
                          f"(not added to {args.out_csv})")
            except Exception as error:
                print(f"[ERROR] could not save the windows collected so far: {error}")


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