#!/usr/bin/env python3
"""Known-answer test of the two eBPF host monitors (modelmon, hostmon).

    sudo python3 live_test/ebpf_known_answer.py --out results/ebpf_ka.json [--repeats 3]

Fixtures: tests/validation/known_answer.c (its own operations) and
live_test/fs_ops.c (rename/unlink/open variants). Every operation is run next
to a matched --baseline run with identical startup, and the monitor's count
difference (operation minus baseline, median over repeats) is compared with
the number of hooked syscalls the operation issues.

modelmon traces one process tree. The fixture is forked, held on a pipe until
modelmon reports "attached" for its PID, and only then exec'd, so the tree is
tracked from its first instruction.

hostmon traces the whole machine; the fixture runs are told apart by PID in
its per-process rows (parsed with hybrid_collector.parse_host_windows).

tcp_connect / udp_sendto target 127.0.0.1:9099; a sink is started there.
"""
import argparse
import json
import os
import select
import signal
import socket
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
from hybrid_collector import parse_host_windows  # noqa: E402

EXAMPLES = REPO / "libbpf-bootstrap" / "examples" / "c"
MODELMON = EXAMPLES / "modelmon"
HOSTMON = EXAMPLES / "hostmon"
BIN = Path(__file__).resolve().parent / "run" / "bin"

# operation -> expected modelmon count deltas (missing keys: expected 0), and
# a note where the operation does something modelmon by design cannot see
MODELMON_CASES = {
    ("ka", "openat"): ({"host__ebpf_openat_success_count": 1}, ""),
    ("ka", "openat2"): ({"host__ebpf_openat2_success_count": 1}, ""),
    ("ka", "open"): ({}, "GAP: open(2) opens a file but only openat/openat2 are hooked"),
    ("ka", "write"): ({"host__ebpf_file_write_success_count": 1, "host__ebpf_file_write_bytes": 1}, ""),
    ("ka", "pwrite"): ({"host__ebpf_file_pwrite64_success_count": 1, "host__ebpf_file_write_bytes": 1}, ""),
    ("ka", "writev"): ({"host__ebpf_file_writev_success_count": 1, "host__ebpf_file_write_bytes": 1}, ""),
    ("ka", "mmap_write"): ({}, "GAP: a write through a shared mapping issues no write syscall"),
    ("ka", "tcp_connect"): ({"host__ebpf_socket_count": 1, "host__ebpf_connect_count": 1}, ""),
    ("ka", "udp_sendto"): ({"host__ebpf_socket_count": 1, "host__ebpf_sendto_count": 1}, ""),
    ("ka", "fork"): ({}, ""),
    # the grandchild of a double fork writes the scratch file, then the
    # synchronization pipe: two 1-byte writes, both by a descendant
    ("ka", "double_fork"): ({"host__ebpf_file_write_success_count": 2, "host__ebpf_file_write_bytes": 2}, ""),
}
MODELMON_KEYS = ["host__ebpf_connect_count", "host__ebpf_file_pwrite64_success_count",
                 "host__ebpf_file_write_bytes", "host__ebpf_file_write_success_count",
                 "host__ebpf_file_writev_success_count", "host__ebpf_openat2_success_count",
                 "host__ebpf_openat_success_count", "host__ebpf_sendto_count", "host__ebpf_socket_count"]

# operation -> (counts a monitor of these events should report, keys checked).
# The expectation is the operation itself; where hostmon has no hook for the
# syscall variant the check fails and the result shows what it reports.
HOSTMON_KEYS = ["exec", "open", "ren", "del", "conn", "uniqip", "uniqprt"]
HOSTMON_CASES = {
    ("fs", "openat"): ({"open": 1}, HOSTMON_KEYS),
    ("fs", "open"): ({"open": 1}, HOSTMON_KEYS),
    ("fs", "creat"): ({"open": 1}, HOSTMON_KEYS),
    ("fs", "renameat"): ({"ren": 1}, HOSTMON_KEYS),
    ("fs", "rename"): ({"ren": 1}, HOSTMON_KEYS),
    ("fs", "renameat2"): ({"ren": 1}, HOSTMON_KEYS),
    ("fs", "unlinkat"): ({"del": 1}, HOSTMON_KEYS),
    ("fs", "unlink"): ({"del": 1}, HOSTMON_KEYS),
    ("ka", "tcp_connect"): ({"conn": 1, "uniqip": 1, "uniqprt": 1}, HOSTMON_KEYS),
    # the new image's loader also opens files: only the exec count is checked
    ("fs", "exec_dir"): ({"exec": 1}, ["exec"]),
    ("fs", "exec_usr"): ({"exec": 1}, ["exec"]),
}


def build():
    BIN.mkdir(parents=True, exist_ok=True)
    for src, out in ((REPO / "tests" / "validation" / "known_answer.c", BIN / "known_answer"),
                     (Path(__file__).resolve().parent / "fs_ops.c", BIN / "fs_ops")):
        subprocess.run(["gcc", "-O2", "-Wall", "-o", str(out), str(src), "-lresolv"], check=True)


def fixture_argv(kind, op, scratch, baseline):
    if kind == "ka":
        argv = [str(BIN / "known_answer"), op, str(scratch / "ka_file")]
    else:
        argv = [str(BIN / "fs_ops"), op, str(scratch)]
    return argv + (["--baseline"] if baseline else [])


def start_sink(port=9099):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(64)

    def loop():
        while True:
            try:
                c, _ = srv.accept()
                c.close()
            except OSError:
                return
    threading.Thread(target=loop, daemon=True).start()
    return srv


def run_under_modelmon(argv, window=0.2):
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(w)
        os.read(r, 1)
        os.execv(argv[0], argv)
    os.close(r)
    mm = subprocess.Popen([str(MODELMON), str(pid), str(window)], stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, text=True)
    deadline = time.time() + 30
    attached = False
    err = []
    while time.time() < deadline and not attached:
        ready, _, _ = select.select([mm.stderr], [], [], 0.5)
        if ready:
            line = mm.stderr.readline()
            err.append(line)
            attached = "modelmon attached" in line
        if mm.poll() is not None:
            break
    if not attached:
        os.kill(pid, signal.SIGKILL)
        os.waitpid(pid, 0)
        raise RuntimeError("modelmon did not attach: " + "".join(err) + mm.stderr.read())
    os.write(w, b"x")
    os.close(w)
    _, status = os.waitpid(pid, 0)
    time.sleep(0.5)                       # let the last events reach the ring buffer
    mm.send_signal(signal.SIGINT)
    out, _ = mm.communicate(timeout=10)
    windows = [json.loads(line) for line in out.splitlines() if line.startswith("{")]
    totals = {k: sum(wd["counts"][k] for wd in windows) for k in MODELMON_KEYS}
    lost = max((wd["ringbuf_lost_total"] for wd in windows), default=0)
    return totals, os.waitstatus_to_exitcode(status), lost, len(windows)


def median_delta(op_runs, base_runs, keys):
    return {k: statistics.median(r[k] for r in op_runs) - statistics.median(r[k] for r in base_runs) for k in keys}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--repeats", type=int, default=3)
    ap.add_argument("--only", choices=["modelmon", "hostmon"])
    args = ap.parse_args()
    build()
    sink = start_sink()
    scratch = Path(tempfile.mkdtemp(prefix="ebpf_ka_"))
    subprocess.run(["cp", "/usr/bin/true", str(scratch / "true")], check=True)
    results = {"modelmon": {}, "hostmon": {}, "checks": []}

    def check(name, ok, detail=""):
        results["checks"].append({"name": name, "ok": bool(ok), "detail": detail})
        print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f"  ({detail})" if detail else ""), flush=True)

    # ------------------------------------------------------------- modelmon
    print("== modelmon (process-tree monitor feeding the model's host__ebpf_* fields)", flush=True)
    for (kind, op), (expected, note) in (MODELMON_CASES.items() if args.only != "hostmon" else []):
        runs = {"op": [], "base": []}
        lost = 0
        for _ in range(args.repeats):
            for mode in ("base", "op"):
                totals, rc, l, nwin = run_under_modelmon(fixture_argv(kind, op, scratch, mode == "base"))
                if rc != 0:
                    raise RuntimeError(f"fixture {op} ({mode}) exited with {rc}")
                runs[mode].append(totals)
                lost += l
        delta = median_delta(runs["op"], runs["base"], MODELMON_KEYS)
        want = {k: expected.get(k, 0) for k in MODELMON_KEYS}
        diff = {k: (delta[k], want[k]) for k in MODELMON_KEYS if delta[k] != want[k]}
        results["modelmon"][op] = {"delta": delta, "expected": want, "note": note, "baseline_median":
                                   {k: statistics.median(r[k] for r in runs["base"]) for k in MODELMON_KEYS},
                                   "ringbuf_lost": lost}
        shown = {k.replace("host__ebpf_", ""): v for k, v in delta.items() if v}
        check(f"modelmon {op}", not diff and lost == 0,
              (f"delta(got, want) {diff}" if diff else f"delta {shown or 'none'}") + (f", lost={lost}" if lost else "")
              + (f" -- {note}" if note else ""))

    # -------------------------------------------------------------- hostmon
    if args.only == "modelmon":
        return finish(results, args, sink)
    print("== hostmon (machine-wide monitor of the hybrid collector)", flush=True)
    log = scratch / "hostmon.log"
    with open(log, "w") as fout:
        hm = subprocess.Popen([str(HOSTMON), "1"], stdout=fout, stderr=subprocess.STDOUT)
    time.sleep(3.0)
    pids = []
    for _ in range(args.repeats):
        for (kind, op) in HOSTMON_CASES:
            for mode in ("base", "op"):
                p = subprocess.Popen(fixture_argv(kind, op, scratch, mode == "base"))
                if p.wait() != 0:
                    raise RuntimeError(f"fixture {op} ({mode}) failed")
                pids.append((kind, op, mode, p.pid))
                time.sleep(0.15)
    time.sleep(2.5)
    hm.send_signal(signal.SIGINT)
    hm.wait(timeout=10)
    windows = parse_host_windows(log.read_text())
    per_pid = {}
    for win in windows:
        for row in win["rows"]:
            acc = per_pid.setdefault(row["pid"], {k: 0 for k in HOSTMON_KEYS + ["total_syscalls"]})
            for k in HOSTMON_KEYS + ["total_syscalls"]:
                acc[k] += row[k]
    missing_pids = [x for x in pids if x[3] not in per_pid]
    check("hostmon sees every fixture process", not missing_pids,
          f"{len(pids) - len(missing_pids)}/{len(pids)} PIDs in its rows")
    zero = {k: 0 for k in HOSTMON_KEYS + ["total_syscalls"]}
    for (kind, op), (expected, keys) in HOSTMON_CASES.items():
        op_runs = [per_pid.get(p, zero) for k2, o, m, p in pids if (k2, o, m) == (kind, op, "op")]
        base_runs = [per_pid.get(p, zero) for k2, o, m, p in pids if (k2, o, m) == (kind, op, "base")]
        delta = median_delta(op_runs, base_runs, HOSTMON_KEYS + ["total_syscalls"])
        want = {k: expected.get(k, 0) for k in keys}
        diff = {k: (delta[k], want[k]) for k in keys if delta[k] != want[k]}
        results["hostmon"][op] = {"delta": delta, "expected": want}
        shown = {k: v for k, v in delta.items() if v}
        check(f"hostmon {op}", not diff, f"delta(got, want) {diff}" if diff else f"delta {shown or 'none'}")
    finish(results, args, sink)


def finish(results, args, sink):
    sink.close()
    results["summary"] = {"passed": sum(c["ok"] for c in results["checks"]), "total": len(results["checks"])}
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(results, indent=1))
    print(f"\n{results['summary']['passed']}/{results['summary']['total']} checks passed -> {args.out}")


if __name__ == "__main__":
    main()
