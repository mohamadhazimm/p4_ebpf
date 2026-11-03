#!/usr/bin/env python3
"""Run hybrid_collector.py unchanged and record what its CSV leaves out.

    sudo python3 live_test/collector_probe.py --probe-out PROBE.json -- [hybrid_collector.py args]

hybrid_collector.main() runs as it is. Two names are wrapped, only to log:

  * run_p4_reader_json: for every register read, when the collector called it
    and when it returned, and from the reader's payload the switch-side start
    time t_switch, the sync/read/clear durations, the rows and the cleared
    buckets.
  * subprocess.Popen: the time and arguments of every process started. The
    collector sets its window origin global_t0 immediately before it starts
    the workload (the PCAP replay or the command).

The CSV only has relative window bounds and a write-time timestamp; with these
logs a run's windows can be placed on the clock and compared with an offline
derivation of the same traffic.

    --modelmon-gate DIR [--modelmon-window S]
        For command mode, with the command wrapped in
        live_test/gate.py --pidfile DIR/gate.pid --fifo DIR/gate.fifo -- ...:
        once the collector has started the command, modelmon is attached to the
        gate's PID and the gate released, so modelmon sees the whole workload
        tree. Its JSON windows go to DIR/modelmon.jsonl.
"""
import json
import os
import select
import signal
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
import hybrid_collector as hc  # noqa: E402

MODELMON = REPO / "libbpf-bootstrap" / "examples" / "c" / "modelmon"


def own_arg(own, name, default=None):
    return own[own.index(name) + 1] if name in own else default


def main() -> None:
    argv = sys.argv[1:]
    if "--" not in argv or "--probe-out" not in argv[: argv.index("--")]:
        sys.exit("usage: collector_probe.py --probe-out PROBE.json [--modelmon-gate DIR] -- "
                 "[hybrid_collector.py args]")
    split = argv.index("--")
    own, rest = argv[:split], argv[split + 1:]
    probe_out = Path(own_arg(own, "--probe-out"))
    gate_dir = own_arg(own, "--modelmon-gate")
    mm_window = own_arg(own, "--modelmon-window", "10")

    log = {"argv": rest, "reads": [], "popen": [], "started": time.time()}
    orig_reader = hc.run_p4_reader_json
    orig_popen = subprocess.Popen
    modelmon = {}

    if gate_dir:
        gate = Path(gate_dir)
        gate.mkdir(parents=True, exist_ok=True)
        for name in ("gate.pid", "gate.fifo"):
            if (gate / name).exists():
                (gate / name).unlink()
        os.mkfifo(gate / "gate.fifo")
        orig_scenario = hc.run_scenario_command

        def scenario(cmd, shell="/bin/bash"):
            proc = orig_scenario(cmd, shell=shell)
            deadline = time.time() + 30
            while not (gate / "gate.pid").exists():
                if time.time() > deadline or proc.poll() is not None:
                    raise RuntimeError("the workload did not start gate.py")
                time.sleep(0.01)
            pid = int((gate / "gate.pid").read_text())
            out = open(gate / "modelmon.jsonl", "w")
            mm = orig_popen([str(MODELMON), str(pid), str(mm_window)], stdout=out,
                            stderr=subprocess.PIPE, text=True)
            line = ""
            while "modelmon attached" not in line:
                ready, _, _ = select.select([mm.stderr], [], [], 30)
                if not ready or mm.poll() is not None:
                    raise RuntimeError("modelmon did not attach")
                line = mm.stderr.readline()
            log["modelmon"] = {"target_pid": pid, "attached": time.time(), "window_sec": float(mm_window)}
            modelmon.update(proc=mm, out=out)
            with open(gate / "gate.fifo", "wb") as f:
                f.write(b"x")
            return proc

        hc.run_scenario_command = scenario

    def reader(*args, **kwargs):
        t0 = time.time()
        payload = orig_reader(*args, **kwargs)
        t1 = time.time()
        log["reads"].append({
            "call_start": t0, "call_end": t1,
            "indexes": list(args[1]) if len(args) > 1 else kwargs.get("indexes"),
            "t_switch": payload.get("t_switch"), "sync_s": payload.get("sync_s"),
            "read_s": payload.get("read_s"), "clear_s": payload.get("clear_s"),
            "snapshot": payload.get("snapshot"), "errors": payload.get("errors", []),
            "cleared": payload.get("cleared", []), "rows": payload.get("rows", []),
            "dst_rows": payload.get("dst_rows", []),
        })
        return payload

    class Popen(orig_popen):
        def __init__(self, args, *a, **kw):
            entry = {"t": time.time(),
                     "args": [str(x) for x in args] if isinstance(args, (list, tuple)) else str(args)}
            log["popen"].append(entry)
            super().__init__(args, *a, **kw)
            entry["pid"] = self.pid

    log["collector_pid"] = os.getpid()

    def hostmon_pids():
        res = subprocess.run(["pgrep", "-x", "hostmon"], capture_output=True, text=True)
        return {int(p) for p in res.stdout.split()}

    hc.run_p4_reader_json = reader
    subprocess.Popen = Popen
    sys.argv = ["hybrid_collector.py"] + rest
    before = hostmon_pids()
    try:
        hc.main()
    finally:
        subprocess.Popen = orig_popen
        # Before the collector fix, stop_hostmon() signalled a sudo wrapper that
        # does not relay a signal from its own process group, and hostmon
        # outlived the run. This check reports (and stops) any that does.
        leaked = sorted(hostmon_pids() - before)
        for pid in leaked:
            os.kill(pid, signal.SIGINT)
        log["leaked_hostmon_pids"] = leaked
        if leaked:
            print(f"[probe] hostmon still running after the collector stopped it: {leaked}; sent SIGINT")
        if modelmon:
            modelmon["proc"].send_signal(signal.SIGINT)
            try:
                modelmon["proc"].wait(timeout=10)
            except subprocess.TimeoutExpired:
                modelmon["proc"].kill()
            modelmon["out"].close()
            log["modelmon"]["stopped"] = time.time()
        log["finished"] = time.time()
        probe_out.write_text(json.dumps(log, indent=1))
        print(f"[probe] {len(log['reads'])} register reads, {len(log['popen'])} processes -> {probe_out}")


if __name__ == "__main__":
    main()
