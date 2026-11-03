#!/usr/bin/env python3
"""Clear the detector's registers through bfrt_python, before a collection run.

    reset_registers.py [--ssh root@172.168.1.2] [--timeout 1800]

Clears the 14 flow registers and reg_newconn_dst; registers a build does not
have (the forwarding-only variant) are skipped. After each clear a few cells
are read back from the hardware and must be zero.

hybrid_collector.py runs this at the start of every run. Without it, a bucket
left from an earlier run keeps dir_valid = 1: a new flow that lands in it sends
no CPU report, so the collector never reads it, and its packets are added to
the old counters. reg_newconn_dst is never cleared during a run, so its first
read would return the count since the switch started.

On the Tofino model of a VM a full clear took 202 s; on the switch it is a
bulk operation per register.
"""
import argparse
import socket
import sys
import time
from pathlib import Path

from bfshell_run import DEFAULT_REMOTE_SDE_INSTALL, BfshellError, default_bfshell, run_bfshell_script

REGISTERS = ["reg_pkts", "reg_bytes", "reg_pkts_ab", "reg_bytes_ab", "reg_ref_src_port",
             "reg_ref_dst_port", "reg_dir_valid", "reg_min_len", "reg_max_len", "reg_first_ts",
             "reg_last_ts", "reg_syn", "reg_ack", "reg_rst", "reg_newconn_dst"]
# Cells read back after each clear (both registers have 65,536 buckets).
CHECK_INDEXES = [0, 1, 32767, 65535]

# Runs inside bfrt_python: SDE 9.6 embeds Python 3.4 (no f-strings) and runs a
# script with separate globals and locals, so everything lives in one function.
INNER_TEMPLATE = r'''
def _reset_registers_main():
    import time
    names = __NAMES__
    check = __CHECK__
    ing = bfrt.basic.pipe.Ingress

    def as_list(r):
        if r is None:
            return []
        if isinstance(r, (list, tuple)):
            return list(r)
        return [r]

    def cell(reg, idx):
        entry = as_list(reg.get(REGISTER_INDEX=idx, from_hw=True, print_ents=False))[0]
        for k, v in entry.data.items():
            k = k.decode() if isinstance(k, bytes) else k
            if k.endswith(".f1"):
                return [int(x) for x in as_list(v)]
        raise RuntimeError("no .f1 field in register entry")

    t_all = time.time()
    cleared = 0
    for name in names:
        try:
            reg = getattr(ing, name)
        except AttributeError:
            print("[RESET-SKIP] %s is not in this build" % name)
            continue
        t = time.time()
        reg.clear()
        bfrt.complete_operations()
        left = [idx for idx in check if any(cell(reg, idx))]
        if left:
            print("[RESET-FAIL] %s is not zero at %s after clear()" % (name, left))
            return
        cleared += 1
        print("[RESET] %s %.1f s" % (name, time.time() - t))
    print("[RESET-OK] %d registers cleared in %.1f s" % (cleared, time.time() - t_all))

_reset_registers_main()
'''


def build_inner_script(names=None, check=None) -> str:
    return (INNER_TEMPLATE.replace("__NAMES__", repr(list(names or REGISTERS)))
            .replace("__CHECK__", repr(list(check or CHECK_INDEXES))))


def port_open(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def reset_registers(bfshell=None, port=9999, ssh_host=None, remote_sde_install=DEFAULT_REMOTE_SDE_INSTALL,
                    timeout=1800.0, attempts=3, retry_delay=5.0):
    """Clear all registers; return the [RESET...] lines, raise RuntimeError on failure.

    Retried: the first bfshell session right after BFRT starts listening can fail."""
    script = build_inner_script()
    out = ""
    for attempt in range(1, attempts + 1):
        try:
            out = run_bfshell_script(script, bfshell=bfshell, port=port, ssh_host=ssh_host,
                                     remote_sde_install=remote_sde_install, timeout=timeout)
        except BfshellError as error:
            out = str(error)
        lines = [line.strip() for line in out.splitlines() if line.strip().startswith("[RESET")]
        if any(line.startswith("[RESET-OK]") for line in lines):
            return lines
        failed = [line for line in lines if line.startswith("[RESET-FAIL]")]
        print("[WARN] register reset attempt %d of %d did not complete%s" % (
            attempt, attempts, (": " + failed[0]) if failed else ""), file=sys.stderr)
        if attempt < attempts:
            time.sleep(retry_delay)
    raise RuntimeError("register reset failed after %d attempts:\n%s" % (attempts, out[-2000:]))


def main() -> None:
    ap = argparse.ArgumentParser(description="Clear the detector's registers before a collection run")
    ap.add_argument("--bfshell", default=default_bfshell())
    ap.add_argument("--bf-port", type=int, default=9999)
    ap.add_argument("--ssh", help="run bfshell on this switch, e.g. root@172.168.1.2")
    ap.add_argument("--remote-sde-install", default=DEFAULT_REMOTE_SDE_INSTALL)
    ap.add_argument("--timeout", type=float, default=1800, help="seconds for one bfshell session")
    ap.add_argument("--attempts", type=int, default=3)
    args = ap.parse_args()

    if not args.ssh:
        if not Path(args.bfshell).exists():
            print(f"[ERROR] bfshell not found at: {args.bfshell}", file=sys.stderr)
            sys.exit(1)
        if not port_open("127.0.0.1", args.bf_port):
            print(f"[ERROR] Connection refused on 127.0.0.1:{args.bf_port}", file=sys.stderr)
            sys.exit(1)
    try:
        lines = reset_registers(bfshell=args.bfshell, port=args.bf_port, ssh_host=args.ssh,
                                remote_sde_install=args.remote_sde_install, timeout=args.timeout,
                                attempts=args.attempts)
    except RuntimeError as error:
        print(f"[ERROR] {error}", file=sys.stderr)
        sys.exit(1)
    print("\n".join(lines))


if __name__ == "__main__":
    main()
