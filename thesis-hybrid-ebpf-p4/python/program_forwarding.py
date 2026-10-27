#!/usr/bin/env python3
"""Program the forwarding table and the CPU-report mirror session through BFRT.

Model defaults: ports 0/1, reports to port 2. On the NETLAB Tofino (Wedge100BF-32X)
the front-panel ports 1/0 and 2/0 are dev_ports 132 and 140, and the PCIe CPU
port is 192; use --ssh to run bfshell on the switch, e.g.

    program_forwarding.py --ssh root@172.168.1.2 --int-port 132 --ext-port 140 --report-port 192
"""
import argparse
import socket
import sys
from pathlib import Path

from bfshell_run import DEFAULT_REMOTE_SDE_INSTALL, default_bfshell, run_bfshell_script

DEFAULT_BFSHELL = default_bfshell()
DEFAULT_BF_PORT = 9999

DEFAULT_INT_PORT = 0
DEFAULT_EXT_PORT = 1
DEFAULT_REPORT_PORT = 2
DEFAULT_MIRROR_SID = 1
DEFAULT_MIRROR_MAX_LEN = 64


def port_open(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def build_bfrt_script(
    int_port: int,
    ext_port: int,
    report_port: int,
    mirror_sid: int,
    mirror_max_len: int,
    configure_mirror: bool = True,
) -> str:
    completion_message = (
        "Forwarding programmed"
        if not configure_mirror
        else "Forwarding + mirroring programmed"
    )
    return f"""\
p4 = bfrt.basic.pipe.Ingress.forwarding

# ---------------------------
# Forwarding
# ---------------------------
p4.clear()
print("[INFO] Cleared forwarding table")

p4.add_with_send_using_port({int_port}, port={ext_port})
print("[INFO] Added forwarding entry: {int_port} -> {ext_port}")

p4.add_with_send_using_port({ext_port}, port={int_port})
print("[INFO] Added forwarding entry: {ext_port} -> {int_port}")

if {configure_mirror}:
    mirror_cfg = bfrt.mirror.cfg
    try:
        mirror_cfg.delete(sid={mirror_sid})
        print("[INFO] Deleted existing mirror session sid={mirror_sid}")
    except Exception as error:
        print("[INFO] No existing mirror session sid={mirror_sid}: " + str(error))

    mirror_cfg.add_with_normal(
        sid={mirror_sid},
        session_enable=True,
        direction="INGRESS",
        ucast_egress_port={report_port},
        ucast_egress_port_valid=True,
        max_pkt_len={mirror_max_len}
    )
    print("[INFO] Added mirror session sid={mirror_sid} -> port {report_port}")

bfrt.complete_operations()

print("[OK] {completion_message}")
"""
    # If your SDE rejects the keyword form above for mirror_cfg,
    # use the alternative "$field" version shown below instead:
    #
    # mirror_cfg.add_with_normal(**{{
    #     "$sid": {mirror_sid},
    #     "$session_enable": True,
    #     "$direction": "INGRESS",
    #     "$ucast_egress_port": {report_port},
    #     "$ucast_egress_port_valid": True,
    #     "$max_pkt_len": {mirror_max_len}
    # }})


def main() -> None:
    ap = argparse.ArgumentParser(description="Program BFRT forwarding table and mirror session")
    ap.add_argument("--bfshell", default=DEFAULT_BFSHELL)
    ap.add_argument("--bf-port", type=int, default=DEFAULT_BF_PORT)
    ap.add_argument("--ssh", help="run bfshell on this switch, e.g. root@172.168.1.2")
    ap.add_argument("--remote-sde-install", default=DEFAULT_REMOTE_SDE_INSTALL)

    ap.add_argument("--int-port", type=int, default=DEFAULT_INT_PORT)
    ap.add_argument("--ext-port", type=int, default=DEFAULT_EXT_PORT)

    ap.add_argument("--report-port", type=int, default=DEFAULT_REPORT_PORT)
    ap.add_argument("--mirror-sid", type=int, default=DEFAULT_MIRROR_SID)
    ap.add_argument("--mirror-max-len", type=int, default=DEFAULT_MIRROR_MAX_LEN)
    ap.add_argument(
        "--skip-mirror",
        action="store_true",
        help="Do not configure a mirror session when the compiled pipeline has reports disabled",
    )

    args = ap.parse_args()

    if not args.ssh:
        if not Path(args.bfshell).exists():
            print(f"[ERROR] bfshell not found at: {args.bfshell}")
            sys.exit(1)

        if not port_open("127.0.0.1", args.bf_port):
            print(f"[ERROR] Connection refused on 127.0.0.1:{args.bf_port}")
            sys.exit(1)

    script = build_bfrt_script(
        int_port=args.int_port,
        ext_port=args.ext_port,
        report_port=args.report_port,
        mirror_sid=args.mirror_sid,
        mirror_max_len=args.mirror_max_len,
        configure_mirror=not args.skip_mirror,
    )

    where = args.ssh or "local"
    print(f"[INFO] Running bfshell ({where}) to program forwarding "
          f"{args.int_port}<->{args.ext_port}" + ("" if args.skip_mirror else
                                                   f", mirror sid {args.mirror_sid} -> {args.report_port}"))
    out = run_bfshell_script(script, bfshell=args.bfshell, port=args.bf_port, ssh_host=args.ssh,
                             remote_sde_install=args.remote_sde_install, timeout=120)
    print(out)
    if "[OK]" not in out:
        print("[ERROR] the BFRT script did not report success")
        sys.exit(1)


if __name__ == "__main__":
    main()