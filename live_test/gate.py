#!/usr/bin/env python3
"""Hold a command until a monitor is attached to this process, then exec it.

    gate.py --pidfile P --fifo F -- COMMAND [ARGS...]

Writes its PID to P and blocks until one byte arrives on the FIFO F, then
execs COMMAND in place (same PID). A monitor that tracks a process tree from
one PID (modelmon) can therefore attach to P's PID first and see the command
and all its children from their first instruction.
"""
import argparse
import os
import sys


def main():
    if "--" not in sys.argv:
        sys.exit(__doc__)
    split = sys.argv.index("--")
    ap = argparse.ArgumentParser()
    ap.add_argument("--pidfile", required=True)
    ap.add_argument("--fifo", required=True)
    args = ap.parse_args(sys.argv[1:split])
    cmd = sys.argv[split + 1:]
    if not cmd:
        sys.exit("no command")
    tmp = args.pidfile + ".tmp"
    with open(tmp, "w") as f:
        f.write(str(os.getpid()))
    os.replace(tmp, args.pidfile)
    with open(args.fifo, "rb") as f:   # blocks until the monitor side opens it
        f.read(1)
    os.execvp(cmd[0], cmd)


if __name__ == "__main__":
    main()
