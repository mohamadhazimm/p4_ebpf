#!/usr/bin/env python3
"""Run a bfrt_python script through bfshell non-interactively. Runs on the switch.

    sw_bfshell_b.py SCRIPT [TIMEOUT_S]

`bfshell -b SCRIPT` sends "bfrt_python SCRIPT" and "exit" to the switchd CLI
server and then forwards its own stdin; it disconnects as soon as stdin hits
EOF. With stdin=/dev/null that happens before the server has even started the
script, so nothing runs. Here bfshell's stdin is a pipe that is held open and
never written, so the client stays connected until the server closes the
session after "exit". bfshell is killed after TIMEOUT_S (default 600).
"""
import os
import subprocess
import sys

SDE = "/root/bf-sde-9.6.0"
SDE_INSTALL = SDE + "/install"


def main():
    script = sys.argv[1]
    timeout = int(sys.argv[2]) if len(sys.argv) > 2 else 600
    env = dict(os.environ, SDE=SDE, SDE_INSTALL=SDE_INSTALL,
               LD_LIBRARY_PATH="/usr/local/lib:%s/lib" % SDE_INSTALL,
               PATH="%s/bin:%s" % (SDE_INSTALL, os.environ.get("PATH", "")))
    p = subprocess.Popen([SDE_INSTALL + "/bin/bfshell", "-b", script],
                         stdin=subprocess.PIPE, env=env)
    try:
        rc = p.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        p.kill()
        rc = p.wait()
        print("sw_bfshell_b: bfshell killed after %d s" % timeout)
    p.stdin.close()
    sys.exit(rc)


if __name__ == "__main__":
    main()
