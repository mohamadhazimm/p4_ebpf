"""Run a bfrt_python script through bfshell, on this host or on a switch over SSH.

`bfshell -b SCRIPT` sends "bfrt_python SCRIPT" and "exit" to bf_switchd's CLI
server and then forwards its own stdin; it disconnects as soon as that stdin
reaches EOF. Without a terminal (stdin closed, /dev/null, or subprocess pipes
that get closed) it therefore leaves before the script has even run. Here
bfshell's stdin is a pipe that is held open and never written, so the client
stays connected until the server ends the session after "exit".

Over SSH the script is copied to the switch first and bfshell runs there with
the SDE libraries; SSH carries the held-open stdin. Before connecting, the
remote side checks that bf_switchd survives a CLI disconnect: a bf_switchd
started as a session leader that does not ignore SIGHUP can be killed by the
hangup of the CLI pseudo-terminal (seen on SDE 9.6), so such a session is
refused unless allow_unsafe is set.
"""
import os
import shlex
import subprocess
import tempfile
import threading
from typing import Optional

DEFAULT_REMOTE_SDE_INSTALL = "/root/bf-sde-9.6.0/install"

# Refuses (exit 98) if bf_switchd is a session leader without SIGHUP ignored.
_SAFETY_CHECK = r'''
pid=$(pgrep -x bf_switchd | head -1)
if [ -z "$pid" ]; then echo "bfshell_run: no bf_switchd running" >&2; exit 97; fi
sid=$(ps -o sid= -p "$pid" | tr -d ' ')
ign=$(awk '/^SigIgn:/ {print $2}' /proc/"$pid"/status)
if [ "$sid" = "$pid" ] && [ $(( 0x$ign & 1 )) -eq 0 ]; then
    echo "bfshell_run: bf_switchd (pid $pid) is a session leader that does not ignore SIGHUP;" >&2
    echo "bfshell_run: a CLI disconnect could kill it. Refusing." >&2
    exit 98
fi
'''


class BfshellError(RuntimeError):
    pass


def default_bfshell() -> str:
    sde_install = os.environ.get("SDE_INSTALL")
    if sde_install:
        return os.path.join(sde_install, "bin", "bfshell")
    return "/home/ubuntu/open-p4studio/install/bin/bfshell"


def _run_holding_stdin(cmd, timeout: float) -> str:
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT)
    chunks = []
    reader = threading.Thread(target=lambda: chunks.append(proc.stdout.read()), daemon=True)
    reader.start()
    try:
        rc = proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        raise BfshellError("bfshell did not finish within %s s" % timeout)
    finally:
        reader.join(timeout=5)
        for pipe in (proc.stdin, proc.stdout):
            try:
                pipe.close()
            except OSError:
                pass
    out = b"".join(c for c in chunks if c).decode(errors="replace")
    if rc != 0:
        raise BfshellError("bfshell exited with %d:\n%s" % (rc, out[-2000:]))
    return out


def run_bfshell_script(script_text: str, bfshell: Optional[str] = None, port: int = 9999,
                       ssh_host: Optional[str] = None,
                       remote_sde_install: str = DEFAULT_REMOTE_SDE_INSTALL,
                       timeout: float = 600, allow_unsafe: bool = False) -> str:
    """Run script_text as a bfrt_python script; return bfshell's combined output."""
    if ssh_host is None:
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".py") as f:
            f.write(script_text)
            path = f.name
        try:
            return _run_holding_stdin([bfshell or default_bfshell(), "-p", str(port), "-b", path],
                                      timeout)
        finally:
            try:
                os.unlink(path)
            except OSError:
                pass

    ssh = ["ssh", "-o", "BatchMode=yes", ssh_host]
    remote_path = "/tmp/bfrt_script_%d_%d.py" % (os.getpid(), threading.get_ident())
    copy = subprocess.run(ssh + ["cat > %s" % remote_path], input=script_text.encode(),
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=60)
    if copy.returncode != 0:
        raise BfshellError("could not copy the script to %s: %s" % (ssh_host, copy.stdout.decode()))
    sde = shlex.quote(remote_sde_install)
    remote = ("%s SDE_INSTALL=%s; export LD_LIBRARY_PATH=/usr/local/lib:$SDE_INSTALL/lib; "
              "$SDE_INSTALL/bin/bfshell -p %d -b %s; rc=$?; rm -f %s; exit $rc"
              % ("" if allow_unsafe else _SAFETY_CHECK, sde, port, remote_path, remote_path))
    return _run_holding_stdin(ssh + ["-T", "bash -c %s" % shlex.quote(remote)], timeout)
