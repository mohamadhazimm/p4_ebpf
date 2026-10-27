#!/usr/bin/env bash
# Workload for check_agg.sh (runs inside the monitored cgroup, as the invoking
# user). Paced so that hostmon's 128-process table and ring buffer are never the
# limit; otherwise the comparison would measure hostmon's losses.
# Usage: check_workload.sh BUILD_DIR OUT_DIR
set -u
B=$1 OUT=$2
TMP="$OUT/workload-tmp"
mkdir -p "$TMP"

"$B/bench_load" - getppid 300000 100000 > /dev/null    # 3 s, one syscall id
"$B/bench_load" - openclose 40000 20000 > /dev/null    # openat+read+close
"$B/bench_load" - fstat 50000 25000 /etc/hostname > /dev/null
"$B/bench_load" - forkexec 60 30 > /dev/null           # 60 short-lived processes over 2 s
for _ in $(seq 20); do ls /etc | wc -l > /dev/null; done

# openat/renameat/unlinkat through dir_fd (these map to the named hostmon events),
# and connect() to 70 local addresses and ports (more than the 64-entry sets).
/usr/bin/python3 -I - "$TMP" <<'PY'
import os, socket, sys
d = os.open(sys.argv[1], os.O_RDONLY | os.O_DIRECTORY)
for i in range(200):
    fd = os.open(f"f{i}", os.O_CREAT | os.O_WRONLY, 0o600, dir_fd=d)
    os.write(fd, b"x")
    os.close(fd)
    os.rename(f"f{i}", f"g{i}", src_dir_fd=d, dst_dir_fd=d)
    os.unlink(f"g{i}", dir_fd=d)
for k in range(70):
    s = socket.socket()
    s.settimeout(0.2)
    s.connect_ex((f"127.0.0.{k + 2}", 20000 + k))
    s.close()
PY

# One multi-threaded process: its threads' syscalls interleave, so only the
# order-independent columns are compared for it.
/usr/bin/python3 -I - "$OUT/threaded.pid" <<'PY'
import os, sys, threading
with open(sys.argv[1], "w") as f:
    f.write(str(os.getpid()))
def work():
    for _ in range(20000):
        os.stat("/")
threads = [threading.Thread(target=work) for _ in range(4)]
for t in threads:
    t.start()
for t in threads:
    t.join()
PY
rm -rf "$TMP"
