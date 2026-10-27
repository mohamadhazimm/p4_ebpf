#!/usr/bin/env bash
# Server-throughput workloads common in the eBPF-monitor literature (SysComb, saBPF,
# CamFlow, BPFContain, bpfbox, auditd patch): the server and the load generator both
# run inside the workload, so both are monitored, as with a system-wide monitor.
#
# Usage: http_kv.sh wrk THREADS CONNECTIONS SECONDS   nginx static 673-byte page, wrk -t -c -d
#        http_kv.sh redis REQUESTS CLIENTS            redis-server, redis-benchmark -t set,get --csv
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$HERE")"
T="$ROOT/tools"
export LD_LIBRARY_PATH="$T/root/usr/lib/x86_64-linux-gnu"
WORK="${EAUDIT_WORKDIR:-${XDG_CACHE_HOME:-$HOME/.cache}/hostmon-bench}/$1"
mkdir -p "$WORK"

wait_port() { for _ in $(seq 200); do (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null && return 0; sleep 0.05; done; return 1; }

case $1 in
  wrk)
    PORT=8082
    cat > "$WORK/nginx.conf" <<EOF
worker_processes 12;
pid $WORK/nginx.pid;
error_log $WORK/error.log;
events { worker_connections 1024; }
http {
  sendfile on; tcp_nopush on; types_hash_max_size 2048;
  include $T/root/etc/nginx/mime.types;
  default_type application/octet-stream;
  access_log $WORK/access.log;
  client_body_temp_path $WORK/body; proxy_temp_path $WORK/proxy;
  fastcgi_temp_path $WORK/fastcgi; uwsgi_temp_path $WORK/uwsgi; scgi_temp_path $WORK/scgi;
  server { listen 127.0.0.1:$PORT; root $T/httperf-content; location / { } }
}
EOF
    : > "$WORK/access.log"
    "$T/root/usr/sbin/nginx" -p "$WORK" -c "$WORK/nginx.conf" -g 'daemon off;' 2> "$WORK/stderr.log" &
    SERVER=$!
    trap 'kill -QUIT $SERVER 2>/dev/null; wait $SERVER 2>/dev/null || true' EXIT
    wait_port $PORT
    "$T/root/usr/bin/wrk" -t "$2" -c "$3" -d "${4}s" "http://127.0.0.1:$PORT/content/footer.html" ;;
  redis)
    PORT=6380
    "$T/root/usr/bin/redis-server" --port $PORT --bind 127.0.0.1 --save '' --appendonly no \
      --dir "$WORK" --daemonize no > "$WORK/server.log" 2>&1 &
    SERVER=$!
    trap 'kill $SERVER 2>/dev/null; wait $SERVER 2>/dev/null || true' EXIT
    wait_port $PORT
    "$T/root/usr/bin/redis-benchmark" -p $PORT -n "$2" -c "$3" -t set,get --csv ;;
  *) echo "usage: $0 wrk|redis ..." >&2; exit 2 ;;
esac
