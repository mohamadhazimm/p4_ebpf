#!/usr/bin/env bash
# Re-implementation of the eAudit (IEEE S&P 2024) benchmark workloads, written for
# this harness. The semantics and default totals follow eAudit's eval/run_* and
# eval/bmrunall scripts: a fixed total amount of work is split across N parallel
# tasks (per-task loops = round(TOTAL / N)).
#
# Usage: eaudit.sh BENCH N [TOTAL]
#   shbm      TOTAL /bin/echo executions (default 200000), output piped to wc
#   find      TOTAL runs of `find /usr -type f -print | wc -l` (default 288)
#   tar       TOTAL runs of `tar cvf - /usr/src | wc --bytes` (default 144)
#   rdwr      TOTAL one-byte read+write pairs (default 100000000), own files per task
#   postmark  TOTAL Postmark runs of eAudit's "sm" config (default 24)
#   httperf   TOTAL httperf sessions (default 3000) at 50 sessions/s per client,
#             against nginx serving the mirrored eAudit session content
#   kernel    `make -jN` of a defconfig Linux tree in $KERNEL_TREE (prepared beforehand)
# PREPARE_ONLY=1 creates rdwr inputs and exits, so it can run untimed as --setup.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$HERE")"
T="$ROOT/tools"
BENCH=$1 N=$2
declare -A DEFAULT=([shbm]=200000 [find]=288 [tar]=144 [rdwr]=100000000 [postmark]=24 [httperf]=3000 [kernel]=1)
[[ -n ${DEFAULT[$BENCH]:-} ]] || { echo "unknown benchmark $BENCH" >&2; exit 2; }
TOTAL=${3:-${DEFAULT[$BENCH]}}
PER=$(( (TOTAL + N / 2) / N ))
WORK="${EAUDIT_WORKDIR:-${XDG_CACHE_HOME:-$HOME/.cache}/hostmon-bench}/$BENCH"
mkdir -p "$WORK"

task() {
  local i=$1 j
  set +e +o pipefail   # like eAudit's scripts: find/tar warnings must not stop the loop
  case $BENCH in
    shbm) for (( j = 0; j < PER; j++ )); do /bin/echo "$j"; done | wc > /dev/null ;;
    find) for (( j = 0; j < PER; j++ )); do find /usr -type f -print |& wc -l > /dev/null; done ;;
    tar)  for (( j = 0; j < PER; j++ )); do tar cvf - /usr/src |& wc --bytes > /dev/null; done ;;
    rdwr) "$ROOT/build/bench_load" - rdwr "$PER" 0 "$WORK/in$i:$WORK/out$i" > /dev/null ;;
    postmark)
      for (( j = 0; j < PER; j++ )); do
        rm -rf "$WORK/$i"; mkdir -p "$WORK/$i"
        (cd "$WORK/$i" && printf 'set number 4500\nset transactions 150000\nset size 4096 51200\nset subdirectories 10\nrun\nquit\n' \
          | "$T/root/usr/bin/postmark" > /dev/null)
      done ;;
    httperf)
      "$T/root/usr/bin/httperf" --client="$i/$N" --hog --server 127.0.0.1 --port "$HTTP_PORT" \
        --wsesslog="$PER,0,$WORK/uris.txt" --rate 50 > "$WORK/httperf.$i.out" 2>&1 ;;
  esac
}

case $BENCH in
  rdwr)
    # Inputs must hold PER bytes so every task really does PER read/write pairs.
    for (( i = 0; i < N; i++ )); do
      [[ $(stat -c %s "$WORK/in$i" 2>/dev/null || echo 0) -ge $PER ]] || head -c "$PER" /dev/urandom > "$WORK/in$i"
    done
    [[ -z ${PREPARE_ONLY:-} ]] || exit 0 ;;
  httperf)
    HTTP_PORT=${HTTP_PORT:-8081}
    CONTENT="$T/httperf-content"
    # Session file: the 157 URIs of eAudit's uris.txt (156 unique, one listed twice).
    { (cd "$CONTENT" && find content -type f | sed 's|^|/|' | sort); echo /content/vnetlab/arch.png; } > "$WORK/uris.txt"
    mkdir -p "$WORK/nginx"
    cat > "$WORK/nginx/nginx.conf" <<EOF
worker_processes 12;
pid $WORK/nginx/nginx.pid;
error_log $WORK/nginx/error.log;
events { worker_connections 768; }
http {
  sendfile on; tcp_nopush on; types_hash_max_size 2048;
  include $T/root/etc/nginx/mime.types;
  default_type application/octet-stream;
  access_log $WORK/nginx/access.log;
  client_body_temp_path $WORK/nginx/body; proxy_temp_path $WORK/nginx/proxy;
  fastcgi_temp_path $WORK/nginx/fastcgi; uwsgi_temp_path $WORK/nginx/uwsgi; scgi_temp_path $WORK/nginx/scgi;
  server { listen 127.0.0.1:$HTTP_PORT; root $CONTENT; location / { } }
}
EOF
    : > "$WORK/nginx/access.log"
    "$T/root/usr/sbin/nginx" -p "$WORK/nginx" -c "$WORK/nginx/nginx.conf" -g 'daemon off;' 2> "$WORK/nginx/stderr.log" &
    NGINX=$!
    trap 'kill -QUIT $NGINX 2>/dev/null; wait $NGINX 2>/dev/null || true' EXIT
    for _ in $(seq 100); do (exec 3<>/dev/tcp/127.0.0.1/$HTTP_PORT) 2>/dev/null && break; sleep 0.05; done ;;
  kernel)
    source "$HERE/kernel_env.sh"
    cd "$KERNEL_TREE"
    make -j"$N" > "$WORK/make.log" 2>&1
    exit ;;
esac

pids=()
for (( i = 0; i < N; i++ )); do task "$i" & pids+=($!); done
rc=0
for p in "${pids[@]}"; do wait "$p" || rc=1; done
exit $rc
