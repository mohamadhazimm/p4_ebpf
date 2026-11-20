#!/usr/bin/env bash
# The socket tracer's per-datagram cost on this machine (PC1.md Part 5). Run as root from p4_ebpf:
#   sudo host/sockowner/bench/bench_cost.sh OUTDIR [ROUNDS]
# Each round sends 200,000 datagrams to a closed port on 127.0.0.1, with one 5-tuple (steady
# state) and with 50,000 (a new 5-tuple, hence a FLOW event, for each of the first 50,000), first
# with the tracer off, then on (attached to the root cgroup, as the collector attaches it). The
# rounds alternate so that drift hits both. Benign: loopback only, nothing leaves the host.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="${1:?usage: bench_cost.sh OUTDIR [ROUNDS]}"
ROUNDS="${2:-10}"
TRACER="${TRACER:-$HERE/../build/sockowner}"
[ "$(id -u)" = 0 ] || { echo "run as root (the tracer attaches eBPF programs)"; exit 1; }
[ -x "$TRACER" ] || { echo "build the tracer first: host/sockowner/build.sh"; exit 1; }
mkdir -p "$OUT"
cc -O2 -Wall -o "$OUT/udp_send_bench" "$HERE/udp_send_bench.c"
uname -r > "$OUT/kernel.txt"
nproc > "$OUT/nproc.txt"
sha256sum "$TRACER" "$HERE/udp_send_bench.c" > "$OUT/sha256.txt"
run() {  # label
  "$OUT/udp_send_bench" 127.0.0.1 10000 200000 "$1-1tuple" 1 >> "$OUT/bench.jsonl"
  "$OUT/udp_send_bench" 127.0.0.1 10000 200000 "$1-50ktuples" 50000 >> "$OUT/bench.jsonl"
}
for r in $(seq 1 "$ROUNDS"); do
  run off
  "$TRACER" /sys/fs/cgroup > "$OUT/sockowner-$r.log" 2> "$OUT/sockowner-$r.err" &
  pid=$!
  for _ in $(seq 1 100); do grep -q SOCKOWNER_READY "$OUT/sockowner-$r.log" 2>/dev/null && break; sleep 0.1; done
  grep -q SOCKOWNER_READY "$OUT/sockowner-$r.log" || { echo "tracer not ready (round $r)"; kill "$pid"; exit 1; }
  run on
  kill -INT "$pid"; wait "$pid" || true
  grep SOCKOWNER_HEALTH "$OUT/sockowner-$r.log" || echo "round $r: no SOCKOWNER_HEALTH line"
done
python3 - "$OUT" <<'PY'
import json, statistics, sys
from pathlib import Path
out = Path(sys.argv[1])
runs = [json.loads(l) for l in (out / "bench.jsonl").read_text().splitlines() if l.strip()]
res = {}
for kind in ("1tuple", "50ktuples"):
    off = [r["ns_per_send"] for r in runs if r["label"] == "off-" + kind]
    on = [r["ns_per_send"] for r in runs if r["label"] == "on-" + kind]
    res[kind] = {"off_median_ns": statistics.median(off), "on_median_ns": statistics.median(on),
                 "added_ns_per_datagram": statistics.median(on) - statistics.median(off),
                 "off_range": [min(off), max(off)], "on_range": [min(on), max(on)], "rounds": len(off),
                 "failed_sends": sum(r["failed"] for r in runs if r["label"].endswith(kind))}
(out / "summary.json").write_text(json.dumps(res, indent=1) + "\n")
print(json.dumps(res, indent=1))
PY
