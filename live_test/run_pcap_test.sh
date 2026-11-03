#!/usr/bin/env bash
# The collector in PCAP mode on a synthetic benign capture, with captures of
# the switch ingress and the comparison (analyze_run.py).
#
#   sudo live_test/run_pcap_test.sh            WIN=30 INTERVAL=0.08 NAME=benign_mix
#
# Frames are injected on veth0/veth2 (the collector's --int-iface/--ext-iface),
# so "tcpdump -Q in" on veth1/veth3 records exactly what enters model ports 0
# and 1. Register reads take ~16 s on the model (register sync), so windows
# shorter than ~20 s overrun; WIN defaults to 30.
set -euo pipefail
REPO=$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)
LT=$REPO/live_test
WIN=${WIN:-30}
INTERVAL=${INTERVAL:-0.08}
NAME=${NAME:-benign_mix}
EXTRA=${EXTRA:-}
OUT=$LT/results/pcap_${NAME}_w${WIN}_$(date +%Y%m%d_%H%M%S)
mkdir -p "$OUT" "$LT/data"
[ -f "$LT/data/$NAME.pcap" ] || python3 "$LT/make_benign_pcap.py" --out "$LT/data/$NAME.pcap" \
    --truth "$LT/data/${NAME}_truth.json"
"$LT/testbed.sh" mode replay

tcpdump -i veth1 -Q in -U -s 0 --time-stamp-precision=nano -w "$OUT/ingress_port0.pcap" 2> "$OUT/tcpdump0.log" & P0=$!
tcpdump -i veth3 -Q in -U -s 0 --time-stamp-precision=nano -w "$OUT/ingress_port1.pcap" 2> "$OUT/tcpdump1.log" & P1=$!
sleep 2
set +e
# shellcheck disable=SC2086
(cd "$OUT" && python3 "$LT/collector_probe.py" --probe-out "$OUT/probe.json" -- \
    --mode pcap --scenario-name "${NAME}_replay" --label benign --pcap "$LT/data/$NAME.pcap" \
    --window-sec "$WIN" --drain-seconds 2 --int-iface veth0 --ext-iface veth2 --interval "$INTERVAL" \
    --out-csv "$OUT/windows.csv" --hostmon-log "$OUT/hostmon_capture.log" $EXTRA) > "$OUT/collector.log" 2>&1
rc=$?
set -e
sleep 1
kill -INT $P0 $P1; wait $P0 $P1 2>/dev/null || true
grep -v -E '^\[[0-9]+/[0-9]+\] via|Cryptography|cipher=' "$OUT/collector.log" | tail -25
echo "collector exit code: $rc"
chown -R "${SUDO_USER:-root}" "$OUT"
[ $rc -eq 0 ] || exit $rc
python3 "$LT/analyze_run.py" --csv "$OUT/windows.csv" --probe "$OUT/probe.json" \
    --ingress "$OUT/ingress_port0.pcap" "$OUT/ingress_port1.pcap" --window-sec "$WIN" \
    --truth "$LT/data/${NAME}_truth.json" --out "$OUT/analysis.json" 2>&1 \
    | grep -v -E 'Cryptography|cipher=' | tee "$OUT/analysis.txt"
chown -R "${SUDO_USER:-root}" "$OUT"
echo "results: $OUT"
