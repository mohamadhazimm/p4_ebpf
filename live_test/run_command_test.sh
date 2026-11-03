#!/usr/bin/env bash
# The collector in command mode on a benign workload whose traffic crosses the
# switch (testbed "live" mode), with modelmon on the workload's process tree
# and captures of the switch ingress.
#
#   sudo live_test/run_command_test.sh [http|tcp|files|fanout|mixed|idle]    WIN=30 EXTRA="..."
#
# The workload (benign_workload.sh) runs in netns p4int as $SUDO_USER, behind
# gate.py, so modelmon is attached before its first instruction.
set -euo pipefail
REPO=$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)
LT=$REPO/live_test
SCEN=${1:-mixed}
WIN=${WIN:-30}
EXTRA=${EXTRA:-}
USER_=${SUDO_USER:-root}
OUT=$LT/results/cmd_${SCEN}_w${WIN}_$(date +%Y%m%d_%H%M%S)
GATE=$OUT/gate
mkdir -p "$GATE"
chown "$USER_" "$GATE"
"$LT/testbed.sh" mode live

tcpdump -i veth1 -Q in -U -s 0 --time-stamp-precision=nano -w "$OUT/ingress_port0.pcap" 2> "$OUT/tcpdump0.log" & P0=$!
tcpdump -i veth3 -Q in -U -s 0 --time-stamp-precision=nano -w "$OUT/ingress_port1.pcap" 2> "$OUT/tcpdump1.log" & P1=$!
sleep 2
CMD="ip netns exec p4int setpriv --reuid=$USER_ --regid=$USER_ --init-groups python3 $LT/gate.py --pidfile $GATE/gate.pid --fifo $GATE/gate.fifo -- bash $LT/benign_workload.sh $SCEN"
set +e
# shellcheck disable=SC2086
(cd "$OUT" && python3 "$LT/collector_probe.py" --probe-out "$OUT/probe.json" --modelmon-gate "$GATE" \
    --modelmon-window "$WIN" -- --mode command --scenario-name "benign_$SCEN" --label benign \
    --command "$CMD" --window-sec "$WIN" --out-csv "$OUT/windows.csv" \
    --hostmon-log "$OUT/hostmon_capture.log" $EXTRA) > "$OUT/collector.log" 2>&1
rc=$?
set -e
sleep 1
kill -INT $P0 $P1; wait $P0 $P1 2>/dev/null || true
grep -v -E 'Cryptography|cipher=' "$OUT/collector.log" | grep -E '^\[|Traceback|Error' | tail -20
echo "collector exit code: $rc tcpdump pids: $P0 $P1" | tee "$OUT/run_info.txt"
chown -R "$USER_" "$OUT"
[ $rc -eq 0 ] || exit $rc
python3 "$LT/analyze_run.py" --csv "$OUT/windows.csv" --probe "$OUT/probe.json" \
    --ingress "$OUT/ingress_port0.pcap" "$OUT/ingress_port1.pcap" --window-sec "$WIN" \
    --workload-match gate.py --out "$OUT/analysis.json" 2>&1 | grep -v -E 'Cryptography|cipher=' | tee "$OUT/analysis.txt"
chown -R "$USER_" "$OUT"
echo "results: $OUT"
