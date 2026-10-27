#!/usr/bin/env bash
# Start, stop or inspect bf_switchd on the switch. Runs on the switch.
#
#   sw_switchd.sh start CONF_FILE LOG_DIR   start our switchd in tmux session hz_sw
#   sw_switchd.sh stop                       stop the switchd running in hz_sw
#   sw_switchd.sh stop-lab                   Ctrl-C the lab switchd in tmux session sw
#   sw_switchd.sh status                     print switchd processes and listeners
#   sw_switchd.sh safety                     check our switchd survives a bfshell disconnect
#   sw_switchd.sh ready [SECONDS]            wait until device 0 is ready (status server)
#
# Our switchd runs via the lab's run_switchd.sh, under nohup, with
# --background, inside a tmux pane: it ignores SIGHUP, has the pane as its
# controlling terminal and is not a session leader, so the bfshell PTY hangup
# that killed a setsid-launched switchd in Phase 0 cannot reach it.
set -u
SDE=/root/bf-sde-9.6.0
ENV_SH=/root/P4_labs/lab2/config_env.sh
SESSION=hz_sw
LAB_SESSION=sw

switchd_pids() { pgrep -x bf_switchd || true; }

listening() {  # listening PORT -> 0 if some process listens on TCP PORT
    ss -ltn 2> /dev/null | awk '{print $4}' | grep -qE "[:.]$1\$"
}

wait_gone() {  # wait_gone PID SECONDS
    local i
    for ((i = 0; i < $2; i++)); do
        kill -0 "$1" 2> /dev/null || return 0
        sleep 1
    done
    return 1
}

is_descendant() {  # is_descendant PID ANCESTOR
    local p=$1
    while [ -n "$p" ] && [ "$p" -gt 1 ]; do
        [ "$p" = "$2" ] && return 0
        p=$(ps -o ppid= -p "$p" | tr -d ' ')
    done
    return 1
}

show_status() {
    local pids
    pids=$(switchd_pids | paste -sd, -)
    echo "--- bf_switchd processes:"
    if [ -n "$pids" ]; then
        ps -o pid,ppid,sid,tty,etime,args -p "$pids" | cut -c1-200
    else
        echo "(none)"
    fi
    echo "--- listeners 7777/9999/9090/50052:"
    ss -ltnp 2> /dev/null | grep -E ":(7777|9999|9090|50052)\b" || echo "(none)"
    echo "--- tmux sessions:"
    tmux ls 2>&1
}

safety() {
    local pid sid ign
    pid=$(pgrep -x bf_switchd | head -1)
    if [ -z "$pid" ]; then
        echo "SAFETY: no bf_switchd running"
        return 1
    fi
    sid=$(ps -o sid= -p "$pid" | tr -d ' ')
    ign=$(awk '/^SigIgn:/ {print $2}' /proc/"$pid"/status)
    # SIGHUP is signal 1, i.e. bit 0 of the SigIgn mask.
    local hup_ignored=$(( 0x$ign & 1 ))
    echo "pid=$pid sid=$sid tty=$(ps -o tty= -p "$pid" | tr -d ' ') SigIgn=$ign" \
         "sighup_ignored=$hup_ignored session_leader=$([ "$sid" = "$pid" ] && echo yes || echo no)"
    if [ "$hup_ignored" = 1 ] && [ "$sid" != "$pid" ]; then
        echo "SAFETY: OK (SIGHUP ignored and not a session leader)"
    else
        echo "SAFETY: NOT SAFE for bfshell"
        return 1
    fi
}

case "${1:-}" in
start)
    conf=${2:?conf file}; logdir=${3:?log dir}
    if [ -n "$(switchd_pids)" ]; then
        echo "refusing to start: bf_switchd already running"; show_status; exit 1
    fi
    [ -r "$conf" ] || { echo "conf not readable: $conf"; exit 1; }
    mkdir -p "$logdir"
    # One console log per start, so a stopped switchd's log is neither
    # overwritten nor mistaken for this one's.
    log=$logdir/switchd_console_$(basename "$conf" .conf)_$(date -u +%Y%m%dT%H%M%SZ).log
    tmux has-session -t "$SESSION" 2> /dev/null && tmux kill-session -t "$SESSION"
    tmux new-session -d -s "$SESSION" -x 200 -y 50 \
        "cd $SDE && . $ENV_SH > /dev/null && nohup ./run_switchd.sh -c $conf -- --background \
         < /dev/null > $log 2>&1; \
         echo \"run_switchd.sh exited rc=\$? at \$(date -u +%FT%TZ)\" >> $log; \
         sleep 86400"
    echo "started tmux session $SESSION at $(date -u +%FT%TZ); console log $log"
    echo "waiting for 9999 and 50052"
    for ((i = 0; i < 240; i += 2)); do
        if listening 9999 && listening 50052; then
            echo "listeners up after ${i}s"
            break
        fi
        if ! tmux has-session -t "$SESSION" 2> /dev/null || grep -qs "run_switchd.sh exited" "$log"; then
            echo "switchd exited during start-up"; tail -30 "$log"; exit 1
        fi
        sleep 2
    done
    listening 9999 && listening 50052 || { echo "timeout waiting for listeners"; exit 1; }
    show_status
    safety
    ;;
stop)
    pid=$(switchd_pids | head -1)
    [ -z "$pid" ] && { echo "no bf_switchd running"; exit 0; }
    pane=$(tmux list-panes -t "$SESSION" -F '#{pane_pid}' 2> /dev/null | head -1)
    if [ -z "$pane" ] || ! is_descendant "$pid" "$pane"; then
        echo "pid $pid was not started from tmux session $SESSION; not stopping it"; exit 1
    fi
    kill -INT "$pid"
    wait_gone "$pid" 30 || { echo "still running after SIGINT; sending SIGTERM"; kill -TERM "$pid"; wait_gone "$pid" 15; }
    kill -0 "$pid" 2> /dev/null && { echo "pid $pid did not exit"; exit 1; }
    echo "stopped pid $pid"
    show_status
    ;;
stop-lab)
    pid=$(switchd_pids | head -1)
    [ -z "$pid" ] && { echo "no bf_switchd running"; exit 0; }
    echo "lab switchd: $(ps -o pid,etime,args -p "$pid" | tail -1 | cut -c1-160)"
    tmux has-session -t "$LAB_SESSION" 2> /dev/null || { echo "no tmux session $LAB_SESSION"; exit 1; }
    lpane=$(tmux list-panes -t "$LAB_SESSION" -F '#{pane_pid}' | head -1)
    if ! is_descendant "$pid" "$lpane"; then
        echo "pid $pid is not running in tmux session $LAB_SESSION; not sending Ctrl-C"; exit 1
    fi
    tmux send-keys -t "$LAB_SESSION" C-c
    if wait_gone "$pid" 30; then
        echo "lab switchd pid $pid exited after Ctrl-C"
    else
        echo "pid $pid still running 30 s after Ctrl-C; not escalating"; exit 1
    fi
    sleep 1
    show_status
    echo "--- last lines of the lab pane:"
    tmux capture-pane -p -t "$LAB_SESSION" | grep -v '^$' | tail -5
    ;;
status) show_status ;;
safety) safety ;;
ready)
    # The SDE's bf_switchd_dev_status.py asks "localhost", which does not
    # resolve here; ask the status server on 127.0.0.1 directly.
    python3 - "${2:-120}" << 'EOF'
import socket, sys, time
deadline = time.time() + int(sys.argv[1])
while True:
    try:
        s = socket.create_connection(("127.0.0.1", 7777), timeout=2)
        s.sendall(b"0")
        r = s.recv(1)
        s.close()
        if r == b"1":
            print("device 0 ready")
            sys.exit(0)
    except OSError:
        pass
    if time.time() > deadline:
        print("device 0 not ready before timeout")
        sys.exit(1)
    time.sleep(1)
EOF
    ;;
*) sed -n '2,10p' "$0"; exit 2 ;;
esac
