#!/usr/bin/env bash
# Benign workloads for command-mode collector runs (testbed.sh mode live).
# Run inside netns p4int as the unprivileged user; all network traffic goes to
# 10.0.0.2 (netns p4ext) through the P4 switch. Uses the repository's testers.
#
#   benign_workload.sh http|tcp|files|fanout|mixed|idle
set -u
T=$(cd "$(dirname "$(readlink -f "$0")")/../testers" && pwd)
SRV=10.0.0.2

http()   { python3 "$T/http_fetch_burst.py" --url "http://$SRV:8088/file_100k.bin" --count "${1:-30}" --sleep-ms 300; }
tcp()    { python3 "$T/tcp_burst.py" --host "$SRV" --port 9099 --count "${1:-50}" --sleep-ms 150; }
files()  { python3 "$T/archive_hash.py" --files 300; python3 "$T/bulk_copy_cleanup.py" --files 300 --sleep-ms 5; }
fanout() { python3 "$T/proc_fanout.py" --rounds 12 --procs-per-round 5 --sleep-ms 250; }

case "${1:-}" in
    http) http 40 ;;
    tcp) tcp 80 ;;
    files) files ;;
    fanout) fanout ;;
    mixed)
        http 20
        files
        tcp 40
        sleep 5
        fanout
        http 10
        ;;
    idle) sleep "${2:-30}" ;;
    *) echo "usage: $0 http|tcp|files|fanout|mixed|idle [seconds]" >&2; exit 2 ;;
esac
