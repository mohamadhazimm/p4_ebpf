#!/usr/bin/env python3
import argparse
import socket
import time

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--count", type=int, default=100)
    ap.add_argument("--sleep-ms", type=int, default=20)
    ap.add_argument("--timeout", type=float, default=0.5)
    args = ap.parse_args()

    ok = 0
    fail = 0

    for i in range(args.count):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(args.timeout)
        try:
            s.connect((args.host, args.port))
            s.sendall(f"msg {i}\n".encode())
            ok += 1
        except Exception:
            fail += 1
        finally:
            s.close()

        if args.sleep_ms > 0:
            time.sleep(args.sleep_ms / 1000.0)

    print(f"[INFO] done ok={ok} fail={fail}")

if __name__ == "__main__":
    main()

#LIGHT => python3 tcp_burst.py --host 192.168.100.1 --port 8080 --count 50 --sleep-ms 100
#HEAVY => python3 tcp_burst.py --host 192.168.100.1 --port 8080 --count 500 --sleep-ms 5