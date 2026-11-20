#!/usr/bin/env python3
import argparse
import tempfile
import time
import urllib.request
from pathlib import Path

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True)
    ap.add_argument("--count", type=int, default=100)
    ap.add_argument("--sleep-ms", type=int, default=50)
    args = ap.parse_args()

    outdir = Path(tempfile.mkdtemp(prefix="http_fetch_"))
    print(f"[INFO] outdir={outdir}")

    for i in range(args.count):
        out = outdir / f"resp_{i:04d}.bin"
        with urllib.request.urlopen(args.url, timeout=2) as r:
            out.write_bytes(r.read())
        if args.sleep_ms > 0:
            time.sleep(args.sleep_ms / 1000.0)

    print("[INFO] done")

if __name__ == "__main__":
    main()

#LIGHT => python3 http_fetch_burst.py --url http://192.168.100.1:8000/test.bin --count 30 --sleep-ms 200
#HEAVY => python3 http_fetch_burst.py --url http://192.168.100.1:8000/test.bin --count 300 --sleep-ms 10