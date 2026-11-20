#!/usr/bin/env python3
import argparse
import subprocess
import tempfile
import time
from pathlib import Path

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rounds", type=int, default=30)
    ap.add_argument("--procs-per-round", type=int, default=8)
    ap.add_argument("--sleep-ms", type=int, default=50)
    args = ap.parse_args()

    workdir = Path(tempfile.mkdtemp(prefix="proc_fanout_"))
    print(f"[INFO] workdir={workdir}")

    for r in range(args.rounds):
        batch = []
        for i in range(args.procs_per_round):
            f = workdir / f"round{r:03d}_file{i:03d}.txt"
            f.write_text(f"hello round={r} file={i}\n")
            p = subprocess.Popen(
                ["python3", "-c", f"open(r'{f}', 'r').read()"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            batch.append(p)

        for p in batch:
            p.wait()

        if args.sleep_ms > 0:
            time.sleep(args.sleep_ms / 1000.0)

    print("[INFO] done")

if __name__ == "__main__":
    main()


#LIGHT => python3 proc_fanout.py --rounds 20 --procs-per-round 5 --sleep-ms 80
#HEAVY => python3 proc_fanout.py --rounds 80 --procs-per-round 20 --sleep-ms 10