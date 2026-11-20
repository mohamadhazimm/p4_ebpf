#!/usr/bin/env python3
import argparse
import shutil
import tempfile
import time
from pathlib import Path

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--files", type=int, default=1000)
    ap.add_argument("--sleep-ms", type=int, default=2)
    args = ap.parse_args()

    base = Path(tempfile.mkdtemp(prefix="bulk_copy_"))
    src = base / "src"
    dst = base / "dst"
    src.mkdir()
    dst.mkdir()

    for i in range(args.files):
        (src / f"file_{i:05d}.txt").write_text("A" * 512)

    for f in src.glob("*.txt"):
        out = dst / f.name
        shutil.copy2(f, out)
        renamed = out.with_suffix(".copied")
        out.rename(renamed)
        if f.stat().st_size % 2 == 0:
            f.unlink()
        if args.sleep_ms > 0:
            time.sleep(args.sleep_ms / 1000.0)

    print(f"[INFO] finished in {base}")

if __name__ == "__main__":
    main()

#LIGHT => python3 bulk_copy_cleanup.py --files 300 --sleep-ms 5
#HEAVY => python3 bulk_copy_cleanup.py --files 3000 --sleep-ms 1