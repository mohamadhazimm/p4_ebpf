#!/usr/bin/env python3
import argparse
import hashlib
import tarfile
import tempfile
from pathlib import Path

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--files", type=int, default=500)
    args = ap.parse_args()

    base = Path(tempfile.mkdtemp(prefix="archive_hash_"))
    src = base / "src"
    ext = base / "extract"
    src.mkdir()
    ext.mkdir()

    for i in range(args.files):
        (src / f"item_{i:05d}.txt").write_text(("data-%d\n" % i) * 50)

    archive = base / "bundle.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        tar.add(src, arcname="src")

    with tarfile.open(archive, "r:gz") as tar:
        tar.extractall(ext)

    count = 0
    for f in (ext / "src").glob("*.txt"):
        _ = sha256_file(f)
        count += 1

    print(f"[INFO] files={count} base={base}")

if __name__ == "__main__":
    main()

#LIGHT => python3 archive_hash.py --files 200
#HEAVY => python3 archive_hash.py --files 2000