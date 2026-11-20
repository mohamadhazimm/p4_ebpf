#!/usr/bin/env python3
import argparse
import os
import random
import shutil
import socket
import string
import tempfile
import time
from pathlib import Path


def rand_text(size: int) -> str:
    alphabet = string.ascii_letters + string.digits + " \n"
    return "".join(random.choice(alphabet) for _ in range(size))


def make_seed_files(base: Path, num_files: int, min_size: int, max_size: int) -> None:
    base.mkdir(parents=True, exist_ok=True)
    for i in range(num_files):
        subdir = base / f"dir_{i % 20:02d}"
        subdir.mkdir(parents=True, exist_ok=True)
        f = subdir / f"file_{i:05d}.txt"
        if not f.exists():
            size = random.randint(min_size, max_size)
            f.write_text(rand_text(size), encoding="utf-8")


def rewrite_and_rename(
    base: Path,
    sleep_ms: int,
    delete_original: bool,
    append_marker: str,
) -> None:
    files = sorted(base.rglob("*.txt"))
    for f in files:
        try:
            original = f.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        transformed = original[::-1] + f"\n{append_marker}\n"

        tmp_out = f.with_suffix(".tmp")
        processed = f.with_suffix(".processed")
        backup = f.with_suffix(".bak")

        try:
            tmp_out.write_text(transformed, encoding="utf-8")
            os.replace(f, backup)          # rename original -> .bak
            os.replace(tmp_out, processed) # rename tmp -> .processed

            if delete_original and backup.exists():
                backup.unlink()

        except Exception as e:
            print(f"[WARN] failed on {f}: {e}")

        if sleep_ms > 0:
            time.sleep(sleep_ms / 1000.0)


def local_connect_burst(host: str, port: int, count: int, timeout: float, sleep_ms: int) -> None:
    for _ in range(count):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect((host, port))
            try:
                s.sendall(b"hello\n")
            except Exception:
                pass
        except Exception:
            pass
        finally:
            s.close()

        if sleep_ms > 0:
            time.sleep(sleep_ms / 1000.0)


def main() -> None:
    ap = argparse.ArgumentParser(description="Safe synthetic file churn workload")
    ap.add_argument("--workdir", default="", help="Directory to operate in; default creates a temp dir")
    ap.add_argument("--files", type=int, default=500, help="Number of seed files")
    ap.add_argument("--min-size", type=int, default=200, help="Minimum file size in bytes")
    ap.add_argument("--max-size", type=int, default=1200, help="Maximum file size in bytes")
    ap.add_argument("--sleep-ms", type=int, default=5, help="Sleep between file operations")
    ap.add_argument("--delete-original", action="store_true", help="Delete .bak after rename")
    ap.add_argument("--append-marker", default="SAFE_SYNTHETIC_CHURN", help="Marker appended to processed files")

    ap.add_argument("--connect-burst", type=int, default=0, help="Number of TCP connect attempts")
    ap.add_argument("--connect-host", default="127.0.0.1", help="Host for TCP connects")
    ap.add_argument("--connect-port", type=int, default=8080, help="Port for TCP connects")
    ap.add_argument("--connect-timeout", type=float, default=0.2, help="TCP connect timeout")
    ap.add_argument("--connect-sleep-ms", type=int, default=10, help="Sleep between connect attempts")

    ap.add_argument("--cleanup", action="store_true", help="Delete workdir at the end if it was auto-created")
    args = ap.parse_args()

    random.seed(42)

    auto_dir = False
    if args.workdir:
        base = Path(args.workdir).expanduser().resolve()
        base.mkdir(parents=True, exist_ok=True)
    else:
        base = Path(tempfile.mkdtemp(prefix="safe_churn_"))
        auto_dir = True

    print(f"[INFO] workdir={base}")
    print("[INFO] creating seed files")
    make_seed_files(base, args.files, args.min_size, args.max_size)

    print("[INFO] rewriting and renaming files")
    rewrite_and_rename(
        base=base,
        sleep_ms=args.sleep_ms,
        delete_original=args.delete_original,
        append_marker=args.append_marker,
    )

    if args.connect_burst > 0:
        print(f"[INFO] performing {args.connect_burst} TCP connect attempts to {args.connect_host}:{args.connect_port}")
        local_connect_burst(
            host=args.connect_host,
            port=args.connect_port,
            count=args.connect_burst,
            timeout=args.connect_timeout,
            sleep_ms=args.connect_sleep_ms,
        )

    print("[INFO] done")

    if args.cleanup and auto_dir:
        print(f"[INFO] cleaning up {base}")
        shutil.rmtree(base, ignore_errors=True)


if __name__ == "__main__":
    main()