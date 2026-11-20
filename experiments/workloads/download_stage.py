#!/usr/bin/env python3
import os
import time
import urllib.request
from pathlib import Path

URL = "http://172.16.11.2:8005/payload.bin"
OUTDIR = Path("/tmp/hybrid_stage")
OUTDIR.mkdir(parents=True, exist_ok=True)

for i in range(10):
    tmp_file = OUTDIR / f"tmp_{i}.bin"
    final_file = OUTDIR / f"stage_{i}.dat"

    with urllib.request.urlopen(URL, timeout=3) as r:
        data = r.read()

    with open(tmp_file, "wb") as f:
        f.write(data)

    os.rename(tmp_file, final_file)

    with open(final_file, "rb") as f:
        _ = f.read(64)

    time.sleep(0.3)

