#!/usr/bin/env python3
import time
import urllib.request

URL = "http://172.16.11.2:8000/test.txt"
ROUNDS = 20
SLEEP_SEC = 0.5

for i in range(ROUNDS):
    with urllib.request.urlopen(URL, timeout=3) as r:
        _ = r.read()
    time.sleep(SLEEP_SEC)