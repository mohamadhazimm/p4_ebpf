#!/usr/bin/env python3
"""
Hybrid Dataset Activity Generator (P4 veth version)
---------------------------------------------------

All HTTP and TCP traffic now goes through the P4 veth interfaces (e.g., 10.0.0.2),
so the hybrid collector can capture non-zero network features. HostMon activity
(file writes, processes, child commands) is unchanged.
"""

import argparse
import base64
import csv
import hashlib
import http.server
import os
import random
import socket
import string
import subprocess
import sys
import threading
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

# ========================
# Utility functions
# ========================

def utc_now():
    return datetime.now(timezone.utc).isoformat()

def random_text(size=128):
    alphabet = string.ascii_letters + string.digits + " "
    return "".join(random.choice(alphabet) for _ in range(size))

def random_bytes(size=1024):
    return os.urandom(size)

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(4096):
            h.update(chunk)
    return h.hexdigest()

def ensure_dir(path):
    Path(path).mkdir(parents=True, exist_ok=True)

def safe_sleep(min_s=0.2, max_s=1.5):
    time.sleep(random.uniform(min_s, max_s))

def write_label(writer, scenario, label, pid, details=""):
    writer.writerow({
        "timestamp_utc": utc_now(),
        "scenario": scenario,
        "label": label,
        "pid": pid,
        "details": details
    })

# ========================
# Local HTTP server
# ========================

class QuietHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        return

def start_local_http_server(directory, host="0.0.0.0", port=8088):
    old_cwd = os.getcwd()
    os.chdir(directory)
    server = http.server.ThreadingHTTPServer((host, port), QuietHTTPRequestHandler)

    def run_server():
        try:
            server.serve_forever()
        except Exception:
            pass

    thread = threading.Thread(target=run_server, daemon=True)
    thread.start()
    os.chdir(old_cwd)
    return server

# ========================
# Local TCP sink
# ========================

def start_tcp_sink(host="0.0.0.0", port=9099):
    stop_event = threading.Event()

    def server_loop():
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((host, port))
        srv.listen(50)
        srv.settimeout(1.0)
        while not stop_event.is_set():
            try:
                conn, _ = srv.accept()
                conn.settimeout(1.0)
                try:
                    _ = conn.recv(4096)
                    conn.sendall(b"OK\n")
                except Exception:
                    pass
                finally:
                    conn.close()
            except socket.timeout:
                continue
            except Exception:
                break
        srv.close()

    thread = threading.Thread(target=server_loop, daemon=True)
    thread.start()
    return stop_event

# ========================
# Child scenarios
# ========================

def child_benign_http(base_url, workdir):
    paths = ["/index.html","/about.html","/image.txt","/data.json","/notes.txt"]
    for _ in range(random.randint(5,12)):
        url = base_url + random.choice(paths)
        try:
            with urllib.request.urlopen(url, timeout=5) as resp:
                _ = resp.read()
        except Exception:
            pass
        safe_sleep(0.3,1.2)

def child_benign_dns():
    domains = ["example.com","openai.com","github.com","python.org","wikipedia.org"]
    for d in domains:
        try:
            socket.gethostbyname(d)
        except Exception:
            pass
        safe_sleep(0.4,1.4)

def child_benign_file_activity(workdir):
    ensure_dir(workdir)
    for i in range(random.randint(5,10)):
        path = Path(workdir)/f"benign_note_{os.getpid()}_{i}.txt"
        with open(path,"w",encoding="utf-8") as f:
            f.write("Normal user note\n")
            f.write(random_text(random.randint(100,600)))
        with open(path,"r",encoding="utf-8") as f: _ = f.read()
        safe_sleep(0.2,1.0)

def child_benign_local_tcp(host, port):
    for i in range(random.randint(5,15)):
        try:
            s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect((host, port))  # now goes through veth
            s.sendall(f"normal-message-{i}".encode())
            _ = s.recv(1024)
            s.close()
        except Exception:
            pass
        safe_sleep(0.3,1.3)

def child_suspicious_beacon(host, port):
    for i in range(random.randint(12,25)):
        try:
            s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect((host, port))
            s.sendall(str({"type":"simulated_beacon","seq":i,"pid":os.getpid(),"note":"safe_local_simulation"}).encode())
            _ = s.recv(1024)
            s.close()
        except Exception:
            pass
        safe_sleep(0.4,1.0)

def child_suspicious_port_sweep(host):
    ports = list(range(8000,8025)) + [8088,9099,22,80,443]
    random.shuffle(ports)
    for p in ports:
        try:
            s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            s.settimeout(0.25)
            s.connect_ex((host,p))
            s.close()
        except Exception:
            pass
        safe_sleep(0.03,0.12)

def child_suspicious_burst_connections(host, port):
    for i in range(random.randint(30,70)):
        try:
            s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            s.settimeout(1)
            s.connect((host, port))
            s.sendall(f"burst-{i}".encode())
            s.close()
        except Exception:
            pass
        safe_sleep(0.01,0.08)

def child_suspicious_file_burst(workdir):
    suspicious_dir = Path(workdir)/f"suspicious_file_burst_{os.getpid()}"
    ensure_dir(suspicious_dir)
    for i in range(random.randint(30,80)):
        path = suspicious_dir/f"generated_{i}.dat"
        with open(path,"wb") as f:
            f.write(random_bytes(random.randint(512,4096)))
        if i%10==0:
            try: _ = sha256_file(path)
            except Exception: pass
        safe_sleep(0.01,0.06)

def child_suspicious_encoded_payload(workdir, host, port):
    ensure_dir(workdir)
    harmless = "This is a harmless encoded payload used only for dataset generation. It simulates suspicious encoding behavior without executing malware."
    encoded = base64.b64encode(harmless.encode()).decode()
    payload_file = Path(workdir)/f"encoded_payload_{os.getpid()}.txt"
    decoded_file = Path(workdir)/f"decoded_payload_{os.getpid()}.txt"
    with open(payload_file,"w",encoding="utf-8") as f: f.write(encoded)
    safe_sleep(0.2,0.8)
    decoded = base64.b64decode(encoded.encode()).decode()
    with open(decoded_file,"w",encoding="utf-8") as f: f.write(decoded)
    try:
        s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((host, port))
        s.sendall(encoded[:128].encode())
        s.close()
    except Exception:
        pass

# ========================
# Parent process
# ========================

def launch_child(scenario, args):
    cmd = [
        sys.executable,
        os.path.abspath(__file__),
        "--child",
        "--scenario", scenario,
        "--workdir", args.workdir,
        "--http-port", str(args.http_port),
        "--tcp-port", str(args.tcp_port)
    ]
    return subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def create_http_files(workdir):
    ensure_dir(workdir)
    files = {
        "index.html":"<html><body><h1>Test Page</h1></body></html>",
        "about.html":"<html><body><p>Benign local page.</p></body></html>",
        "image.txt":random_text(2048),
        "data.json":'{"status":"ok","source":"local-test"}',
        "notes.txt":random_text(4096)
    }
    for name, content in files.items():
        with open(Path(workdir)/name,"w",encoding="utf-8") as f: f.write(content)

# ========================
# Run parent / dispatcher
# ========================

def run_parent(args):
    ensure_dir(args.workdir)
    http_dir = Path(args.workdir)/"http_root"
    create_http_files(http_dir)

    print("[+] Starting local HTTP server...")
    # http_server = start_local_http_server(
    #     str(http_dir),
    #     host="0.0.0.0",
    #     port=args.http_port
    # )    
    print("[+] Starting local TCP sink...")
    # tcp_stop_event = start_tcp_sink(
    #     host="0.0.0.0",
    #     port=args.tcp_port
    # )

    scenarios = [
        ("benign_http_browsing","benign"),
        ("benign_dns_lookup","benign"),
        ("benign_file_activity","benign"),
        ("benign_local_tcp","benign"),
        ("suspicious_beacon","suspicious"),
        ("suspicious_port_sweep","suspicious"),
        ("suspicious_burst_connections","suspicious"),
        ("suspicious_file_burst","suspicious"),
        ("suspicious_encoded_payload","suspicious"),
    ]

    start = time.time()
    end = start + args.duration
    with open(args.out,"w",newline="",encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=["timestamp_utc","scenario","label","pid","details"])
        writer.writeheader()
        running = []
        while time.time()<end:
            scenario,label = random.choice(scenarios)
            proc = launch_child(scenario,args)
            running.append(proc)
            write_label(writer,scenario,label,proc.pid,f"child process launched for {scenario}")
            csvfile.flush()
            safe_sleep(args.min_gap,args.max_gap)
            running = [p for p in running if p.poll() is None]

        for p in running:
            try: p.wait(timeout=10)
            except subprocess.TimeoutExpired: p.terminate()
    try: http_server.shutdown()
    except Exception: pass
    try: tcp_stop_event.set()
    except Exception: pass
    print("[+] Done. Labels saved in:", args.out)

def run_child(args):
    host = "10.0.0.2"  # P4 veth external port
    base_url = f"http://{host}:{args.http_port}"
    if args.scenario=="benign_http_browsing": child_benign_http(base_url,args.workdir)
    elif args.scenario=="benign_dns_lookup": child_benign_dns()
    elif args.scenario=="benign_file_activity": child_benign_file_activity(args.workdir)
    elif args.scenario=="benign_local_tcp": child_benign_local_tcp(host,args.tcp_port)
    elif args.scenario=="suspicious_beacon": child_suspicious_beacon(host,args.tcp_port)
    elif args.scenario=="suspicious_port_sweep": child_suspicious_port_sweep(host)
    elif args.scenario=="suspicious_burst_connections": child_suspicious_burst_connections(host,args.tcp_port)
    elif args.scenario=="suspicious_file_burst": child_suspicious_file_burst(args.workdir)
    elif args.scenario=="suspicious_encoded_payload": child_suspicious_encoded_payload(args.workdir,host,args.tcp_port)
    else: raise ValueError(f"Unknown scenario: {args.scenario}")

def parse_args():
    parser = argparse.ArgumentParser(description="Safe hybrid dataset generator")
    parser.add_argument("--duration",type=int,default=600)
    parser.add_argument("--out",type=str,default="hybrid_labels.csv")
    parser.add_argument("--workdir",type=str,default="./hybrid_dataset_workdir")
    parser.add_argument("--http-port",type=int,default=8088)
    parser.add_argument("--tcp-port",type=int,default=9099)
    parser.add_argument("--min-gap",type=float,default=1.0)
    parser.add_argument("--max-gap",type=float,default=4.0)
    parser.add_argument("--child",action="store_true")
    parser.add_argument("--scenario",type=str,default=None)
    return parser.parse_args()

def main():
    args = parse_args()
    if args.child:
        if not args.scenario: raise ValueError("Child mode requires --scenario")
        run_child(args)
    else:
        try: run_parent(args)
        finally:
            if os.path.exists(args.workdir):
                print(f"[i] Generated files remain in: {args.workdir}")
                print("[i] You can delete them later with: rm -rf {args.workdir}")

if __name__=="__main__":
    main()