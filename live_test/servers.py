#!/usr/bin/env python3
"""Benign servers on the external side of the testbed (netns p4ext, 10.0.0.2).

    servers.py --bind 10.0.0.2 --www DIR [--http-port 8088] [--sink-port 9099]

HTTP (8088) serves the files in DIR. The TCP sink (9099) reads one message of
up to 64 KiB and answers "OK\n", as hybrid_data_generator.py and the testers
expect. Both run in one process whose name (comm) is set to "p4ext-srv", so its
syscalls can be told apart from the workload's in hostmon's per-process rows:
hostmon traces the whole machine, and in a real deployment this server would be
a different host.
"""
import argparse
import ctypes
import functools
import http.server
import socketserver
import threading

PR_SET_NAME = 15


def set_comm(name: str) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl(PR_SET_NAME, ctypes.c_char_p(name.encode()[:15]), 0, 0, 0)


class QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        pass


class SinkHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(2.0)
        try:
            data = self.request.recv(65536)
            if data:
                self.request.sendall(b"OK\n")
        except OSError:
            pass


class ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--bind", default="10.0.0.2")
    ap.add_argument("--www", required=True)
    ap.add_argument("--http-port", type=int, default=8088)
    ap.add_argument("--sink-port", type=int, default=9099)
    args = ap.parse_args()

    # Before any thread starts: threads inherit the name.
    set_comm("p4ext-srv")

    http.server.ThreadingHTTPServer.allow_reuse_address = True
    httpd = http.server.ThreadingHTTPServer(
        (args.bind, args.http_port), functools.partial(QuietHandler, directory=args.www))
    sink = ThreadingTCPServer((args.bind, args.sink_port), SinkHandler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    print(f"[servers] http://{args.bind}:{args.http_port}/ ({args.www}), "
          f"sink {args.bind}:{args.sink_port}", flush=True)
    sink.serve_forever()


if __name__ == "__main__":
    main()
