import argparse
import hashlib
import json
import socket
import time
from probe_format import build_probe, mac_bytes

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--iface', default='eth1')
    parser.add_argument('--dst-mac', required=True, help='PC2 eth1 MAC, read on PC2')
    parser.add_argument('--count', type=int, default=1010)
    parser.add_argument('--rate', type=float, default=100)
    parser.add_argument('--log', default='sent_probes.jsonl')
    args = parser.parse_args()
    if args.count <= 0 or args.rate <= 0:
        parser.error('count and rate must be positive')
    destination = mac_bytes(args.dst_mac)
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    sock.bind((args.iface, 0))
    source = sock.getsockname()[4]
    start = time.monotonic()
    print('Sending {} probes at {} packets/s'.format(args.count, args.rate), flush=True)
    with open(args.log, 'w') as log:
        for seq in range(args.count):
            remaining = start + seq / args.rate - time.monotonic()
            if remaining > 0:
                time.sleep(remaining)
            frame = build_probe(seq, source, destination)
            sent = sock.send(frame)
            if sent != len(frame):
                raise RuntimeError('Incomplete packet transmission')
            log.write(json.dumps({'seq': seq, 'length': sent,
                                  'original_sha256': hashlib.sha256(frame).hexdigest()}) + '\n')
    sock.close()
    elapsed = time.monotonic() - start
    print('Sent {}; elapsed {:.3f} s. These are software submission counts, not a wire-rate qualification.'.format(args.count, elapsed))

if __name__ == '__main__':
    main()
