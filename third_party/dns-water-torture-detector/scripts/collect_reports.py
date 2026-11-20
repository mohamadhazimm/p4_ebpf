import argparse
import csv
import json
import math
from pathlib import Path
import socket
import statistics
import time
from probe_format import ETHER_TYPE, build_probe, decode_report, pcap_frames, pcap_header, pcap_record

def quantile(values, fraction):
    ordered = sorted(values)
    point = (len(ordered) - 1) * fraction
    lo = int(math.floor(point))
    hi = int(math.ceil(point))
    return ordered[lo] + (ordered[hi] - ordered[lo]) * (point - lo)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--iface', default='eth1')
    parser.add_argument('--pcap', help='Offline input, instead of live capture')
    parser.add_argument('--seconds', type=float, default=60)
    parser.add_argument('--expected-count', type=int, default=1010)
    parser.add_argument('--warmup', type=int, default=10)
    parser.add_argument('--out', default='run1')
    args = parser.parse_args()
    if args.seconds <= 0 or args.expected_count <= args.warmup or args.warmup < 0:
        parser.error('Positive duration/count required; count must exceed warmup')
    output = Path(args.out)
    output.mkdir(parents=True, exist_ok=False)
    rows = {}
    counts = {'malformed_reports': 0, 'out_of_range': 0, 'duplicates': 0}

    def accept(raw):
        try:
            row = decode_report(raw)
        except (ValueError, UnicodeDecodeError, IndexError):
            counts['malformed_reports'] += 1
            return
        if not 0 <= row['seq'] < args.expected_count:
            counts['out_of_range'] += 1
        elif row['seq'] in rows:
            counts['duplicates'] += 1
        else:
            rows[row['seq']] = row

    if args.pcap:
        for raw in pcap_frames(args.pcap):
            if len(raw) >= 14 and int.from_bytes(raw[12:14], 'big') == ETHER_TYPE:
                accept(raw)
    else:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETHER_TYPE))
        sock.bind((args.iface, 0))
        sock.settimeout(0.25)
        deadline = time.monotonic() + args.seconds
        with open(str(output / 'reports.pcap'), 'wb') as capture:
            capture.write(pcap_header())
            print('READY on {}; start PC1 sender now.'.format(args.iface), flush=True)
            while time.monotonic() < deadline and len(rows) < args.expected_count:
                try:
                    raw, address = sock.recvfrom(65535)
                except socket.timeout:
                    continue
                if address[2] == socket.PACKET_OUTGOING:
                    continue

                capture.write(pcap_record(raw, time.time()))
                accept(raw)
        sock.close()
    ordered = [rows[key] for key in sorted(rows)]
    fields = ['seq', 'qname', 'ingress_ns', 'egress_ns', 'latency_ns', 'score', 'tier', 'original_sha256']
    with open(str(output / 'packet_latencies.csv'), 'w', newline='') as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(ordered)
    measured = [row['latency_ns'] for row in ordered if row['seq'] >= args.warmup]
    summary = {'boundary': 'ingress-parser arrival to egress-parser arrival',
               'units': 'nanoseconds', 'expected_sent': args.expected_count,
               'probe_ethernet_bytes_without_fcs': len(build_probe(0, bytes(6), bytes(6))),
               'output_report_overhead_bytes': 20,
               'unique_reports': len(ordered), 'missing_reports': args.expected_count - len(ordered),
               'warmup_sequence_range': [0, args.warmup - 1] if args.warmup else [],
               'measured_packets': len(measured), 'capture_counts': counts,
               'clock_source': 'two 48-bit timestamps from the Tofino ASIC',
               'includes': 'ingress processing and intervening traffic-manager buffering',
               'excludes': 'remaining egress processing, output MAC and cables, BlueField trip',
               'pcap_timestamps_used_for_latency': False,
               'missing_reports_note': 'Missing reports can include path loss or capture loss; inspect port/capture counters.'}
    if measured:
        summary.update(min_ns=min(measured), mean_ns=statistics.mean(measured),
                       median_ns=statistics.median(measured), p95_ns=quantile(measured, .95),
                       p99_ns=quantile(measured, .99), max_ns=max(measured))
    else:
        summary['error'] = 'No measured probes; check runtime, ports and loader.'
    with open(str(output / 'summary.json'), 'w') as handle:
        json.dump(summary, handle, indent=2)
        handle.write('\n')
    print(json.dumps(summary, indent=2))

if __name__ == '__main__':
    main()
