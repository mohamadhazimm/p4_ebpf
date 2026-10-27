import hashlib
import re
import socket
import struct

MAGIC = 0x48574C31
ETHER_TYPE = 0x88BC
MASK48 = (1 << 48) - 1

def mac_bytes(value):
    raw = bytes.fromhex(value.replace(':', ''))
    if len(raw) != 6:
        raise ValueError('A MAC address must contain 6 bytes')
    return raw

def checksum(raw):
    if len(raw) % 2:
        raw += b'\x00'
    total = sum(struct.unpack('!%dH' % (len(raw) // 2), raw))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff

def build_probe(seq, source_mac, dest_mac):
    if not 0 <= seq <= 0xffffffff:
        raise ValueError('Sequence must fit in 32 bits')
    name = 'p%08x.latency.test' % seq
    qname = b''.join(bytes([len(label)]) + label.encode('ascii') for label in name.split('.')) + b'\x00'
    dns = struct.pack('!HHHHHH', seq & 0xffff, 0x0100, 1, 0, 0, 0) + qname + struct.pack('!HH', 1, 1)
    udp = struct.pack('!HHHH', 40000, 53, len(dns) + 8, 0) + dns
    src = socket.inet_aton('192.168.0.1')
    dst = socket.inet_aton('192.168.0.2')
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), seq & 0xffff, 0, 64, 17, 0, src, dst)
    ip = ip[:10] + struct.pack('!H', checksum(ip)) + ip[12:]
    return dest_mac + source_mac + struct.pack('!H', 0x0800) + ip + udp

def decode_report(raw):
    if len(raw) < 34 or struct.unpack('!H', raw[12:14])[0] != ETHER_TYPE:
        raise ValueError('Not a complete HWL1 Ethernet report')
    magic, original_type = struct.unpack('!IH', raw[14:20])
    if magic != MAGIC or original_type != 0x0800:
        raise ValueError('Unexpected report magic or original EtherType')
    t1 = int.from_bytes(raw[20:26], 'big')
    t2 = int.from_bytes(raw[26:32], 'big')
    score, tier = raw[32], raw[33]
    ip = raw[34:]
    if len(ip) < 40 or ip[0] != 0x45 or ip[9] != 17 or checksum(ip[:20]) != 0:
        raise ValueError('Expected a valid IPv4/UDP probe without IPv4 options')
    ip_length = struct.unpack('!H', ip[2:4])[0]
    if ip_length > len(ip) or ip_length < 40:
        raise ValueError('Truncated IPv4 probe')
    if ip[12:16] != socket.inet_aton('192.168.0.1') or ip[16:20] != socket.inet_aton('192.168.0.2'):
        raise ValueError('Probe addresses do not match the NETLAB test path')
    sport, dport, udp_length, _ = struct.unpack('!HHHH', ip[20:28])
    if sport != 40000 or dport != 53 or udp_length != ip_length - 20:
        raise ValueError('Unexpected probe UDP header')
    dns = ip[28:ip_length]
    dns_id, flags, qd, an, ns, ar = struct.unpack('!HHHHHH', dns[:12])
    if (flags, qd, an, ns, ar) != (0x0100, 1, 0, 0, 0):
        raise ValueError('Unexpected DNS probe header')
    labels = []
    pos = 12
    while True:
        if pos >= len(dns):
            raise ValueError('Truncated DNS name')
        length = dns[pos]
        pos += 1
        if length == 0:
            break
        if length > 63 or pos + length > len(dns):
            raise ValueError('Invalid DNS label')
        labels.append(dns[pos:pos + length].decode('ascii'))
        pos += length
    name = '.'.join(labels)
    if not re.fullmatch(r'p[0-9a-f]{8}\.latency\.test', name):
        raise ValueError('Not a generated latency probe name')
    if dns[pos:] != struct.pack('!HH', 1, 1):
        raise ValueError('Unexpected DNS question suffix')
    seq = int(labels[0][1:], 16)
    if dns_id != (seq & 0xffff):
        raise ValueError('Probe name and DNS ID disagree')
    original = raw[:12] + struct.pack('!H', original_type) + ip[:ip_length]

    if original != build_probe(seq, raw[6:12], raw[:6]):
        raise ValueError('Original probe bytes changed in the switch path')
    return {'seq': seq, 'qname': name, 'ingress_ns': t1, 'egress_ns': t2,
            'latency_ns': (t2 - t1) & MASK48, 'score': score, 'tier': tier,
            'original_sha256': hashlib.sha256(original).hexdigest()}

def pcap_header():
    return struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)

def pcap_record(raw, wall_time):
    sec = int(wall_time)
    usec = int((wall_time - sec) * 1e6)
    return struct.pack('<IIII', sec, usec, len(raw), len(raw)) + raw

def pcap_frames(path):
    with open(path, 'rb') as handle:
        head = handle.read(24)
        if len(head) != 24:
            raise ValueError('Truncated pcap header')
        formats = {b'\xd4\xc3\xb2\xa1': '<', b'\xa1\xb2\xc3\xd4': '>',
                   b'\x4d\x3c\xb2\xa1': '<', b'\xa1\xb2\x3c\x4d': '>'}
        endian = formats.get(head[:4])
        if not endian or struct.unpack(endian + 'I', head[20:24])[0] != 1:
            raise ValueError('Use classic Ethernet pcap, not pcapng or cooked capture')
        while True:
            record = handle.read(16)
            if not record:
                return
            if len(record) != 16:
                raise ValueError('Truncated pcap record header')
            _, _, caplen, _ = struct.unpack(endian + 'IIII', record)
            if caplen > 65535:
                raise ValueError('Invalid pcap capture length')
            raw = handle.read(caplen)
            if len(raw) != caplen:
                raise ValueError('Truncated pcap packet')
            yield raw
