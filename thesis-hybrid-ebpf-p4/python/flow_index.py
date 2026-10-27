"""Flow index of thesis-hybrid-ebpf-p4, computed exactly as the Tofino does.

ingress.p4 hashes {srcAddr, dstAddr, l4_sport, l4_dport, protocol} with
Hash<bit<16>>(HashAlgorithm_t.CRC16) and @symmetric on the address pair and on
the port pair. bf-p4c (SDE 9.6.0) compiles that to CRC-16/ARC (polynomial
0x8005 reflected, init 0, xorout 0) over the 13 bytes

    0x00000000 | sip ^ dip | 0x0000 | sport ^ dport | proto     (network order)

This was checked against the compiled hash matrix (perf/tools/hash_matrix_check.py)
and on the switch. The index is therefore the same for both directions of a
connection, and different flows with equal address XOR and port XOR share a
bucket.

Since the data plane also puts the index into every CPU report
(cpu_report_t.flow_index), this is only needed where no report is available,
e.g. to predict buckets offline.
"""
import socket
import struct
from typing import Union

FLOW_BUCKETS = 65536


def crc16_arc(data: bytes) -> int:
    crc = 0
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
    return crc


def ip_to_u32(ip: Union[str, int]) -> int:
    if isinstance(ip, int):
        return ip & 0xFFFFFFFF
    return struct.unpack("!I", socket.inet_aton(ip))[0]


def compute_flow_index(src_ip: Union[str, int], dst_ip: Union[str, int],
                       sport: int, dport: int, proto: int) -> int:
    ip_x = ip_to_u32(src_ip) ^ ip_to_u32(dst_ip)
    blob = struct.pack("!IIHHB", 0, ip_x, 0, (sport ^ dport) & 0xFFFF, proto & 0xFF)
    return crc16_arc(blob)


# Name used by the earlier scripts; the function is symmetric.
compute_flow_index_symmetric = compute_flow_index
