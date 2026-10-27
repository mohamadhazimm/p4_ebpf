"""Print the register bucket the data plane uses for a 5-tuple.

This used CRC16-CCITT over the raw 5-tuple, which never matched the switch. The
index now comes from flow_index.py (CRC-16/ARC over the @symmetric input), the
function the data plane computes; reports also carry it as flow_index.
"""
from flow_index import compute_flow_index

# ===== Example =====
src_ip  = "10.0.0.1"
dst_ip  = "10.0.0.2"
src_port = 5555
dst_port = 9999
proto    = 17  # UDP

idx = compute_flow_index(src_ip, dst_ip, src_port, dst_port, proto)

print("Computed flow_index:", idx)
