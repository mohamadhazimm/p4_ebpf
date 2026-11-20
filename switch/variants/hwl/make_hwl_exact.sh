#!/usr/bin/env bash
# The ASIC latency-report variant of switch/variants/exact (p4_perf.md section 5.7): the HWL1 instrumentation
# of make_hwl_sources.sh (bridge header with the ingress parser timestamp, 20-byte report after Ethernet of
# IPv4/UDP packets, EtherType 0x88BC) applied to the exact build's sources with hwl_exact.patch.
#
#   make_hwl_exact.sh EXACT_SRC_DIR OUT_DIR        (OUT_DIR/basic_hwl_exact)
set -eu
if [ $# -ne 2 ]; then
    echo "usage: $0 EXACT_SRC_DIR OUT_DIR" >&2
    exit 2
fi
here=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$2/basic_hwl_exact"
cp "$1"/*.p4 "$2/basic_hwl_exact/"
patch --quiet -p1 -d "$2/basic_hwl_exact" < "$here/hwl_exact.patch"
(cd "$1" && sha256sum -- *.p4 | grep -v -e ' headers.p4$' -e ' ingress.p4$' -e ' ingress_deparser.p4$' \
    -e ' egress_parser.p4$' -e ' egress.p4$') | (cd "$2/basic_hwl_exact" && sha256sum --quiet -c -)
echo "basic_hwl_exact: hwl_exact.patch applied to 5 files, others unmodified"
