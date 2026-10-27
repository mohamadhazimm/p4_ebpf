#!/usr/bin/env bash
# Make a FLOW_BUCKETS sizing copy of the detector (Phase 1.5). Sizing only:
# the copy is compiled to see whether it fits, never deployed.
#
#   make_bucket_variant.sh SRC_DIR OUT_DIR INDEX_BITS
#
# Copies SRC_DIR/*.p4 to OUT_DIR and widens the flow index from 16 to
# INDEX_BITS bits: FLOW_BUCKETS = 2^INDEX_BITS, the index type of all 14
# Register and 16 RegisterAction declarations, meta.flow_index (and its parser
# initialisation), and the local idx. The hash becomes CRC32 truncated to
# INDEX_BITS, because CRC16 has only 16 output bits. Exits non-zero unless
# every substitution hit its expected count.
set -eu
if [ $# -ne 3 ]; then
    echo "usage: $0 SRC_DIR OUT_DIR INDEX_BITS" >&2
    exit 2
fi
src=$1; out=$2; bits=$3
buckets=$((1 << bits))
mkdir -p "$out"
cp "$src"/*.p4 "$out"/
ing=$out/ingress.p4; hdr=$out/headers.p4; prs=$out/ingress_parser.p4

sed -i \
    -e "s/^const bit<32> FLOW_BUCKETS = 65536;/const bit<32> FLOW_BUCKETS = $buckets;/" \
    -e "s/Register<\(bit<[0-9]*>\), *bit<16>>/Register<\1, bit<$bits>>/" \
    -e "s/RegisterAction<\(bit<[0-9]*>\), *bit<16>, /RegisterAction<\1, bit<$bits>, /" \
    -e "s/Hash<bit<16>>(HashAlgorithm_t.CRC16)/Hash<bit<$bits>>(HashAlgorithm_t.CRC32)/" \
    -e "s/bit<16> idx = /bit<$bits> idx = /" \
    "$ing"
sed -i -e "s/^    bit<16> flow_index;/    bit<$bits> flow_index;/" "$hdr"
sed -i -e "s/meta.flow_index = 16w0;/meta.flow_index = 0;/" "$prs"

check() {
    local n
    n=$(grep -c -- "$2" "$1" || true)
    if [ "$n" -ne "$3" ]; then
        echo "expected $3 line(s) matching '$2' in $1, found $n" >&2
        exit 1
    fi
}
check "$ing" "^const bit<32> FLOW_BUCKETS = $buckets;" 1
check "$ing" "Register<bit<[0-9]*>, bit<$bits>>" 14
check "$ing" "RegisterAction<bit<[0-9]*>, bit<$bits>, " 16
check "$ing" "bit<16>>(FLOW_BUCKETS)" 0
check "$ing" "Hash<bit<$bits>>(HashAlgorithm_t.CRC32)" 1
check "$ing" "bit<$bits> idx = " 1
check "$hdr" "bit<$bits> flow_index;" 1
check "$prs" "meta.flow_index = 0;" 1
echo "$out: FLOW_BUCKETS = $buckets, index bit<$bits>, hash CRC32"
