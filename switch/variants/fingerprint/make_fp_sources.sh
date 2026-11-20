#!/usr/bin/env bash
# Assemble the source directory of the flow-fingerprint variant.
#
#   make_fp_sources.sh DETECTOR_SRC_DIR OUT_DIR
#
# Copies the detector's *.p4 into OUT_DIR and applies fingerprint.patch
# (headers.p4, ingress.p4, ingress_parser.p4). The other files must stay byte
# for byte identical.
set -eu
if [ $# -ne 2 ]; then
    echo "usage: $0 DETECTOR_SRC_DIR OUT_DIR" >&2
    exit 2
fi
det=$1; out=$2
here=$(cd "$(dirname "$0")" && pwd)

mkdir -p "$out"
cp "$det"/*.p4 "$out/"
patch --quiet -p1 -d "$out" < "$here/fingerprint.patch"
(cd "$det" && sha256sum -- *.p4 | grep -v -e ' headers.p4$' -e ' ingress.p4$' -e ' ingress_parser.p4$') | (cd "$out" && sha256sum --quiet -c -)
echo "fingerprint.patch applied to headers.p4, ingress.p4 and ingress_parser.p4; other files unmodified"
