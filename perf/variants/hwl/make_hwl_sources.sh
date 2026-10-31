#!/usr/bin/env bash
# Assemble the source directories of the ASIC latency-report variants: the
# measurement method of reference_evaluation/P4_Code (bridge header with the
# ingress parser timestamp, 20-byte report after Ethernet, EtherType 0x88BC),
# applied to the detector and to the forwarding-only baseline.
#
#   make_hwl_sources.sh DETECTOR_SRC_DIR OUT_DIR
#
# OUT_DIR/basic_hwl     the detector's *.p4 with hwl_detector.patch applied
#                       (headers.p4, ingress.p4, ingress_deparser.p4,
#                       egress_parser.p4, egress.p4); the other files must stay
#                       byte for byte identical
# OUT_DIR/baseline_hwl  perf/variants/baseline.p4 with hwl_baseline.patch, as
#                       baseline_hwl.p4
#
# PC side, unchanged: reference_evaluation/P4_Code/scripts/send_probes.py
# (PC1) and collect_reports.py (PC2).
set -eu
if [ $# -ne 2 ]; then
    echo "usage: $0 DETECTOR_SRC_DIR OUT_DIR" >&2
    exit 2
fi
det=$1; out=$2
here=$(cd "$(dirname "$0")" && pwd)

mkdir -p "$out/basic_hwl" "$out/baseline_hwl"
cp "$det"/*.p4 "$out/basic_hwl/"
patch --quiet -p1 -d "$out/basic_hwl" < "$here/hwl_detector.patch"
(cd "$det" && sha256sum -- *.p4 | grep -v -e ' headers.p4$' -e ' ingress.p4$' -e ' ingress_deparser.p4$' \
    -e ' egress_parser.p4$' -e ' egress.p4$') | (cd "$out/basic_hwl" && sha256sum --quiet -c -)

cp "$here/../baseline.p4" "$out/baseline_hwl/baseline_hwl.p4"
patch --quiet "$out/baseline_hwl/baseline_hwl.p4" < "$here/hwl_baseline.patch"
echo "basic_hwl: hwl_detector.patch applied to 5 files, others unmodified; baseline_hwl: hwl_baseline.patch applied"
