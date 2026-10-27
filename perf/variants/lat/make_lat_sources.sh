#!/usr/bin/env bash
# Assemble the source directories of the Phase 2.5 latency variants.
#
#   make_lat_sources.sh DETECTOR_SRC_DIR OUT_DIR
#
# OUT_DIR/basic_lat     basic_lat.p4 + lat_wrapper.p4 + the detector's *.p4,
#                       copied byte for byte (checked against the originals);
#                       then only the header keys of @symmetric annotations in
#                       ingress.p4 are rewritten to hdr.det.* (see below)
# OUT_DIR/baseline_lat  baseline_lat.p4 + lat_wrapper.p4 + baseline_body.p4,
#                       i.e. perf/variants/baseline.p4 without its last
#                       Pipeline(...)/Switch(...) lines
set -eu
if [ $# -ne 2 ]; then
    echo "usage: $0 DETECTOR_SRC_DIR OUT_DIR" >&2
    exit 2
fi
det=$1; out=$2
here=$(cd "$(dirname "$0")" && pwd)

mkdir -p "$out/basic_lat" "$out/baseline_lat"
cp "$det"/*.p4 "$out/basic_lat/"
cp "$here/basic_lat.p4" "$here/lat_wrapper.p4" "$out/basic_lat/"
(cd "$det" && sha256sum -- *.p4) | (cd "$out/basic_lat" && sha256sum --quiet -c -)
# @symmetric names its fields by their path in the final program. Inside the
# wrapper the detector's headers are hdr.det.*, so rewrite those annotation keys
# (only them; the hash is unchanged). The detector's own build is not affected.
sym=$(grep -c '@symmetric("hdr\.' "$out/basic_lat/ingress.p4" || true)
sed -i 's/@symmetric("hdr\.\([A-Za-z0-9_]*\)\.\([A-Za-z0-9_]*\)", "hdr\.\([A-Za-z0-9_]*\)\.\([A-Za-z0-9_]*\)")/@symmetric("hdr.det.\1.\2", "hdr.det.\3.\4")/' "$out/basic_lat/ingress.p4"
if [ "$(grep -c '@symmetric("hdr\.det\.' "$out/basic_lat/ingress.p4" || true)" -ne "$sym" ]; then
    echo "ingress.p4: @symmetric rewrite incomplete" >&2
    exit 1
fi

cp "$here/baseline_lat.p4" "$here/lat_wrapper.p4" "$out/baseline_lat/"
sed '/^Pipeline($/,$d' "$here/../baseline.p4" > "$out/baseline_lat/baseline_body.p4"
removed=$(diff "$here/../baseline.p4" "$out/baseline_lat/baseline_body.p4" | grep -c '^<' || true)
if [ "$removed" -ne 9 ] || grep -q 'Pipeline(\|Switch(' "$out/baseline_lat/baseline_body.p4"; then
    echo "baseline_body.p4: unexpected cut ($removed lines removed)" >&2
    exit 1
fi
echo "detector files copied; $sym @symmetric line(s) rewritten to hdr.det.*; baseline_body.p4 = baseline.p4 minus its 9 Pipeline/Switch lines"
