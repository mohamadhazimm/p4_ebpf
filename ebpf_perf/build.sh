#!/usr/bin/env bash
# Build HostMon (unchanged working-tree sources) and the load generator into build/.
# No root needed. Uses the workspace-local Clang 14 and libelf already extracted
# for the attribution builds; set DEP to override.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
P4EBPF="$(dirname "$HERE")"
BOOT="$P4EBPF/libbpf-bootstrap"
SRC="$BOOT/examples/c"
DEP="${DEP:-$(dirname "$P4EBPF")/vbox-runs/hybrid-rf-study-20261010/data/versioned-collector/additional-study-review-20261022/remediation-preparation/20261022T122641888212Z/dependencies/root/usr}"
OUT="$HERE/build"
BPFTOOL="${BPFTOOL:-/usr/sbin/bpftool}"

rm -rf "$OUT"
mkdir -p "$OUT/libbpf-obj" "$OUT/hdr"
cp "$SRC/hostmon.bpf.c" "$SRC/hostmon.c" "$SRC/hostmon.h" "$OUT/"
export LD_LIBRARY_PATH="$DEP/lib/x86_64-linux-gnu" C_INCLUDE_PATH="$DEP/include" LIBRARY_PATH="$DEP/lib/x86_64-linux-gnu"

make -s -C "$BOOT/libbpf/src" -j8 BUILD_STATIC_ONLY=1 OBJDIR="$OUT/libbpf-obj/" \
    DESTDIR="$OUT/hdr" INCLUDEDIR=/include LIBDIR=/lib UAPIDIR=/include install > "$OUT/libbpf-build.log" 2>&1
"$DEP/bin/clang-14" -target bpf -D__TARGET_ARCH_x86 -O2 -g -Wall \
    -I"$BOOT/vmlinux.h/include/x86" -I"$OUT/hdr/include" \
    -c "$OUT/hostmon.bpf.c" -o "$OUT/hostmon.bpf.o"
"$BPFTOOL" gen skeleton "$OUT/hostmon.bpf.o" > "$OUT/hostmon.skel.h"
# Static link so the binary runs under sudo without LD_LIBRARY_PATH.
cc -std=gnu11 -O2 -g -Wall -Wno-stringop-truncation -I"$OUT/hdr/include" -I"$OUT" \
    "$OUT/hostmon.c" "$OUT/hdr/lib/libbpf.a" "$DEP/lib/x86_64-linux-gnu/libelf.a" \
    /usr/lib/x86_64-linux-gnu/libz.a -lm -static -o "$OUT/hostmon"
cc -std=gnu11 -O2 -Wall -Wextra -Werror "$HERE/bench_load.c" -o "$OUT/bench_load"

# hostmon_agg: same features with in-kernel aggregation (hostmon_agg/README.md).
AGG_SRC=(hostmon_agg.bpf.c hostmon_agg.c hostmon_agg.h hostmon_agg_logic.h hostmon_agg_fmt.h test_agg_equiv.c)
for f in "${AGG_SRC[@]}"; do cp "$HERE/hostmon_agg/$f" "$OUT/"; done
"$DEP/bin/clang-14" -target bpf -D__TARGET_ARCH_x86 -O2 -g -Wall \
    -I"$BOOT/vmlinux.h/include/x86" -I"$OUT/hdr/include" -I"$OUT" \
    -c "$OUT/hostmon_agg.bpf.c" -o "$OUT/hostmon_agg.bpf.o"
"$BPFTOOL" gen skeleton "$OUT/hostmon_agg.bpf.o" > "$OUT/hostmon_agg.skel.h"
cc -std=gnu11 -O2 -g -Wall -I"$OUT/hdr/include" -I"$OUT" \
    "$OUT/hostmon_agg.c" "$OUT/hdr/lib/libbpf.a" "$DEP/lib/x86_64-linux-gnu/libelf.a" \
    /usr/lib/x86_64-linux-gnu/libz.a -lm -static -o "$OUT/hostmon_agg"
# Offline equivalence test against the unchanged hostmon.c consumer (no root needed).
cc -std=gnu11 -O2 -g -Wall -Wno-unused-function -Wno-stringop-truncation -I"$OUT/hdr/include" -I"$OUT" \
    "$OUT/test_agg_equiv.c" "$OUT/hdr/lib/libbpf.a" "$DEP/lib/x86_64-linux-gnu/libelf.a" \
    /usr/lib/x86_64-linux-gnu/libz.a -lm -o "$OUT/test_agg_equiv"

(cd "$OUT" && sha256sum hostmon.bpf.c hostmon.c hostmon.h hostmon.bpf.o hostmon bench_load \
    "${AGG_SRC[@]}" hostmon_agg.bpf.o hostmon_agg > sha256.txt)
"$BPFTOOL" --version | head -1 > "$OUT/bpftool-version.txt"
"$DEP/bin/clang-14" --version | head -1 > "$OUT/clang-version.txt"
echo "built: $OUT/hostmon $OUT/hostmon_agg $OUT/bench_load"
