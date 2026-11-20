#!/usr/bin/env bash
# Build sockowner into build/ (no root needed). Same toolchain as ../build.sh: the
# workspace-local Clang 14 and libelf, and the vendored libbpf; DEP=/usr uses the
# system's. Loading and attaching need root and cgroup v2.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"
P4EBPF="$(dirname "$(dirname "$HERE")")"
BOOT="$P4EBPF/third_party/libbpf-bootstrap"
DEP="${DEP:-$(dirname "$P4EBPF")/vbox-runs/hybrid-rf-study-20261010/data/versioned-collector/additional-study-review-20261022/remediation-preparation/20261022T122641888212Z/dependencies/root/usr}"
CLANG="${CLANG:-$DEP/bin/clang-14}"
OUT="${OUT:-$HERE/build}"
BPFTOOL="${BPFTOOL:-/usr/sbin/bpftool}"

rm -rf "$OUT"
mkdir -p "$OUT/libbpf-obj" "$OUT/hdr"
cp "$HERE/sockowner.bpf.c" "$HERE/sockowner.c" "$HERE/sockowner.h" "$OUT/"
export LD_LIBRARY_PATH="$DEP/lib/x86_64-linux-gnu" C_INCLUDE_PATH="$DEP/include" LIBRARY_PATH="$DEP/lib/x86_64-linux-gnu"

make -s -C "$BOOT/libbpf/src" -j8 BUILD_STATIC_ONLY=1 OBJDIR="$OUT/libbpf-obj/" \
    DESTDIR="$OUT/hdr" INCLUDEDIR=/include LIBDIR=/lib UAPIDIR=/include install > "$OUT/libbpf-build.log" 2>&1
"$CLANG" -target bpf -D__TARGET_ARCH_x86 -O2 -g -Wall -fno-common \
    -I"$BOOT/vmlinux.h/include/x86" -I"$OUT/hdr/include" -I"$OUT" \
    -c "$OUT/sockowner.bpf.c" -o "$OUT/sockowner.bpf.o"
"$BPFTOOL" gen skeleton "$OUT/sockowner.bpf.o" > "$OUT/sockowner.skel.h"
# Static link so the binary runs under sudo and in the analysis VM without libraries.
cc -std=gnu11 -O2 -g -Wall -Wextra -I"$OUT/hdr/include" -I"$OUT" \
    "$OUT/sockowner.c" "$OUT/hdr/lib/libbpf.a" "$DEP/lib/x86_64-linux-gnu/libelf.a" \
    /usr/lib/x86_64-linux-gnu/libz.a -lm -static -o "$OUT/sockowner"
(cd "$OUT" && sha256sum sockowner.bpf.c sockowner.c sockowner.h sockowner.bpf.o sockowner > sha256.txt)
"$BPFTOOL" --version | sed -n 1p > "$OUT/bpftool-version.txt"
"$CLANG" --version | sed -n 1p > "$OUT/clang-version.txt"
echo "built: $OUT/sockowner"
