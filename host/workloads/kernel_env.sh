# Sourced by the kernel-build workload: point the kernel's host tools at the
# signed Ubuntu packages unpacked under tools/root (flex, bison, m4, OpenSSL and
# libelf headers) instead of system installs.
_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
_T="$_ROOT/tools/root"
export PATH="$_T/usr/bin:$PATH"
export M4="$_T/usr/bin/m4"
export BISON_PKGDATADIR="$_T/usr/share/bison"
export LD_LIBRARY_PATH="$_T/usr/lib/x86_64-linux-gnu${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export HOSTCFLAGS="-I$_T/usr/include -I$_T/usr/include/x86_64-linux-gnu"
export HOSTLDFLAGS="-L$_T/usr/lib/x86_64-linux-gnu"
export KERNEL_TREE="${KERNEL_TREE:-${XDG_CACHE_HOME:-$HOME/.cache}/hostmon-bench/kernel/linux-source-5.15.0}"
