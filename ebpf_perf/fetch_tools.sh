#!/usr/bin/env bash
# Fetch the literature benchmark tools as signed Ubuntu 22.04 packages and unpack
# them under tools/root. No root, no system install, no maintainer scripts:
# apt verifies the archive signatures against the system Ubuntu keyring, and
# dpkg-deb -x only unpacks files.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
T="$HERE/tools"
mkdir -p "$T/apt/lists/partial" "$T/debs" "$T/root"
KEY=/usr/share/keyrings/ubuntu-archive-keyring.gpg
cat > "$T/apt/sources.list" <<EOF
deb [signed-by=$KEY] https://archive.ubuntu.com/ubuntu jammy main universe multiverse
deb [signed-by=$KEY] https://archive.ubuntu.com/ubuntu jammy-updates main universe multiverse
deb [signed-by=$KEY] https://security.ubuntu.com/ubuntu jammy-security main universe multiverse
EOF
APT=(-o Dir::Etc::main=- -o Dir::Etc::parts=- -o "Dir::Etc::sourcelist=$T/apt/sources.list"
     -o Dir::Etc::sourceparts=- -o "Dir::State::lists=$T/apt/lists" -o Dir::State::status=/var/lib/dpkg/status
     -o Dir::Cache::pkgcache= -o Dir::Cache::srcpkgcache= -o Debug::NoLocking=true
     -o APT::Get::List-Cleanup=false -o Acquire::Languages=none)

apt-get "${APT[@]}" update
PACKAGES=(lmbench postmark httperf wrk nginx-core nginx-common sysbench stress-ng linux-source-5.15.0 "$@")
cd "$T/debs"
apt-get "${APT[@]}" download "${PACKAGES[@]}"
for deb in ./*.deb; do dpkg-deb -x "$deb" "$T/root"; done
sha256sum ./*.deb > "$T/package-sha256.txt"
for p in "${PACKAGES[@]}"; do apt-cache "${APT[@]}" policy "$p" | sed -n '1p;3p'; done > "$T/package-versions.txt"
echo "unpacked into $T/root"
