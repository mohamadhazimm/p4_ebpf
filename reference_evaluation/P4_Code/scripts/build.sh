#!/bin/bash
set -eu
export SDE="${SDE:-/root/bf-sde-9.6.0}"
export SDE_INSTALL="${SDE_INSTALL:-$SDE/install}"
cd "$(dirname "$0")/.."
mkdir -p evidence
"$SDE_INSTALL/bin/bf-p4c" --version > evidence/compiler_version.txt
if /root/tools/p4_build.sh --with-p4c=bf-p4c p4src/basic.p4 > evidence/build.log 2>&1; then
    cat evidence/compiler_version.txt
    echo 'Build completed. Review the resource report and generated configuration before loading.'
    ls "$SDE_INSTALL/share/p4/targets/tofino/basic.conf"
else
    tail -n 100 evidence/build.log
    exit 1
fi
