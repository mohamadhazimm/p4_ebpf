#!/usr/bin/env bash
# Phase 1 batch: the remaining five compiles, one after another.
T=/root/hazim_perf/tools/sw_compile.sh; S=/root/hazim_perf/src; B=/root/hazim_perf/build
$T $S/baseline  baseline.p4 $B/baseline
$T $S/basic_wt  basic.p4    $B/basic_noreports  -DP4_ENABLE_CPU_REPORTS=0
$T $S/basic_wt  basic.p4    $B/basic_nofeatures -DP4_ENABLE_FEATURES=0 -DP4_ENABLE_CPU_REPORTS=0
$T $S/basic_b17 basic.p4    $B/basic_b17
$T $S/basic_b18 basic.p4    $B/basic_b18
echo "batch1 done $(date -u +%FT%TZ)" > $B/batch1.done
