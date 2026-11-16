#!/usr/bin/env python3
"""Run the dataset's own static benign programs live on PC1 (PC1.md Part 6), one dataset row each.

    python3 live_test/static_benign/run_static_benign.py --root ROOT --out OUT [--startup-free] [--only N] [--dry-run]

ROOT is the unpacked static-benign.tar.gz (cases.tsv, bin/, fixtures/). Each case runs as PC1.md runs a program:
the common collector command C of section 0 (--profile dataset: 0.5 s windows, 40 of them, the dataset launcher)
and hostmon_agg; then live_test/dataset_row.py appends the row to OUT/rows.csv with the case's dataset
execution_id, so compare_static_benign.py can put it next to its dataset twin. Run from p4_ebpf; the collector
needs sudo. Two ways to start the program:
- default (part 2): hostmon_agg watches the launcher's cgroup, bin/outto stands in for the dataset runner's
  stdout redirection; compare with the published rows (their launcher made 178 calls, PC1's makes 107).
- --startup-free (part 3, recommended): live_test/prologuefree/pfexec moves the program into the watched cgroup
  at its exec, so the first call counted is the program's first; compare with
  live_test/prologuefree/features_05s_prologuefree.csv (the dataset rows without the launcher).
"""
import argparse
import csv
import json
import re
import shlex
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
COLLECTOR = ("sudo python3 hybrid_collector.py --profile dataset --mode command "
             "--switch-ssh root@172.168.1.2 --forward-int-port 132 --forward-ext-port 140 --cpu-iface enp5s0 "
             "--p4-reader thesis-hybrid-ebpf-p4/python/read_registers_with_index.py "
             "--p4-forwarder thesis-hybrid-ebpf-p4/python/program_forwarding.py")
ENDED = re.compile(r"the command ended with code (-?\d+)")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", required=True, help="the unpacked static-benign folder")
    ap.add_argument("--out", required=True, help="a new folder for the runs (rows.csv is appended to)")
    ap.add_argument("--collector", default=COLLECTOR, help="the common collector command (PC1.md section 0)")
    ap.add_argument("--hostmon", default="ebpf_perf/build/hostmon_agg")
    ap.add_argument("--cgroup", default="/sys/fs/cgroup/unified/hazim_collect")
    ap.add_argument("--outto", default="perf/results/dataset_v1/benign_cli/bin/outto")
    ap.add_argument("--startup-free", action="store_true", help="start each program with pfexec (part 3)")
    ap.add_argument("--pfexec", default="live_test/prologuefree/pfexec", help="the built pfexec.c")
    ap.add_argument("--launch-cgroup", default="/sys/fs/cgroup/unified/hazim_launch")
    ap.add_argument("--prog-cgroup", default="/sys/fs/cgroup/unified/hazim_prog")
    ap.add_argument("--release", default=str(REPO.parent / "p4-ebpf-malware-detection"))
    ap.add_argument("--only", type=int, default=0, help="run only the first N cases (a trial)")
    ap.add_argument("--dry-run", action="store_true", help="print the commands, run nothing")
    args = ap.parse_args()
    root = Path(args.root).resolve()
    out = Path(args.out).resolve()
    outto = Path(args.outto).resolve()
    pfexec = Path(args.pfexec).resolve()
    hostmon, cgroup = args.hostmon, args.cgroup
    if not args.dry_run:
        out.mkdir(parents=True, exist_ok=True)
        need = pfexec if args.startup_free else outto
        if not need.is_file():
            sys.exit("missing %s; give --%s" % (need, "pfexec" if args.startup_free else "outto"))
    if args.startup_free:
        # the collector starts HOSTMON WINDOW_SEC CGROUP; watch the program's cgroup instead (part 3's wrapper)
        wrapper = out / "hostmon_prog.sh"
        if not args.dry_run:
            wrapper.write_text('#!/bin/sh\nexec %s "$1" %s\n' % (shlex.quote(str(Path(args.hostmon).resolve())),
                                                                 shlex.quote(args.prog_cgroup)))
            wrapper.chmod(0o755)
        hostmon, cgroup = str(wrapper), args.launch_cgroup
    with open(root / "cases.tsv", newline="") as f:
        cases = list(csv.DictReader(f, delimiter="\t"))
    if args.only:
        cases = cases[:args.only]
    for k, c in enumerate(cases, 1):
        eid = c["execution_id"]
        task = [str(root / c["binary"])] + [a.replace("@ROOT@", str(root)) for a in json.loads(c["args"])]
        if args.startup_free:
            start = [str(pfexec), args.prog_cgroup, "-o", str(out / (eid + ".stdout"))]
        else:
            start = [str(outto), str(out / (eid + ".stdout"))]
        command = " ".join(shlex.quote(x) for x in start + task)
        collect = shlex.split(args.collector) + [
            "--scenario-name", eid, "--label", "benign", "--hostmon", hostmon, "--hostmon-cgroup", cgroup,
            "--command", command, "--out-csv", str(out / (eid + ".csv")),
            "--reader-timing-file", str(out / (eid + ".timing.jsonl"))]
        print("[%d/%d] %s (%s, %s)" % (k, len(cases), eid, c["mode"], c["program"]), flush=True)
        if args.dry_run:
            print("  " + " ".join(shlex.quote(x) for x in collect))
            continue
        if (out / (eid + ".csv")).exists():
            print("  already collected; skipped (remove the CSV to redo it)")
            continue
        with open(out / (eid + ".collector.log"), "w") as log:
            rc = subprocess.call(collect, cwd=str(REPO), stdout=log, stderr=subprocess.STDOUT)
        text = (out / (eid + ".collector.log")).read_text(errors="replace")
        ended = ENDED.findall(text)
        print("  collector exit %d; program ended with %s (dataset: %s)" % (
            rc, ended[-1] if ended else "?", c["expected_returncodes"]), flush=True)
        if rc != 0:
            print("  the collector failed; see %s" % (out / (eid + ".collector.log")))
            continue
        row = [sys.executable, str(REPO / "live_test" / "dataset_row.py"), str(out / (eid + ".csv")),
               "--execution-id", eid, "--category", "benign", "--label", "0", "--release", args.release,
               "--out", str(out / "rows.csv")] + (["--return-code", ended[-1]] if ended else [])
        subprocess.call(row, cwd=str(REPO))


if __name__ == "__main__":
    main()
