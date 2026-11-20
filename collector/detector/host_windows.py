#!/usr/bin/env python3
"""The host half of the detectors' window table at another window length, from the dataset runs' raw system calls
(PC1.md part 13). Run it on the lab workstation, where the run archives are; PC1 has none of them.

Each dataset run saved run.json and syscall_events.csv (timestamp_ns, window_id, pid, tid, comm, event, detail
id=N; RUNBOOK 19.5.3): every system call of the program and its children after the sample started, with the 0.5 s
window the runner gave it. This script:
1. Finds the runs of collector/detector/dataset_windows.csv.gz under the --root folders. A run is a folder that
   holds run.json and syscall_events.csv, on disk or inside a zip file (a campaign's runs/NAME.zip with
   output/run_*/ inside). It is named by its folder's run_id (the capture manifests give 110 of them), by the zip's
   or a folder's name, or by a string in its run.json equal to an execution_id. Unnamed runs are matched by their
   content (step 2) unless --no-content-match is given. --index CSV (execution_id,path[,member]) names them
   instead; every run writes the index it used next to its report.
2. Checks each run: the release's host features of its calls binned by window_id (0.5 s) must equal the training
   table's 18 host columns in all 40 windows. When an execution has several runs (an attempt collected again),
   the one that matches is used.
3. Bins the calls by timestamp into windows of --window seconds from the sample start, and computes the release's
   host features (features/host_model.py window_features, unchanged) in each of the 20 s / --window windows.

The sample start, in the clock of timestamp_ns. Each call's window_id bounds it: every start in
[max(ts - 0.5 s * (window_id + 1)) + 1 ns, min(ts - 0.5 s * window_id)] gives the same 0.5 s windows, so the new
windows always nest inside the 0.5 s ones. Inside that interval the script uses:
- the run.json number named by --start-key (--start-unit ns or us), if given;
- otherwise a run.json number found inside the interval in every run where it exists (in ns, or in us * 1000);
- otherwise an estimate: the first call minus the median delay from the start to the first call, over the runs
  whose calls pin the start within 0.2 ms, kept inside the interval. The report then counts, per run, the calls
  close enough to a new window boundary (within the spread of that delay) that their window could differ.

Output: with the PC1 network half (--network, default collector/detector/net_windows_<window>s.csv.gz) the whole
table, collector/detector/dataset_windows_<window>s.csv.gz, in the layout and run order of the training table;
without it, host_windows_<window>s.csv.gz with the host columns only. Also a report (.json next to it) and the
index of the runs used. Nothing is written but the report and the index unless every run is found and checked; the
exit status is then 1.

    cd p4_ebpf      # the workspace folder holds p4_ebpf, p4-ebpf-malware-detection and vbox-runs
    python3 collector/detector/host_windows.py --window 0.25 --release ../p4-ebpf-malware-detection \\
        --root ../vbox-runs/hybrid-rf-study-20261010/data/versioned-collector

Python 3.6 or later, standard library only. --only ID (repeatable) tries a few runs and writes only the report.
"""
import argparse
import csv
import gzip
import io
import json
import math
import os
import posixpath
import re
import statistics
import sys
import tarfile
import zipfile
import zlib
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
STREAMING = REPO / "collector" / "detector"
CAPS = REPO / "experiments" / "captures"
RUN_S = 20.0
BASE_S = 0.5
BASE_NS = 500000000
BASE_WINDOWS = 40
EVENT_FILES = ("syscall_events.csv", "syscall_events.csv.gz")
ID_RE = re.compile(r"(?:^|[\s,;])id=(-?\d+)")
PIN_NS = 200000           # a start known within 0.2 ms
TOL = 1e-9
# a run's files could not be read: a damaged or encrypted zip member (BadZipFile, zlib.error, EOFError,
# RuntimeError), a compression this Python lacks (NotImplementedError), bad text or numbers (ValueError)
READ_ERRORS = (ValueError, OSError, EOFError, RuntimeError, NotImplementedError, zipfile.BadZipFile, zlib.error)


def windows_in_run(window_s):
    n = RUN_S / window_s
    if window_s <= 0 or abs(n - round(n)) > 1e-9:
        raise SystemExit("--window must divide the 20 s of a run")
    return int(round(n))


def load_table(path):
    """The training table: header, and per run (in file order) its metadata and 0.5 s host windows by column."""
    with gzip.open(str(path), "rt", newline="") as f:
        reader = csv.reader(f)
        header = next(reader)
        assert header[:6] == ["execution_id", "label", "category", "cv_group", "split", "window"], header[:6]
        host = [(i, h) for i, h in enumerate(header) if h.startswith("host_")]
        runs = {}
        for row in reader:
            run = runs.setdefault(row[0], {"meta": row[:5], "host": {}})
            run["host"][int(row[5])] = {h: float(row[i]) for i, h in host}
    return header, [h for _, h in host], runs


def manifest_run_ids(caps):
    """run_id -> execution_id from the capture manifests (110 runs), when they are there."""
    out = {}
    for path in (caps / "cohort" / "manifest.csv", caps / "cohort-extra" / "manifest.csv"):
        try:
            with open(str(path), newline="") as f:
                out.update((r["run_id"], r["execution_id"]) for r in csv.DictReader(f))
        except OSError:
            if path.parent.name == "cohort-extra":      # not unpacked: read it from the archive
                try:
                    with tarfile.open(str(caps / "cohort-extra.tar.gz"), "r:gz") as tar:
                        f = io.TextIOWrapper(tar.extractfile("cohort-extra/manifest.csv"), newline="")
                        out.update((r["run_id"], r["execution_id"]) for r in csv.DictReader(f))
                except (OSError, KeyError, tarfile.TarError):
                    pass
    return out


def strings(obj):
    if isinstance(obj, dict):
        for v in obj.values():
            yield from strings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from strings(v)
    elif isinstance(obj, str):
        yield obj


def numbers(obj, key=""):
    """(key path, integer) of the integers in run.json, integer strings included."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from numbers(v, "%s/%s" % (key, k) if key else str(k))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from numbers(v, "%s[%d]" % (key, i))
    elif isinstance(obj, bool):
        return
    elif isinstance(obj, int):
        yield key, obj
    elif isinstance(obj, float) and obj.is_integer():
        yield key, int(obj)
    elif isinstance(obj, str) and obj.isdigit():
        yield key, int(obj)


def name_forms(text):
    """A string, its last path element, and that element without its extensions."""
    out = {text}
    base = text.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]
    out.add(base)
    while "." in base:
        base = base.rsplit(".", 1)[0]
        out.add(base)
    return out


class Run:
    """One run folder: on disk (container None, member its path) or inside a zip (member its folder there)."""

    def __init__(self, container, member, events_name, meta, path_names):
        self.container, self.member, self.events_name, self.meta = container, member, events_name, meta
        self.folder = posixpath.basename(member.rstrip("/")) if container else os.path.basename(member)
        self.names = set()
        for text in list(path_names) + list(strings(meta)):
            self.names |= name_forms(text)
        self.base = None          # cached result of the 0.5 s pass

    def where(self):
        return "%s!%s" % (self.container, self.member) if self.container else self.member

    def rows(self, stats):
        """(timestamp_ns, window_id, pid, syscall_id) of every call, in file order."""
        zf = zipfile.ZipFile(self.container) if self.container else None
        try:
            if zf:
                raw = zf.open(posixpath.join(self.member, self.events_name))
            else:
                raw = open(os.path.join(self.member, self.events_name), "rb")
            with raw:
                stream = gzip.GzipFile(fileobj=raw) if self.events_name.endswith(".gz") else raw
                reader = csv.reader(io.TextIOWrapper(stream, encoding="utf-8", errors="replace", newline=""))
                col = {h.strip(): i for i, h in enumerate(next(reader))}
                missing = [c for c in ("timestamp_ns", "window_id", "pid", "detail") if c not in col]
                if missing:
                    raise ValueError("%s has no column %s" % (self.events_name, missing))
                its, iwin, ipid, idet = col["timestamp_ns"], col["window_id"], col["pid"], col["detail"]
                for row in reader:
                    if not row:
                        continue
                    m = ID_RE.search(row[idet])
                    if m is None:
                        stats["rows_without_id"] = stats.get("rows_without_id", 0) + 1
                        continue
                    yield int(row[its]), int(row[iwin]), int(row[ipid]), int(m.group(1))
        finally:
            if zf:
                zf.close()


def discover(roots, log, skipped):
    """Every run folder under the roots, on disk or inside zip files. Archives that can't be read are skipped and
    listed in skipped: a campaign folder can hold other zips, such as a toolchain's malformed test archives."""
    runs = []
    for root in roots:
        root = os.path.abspath(os.path.expanduser(root))
        for d, dirs, files in os.walk(root):
            dirs.sort()
            rel = os.path.relpath(d, root).split(os.sep)
            events = [e for e in EVENT_FILES if e in files]
            if "run.json" in files and events:
                with open(os.path.join(d, "run.json"), "rb") as f:
                    runs.append(load_run(None, d, events[0], f.read(), rel))
            for z in sorted(f for f in files if f.lower().endswith(".zip")):
                path = os.path.join(d, z)
                try:
                    zf = zipfile.ZipFile(path)
                except READ_ERRORS as e:          # a member name that isn't UTF-8 is a UnicodeDecodeError
                    skipped.append({"where": path, "error": "%s: %s" % (type(e).__name__, e)})
                    log("skipping %s: %s" % (path, skipped[-1]["error"]))
                    continue
                with zf:
                    names = set(zf.namelist())
                    for name in sorted(names):
                        if posixpath.basename(name) != "run.json":
                            continue
                        member = posixpath.dirname(name)
                        ev = [e for e in EVENT_FILES if posixpath.join(member, e) in names]
                        if not ev:
                            continue
                        try:
                            raw = zf.read(name)
                        except READ_ERRORS as e:
                            skipped.append({"where": path + "/" + name, "error": "%s: %s" % (type(e).__name__, e)})
                            log("skipping %s: %s" % (skipped[-1]["where"], skipped[-1]["error"]))
                            continue
                        runs.append(load_run(path, member, ev[0], raw, rel + [z] + member.split("/")))
    return runs


def load_run(container, member, events_name, raw_json, path_names):
    try:
        meta = json.loads(raw_json.decode("utf-8", "replace"))
    except ValueError:
        meta = {}
    return Run(container, member, events_name, meta if isinstance(meta, dict) else {}, path_names)


def base_pass(run, host_model):
    """The 0.5 s pass: host windows from window_id, and the interval of sample starts the window_ids allow."""
    stats = {"calls": 0}
    bounds = {"lo": None, "hi": None, "first": None}

    def calls():
        lo = hi = first = None
        for ts, wid, pid, sid in run.rows(stats):
            a, b = ts - BASE_NS * (wid + 1) + 1, ts - BASE_NS * wid
            lo = a if lo is None or a > lo else lo
            hi = b if hi is None or b < hi else hi
            first = ts if first is None or ts < first else first
            stats["calls"] += 1
            yield wid, pid, sid
        bounds.update(lo=lo, hi=hi, first=first)

    windows = host_model.window_features(calls(), BASE_WINDOWS)
    return dict(windows=windows, stats=stats, **bounds)


def cells_off(windows, ref, columns):
    off = []
    for w in range(BASE_WINDOWS):
        for c in columns:
            a, b = float(windows[w][c]), ref[w][c]
            if not math.isclose(a, b, rel_tol=TOL, abs_tol=TOL):
                off.append([w, c, a, b])
    return off


def target_pass(run, host_model, start, window_ns, n, sub, slack_ns):
    """Host windows of window_ns from start; calls whose window could change with the start; nesting failures."""
    stats = {"calls": 0, "calls_outside": 0, "uncertain_calls": 0, "nesting_failures": 0}

    def calls():
        for ts, wid, pid, sid in run.rows(stats):
            off = ts - start
            w = off // window_ns
            stats["calls"] += 1
            if not 0 <= w < n:
                stats["calls_outside"] += 1
            if sub and 0 <= wid < BASE_WINDOWS and w // sub != wid:
                stats["nesting_failures"] += 1
            if slack_ns:
                r = off % window_ns
                # a boundary within slack_ns, other than a 0.5 s one (window_id fixes those)
                if (r < slack_ns and not (sub and w % sub == 0)) or \
                        (window_ns - r <= slack_ns and not (sub and (w + 1) % sub == 0)):
                    stats["uncertain_calls"] += 1
            yield w, pid, sid

    return host_model.window_features(calls(), n), stats


def start_keys(cands):
    """The run.json numbers that lie in the start interval of every run where they exist: (key, unit) -> runs."""
    seen, bad = {}, set()
    for run, b in cands:
        for key, v in numbers(run.meta):
            for unit, ns in (("ns", v), ("us", v * 1000)):
                if b["lo"] <= ns <= b["hi"]:
                    seen.setdefault((key, unit), set()).add(id(run))
                else:
                    bad.add((key, unit))
    return {k: len(v) for k, v in seen.items() if k not in bad}


def gzip_writer(path):
    raw = open(str(path), "wb")
    return io.TextIOWrapper(gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0), newline=""), raw


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--window", type=float, required=True, help="window length in seconds (0.25, 0.1, ...)")
    ap.add_argument("--root", action="append", default=[], help="folder holding run archives (repeatable)")
    ap.add_argument("--index", help="CSV execution_id,path[,member] naming the runs, instead of --root")
    ap.add_argument("--release", default=str(REPO.parent / "p4-ebpf-malware-detection"))
    ap.add_argument("--table", default=str(STREAMING / "dataset_windows.csv.gz"))
    ap.add_argument("--network", help="the network half (default collector/detector/net_windows_<window>s.csv.gz)")
    ap.add_argument("--out", help="default collector/detector/dataset_windows_<window>s.csv.gz "
                                  "(host_windows_<window>s.csv.gz without the network half)")
    ap.add_argument("--start-key", help="run.json key of the sample start, in the clock of timestamp_ns")
    ap.add_argument("--start-unit", choices=("ns", "us"), default="ns")
    ap.add_argument("--no-content-match", action="store_true", help="do not match unnamed runs by their content")
    ap.add_argument("--only", action="append", default=[], help="only this execution_id (repeatable): a trial")
    args = ap.parse_args(argv)
    if not args.root and not args.index:
        ap.error("give --root (or --index)")
    sys.path.insert(0, str(Path(args.release) / "features"))
    import host_model

    ws = args.window
    n = windows_in_run(ws)
    window_ns = int(round(ws * 1e9))
    sub = BASE_S / ws
    sub = int(round(sub)) if abs(sub - round(sub)) < 1e-9 else None
    tag = "%gs" % ws
    header, host_cols, table = load_table(args.table)
    if sorted(host_cols) != sorted(host_model.FEATURES):
        raise SystemExit("the release's host features are not the training table's host columns")
    wanted = [e for e in table if not args.only or e in args.only]
    if args.only and len(wanted) != len(set(args.only)):
        raise SystemExit("not in the training table: %s" % sorted(set(args.only) - set(wanted)))
    network = Path(args.network or STREAMING / ("net_windows_%s.csv.gz" % tag))
    if args.out:
        out = Path(args.out)
    else:
        out = STREAMING / (("dataset_windows_%s.csv.gz" if network.exists() else "host_windows_%s.csv.gz") % tag)
    report_path = Path(str(out).replace(".csv.gz", "") + ".json")
    index_path = Path(str(out).replace(".csv.gz", "") + "_index.csv")

    def log(msg):
        print(msg, flush=True)

    # 1. the runs and their names
    skipped = []
    if args.index:
        runs = []
        for r in csv.DictReader(open(args.index, newline="")):
            path, member = r["path"], (r.get("member") or "")
            if path.lower().endswith(".zip"):
                with zipfile.ZipFile(path) as zf:
                    names = set(zf.namelist())
                    ev = [e for e in EVENT_FILES if posixpath.join(member, e) in names]
                    raw = zf.read(posixpath.join(member, "run.json"))
                runs.append(load_run(path, member, ev[0], raw, [r["execution_id"]]))
            else:
                ev = [e for e in EVENT_FILES if os.path.exists(os.path.join(path, e))]
                runs.append(load_run(None, path, ev[0], open(os.path.join(path, "run.json"), "rb").read(),
                                     [r["execution_id"]]))
    else:
        runs = discover(args.root, log, skipped)
    log("%d run folders with run.json and syscall_events.csv" % len(runs))
    by_run_id = manifest_run_ids(CAPS)
    ids = set(wanted)
    named = {e: [] for e in wanted}
    unnamed = []
    for run in runs:
        hit = []
        parts = run.folder.split("_")              # run_20261026T165738Z, or with a suffix (..._flood_gen)
        for k in range(len(parts), 1, -1):
            e = by_run_id.get("_".join(parts[:k]))
            if e in ids:
                hit.append((0, e, "run_id"))
                break
        hit += [(1, e, "name") for e in sorted(run.names & ids)]
        for rank, e, how in hit:
            named[e].append((rank, how, run))
        if not hit:
            unnamed.append(run)

    # 2. the check at 0.5 s
    chosen, rejected = {}, {}

    def check(run, e):
        if run.base is None:
            try:
                run.base = base_pass(run, host_model)
            except READ_ERRORS as err:
                run.base = {"error": "%s: %s" % (type(err).__name__, err)}
        if "error" in run.base:
            rejected.setdefault(e, []).append({"where": run.where(), "error": run.base["error"]})
            return False
        off = cells_off(run.base["windows"], table[e]["host"], host_cols)
        if off:
            rejected.setdefault(e, []).append({"where": run.where(), "cells_off": len(off), "first": off[:3]})
            return False
        return True

    for e in wanted:
        tried = set()
        for rank, how, run in sorted(named[e], key=lambda t: t[0]):
            if id(run) in tried:
                continue
            tried.add(id(run))
            if check(run, e):
                chosen[e] = (run, how)
                break
        log("[%d/%d] %s: %s" % (len(chosen), len(wanted), e[:24], "ok (%s)" % chosen[e][1] if e in chosen else
                                "no named run matches" if named[e] else "no named run"))
    left = [e for e in wanted if e not in chosen]
    if left and unnamed and not args.no_content_match:
        log("matching %d runs by content against %d executions" % (len(unnamed), len(left)))
        for k, run in enumerate(unnamed, 1):
            if not left:
                break
            if run.base is None:
                try:
                    run.base = base_pass(run, host_model)
                except READ_ERRORS as err:
                    run.base = {"error": "%s: %s" % (type(err).__name__, err)}
            if "error" in run.base:
                continue
            for e in left:
                if not cells_off(run.base["windows"], table[e]["host"], host_cols):
                    chosen[e] = (run, "content")
                    left.remove(e)
                    log("  %s: %s by content (%d of %d runs read)" % (e[:24], run.where(), k, len(unnamed)))
                    break

    # 3. the sample start, then the new windows
    cands = [(run, run.base) for run, _ in chosen.values()]
    if args.start_key:
        key_unit = (args.start_key, args.start_unit)
        source = "run.json %s (%s, given)" % key_unit
    else:
        keys = start_keys(cands)
        key_unit = max(keys, key=lambda k: (keys[k], k[1] == "ns", k[0])) if keys else None
        source = "run.json %s (%s, found in %d runs)" % (key_unit + (keys[key_unit],)) if key_unit else None
    pinned = [b["first"] - (b["lo"] + b["hi"]) // 2 for _, b in cands if b["hi"] - b["lo"] <= PIN_NS]
    delay = int(statistics.median(pinned)) if pinned else 0
    spread = max([abs(d - delay) for d in pinned] + [PIN_NS]) if pinned else BASE_NS
    report = {"window_s": ws, "windows": n, "executions": len(wanted), "found": len(chosen),
              "missing": [e for e in wanted if e not in chosen], "run_folders": len(runs), "skipped": skipped,
              "start": {"key": source, "pinned_runs": len(pinned), "first_call_delay_ns_median": delay,
                        "first_call_delay_spread_ns": spread},
              "runs": {}, "rejected": rejected}
    host = {}
    for e in wanted:
        if e not in chosen:
            continue
        run, how = chosen[e]
        b = run.base
        start, slack, origin = None, 0, None
        if key_unit:
            vals = dict(numbers(run.meta))
            if key_unit[0] in vals:
                start = vals[key_unit[0]] * (1000 if key_unit[1] == "us" else 1)
                origin = "key"
                if not b["lo"] <= start <= b["hi"]:
                    raise SystemExit("%s: run.json %s is outside the start interval its window_ids allow"
                                     % (e, key_unit[0]))
        if start is None:
            start = min(max(b["first"] - delay, b["lo"]), b["hi"])
            origin = "pinned" if b["hi"] - b["lo"] <= PIN_NS else "estimated"
            slack = min(b["hi"] - b["lo"], spread)
        windows, st = target_pass(run, host_model, start, window_ns, n, sub, slack)
        host[e] = windows
        report["runs"][e] = {"where": run.where(), "matched_by": how, "start": origin,
                             "start_interval_us": round((b["hi"] - b["lo"]) / 1000.0, 3),
                             "calls": st["calls"], "calls_outside": st["calls_outside"],
                             "uncertain_calls": st["uncertain_calls"], "nesting_failures": st["nesting_failures"],
                             "rows_without_id": b["stats"].get("rows_without_id", 0)}
        if st["nesting_failures"]:
            raise SystemExit("%s: %d calls left their 0.5 s window; a bug" % (e, st["nesting_failures"]))
    report["uncertain_calls"] = sum(r["uncertain_calls"] for r in report["runs"].values())
    report["runs_with_uncertain_calls"] = sum(1 for r in report["runs"].values() if r["uncertain_calls"])
    report["calls"] = sum(r["calls"] for r in report["runs"].values())

    with open(str(index_path), "w", newline="") as f:
        w = csv.writer(f, lineterminator="\n")
        w.writerow(["execution_id", "path", "member"])
        for e in wanted:
            if e in chosen:
                run = chosen[e][0]
                w.writerow([e, run.container or run.member, run.member if run.container else ""])
    ok = not report["missing"] and not args.only
    if ok:
        net = {}
        if network.exists():
            with gzip.open(str(network), "rt", newline="") as f:
                r = csv.reader(f)
                nh = next(r)
                for row in r:
                    net.setdefault(row[0], {})[int(row[5])] = dict(zip(nh[6:], row[6:]))
            bad = [e for e in wanted if len(net.get(e, {})) != n]
            if bad or sorted(nh[6:]) != sorted(h for h in header[6:] if h.startswith("net_")):
                raise SystemExit("%s is not the network half of %d windows for every run (%s)" % (network, n, bad[:3]))
            columns = header[6:]
        else:
            columns = host_cols
        text, raw = gzip_writer(out)
        with raw, text:
            w = csv.writer(text, lineterminator="\n")
            w.writerow(header[:6] + columns)
            for e in wanted:
                for k in range(n):
                    values = [repr(float(host[e][k][c])) if c.startswith("host_") else net[e][k][c] for c in columns]
                    w.writerow(table[e]["meta"] + [k] + values)
        report["out"] = str(out)
    report["ok"] = ok
    report_path.write_text(json.dumps(report, indent=1) + "\n")
    log("%d of %d executions found and equal to the training table at 0.5 s%s" % (
        len(chosen), len(wanted), "" if not report["missing"] else "; missing: %s" % report["missing"][:5]))
    log("sample start: %s" % (source or "estimated from the first call (%d runs pin it, median delay %.3f ms, "
                                         "spread %.3f ms)" % (len(pinned), delay / 1e6, spread / 1e6)))
    log("%d calls, %d of them within the start's uncertainty of a new window boundary (in %d runs)" % (
        report["calls"], report["uncertain_calls"], report["runs_with_uncertain_calls"]))
    log("wrote %s%s" % (report_path, ", %s" % out if ok else ""))
    return 0 if ok or (args.only and not report["missing"]) else 1


if __name__ == "__main__":
    sys.exit(main())
