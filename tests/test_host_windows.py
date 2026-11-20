"""collector/detector/host_windows.py: the host half of the window table at 0.25 s from raw system calls (PC1.md
part 13). Synthetic runs in the dataset runner's layout (run.json and syscall_events.csv, in a folder or in a zip's
output/run_*/), a training table made from them at 0.5 s with the release's host model, and a network half. Needs the
release repository next to p4_ebpf (features/host_model.py), as the script does; skipped without it."""
import csv
import gzip
import importlib.util
import io
import json
import os
import struct
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
RELEASE = Path(os.environ.get("RELEASE_DIR") or Path(__file__).resolve().parents[2] / "p4-ebpf-malware-detection")
HAVE = (RELEASE / "features" / "host_model.py").exists()
NS = 1000000000
# E1 is a real execution_id: the capture manifest gives its run_id, run_20261025T124339Z
E1, E2, E3 = "0004b57f7671cb3dbc993e632279e883d138ea72a271b3ab84637c918e391023", "tool-x-amd64_dynamic", "null1"


def load_script():
    spec = importlib.util.spec_from_file_location("host_windows", str(REPO / "collector/detector/host_windows.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def calls_busy(t0):
    """Calls every 0.9 ms for 3 s (they pin the start within 0.1 ms), then a few: 0.2 ms after 1.25 s, after 20 s."""
    out = [(t0 + 1000000 + k * 900000, 100 + (k % 3 == 0), k % 7) for k in range(3300)]
    out += [(t0 + int(1.25 * NS) + 200000, 100, 3), (t0 + int(7.3 * NS), 100, 1), (t0 + int(19.9 * NS), 101, 2),
            (t0 + int(20.2 * NS), 101, 2)]                   # the last one after the 20 s
    return sorted(out)


def calls_short(t0):
    return [(t0 + 1000000 + k * 50000, 200, (k * 5) % 11) for k in range(3000)]       # 1 ms .. 151 ms


def calls_sparse(t0, second=12):
    return [(t0 + 1000000, 300, 59), (t0 + int(0.3 * NS), 300, second), (t0 + int(2.6 * NS), 300, 60)]


def windows_of(hm, calls, t0, window_ns, n):
    return hm.window_features([((ts - t0) // window_ns, pid, sid) for ts, pid, sid in calls], n)


def write_events(fileobj_text, calls, t0):
    w = csv.writer(fileobj_text, lineterminator="\n")
    w.writerow(["timestamp_ns", "window_id", "pid", "tid", "comm", "event", "detail"])
    for ts, pid, sid in calls:
        w.writerow([ts, (ts - t0) // (NS // 2), pid, pid, "prog,x", "syscall", "id=%d" % sid])


def bad_name_zip(path):
    """A zip with a member name flagged UTF-8 that isn't (as in Go's archive/zip test data): ZipFile() fails on it
    with a UnicodeDecodeError."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("testdata/aé.txt", b"x")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(buf.getvalue().replace("aé".encode("utf-8"), b"a\xff\xa9"))


def damage_member(path, name):
    """Give a deflated member an invalid first block type (BTYPE 11): reading it raises zlib.error."""
    with zipfile.ZipFile(str(path)) as zf:
        offset = zf.getinfo(name).header_offset
    raw = bytearray(path.read_bytes())
    n, m = struct.unpack("<HH", bytes(raw[offset + 26:offset + 30]))
    raw[offset + 30 + n + m] = 0x07
    path.write_bytes(bytes(raw))


@unittest.skipUnless(HAVE, "needs the release repository next to p4_ebpf")
class HostWindowsTest(unittest.TestCase):
    def setUp(self):
        sys.path.insert(0, str(RELEASE / "features"))
        import host_model
        self.hm = host_model
        self.hw = load_script()
        self.dir = tempfile.TemporaryDirectory()
        self.d = Path(self.dir.name)
        with gzip.open(str(REPO / "collector/detector/dataset_windows.csv.gz"), "rt") as f:
            self.header = next(csv.reader(f))
        self.host_cols = [h for h in self.header if h.startswith("host_")]
        self.net_cols = [h for h in self.header if h.startswith("net_")]
        self.t0 = {E1: 5000 * NS + 123456789, E2: 7000 * NS + 987654321, E3: 9000 * NS + 5}
        self.calls = {E1: calls_busy(self.t0[E1]), E2: calls_short(self.t0[E2]), E3: calls_sparse(self.t0[E3])}

    def tearDown(self):
        sys.path.remove(str(RELEASE / "features"))
        self.dir.cleanup()

    def make(self, start_key=True, spoil=None):
        root = self.d / "runs"
        # E1: in a zip, named by its folder's run_id; E2: a folder, named by a nested string in run.json; E3: no name,
        # and a rejected attempt named null1 with other calls
        z = root / "campA" / "runs" / "sample17.zip"
        z.parent.mkdir(parents=True)
        meta1 = {"window_seconds": 0.5, "windows": 40, "sample_started_wall_us": 1792932220606770}
        if start_key:
            meta1["sample_started_monotonic_ns"] = self.t0[E1]
        with zipfile.ZipFile(str(z), "w") as zf:
            zf.writestr("output/run_20261025T124339Z_x/run.json", json.dumps(meta1))
            text = io.StringIO()
            write_events(text, self.calls[E1], self.t0[E1])
            zf.writestr("output/run_20261025T124339Z_x/syscall_events.csv", text.getvalue())
            zf.writestr("output/run_20261025T124339Z_x/packet_capture.pcap", b"")
        runs = [(root / "campB" / "output" / "run_2", {"workload": {"id": E2}, "windows": 40}, E2),
                (root / "campC" / "run_3", {"windows": 40}, E3),
                (root / "campC" / "run_3_rejected", {"sample": "null1"}, None)]
        for folder, meta, e in runs:
            folder.mkdir(parents=True)
            if start_key and e == E2:
                meta["sample_started_monotonic_ns"] = self.t0[E2]
            (folder / "run.json").write_text(json.dumps(meta))
            with open(str(folder / "syscall_events.csv"), "w", newline="") as f:
                if e:
                    write_events(f, self.calls[e], self.t0[e])
                else:
                    write_events(f, calls_sparse(self.t0[E3], second=59), self.t0[E3])     # a repeat: other features
        bad_name_zip(root / "campD" / "toolchain" / "bad_name.zip")      # not a run archive, and unreadable
        # the training table at 0.5 s (host from the calls, network a marker) and the network half at 0.25 s
        table, net = self.d / "table.csv.gz", self.d / "net.csv.gz"
        meta = {E1: [E1, "1", "malware", "fam::x", "train"], E2: [E2, "0", "benign", "proj::x", "test"],
                E3: [E3, "0", "null", "null", ""]}
        with gzip.open(str(table), "wt", newline="") as f:
            w = csv.writer(f, lineterminator="\n")
            w.writerow(self.header)
            for e in (E1, E2, E3):
                for k, row in enumerate(windows_of(self.hm, self.calls[e], self.t0[e], NS // 2, 40)):
                    host = {c: float(row[c]) for c in self.host_cols}
                    if spoil == e and k == 0:
                        host[self.host_cols[0]] += 1
                    w.writerow(meta[e] + [k] + [repr(host[c]) if c in host else "7.0" for c in self.header[6:]])
        with gzip.open(str(net), "wt", newline="") as f:
            w = csv.writer(f, lineterminator="\n")
            w.writerow(self.header[:6] + self.net_cols)
            for e in (E1, E2, E3):
                for k in range(80):
                    w.writerow(meta[e] + [k] + [repr(float(k))] * len(self.net_cols))
        return root, table, net

    def run_script(self, *extra, root=None, table=None, net=None):
        out = self.d / "out" / "dataset_windows_0.25s.csv.gz"
        out.parent.mkdir(exist_ok=True)
        argv = ["--window", "0.25", "--release", str(RELEASE), "--table", str(table), "--network", str(net),
                "--out", str(out)] + (["--root", str(root)] if root else []) + list(extra)
        code = self.hw.main(argv)
        report = json.loads((self.d / "out" / "dataset_windows_0.25s.json").read_text())
        return code, out, report

    def read(self, out):
        with gzip.open(str(out), "rt") as f:
            rows = list(csv.reader(f))
        return rows[0], rows[1:]

    def test_the_table_at_025_with_a_start_in_run_json(self):
        root, table, net = self.make()
        code, out, report = self.run_script(root=root, table=table, net=net)
        self.assertEqual(code, 0, report)
        self.assertEqual(report["start"]["key"], "run.json sample_started_monotonic_ns (ns, found in 2 runs)")
        self.assertEqual({e: r["matched_by"] for e, r in report["runs"].items()},
                         {E1: "run_id", E2: "name", E3: "content"})
        self.assertEqual([r["where"].endswith("run_3_rejected") for r in report["rejected"][E3]], [True])
        self.assertEqual([(Path(s["where"]).name, s["error"].split(":")[0]) for s in report["skipped"]],
                         [("bad_name.zip", "UnicodeDecodeError")])
        self.assertEqual(report["runs"][E1]["calls_outside"], 1)
        header, rows = self.read(out)
        self.assertEqual(header, self.header)
        self.assertEqual([r[0] for r in rows], [E1] * 80 + [E2] * 80 + [E3] * 80)
        for e in (E1, E2, E3):
            want = windows_of(self.hm, self.calls[e], self.t0[e], NS // 4, 80)
            mine = [r for r in rows if r[0] == e]
            for k in range(80):
                got = dict(zip(header, mine[k]))
                for c in self.host_cols:
                    self.assertEqual(float(got[c]), float(want[k][c]), (e, k, c))
                self.assertEqual(got["net_pkts_total_delta"], repr(float(k)))
            base = windows_of(self.hm, self.calls[e], self.t0[e], NS // 2, 40)
            for k in range(40):
                self.assertEqual(float(mine[2 * k][6]) + float(mine[2 * k + 1][6]), base[k]["host_total_syscalls_total"])
        # the index it wrote names the same runs, and gives the same bytes
        index = self.d / "out" / "dataset_windows_0.25s_index.csv"
        first = out.read_bytes()
        code, out, report = self.run_script("--index", str(index), table=table, net=net)
        self.assertEqual(code, 0)
        self.assertEqual(out.read_bytes(), first)

    def test_the_start_estimated_from_the_first_call(self):
        root, table, net = self.make(start_key=False)
        code, out, report = self.run_script(root=root, table=table, net=net)
        self.assertEqual(code, 0, report)
        self.assertIsNone(report["start"]["key"])
        self.assertEqual(report["start"]["pinned_runs"], 1)
        self.assertEqual(report["runs"][E1]["start"], "pinned")
        self.assertLess(report["runs"][E1]["start_interval_us"], 200)
        self.assertEqual(report["runs"][E1]["uncertain_calls"], 0)       # 0.2 ms from 1.25 s is outside the pin
        self.assertEqual(report["runs"][E2]["start"], "estimated")
        header, rows = self.read(out)
        for e in (E1, E2, E3):
            want = windows_of(self.hm, self.calls[e], self.t0[e], NS // 4, 80)
            mine = [r for r in rows if r[0] == e]
            for k in range(80):
                got = dict(zip(header, mine[k]))
                self.assertEqual([float(got[c]) for c in self.host_cols], [float(want[k][c]) for c in self.host_cols])

    def test_a_run_unlike_its_training_row_writes_no_table(self):
        root, table, net = self.make(spoil=E2)
        code, out, report = self.run_script(root=root, table=table, net=net)
        self.assertEqual(code, 1)
        self.assertEqual(report["missing"], [E2])
        self.assertEqual(report["rejected"][E2][0]["cells_off"], 1)
        self.assertFalse(out.exists())

    def test_a_run_whose_calls_cannot_be_read_is_rejected(self):
        _, table, net = self.make()
        z = self.d / "lone" / "tool-x-amd64_dynamic.zip"                # named E2 by the zip's name
        z.parent.mkdir(parents=True)
        with zipfile.ZipFile(str(z), "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("output/run_9/run.json", json.dumps({"windows": 40}))
            text = io.StringIO()
            write_events(text, self.calls[E2], self.t0[E2])
            zf.writestr("output/run_9/syscall_events.csv", text.getvalue())
        damage_member(z, "output/run_9/syscall_events.csv")
        code, out, report = self.run_script("--only", E2, root=z.parent, table=table, net=net)
        self.assertEqual(code, 1)
        self.assertEqual(report["missing"], [E2])
        self.assertEqual(len(report["rejected"][E2]), 1)
        self.assertIn("invalid block type", report["rejected"][E2][0]["error"])

    def test_a_trial_on_one_run_writes_only_the_report(self):
        root, table, net = self.make()
        code, out, report = self.run_script("--only", E1, root=root, table=table, net=net)
        self.assertEqual(code, 0)
        self.assertEqual(report["found"], 1)
        self.assertFalse(out.exists())


if __name__ == "__main__":
    unittest.main()
