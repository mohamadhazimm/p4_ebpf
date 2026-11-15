"""live_test/replay_capture.py --profile and live_test/dataset_row.py --skip-windows (PC1.md Part 4)."""
import csv
import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
RELEASE = REPO.parent / "p4-ebpf-malware-detection"


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ReplayProfiles(unittest.TestCase):
    def setUp(self):
        self.rc = load("replay_capture", REPO / "live_test" / "replay_capture.py")

    def test_switch_profile_is_unchanged(self):
        window, extra = self.rc.profile_settings("switch", 2)
        self.assertEqual(window, 1.0)
        self.assertEqual(extra, ["--profile", "switch"])

    def test_dataset_profile_runs_k_plus_40_windows_of_half_a_second(self):
        window, extra = self.rc.profile_settings("dataset", 4)
        self.assertEqual(window, 0.5)
        self.assertEqual(extra, ["--profile", "dataset", "--launcher", "shell", "--windows", "44"])

    def test_unknown_profile(self):
        with self.assertRaises(ValueError):
            self.rc.profile_settings("model", 2)

    def test_collector_accepts_the_dataset_replay_options(self):
        hc = load("hybrid_collector_for_test", REPO / "hybrid_collector.py")
        _, extra = self.rc.profile_settings("dataset", 4)
        argv = extra + ["--mode", "command", "--scenario-name", "x", "--label", "replay", "--command", "true",
                        "--out-csv", "w.csv"]
        pre, _ = hc.profile_parser().parse_known_args(argv)
        args = hc.build_arg_parser(pre.profile).parse_args(argv)
        self.assertEqual(args.window_sec, 0.5)
        self.assertEqual(args.windows, 44)
        self.assertEqual(args.launcher, "shell")
        self.assertEqual(args.byte_layer, "frame")
        self.assertEqual(args.duration_unit, "s")


@unittest.skipUnless((RELEASE / "features" / "summary.py").exists(), "release repository not next to p4_ebpf")
class DatasetRowSkip(unittest.TestCase):
    def test_skip_windows_takes_the_dataset_windows(self):
        sm = load("switch_model", RELEASE / "features" / "switch_model.py")
        hm = load("host_model", RELEASE / "features" / "host_model.py")
        feats = sm.FEATURES + hm.FEATURES
        with tempfile.TemporaryDirectory() as d:
            src, out_a, out_b = Path(d) / "w.csv", Path(d) / "a.csv", Path(d) / "b.csv"
            with open(src, "w", newline="") as f:
                w = csv.DictWriter(f, fieldnames=["run_id", "window_id"] + feats)
                w.writeheader()
                for k in range(44):
                    # the 4 windows before the anchor carry junk; windows 4..43 carry k
                    row = {name: (1e6 if k < 4 else float(k)) for name in feats}
                    w.writerow(dict(row, run_id="r", window_id=k))
            only = Path(d) / "only.csv"
            with open(src, newline="") as f, open(only, "w", newline="") as g:
                rows = list(csv.DictReader(f))
                w = csv.DictWriter(g, fieldnames=list(rows[0]))
                w.writeheader()
                for r in rows[4:]:
                    w.writerow(dict(r, window_id=int(r["window_id"]) - 4))
            base = [sys.executable, str(REPO / "live_test" / "dataset_row.py"), "--execution-id", "x",
                    "--category", "benign", "--label", "0", "--release", str(RELEASE)]
            subprocess.run(base + [str(src), "--skip-windows", "4", "--out", str(out_a)], check=True,
                           capture_output=True)
            subprocess.run(base + [str(only), "--out", str(out_b)], check=True, capture_output=True)
            self.assertEqual(out_a.read_text(), out_b.read_text())
            short = subprocess.run(base + [str(src), "--skip-windows", "5", "--out", str(Path(d) / "c.csv")],
                                   capture_output=True, text=True)
            self.assertNotEqual(short.returncode, 0)
            self.assertIn("45 are needed", short.stderr)


if __name__ == "__main__":
    unittest.main()
