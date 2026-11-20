"""collector/detector/stream_verdicts.py: training on extra window tables (PC1.md part 12: the live runs) and the
batched scorer. A small synthetic table and a fake release (evaluation/common.py with a 10-tree forest) keep it fast;
it needs NumPy and scikit-learn (the dataset construction's .venv) and is skipped without them."""
import csv
import gzip
import importlib
import os
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "collector" / "detector"))
sys.path.insert(0, str(REPO / "collector"))
try:
    import numpy as np
    import sklearn  # noqa: F401
    HAVE = True
except ImportError:
    HAVE = False

HEADER = ["execution_id", "label", "category", "cv_group", "split", "window",
          "host_a", "host_b", "net_a", "net_b"]


def write_table(path, runs, header=HEADER, windows=40):
    """runs: (execution_id, label, group, level) -> windows of signals around level."""
    with gzip.open(path, "wt", newline="") as f:
        w = csv.writer(f)
        w.writerow(header)
        for eid, label, group, level in runs:
            for k in range(windows):
                vals = [level + (k % 3), level * 2 + (k % 5), level * 3 + (k % 4), level + (k % 2)]
                w.writerow([eid, label, "x", group, "train", k] + vals[:len(header) - 6])


@unittest.skipUnless(HAVE, "needs NumPy and scikit-learn")
class StreamExtraTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        d = Path(self.dir.name)
        (d / "release" / "evaluation").mkdir(parents=True)
        (d / "release" / "evaluation" / "common.py").write_text(
            "from sklearn.ensemble import RandomForestClassifier\n"
            "def random_forest():\n    return RandomForestClassifier(n_estimators=10, random_state=0)\n")
        self.release = str(d / "release")
        self.base = str(d / "base.csv.gz")
        self.extra = str(d / "extra.csv.gz")
        self.runs = [("m%d" % i, 1, "gm%d" % (i % 3), 50) for i in range(6)] + \
            [("b%d" % i, 0, "gb%d" % (i % 3), 1) for i in range(6)]
        write_table(self.base, self.runs)
        self.t80 = str(d / "t80.csv.gz")
        write_table(self.t80, self.runs, windows=80)
        write_table(self.extra, [("live:x%d" % i, 0, "live::x", 40) for i in range(3)] +
                    [("live:y%d" % i, 0, "live::y", 45) for i in range(3)])
        sys.modules.pop("common", None)
        import stream_verdicts
        self.sv = importlib.reload(stream_verdicts)

    def tearDown(self):
        sys.modules.pop("common", None)
        if self.release + "/evaluation" in sys.path:
            sys.path.remove(self.release + "/evaluation")
        self.dir.cleanup()

    def spy(self):
        seen = {}
        real = self.sv.train_arrays

        def train_arrays(common, signals, W, y, g, detector):
            seen.update(runs=len(y), groups=sorted(set(g.tolist())), benign=int((y == 0).sum()))
            return real(common, signals, W, y, g, detector)
        self.sv.train_arrays = train_arrays
        self.addCleanup(setattr, self.sv, "train_arrays", real)
        return seen

    def test_the_extra_table_is_trained_on_and_held_out_by_group(self):
        seen = self.spy()
        self.sv.train(self.release, self.base, "network")
        self.assertEqual(seen["runs"], 12)
        self.sv.train(self.release, self.base, "network", extra_paths=[self.extra])
        self.assertEqual((seen["runs"], seen["benign"]), (18, 12))
        self.sv.train(self.release, self.base, "network", hold_out=["live::x"], extra_paths=[self.extra])
        self.assertEqual(seen["runs"], 15)
        self.assertNotIn("live::x", seen["groups"])
        self.assertIn("live::y", seen["groups"])

    def test_an_extra_table_with_other_signals_is_refused(self):
        other = str(Path(self.dir.name) / "other.csv.gz")
        write_table(other, [("live:z", 0, "live::z", 1)], header=HEADER[:-1])
        with self.assertRaises(SystemExit):
            self.sv.train(self.release, self.base, "network", extra_paths=[other])

    def test_the_batch_scorer_equals_the_window_scorer(self):
        signals, W, y, g = self.sv.load_windows(self.base)
        host = [i for i, s in enumerate(signals) if s.startswith("host_")]
        net = [i for i, s in enumerate(signals) if s.startswith("net_")]
        for det in ("network", "host", "stacked"):
            _, _, score = self.sv.train(self.release, self.base, det, extra_paths=[self.extra])
            for i in (0, 7):
                for k in (1, 5, 40):
                    one = score(W[i, :k][:, host], W[i, :k][:, net])
                    batch = score.batch(self.sv.summarize(W[i:i + 1, :, host], k),
                                        self.sv.summarize(W[i:i + 1, :, net], k))
                    self.assertAlmostEqual(one, float(batch[0]), places=12, msg=(det, i, k))

    def test_a_table_of_80_windows_trains_on_the_same_times(self):
        _, _, score = self.sv.train(self.release, self.t80, "stacked")
        self.assertEqual((score.windows, score.window_sec), (80, 0.25))
        self.assertEqual(score.prefixes, [1, 2, 3, 4, 8, 12, 20, 32, 40, 60, 80])
        _, _, score40 = self.sv.train(self.release, self.base, "network")
        self.assertEqual((score40.windows, score40.window_sec, score40.prefixes), (40, 0.5, self.sv.PREFIXES))

    def test_tables_of_two_window_lengths_are_not_mixed(self):
        with self.assertRaises(SystemExit):
            self.sv.train(self.release, self.base, "network", extra_paths=[self.t80])
        short = str(Path(self.dir.name) / "short.csv.gz")
        write_table(short, self.runs, windows=80)
        with gzip.open(short, "rt") as f:
            rows = f.readlines()
        with gzip.open(short, "wt") as f:
            f.writelines(rows[:-1])                      # the last run without its last window
        with self.assertRaises(SystemExit):
            self.sv.load_windows(short)

    def test_the_network_half_alone_trains_only_the_network_detector(self):
        net = str(Path(self.dir.name) / "net.csv.gz")
        write_table(net, self.runs, header=HEADER[:6] + ["net_a", "net_b"], windows=80)
        host, net_signals, score = self.sv.train(self.release, net, "network")
        self.assertEqual((host, net_signals, score.windows), ([], ["net_a", "net_b"], 80))
        for det in ("host", "stacked"):
            with self.assertRaises(SystemExit):
                self.sv.train(self.release, net, det)
        # live runs with all the signals train the network half's detector on its own signals
        seen = self.spy()
        live80 = str(Path(self.dir.name) / "live80.csv.gz")
        write_table(live80, [("live:x%d" % i, 0, "live::x", 40) for i in range(3)], windows=80)
        self.sv.train(self.release, net, "network", extra_paths=[live80])
        self.assertEqual(seen["runs"], 15)

    def test_the_block_scorer_refuses_another_window_length(self):
        import block_policy
        with self.assertRaises(ValueError):
            block_policy.load_scorer("network", release=self.release, windows_path=self.base, window_sec=0.25)
        f = block_policy.load_scorer("network", release=self.release, windows_path=self.t80, window_sec=0.25)
        self.assertEqual((f.windows, f.window_sec, f.table), (80, 0.25, self.t80))
        rows = [{"host_a": 1, "host_b": 2, "net_a": 50, "net_b": 1}] * 3
        self.assertGreaterEqual(f(rows), 0.0)

    def test_the_scorer_in_its_own_process_scores_the_same(self):
        # block_policy.ScorerProcess (PC1.md part 13K): trained in a new interpreter, the same forests, the same
        # probabilities; a refused table is refused from there too
        import block_policy
        rows = [{"host_a": 1 + k % 3, "host_b": 2 + k % 2, "net_a": 50 - 2 * k, "net_b": 1} for k in range(20)]
        for det in ("network", "stacked"):
            with self.subTest(detector=det):
                here = block_policy.load_scorer(det, release=self.release, windows_path=self.t80, window_sec=0.25)
                there = block_policy.load_scorer(det, release=self.release, windows_path=self.t80, window_sec=0.25,
                                                 process=True)
                try:
                    self.assertIsInstance(there, block_policy.ScorerProcess)
                    self.assertEqual((there.windows, there.window_sec, there.prefixes, there.table),
                                     (here.windows, here.window_sec, here.prefixes, here.table))
                    for k in (1, 7, 20):
                        self.assertEqual(there(rows[:k]), here(rows[:k]))
                finally:
                    there.close()
                with self.assertRaises(RuntimeError):
                    there(rows)                                     # closed
        with self.assertRaises(ValueError):
            block_policy.load_scorer("network", release=self.release, windows_path=self.base, window_sec=0.25,
                                     process=True)


if __name__ == "__main__":
    unittest.main()
