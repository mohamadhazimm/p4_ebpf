"""live_test/streaming/stream_verdicts.py: training on extra window tables (PC1.md part 12: the live runs) and the
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

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / "live_test" / "streaming"))
try:
    import numpy as np
    import sklearn  # noqa: F401
    HAVE = True
except ImportError:
    HAVE = False

HEADER = ["execution_id", "label", "category", "cv_group", "split", "window",
          "host_a", "host_b", "net_a", "net_b"]


def write_table(path, runs, header=HEADER):
    """runs: (execution_id, label, group, level) -> 40 windows of signals around level."""
    with gzip.open(path, "wt", newline="") as f:
        w = csv.writer(f)
        w.writerow(header)
        for eid, label, group, level in runs:
            for k in range(40):
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
        write_table(self.base, [("m%d" % i, 1, "gm%d" % (i % 3), 50) for i in range(6)] +
                    [("b%d" % i, 0, "gb%d" % (i % 3), 1) for i in range(6)])
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


if __name__ == "__main__":
    unittest.main()
