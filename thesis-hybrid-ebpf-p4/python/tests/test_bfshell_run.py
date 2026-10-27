from __future__ import annotations

import os
import stat
import sys
import tempfile
import unittest

from bfshell_run import BfshellError, run_bfshell_script

# Stands in for bfshell: reports whether its stdin is still open after 0.3 s
# (the real client disconnects at stdin EOF) and echoes the script it was given.
FAKE_BFSHELL = r'''#!%s
import select, sys
args = sys.argv[1:]
script = args[args.index("-b") + 1]
ready, _, _ = select.select([sys.stdin], [], [], 0.3)
state = "EOF" if ready and not sys.stdin.read(1) else "OPEN"
print("stdin " + state)
print(open(script).read())
sys.exit(3 if "FAIL" in open(script).read() else 0)
''' % sys.executable


class RunBfshellScriptTests(unittest.TestCase):
    def setUp(self):
        fd, self.fake = tempfile.mkstemp(suffix=".py")
        with os.fdopen(fd, "w") as f:
            f.write(FAKE_BFSHELL)
        os.chmod(self.fake, os.stat(self.fake).st_mode | stat.S_IXUSR)

    def tearDown(self):
        os.unlink(self.fake)

    def test_stdin_stays_open_until_bfshell_exits(self):
        out = run_bfshell_script("print('hello')", bfshell=self.fake, timeout=10)
        self.assertIn("stdin OPEN", out)
        self.assertIn("print('hello')", out)

    def test_nonzero_exit_raises(self):
        with self.assertRaises(BfshellError):
            run_bfshell_script("FAIL", bfshell=self.fake, timeout=10)


if __name__ == "__main__":
    unittest.main()
