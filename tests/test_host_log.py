"""Tests of hybrid_collector.py's reading of the host monitor's output (host/hostmon_agg):

- a process name may hold any character but NUL: hostmon_agg replaces only \\n and \\r, so a vertical tab, a form
  feed, a file separator, a comma or a quote must not drop or shift the process's row (the parser used to split
  with str.splitlines() and on every comma);
- HOSTMON_WINDOW_DONE,<window> (hostmon_agg since 2026-11-19) makes a window complete as soon as it is printed;
  without it (older monitors) a window is complete when the next one's header is read;
- HostLogTail reads the log in pieces (a line, or a UTF-8 character, cut between two writes) and gives what one
  parse of the whole log gives;
- wait_host_windows() waits for the window it needs, at most its timeout."""
import os
import random
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "switch" / "control"))
sys.path.insert(0, str(HERE.parent / "collector"))
import hybrid_collector as hc  # noqa: E402

HEADER = ",".join(hc.HOST_HEADER)


def quoted(comm):
    """A name as hostmon_agg_fmt.h prints it: CSV-quoted, quotes doubled, \\n and \\r replaced by '?'."""
    return '"' + comm.replace('"', '""').replace("\n", "?").replace("\r", "?") + '"'


def row(comm, pid, total):
    nums = [pid, 0, 1, 0, 0, 0, 0, 0, total, 3, "1.500000", "0.400000", "2.000000", 4, 5, "0.100000", 3, 3]
    return quoted(comm) + "," + ",".join(str(x) for x in nums)


def block(w, rows, done=True):
    text = "\n==== HOST WINDOW %d START=%.6f END=%.6f DUR=0.500000 ====\n%s\n" % (w, w * 0.5, w * 0.5 + 0.5, HEADER)
    text += "".join(r + "\n" for r in rows)
    if done:
        text += "HOSTMON_WINDOW_DONE,%d\n" % w
    return text


ODD = ["vt\x0bname", "ff\x0cname", "fs\x1cgs\x1drs\x1e", "a,b,c", 'say "hi"', 'x","y', "nel\x85", "ls ps ",
       "line\nbreak", "plain"]


class ParseTest(unittest.TestCase):
    def test_every_name_keeps_its_row(self):
        text = "HOSTMON_READY,7\n" + block(0, [row(c, 100 + i, 10 * (i + 1)) for i, c in enumerate(ODD)])
        text += "HOSTMON_HEALTH,0,0,0,0\n"
        (w,) = hc.parse_host_windows(text)
        self.assertEqual(len(w["rows"]), len(ODD))
        for i, (r, c) in enumerate(zip(w["rows"], ODD)):
            self.assertEqual(r["pid"], 100 + i)
            self.assertEqual(r["total_syscalls"], 10 * (i + 1))
            self.assertEqual(r["first100_unique"], 3)
            self.assertEqual(r["comm"], c.replace("\n", "?"))
        # the old parser lost these rows: str.splitlines() cuts at \x0b, \x0c, \x1c-\x1e, \x85,  ,
        old = [line for line in text.splitlines() if line.count(",") == len(hc.HOST_HEADER) - 1]
        self.assertLess(len(old), len(ODD))

    def test_the_done_line_completes_a_window(self):
        ws = hc.parse_host_windows(block(0, [row("p", 1, 5)]) + block(1, [row("p", 1, 6)], done=False))
        self.assertEqual([w["complete"] for w in ws], [True, False])
        self.assertEqual(hc.complete_host_windows(ws), 1)

    def test_without_done_lines_the_next_header_completes_a_window(self):
        text = block(0, [row("p", 1, 5)], done=False) + block(1, [row("p", 1, 6)], done=False)
        ws = hc.parse_host_windows(text)
        self.assertEqual([w["complete"] for w in ws], [True, False])  # as the collector did before

    def test_other_lines_are_not_rows(self):
        text = ("garbage,1,2\n" + block(0, [row("p", 1, 5)]) + "libbpf: some warning\nHOSTMON_HEALTH,0,0,0,0\n"
                + "HOSTMON_WINDOW_DONE,9\n")
        (w,) = hc.parse_host_windows(text)
        self.assertEqual(len(w["rows"]), 1)                       # rows before any header and other lines ignored
        self.assertTrue(w["complete"])

    def test_an_empty_window(self):
        (w,) = hc.parse_host_windows(block(0, []))
        self.assertEqual(w["rows"], [])
        self.assertTrue(w["complete"])

    def test_the_file_is_read_without_newline_translation(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "host.log")
            Path(p).write_bytes(block(0, [row("cr\rname", 1, 5), row("q", 2, 6)]).encode())
            # (the monitor prints \r as '?', but a lone \r in the file must not cut a row either)
            Path(p).write_bytes(Path(p).read_bytes().replace(b"cr?name", b"cr\rname"))
            (w,) = hc.read_host_windows(p)
            self.assertEqual([r["pid"] for r in w["rows"]], [1, 2])


class TailTest(unittest.TestCase):
    def test_pieces_give_what_one_parse_gives(self):
        rng = random.Random(7)
        text = "HOSTMON_READY,7\n"
        for w in range(12):
            text += block(w, [row(rng.choice(ODD + ["é-ünïcode"]), 100 + i, rng.randrange(1, 9999))
                              for i in range(rng.randrange(0, 6))])
        data = text.encode()
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "host.log")
            open(p, "wb").close()
            tail = hc.HostLogTail(p)
            done_seen, i = [], 0
            while i < len(data):
                j = min(len(data), i + rng.randrange(1, 97))      # cuts lines and multibyte characters
                with open(p, "ab") as f:
                    f.write(data[i:j])
                i = j
                done_seen.append(hc.complete_host_windows(tail.poll()))
            self.assertEqual(done_seen, sorted(done_seen))        # windows complete in order, never undone
            self.assertEqual(tail.poll(), hc.parse_host_windows(text))
            self.assertEqual(hc.complete_host_windows(tail.poll()), 12)

    def test_a_window_is_not_complete_before_its_done_line(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "host.log")
            text = block(0, [row("p", 1, 5), row("q", 2, 6)])
            cut = text.index("HOSTMON_WINDOW_DONE")
            Path(p).write_text(text[:cut])
            tail = hc.HostLogTail(p)
            self.assertEqual(hc.complete_host_windows(tail.poll()), 0)
            with open(p, "a") as f:
                f.write(text[cut:])
            ws = tail.poll()
            self.assertEqual(hc.complete_host_windows(ws), 1)
            self.assertEqual(len(ws[0]["rows"]), 2)


class FakeClock:
    def __init__(self, on_sleep):
        self.t, self.on_sleep, self.sleeps = 0.0, on_sleep, 0

    def monotonic(self):
        return self.t

    def sleep(self, d):
        self.t += d
        self.sleeps += 1
        self.on_sleep(self.t)


class WaitTest(unittest.TestCase):
    def test_it_waits_for_the_window_then_stops(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "host.log")
            Path(p).write_text(block(0, [row("p", 1, 5)]))
            tail = hc.HostLogTail(p)

            def monitor(t):                                         # window 1 printed 50 ms later
                if t >= 0.05 and "WINDOW 1 " not in Path(p).read_text():
                    with open(p, "a") as f:
                        f.write(block(1, [row("p", 1, 6)]))
            clock = FakeClock(monitor)
            ws = hc.wait_host_windows(tail, 2, 0.25, clock=clock)
            self.assertEqual(hc.complete_host_windows(ws), 2)
            self.assertLess(clock.t, 0.07)
            clock2 = FakeClock(lambda t: None)                     # window 2 never comes: give up at the timeout
            ws = hc.wait_host_windows(tail, 3, 0.25, clock=clock2)
            self.assertEqual(hc.complete_host_windows(ws), 2)
            self.assertAlmostEqual(clock2.t, 0.25, delta=0.006)

    def test_no_wait_when_the_window_is_there(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "host.log")
            Path(p).write_text(block(0, []))
            clock = FakeClock(lambda t: None)
            hc.wait_host_windows(hc.HostLogTail(p), 1, 0.25, clock=clock)
            self.assertEqual(clock.sleeps, 0)


if __name__ == "__main__":
    unittest.main()
