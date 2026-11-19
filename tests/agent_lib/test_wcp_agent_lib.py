"""Unit tests of resources/agents/wcp_agent_lib.py, run by tests/agent_library.rs.

Usage: python3 -I test_wcp_agent_lib.py <directory holding wcp_agent_lib.py>
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, sys.argv.pop(1))
import wcp_agent_lib as lib  # noqa: E402

HOSTILE = [
    "", "'", "''", "a'b", "$(echo x)", "`echo x`", ";", "|", "a;b|c&d",
    "line1\nline2", "\n", "café 日本語 \U0001F600", "x" * 100000,
    "-n", "--help", "-e\\n", "\\", "\\\\'\\", "a b\tc", "*", "$HOME", "${IFS}",
    "!!", "#c", "~",
]


def old_local_sh_esc(s):
    """The copy that backup-agent and error-log-digest defined before they
    used the library. Kept here as the reference the library must match."""
    return "'" + str(s).replace("'", "'\\''") + "'"


class ShellQuote(unittest.TestCase):
    def test_round_trips_through_sh(self):
        for s in HOSTILE:
            out = subprocess.run(["sh", "-c", "printf %s " + lib.shell_quote(s)],
                                 capture_output=True).stdout
            self.assertEqual(out, s.encode(), repr(s)[:40])

    def test_is_byte_identical_to_every_earlier_copy(self):
        for s in HOSTILE + [123, None, b"x"]:
            self.assertEqual(lib.shell_quote(s), old_local_sh_esc(s))
            self.assertEqual(lib._sh_esc(s), old_local_sh_esc(s))


class MakeLogger(unittest.TestCase):
    def test_writes_the_same_bytes_as_log_entry(self):
        with tempfile.TemporaryDirectory() as d:
            a, b = os.path.join(d, "a", "x.log"), os.path.join(d, "b", "x.log")
            log = lib.make_logger(a)
            for i in range(5):
                log({"n": i, "t": "café"})
                lib.log_entry(b, {"n": i, "t": "café"})
            self.assertEqual(open(a, "rb").read(), open(b, "rb").read())
            self.assertEqual(open(a).read().splitlines()[0], '{"n":0,"t":"caf\\u00e9"}')

    def test_rotates_to_max_lines_keeping_the_newest(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "x.log")
            log = lib.make_logger(p, 10)
            for i in range(25):
                log({"n": i})
            self.assertEqual([json.loads(l)["n"] for l in open(p).read().splitlines()],
                             list(range(15, 25)))

    def test_default_limit_is_the_log_entry_default(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "x.log")
            with open(p, "w") as f:
                f.write('{"n":0}\n' * 2000)
            lib.make_logger(p)({"n": 1})
            self.assertEqual(len(open(p).read().splitlines()), 2000)


class RunCmd(unittest.TestCase):
    def test_string_runs_through_the_shell(self):
        r = lib.run_cmd("echo out; echo err >&2; exit 3")
        self.assertEqual((r.stdout, r.stderr, r.returncode), ("out\n", "err\n", 3))

    def test_list_runs_without_a_shell(self):
        r = lib.run_cmd(["printf", "%s", "a b; $(x)"])
        self.assertEqual(r.stdout, "a b; $(x)")

    def test_timeouts(self):
        for cmd in ("sleep 5", ["sleep", "5"]):
            with self.assertRaises(subprocess.TimeoutExpired):
                lib.run_cmd(cmd, timeout=1)

    def test_pipefail_fails_the_whole_pipeline(self):
        self.assertEqual(lib.run_cmd("false | true").returncode, 0)
        self.assertNotEqual(lib.run_cmd("false | true", pipefail=True).returncode, 0)

    def test_pipefail_keeps_the_quoting_of_the_command(self):
        r = lib.run_cmd("printf %s \"it's\" | cat", pipefail=True)
        self.assertEqual(r.stdout, "it's")

    def test_pipefail_needs_a_string(self):
        with self.assertRaises(ValueError):
            lib.run_cmd(["true"], pipefail=True)


class OlderAgentsKeepWorking(unittest.TestCase):
    def test_every_name_an_installed_agent_imports_still_exists(self):
        for name in ("shell_quote", "run", "run_argv", "read_json", "write_json",
                     "log_entry", "notify", "database_dump_command", "sql_digest"):
            self.assertTrue(callable(getattr(lib, name)), name)

    def test_run_and_run_argv_behave_as_before(self):
        r = lib.run("echo out; exit 2", timeout=5)
        self.assertEqual((r.stdout, r.returncode), ("out\n", 2))
        self.assertEqual(lib.run_argv(["printf", "%s", "a b"], timeout=5).stdout, "a b")


if __name__ == "__main__":
    unittest.main()
