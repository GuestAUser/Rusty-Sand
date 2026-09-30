"""Stdlib helper regression tests; no Windows build or production launch.

Run: PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests/qa -v
Children announce readiness only after installing their input/signal handlers.
Tests subscribe through the real PTY before sending input. The short timeout
test deliberately tests the deadline itself; no sleep or polling is used.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

from pty_session import PtySession
from surface_checks import ARGUMENTS, MARKER, check_outcome

class PtyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)

    def session(self, source: str, timeout: float = 5) -> PtySession:
        return PtySession(
            [sys.executable, "-u", "-c", source], self.directory / "terminal.log",
            cwd=self.directory, env=os.environ.copy(), timeout=timeout,
        )

    def test_real_tty_and_marker_cursor(self) -> None:
        source = (
            "import os,sys; assert os.isatty(0) and os.isatty(2); "
            "os.write(1,b'QA_'); os.write(1,b'READY\\n'); "
            "assert input()=='Y'; print('QA_READY',flush=True); "
            "assert input()=='N'; print('QA_DONE',flush=True)"
        )
        with self.session(source) as child:
            child.ready(b"QA_READY", "startup")
            cursor = child.send(b"Y\n")
            child.ready(b"QA_READY", "hook", cursor)
            child.send(b"N\n")
            self.assertEqual(child.finish(), 0)
            self.assertIn(b"QA_DONE", child.output)
        self.assertFalse(child.forced_cleanup)
        self.assertEqual((self.directory / "terminal.log").read_bytes(), child.output)

    def test_pty_has_nonzero_dimensions_before_the_child_starts(self) -> None:
        source = "import os,json; print(json.dumps(list(os.get_terminal_size(2))))"
        with self.session(source) as child:
            self.assertEqual(child.finish(), 0)
            self.assertEqual(json.loads(child.output), [100, 40])

    def test_canonical_eof_is_delivered(self) -> None:
        with self.session("import sys; print('READY',flush=True); assert sys.stdin.read()==''") as child:
            child.ready(b"READY", "startup")
            child.send(b"\x04")
            self.assertEqual(child.finish(), 0)

    def test_ctrl_c_reaches_foreground_process(self) -> None:
        source = (
            "import signal,sys; signal.signal(signal.SIGINT,lambda *_:sys.exit(130)); "
            "print('READY',flush=True); sys.stdin.read()"
        )
        with self.session(source) as child:
            child.ready(b"READY", "startup")
            child.send(b"\x03")
            self.assertEqual(child.finish(), 130)

    def test_unanswered_deadline_reaps_child(self) -> None:
        child = self.session("import sys; print('READY',flush=True); sys.stdin.read()")
        with self.assertRaises(TimeoutError):
            with child:
                child.ready(b"READY", "startup")
                child.deadline = time.monotonic() + 0.02
                child.finish()
        self.assertIsNotNone(child.process.returncode)
        self.assertTrue(child.forced_cleanup)
        with self.assertRaises(ProcessLookupError):
            os.kill(child.process.pid, 0)

    def test_early_exit_is_not_readiness(self) -> None:
        with self.session("raise SystemExit(7)") as child:
            with self.assertRaises(EOFError):
                child.ready(b"NEVER", "startup")
            self.assertEqual(child.finish(), 7)

    def test_output_is_not_truncated(self) -> None:
        with self.session("import os; os.write(1,b'x'*200000)") as child:
            self.assertEqual(child.finish(), 0)
            self.assertEqual(len(child.output), 200000)
        self.assertEqual((self.directory / "terminal.log").stat().st_size, 200000)

    def test_exec_failure_closes_resources(self) -> None:
        child = self.session("")
        child.command = [str(self.directory / "missing")]
        with self.assertRaises(FileNotFoundError):
            with child:
                self.fail("missing executable entered session")
        with self.assertRaises(OSError):
            os.fstat(child.master)

class OutcomeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        directory = Path(self.temporary.name)
        self.marker = directory / "marker"
        self.report = directory / "report.json"

    def write_report(self, code: int, tags: list[str]) -> None:
        self.report.write_text(json.dumps({"exit_code": code, "events": [
            {"event_type": tag} for tag in tags
        ]}), encoding="utf-8")

    def check(self, name: str, code: int = 0, output: bytes = b"") -> list[str]:
        return check_outcome(name, code, output, self.marker, self.report)

    def test_allow_requires_report_and_exact_marker(self) -> None:
        self.write_report(0, ["HookFileCreate", "SandboxStopped"])
        self.marker.write_bytes(MARKER)
        self.assertEqual(self.check("allow"), [])

    def test_deny_requires_absent_marker_and_block_tag(self) -> None:
        self.write_report(10, ["HookFileCreate", "HookBlocked", "SandboxStopped"])
        self.assertEqual(self.check("deny"), [])
        self.marker.write_bytes(MARKER)
        self.assertEqual(len(self.check("deny")), 1)

    def test_all_failures_are_retained(self) -> None:
        self.write_report(99, [])
        self.assertGreaterEqual(len(self.check("plain", 1, b"\x1b[31m")), 5)

    def test_each_non_ansi_case_rejects_escape(self) -> None:
        self.write_report(0, ["HookFileCreate", "SandboxStopped"])
        self.marker.write_bytes(MARKER)
        for name in ("plain", "no-color", "redirected"):
            with self.subTest(name=name):
                self.assertEqual(self.check(name), [])
                self.assertEqual(len(self.check(name, output=b"\x1b[0m")), 1)

    def test_argument_dump_preserves_empty_unicode_and_spaces(self) -> None:
        self.write_report(0, ["HookFileCreate", "SandboxStopped"])
        self.marker.write_text(json.dumps(ARGUMENTS), encoding="ascii")
        self.assertEqual(self.check("arguments"), [])
        self.marker.write_text(json.dumps(ARGUMENTS[:-1]), encoding="ascii")
        self.assertEqual(len(self.check("arguments")), 1)

    def test_cancellation_does_not_require_success_report(self) -> None:
        self.assertEqual(self.check("eof-startup", 1), [])
        self.assertEqual(len(self.check("ctrl-c-hook", 0)), 1)

    def test_deadline_requires_numeric_timeout_and_resource_event(self) -> None:
        self.write_report(258, ["ResourceLimitReached", "SandboxStopped"])
        self.assertEqual(self.check("deadline-hook"), [])
        self.marker.write_bytes(MARKER)
        self.assertEqual(self.check("wait-deadline"), [])

    def test_invalid_report_is_never_success(self) -> None:
        for value in ([], {"exit_code": False, "events": []}, {"events": None}):
            with self.subTest(value=value):
                self.report.write_text(json.dumps(value), encoding="utf-8")
                self.assertTrue(self.check("allow"))
                self.assertTrue(self.check("eof-startup", 1))


if __name__ == "__main__":
    unittest.main()
