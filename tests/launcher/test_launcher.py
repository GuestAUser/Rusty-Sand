import base64
import contextlib
import io
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import tempfile
import termios
import unittest
from unittest import mock

from transport_fixture import ROOT, load_launcher

launcher = load_launcher()
FIXTURE = Path(__file__).with_name("transport_fixture.py")

class PathTests(unittest.TestCase):
    def setUp(self):
        self.cwd = Path("/checkout with spaces")
        self.conversions = []

        def convert(command, **kwargs):
            self.conversions.append(command)
            return subprocess.CompletedProcess(command, 0, "WIN:" + command[-1] + "\n")

        self.patch = mock.patch.object(launcher.subprocess, "run", side_effect=convert)
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def test_long_short_and_attached_paths(self):
        for args in (
            ["--workdir", "work", "--output", "out", "app.exe"],
            ["--workdir=work", "--output=out", "app.exe"],
            ["-w", "work", "-o", "out", "app.exe"],
            ["-wwork", "-oout", "app.exe"],
            ["-w=work", "-o=out", "app.exe"],
        ):
            with self.subTest(args=args):
                profile, result = launcher.translate_arguments(args, self.cwd)
                self.assertEqual(profile, "release")
                self.assertIn("WIN:/checkout with spaces/work", result)
                self.assertIn("WIN:/checkout with spaces/out", result)
                self.assertEqual(result[-1], "WIN:/checkout with spaces/app.exe")

    def test_short_clusters_and_nonpath_values(self):
        _, result = launcher.translate_arguments(
            ["-vwwork", "-t10", "--color=never", "--plain", "--reduced-motion", "app.exe"], self.cwd
        )
        self.assertIn("-vw", result)
        self.assertIn("10", result)
        self.assertIn("never", result)
        self.assertIn("--plain", result)
        self.assertIn("--reduced-motion", result)
        self.assertEqual(len(self.conversions), 3)  # workdir, executable, default output

    def test_windows_absolute_paths_are_unchanged(self):
        for value in (r"C:\space dir\app.exe", "D:/app.exe", r"\\server\share\app.exe", "//server/share/app.exe"):
            self.assertEqual(launcher.windows_path(value, self.cwd), value)
        self.assertEqual(self.conversions, [])

    def test_drive_relative_paths_are_rejected(self):
        for value in ("C:", "c:app.exe", "Z:..\\app.exe"):
            with self.assertRaises(ValueError):
                launcher.windows_path(value, self.cwd)

    def test_target_arguments_are_opaque(self):
        target = ["--workdir=/linux", "-oX", "C:relative", "--launcher-debug", "--help", "", 'a"b', "a b", "λ"]
        profile, result = launcher.translate_arguments(["app.exe", "--", *target], self.cwd)
        self.assertEqual(result[result.index("--") + 1 :], target)
        self.assertEqual(profile, "release")

    def test_profile_is_explicit_and_default_output_is_checkout_local(self):
        profile, result = launcher.translate_arguments(["--launcher-debug", "app.exe"], self.cwd)
        self.assertEqual(profile, "debug")
        self.assertEqual(result[:2], ["--output", "WIN:" + str(ROOT / "sandbox_output")])

    def test_missing_option_value_fails_before_spawn(self):
        for value in ("--workdir", "--output", "-w", "-o", "--color", "-t"):
            with self.assertRaises(ValueError):
                launcher.translate_arguments([value], self.cwd)

    def test_backend_modes_are_forwarded_without_selecting_a_debug_build(self):
        for mode in ("--static", "--debug", "--shell"):
            with self.subTest(mode=mode):
                profile, result = launcher.translate_arguments(
                    [mode, "app.exe", "--", "--debug", "--restricted"], self.cwd
                )
                self.assertEqual(profile, "release")
                self.assertIn(mode, result[:result.index("--")])
                self.assertIn("WIN:/checkout with spaces/app.exe", result)
                self.assertEqual(result[result.index("--") + 1:], ["--debug", "--restricted"])

    def test_restricted_and_unknown_flags_are_left_for_backend_validation(self):
        profile, result = launcher.translate_arguments(
            ["--debug", "--restricted", "--unknown-analysis-option", "app.exe"], self.cwd
        )
        self.assertEqual(profile, "release")
        self.assertIn("--debug", result)
        self.assertIn("--restricted", result)
        self.assertIn("--unknown-analysis-option", result)
        self.assertEqual(result[-1], "WIN:/checkout with spaces/app.exe")

    def test_debug_backend_and_debug_build_are_independent(self):
        profile, result = launcher.translate_arguments(
            ["--launcher-debug", "--debug", "app.exe"], self.cwd
        )
        self.assertEqual(profile, "debug")
        self.assertIn("--debug", result)
        self.assertNotIn("--launcher-debug", result)

class EntryTests(unittest.TestCase):
    def test_noninteractive_eof_policy_does_not_parse_target_arguments(self):
        for arguments, closes in [
            ([r"C:\app.exe", "--no-interactive"], False),
            ([r"C:\app.exe", "--", "--no-interactive"], True),
        ]:
            with self.subTest(arguments=arguments), mock.patch.dict(
                os.environ, {"WSL_INTEROP": "present"}
            ), mock.patch.object(
                launcher, "windows_path", side_effect=lambda value, _cwd: value
            ), mock.patch.object(Path, "is_file", return_value=True), mock.patch.object(
                launcher, "forward_input", return_value=0
            ) as forward:
                self.assertEqual(launcher.main(arguments), 0)
                self.assertEqual(forward.call_args.kwargs["close_on_eof"], closes)

    def test_help_needs_neither_wsl_nor_backend(self):
        with mock.patch.dict(os.environ, {}, clear=True), contextlib.redirect_stdout(io.StringIO()), mock.patch.object(launcher, "forward_input") as forward:
            self.assertEqual(launcher.main(["--help"]), 0)
            forward.assert_not_called()

    def test_non_wsl_fails_without_spawning(self):
        with mock.patch.dict(os.environ, {}, clear=True), contextlib.redirect_stderr(io.StringIO()), mock.patch.object(launcher, "forward_input") as forward:
            self.assertEqual(launcher.main(["app.exe"]), 2)
            forward.assert_not_called()

    def test_either_wsl_marker_and_exact_artifact_selection(self):
        for marker in ("WSL_DISTRO_NAME", "WSL_INTEROP"):
            for debug in (False, True):
                with self.subTest(marker=marker, debug=debug), mock.patch.dict(os.environ, {marker: "present"}, clear=True), mock.patch.object(launcher, "windows_path", side_effect=lambda value, _cwd: value), mock.patch.object(Path, "is_file", return_value=True), mock.patch.object(launcher, "forward_input", return_value=19) as forward:
                    args = (["--launcher-debug"] if debug else []) + [r"C:\app.exe", "--", "-w/stays"]
                    self.assertEqual(launcher.main(args), 19)
                    command, _environment, cwd = forward.call_args.args
                    self.assertEqual(command[0], str(ROOT / "target/x86_64-pc-windows-gnu" / ("debug" if debug else "release") / "rusty_sand.exe"))
                    self.assertEqual(command[-2:], ["--", "-w/stays"])
                    self.assertEqual(cwd, ROOT)

    def test_missing_release_does_not_try_debug_or_build(self):
        with mock.patch.dict(os.environ, {"WSL_INTEROP": "present"}), mock.patch.object(launcher, "windows_path", side_effect=lambda value, _cwd: value), mock.patch.object(Path, "is_file", return_value=False) as exists, mock.patch.object(launcher, "forward_input") as forward, contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(launcher.main([r"C:\app.exe"]), 2)
            self.assertEqual(exists.call_count, 1)
            forward.assert_not_called()

    def test_wslenv_preserves_unrelated_settings_without_path_flags_on_ui(self):
        source = {"WSLENV": "KEEP/p:OTHER/lu:TERM/p:RUSTY_SAND_COLUMNS/p", "KEEP": "x", "TERM": "xterm-256color", "NO_COLOR": ""}
        with mock.patch.object(os, "isatty", return_value=True), mock.patch.object(os, "get_terminal_size", return_value=os.terminal_size((132, 40))):
            result = launcher.backend_environment(source)
        self.assertEqual(result["RUSTY_SAND_STDERR_TTY"], "1")
        self.assertEqual(result["RUSTY_SAND_STDIN_CONTROL"], "1")
        self.assertEqual(result["RUSTY_SAND_COLUMNS"], "132")
        self.assertEqual(result["WSLENV"].split(":"), ["KEEP/p", "OTHER/lu", "RUSTY_SAND_STDIN_CONTROL", "RUSTY_SAND_STDERR_TTY", "RUSTY_SAND_COLUMNS", "TERM", "NO_COLOR"])
        self.assertEqual(source["WSLENV"], "KEEP/p:OTHER/lu:TERM/p:RUSTY_SAND_COLUMNS/p")

class TransportTests(unittest.TestCase):
    def command(self, mode):
        return [sys.executable, str(FIXTURE), "bridge", mode]

    def test_binary_input_backpressure_and_eof_are_lossless(self):
        data = bytes(range(256)) * 8192
        result = subprocess.run(self.command("read"), input=data, capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        output = json.loads(result.stdout)
        self.assertEqual(base64.b64decode(output["data"]), data)
        self.assertEqual(output["cwd"], str(ROOT))

    def test_regular_file_stdin(self):
        with tempfile.TemporaryFile() as stream:
            stream.write(b"Y\r\n")
            stream.seek(0)
            result = subprocess.run(self.command("read"), stdin=stream, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(base64.b64decode(json.loads(result.stdout)["data"]), b"Y\r\n")

    def test_canonical_terminal_input_and_modes_are_preserved(self):
        master, slave = os.openpty()
        try:
            original = termios.tcgetattr(slave)
            self.assertTrue(original[3] & termios.ICANON)
            with subprocess.Popen(self.command("read"), stdin=slave, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as child:
                os.write(master, b"Y\n\x04")
                stdout, stderr = child.communicate(timeout=10)
                self.assertEqual(child.returncode, 0, stderr)
                self.assertEqual(base64.b64decode(json.loads(stdout)["data"]), b"Y\n")
            self.assertEqual(termios.tcgetattr(slave), original)
        finally:
            os.close(master)
            os.close(slave)

    def ready(self, child):
        with selectors.DefaultSelector() as selector:
            selector.register(child.stdout, selectors.EVENT_READ)
            self.assertTrue(selector.select(10), "fixture did not become ready")
        self.assertEqual(child.stdout.readline(), b"READY\n")

    def test_signals_close_input_and_preserve_backend_cleanup_exit(self):
        for number in (signal.SIGINT, signal.SIGTERM):
            with self.subTest(number=number), subprocess.Popen(self.command("signal"), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as child:
                self.ready(child)
                child.send_signal(number)
                self.assertEqual(child.wait(timeout=10), 23)
                self.assertFalse(child.stdin.closed)
                stdout, stderr = child.communicate(timeout=10)
                self.assertEqual(child.returncode, 23, stderr)
                self.assertEqual(base64.b64decode(json.loads(stdout)["data"]), b"")

    def test_child_exit_wakes_bridge_while_parent_input_stays_open(self):
        with subprocess.Popen(self.command("exit"), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as child:
            self.ready(child)
            self.assertEqual(child.wait(timeout=10), 7)
            self.assertFalse(child.stdin.closed)


if __name__ == "__main__":
    unittest.main()
