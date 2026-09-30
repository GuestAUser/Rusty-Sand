"""Machine-value assertions for real launcher runs; no rendering prose snapshots.

Report tags and numeric target exits come from the shared JSON report contract.
Marker bytes and argument arrays come from the source-known fixture contract.
The current hook intercepts CreateFileW, not WriteFile: allow answers one hook.
Cancellation at startup or at that hook must leave the marker absent. A report
on cancellation is optional, but if present must not claim target success.
"""

from __future__ import annotations

import json
from pathlib import Path

MARKER = b"rusty-sand-qa-marker-v1\n"
ARGUMENTS = ["two words", "caf\u00e9-\u65e5\u672c-\U0001f980", "", 'quote"inside', "tail\\"]
AUTOMATIC = ("arguments", "plain", "no-color", "color-never", "reduced-motion", "redirected")
INTERACTIVE = (
    "allow", "deny", "eof-startup", "ctrl-c-startup", "deadline-startup",
    "eof-hook", "ctrl-c-hook", "deadline-hook", "wait-deadline",
)

def check_outcome(
    name: str, returncode: int, output: bytes, marker: Path, report_path: Path,
) -> list[str]:
    """Return every violated assertion, rather than stopping at the first one."""
    failures = []
    report = None
    if report_path.exists():
        try:
            report = json.loads(report_path.read_text(encoding="utf-8"))
            if not isinstance(report, dict):
                failures.append("report root is not an object")
                report = None
        except (ValueError, OSError) as error:
            failures.append(f"report cannot be parsed: {error}")

    cancelled = name.startswith(("eof-", "ctrl-c-")) or name == "deadline-startup"
    if cancelled:
        if returncode == 0:
            failures.append("cancelled launcher returned success")
        if marker.exists():
            failures.append("marker exists despite unanswered approval")
        if report is not None:
            code = report.get("exit_code")
            if type(code) is not int or code == 0:
                failures.append("cancelled report has successful or invalid target exit")
        return failures

    if returncode != 0:
        failures.append(f"launcher exit {returncode}, expected 0")
    if report is None:
        failures.append("required JSON report missing or invalid")
    else:
        expected = 10 if name == "deny" else 258 if "deadline" in name or name == "reduced-motion" else 0
        if type(report.get("exit_code")) is not int or report.get("exit_code") != expected:
            failures.append(f"target exit {report.get('exit_code')!r}, expected {expected}")
        events = report.get("events")
        if not isinstance(events, list) or any(not isinstance(e, dict) for e in events):
            failures.append("report events are not an array of objects")
            tags = []
        else:
            tags = [event.get("event_type") for event in events]
        required = ["SandboxStopped"]
        if name == "deny":
            required += ["HookFileCreate", "HookBlocked"]
        elif "deadline" in name or name == "reduced-motion":
            required += ["ResourceLimitReached"]
        else:
            required += ["HookFileCreate"]
            if "HookBlocked" in tags:
                failures.append("unexpected hook denial in allowed scenario")
        for tag in required:
            if tag not in tags:
                failures.append(f"missing report event {tag}")

    absent = name in ("deny", "deadline-hook")
    if absent:
        if marker.exists():
            failures.append("denied/unanswered marker was created")
    elif not marker.exists():
        failures.append("allowed marker missing")
    elif name == "arguments":
        try:
            arguments = json.loads(marker.read_text(encoding="ascii"))
            if arguments != ARGUMENTS:
                failures.append(f"argument round trip differs: {arguments!r}")
        except (ValueError, OSError) as error:
            failures.append(f"argument dump cannot be parsed: {error}")
    elif marker.read_bytes() != MARKER:
        failures.append("marker content differs")

    if name in ("plain", "no-color", "color-never", "redirected") and b"\x1b" in output:
        failures.append("ANSI escape found in non-ANSI output case")
    if name == "reduced-motion":
        if b"\x1b[" not in output:
            failures.append("reduced-motion unexpectedly removed semantic colors")
        if b"\x1b[2K" in output or b"\x1b[?25" in output:
            failures.append("reduced-motion emitted animated cursor operations")
    return failures
