"""Linux PTY driver: selector subscriptions, pidfd exit events, no polling.

Only single-threaded callers may use the login_tty pre-exec callback. Python
3.11+ and Linux pidfds are required. Child stdin/stdout/stderr share a real
controlling terminal. Transcripts are streamed to disk without truncation.
The owner must also reap native Windows targets: killing a Linux process group
alone is not evidence of Windows process cleanup.
"""

from __future__ import annotations

import errno
import os
import select
import selectors
import signal
import subprocess
import termios
import time
from contextlib import ExitStack
from pathlib import Path
from typing import BinaryIO

class PtySession:
    """Accumulate terminal events while owning child, descriptors and log."""

    def __init__(
        self, command: list[str], log: Path, *, cwd: Path,
        env: dict[str, str], timeout: float, manual_fd: int | None = None,
        mirror: BinaryIO | None = None,
    ) -> None:
        self.command = command
        self.cwd = cwd
        self.env = env
        self.log = log
        self.timeout = timeout
        self.manual_fd = manual_fd
        self.mirror = mirror
        self.output = bytearray()
        self.exited = False
        self.eof = False
        self.forced_cleanup = False
        self.manual_lines = bytearray()

    def __enter__(self) -> PtySession:
        self.resources = ExitStack()
        try:
            self.transcript = self.resources.enter_context(self.log.open("wb"))
            self.selector = self.resources.enter_context(selectors.DefaultSelector())
            self.master, slave = os.openpty()
            termios.tcsetwinsize(slave, (40, 100))
            self.resources.callback(os.close, self.master)
            self.selector.register(self.master, selectors.EVENT_READ, "output")
            if self.manual_fd is not None:
                self.selector.register(self.manual_fd, selectors.EVENT_READ, "manual")

            try:
                self.process = subprocess.Popen(
                    self.command, stdin=slave, stdout=slave, stderr=slave,
                    cwd=self.cwd, env=self.env, preexec_fn=lambda: os.login_tty(slave),
                )
            finally:
                os.close(slave)

            self.resources.callback(self._reap)
            pidfd = os.pidfd_open(self.process.pid)
            self.resources.callback(os.close, pidfd)
            self.selector.register(pidfd, selectors.EVENT_READ, "exit")
            self.deadline = time.monotonic() + self.timeout
            return self
        except BaseException:
            self.resources.close()
            raise

    def _reap(self) -> None:
        if self.exited:
            return

        pidfd = os.pidfd_open(self.process.pid)
        try:
            try:
                os.killpg(self.process.pid, signal.SIGKILL)
                self.forced_cleanup = True
            except ProcessLookupError:
                self.forced_cleanup = False

            if not select.select([pidfd], [], [], 5)[0]:
                raise TimeoutError("owned Linux child did not exit after SIGKILL")
            self.process.wait()
        finally:
            os.close(pidfd)

    def __exit__(self, *_exception: object) -> None:
        self.resources.close()

    def pump(self) -> None:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError(f"PTY deadline exceeded: {self.command!r}")

        events = self.selector.select(remaining)
        if not events:
            raise TimeoutError(f"PTY deadline exceeded: {self.command!r}")

        for key, _mask in events:
            if key.data == "exit":
                self.exited = True
                self.selector.unregister(key.fd)
                self.process.wait()
                continue

            try:
                chunk = os.read(key.fd, 65536)
            except OSError as error:
                if key.data != "output" or error.errno != errno.EIO:
                    raise
                chunk = b""

            if not chunk:
                self.selector.unregister(key.fd)
                if key.data == "manual":
                    raise EOFError("manual readiness input closed")
                self.eof = True
            elif key.data == "manual":
                self.manual_lines.extend(chunk)
            else:
                self.output.extend(chunk)
                self.transcript.write(chunk)
                self.transcript.flush()
                if self.mirror is not None:
                    self.mirror.write(chunk)
                    self.mirror.flush()

    def ready(self, marker: bytes | None, stage: str, since: int = 0) -> None:
        """Wait for a supplied machine token or an operator's exact stage line."""
        while True:
            if marker is not None and marker in self.output[since:]:
                return
            if marker is None and b"\n" in self.manual_lines:
                line, _, rest = self.manual_lines.partition(b"\n")
                self.manual_lines = bytearray(rest)
                if line.strip().decode("ascii") != stage:
                    raise ValueError(f"expected manual readiness stage {stage!r}")
                return
            if self.exited or self.eof:
                raise EOFError(f"launcher ended before {stage}")
            self.pump()

    def send(self, data: bytes) -> int:
        """Return the output cursor before input, so old tokens cannot satisfy it."""
        cursor = len(self.output)
        written = os.write(self.master, data)
        if written != len(data):
            raise OSError("short PTY input write")
        return cursor

    def finish(self) -> int:
        while not (self.exited and self.eof):
            self.pump()
        return self.process.returncode
