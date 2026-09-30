"""Exercise real Windows input, rendering, and cmd through the launcher bridge."""
import argparse
import os
from pathlib import Path
import selectors
import subprocess
import sys
import time

from transport_fixture import ROOT, load_launcher

TEST = "monitor::input::tests::real_prompt_ordering"

def bridge(executable):
    launcher = load_launcher()
    environment = os.environ.copy()
    environment["RUSTY_SAND_TEST_PROMPT_CHILD"] = "1"
    forwarded = environment.get("WSLENV", "")
    environment["WSLENV"] = ":".join(
        value for value in (forwarded, "RUSTY_SAND_TEST_PROMPT_CHILD") if value
    )
    return launcher.forward_input(
        [str(executable), "--exact", TEST, "--nocapture"],
        launcher.backend_environment(environment),
        ROOT,
    )

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--test-executable", type=Path, required=True)
    parser.add_argument("--bridge", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    executable = args.test_executable.resolve(strict=True)
    if args.bridge:
        return bridge(executable)

    command = [
        sys.executable, str(Path(__file__).resolve()), "--bridge",
        "--test-executable", str(executable),
    ]
    with subprocess.Popen(
        command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        bufsize=0,
    ) as child:
        transcript = bytearray()
        pending = bytearray()
        answers = 0
        completed = False
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(child.stdout, selectors.EVENT_READ)
                deadline = time.monotonic() + 20
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0 or not selector.select(remaining):
                        raise TimeoutError("Windows prompt fixture did not complete")
                    data = os.read(child.stdout.fileno(), 65536)
                    if not data:
                        break
                    transcript.extend(data)
                    pending.extend(data)
                    while b"\n" in pending:
                        line, _, remainder = pending.partition(b"\n")
                        pending = bytearray(remainder)
                        line = line.rstrip(b"\r")
                        if line == b"RS_INPUT_ARMED":
                            # Respond to the exact post-render event immediately;
                            # no human delay or readiness polling can hide a race.
                            child.stdin.write(b"Y\n")
                            answers += 1
                        elif line == b"RS_CMD_EXIT=0":
                            completed = True
            code = child.wait(timeout=5)
            if code or answers != 1 or not completed:
                raise RuntimeError(
                    f"prompt proof failed: exit={code}, answers={answers}, cmd={completed}"
                )
            assert not child.stdin.closed
            print("WSL launcher prompt ordering: cmd exit=0, immediate answers=1")
            return 0
        finally:
            print(transcript.decode(errors="replace"), end="")
            # Let the real Windows reader observe EOF and perform cleanup.
            # The child fixture itself bounds both the answer and process wait.
            child.stdin.close()
            child.wait()


if __name__ == "__main__":
    sys.exit(main())
