"""Explicit installed-WSL probe: python3 probe_wsl_pipe.py --compiler CROSS_GCC."""
import argparse
from pathlib import Path
import subprocess
import tempfile

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compiler", required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="rusty-wsl-pipe-") as directory:
        executable = Path(directory) / "pipe-probe.exe"
        subprocess.run(
            [args.compiler, "-Wall", "-Wextra", "-Werror", str(Path(__file__).with_suffix(".c").with_name("wsl_pipe_probe.c")), "-o", str(executable)],
            check=True,
        )
        with subprocess.Popen([str(executable)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as child:
            # Do not communicate(): it would close stdin and invalidate the
            # assertion that an open, empty WSL pipe returns ERROR_NO_DATA.
            code = child.wait(timeout=10)
            stdout = child.stdout.read().decode()
            stderr = child.stderr.read().decode()
            print(stdout, end="")
            if stderr:
                print(stderr, end="")
            if code:
                raise RuntimeError(f"installed WSL pipe probe failed: exit {code}")
            assert not child.stdin.closed


if __name__ == "__main__":
    main()
