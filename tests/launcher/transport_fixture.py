"""Real subprocess fixture for the launcher's stdin ownership and cleanup."""
import base64
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]

def load_launcher():
    loader = importlib.machinery.SourceFileLoader("rusty_sand_launcher", str(ROOT / "rusty-sand"))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    sys.dont_write_bytecode = True
    loader.exec_module(module)
    return module


if __name__ == "__main__":
    if sys.argv[1] == "bridge":
        launcher = load_launcher()
        sys.exit(launcher.forward_input(
            [sys.executable, __file__, *sys.argv[2:]], os.environ.copy(), ROOT
        ))
    mode = sys.argv[1]
    if mode in ("signal", "exit"):
        print("READY", flush=True)
    if mode == "exit":
        sys.exit(7)
    data = sys.stdin.buffer.read()
    print(json.dumps({"data": base64.b64encode(data).decode(), "cwd": os.getcwd()}), flush=True)
    sys.exit(23 if mode == "signal" else 0)
