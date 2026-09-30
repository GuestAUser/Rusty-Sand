# Rusty Sand

Rusty Sand is a Windows executable-analysis tool written in Rust. It records
process activity, scores intercepted operations, supports interactive approval,
and produces console or JSON reports.

It is not a security boundary. User-mode hooks and Windows Job Objects do not
provide complete filesystem, network, or privilege isolation. Analyze untrusted
programs in a disposable Windows VM.

## Build

Use a native AMD64 Windows Rust toolchain with its C/C++ build tools. Hook
injection does not support WOW64 or ARM emulation. The repository pins Rust in
`rust-toolchain.toml` and checks in `Cargo.lock`.

```powershell
cargo build --locked --release --workspace
.\target\release\rusty_sand.exe --help
```

Build the whole workspace. Hook-enabled execution requires
`rusty_sand_hooks.dll` beside `rusty_sand.exe`, built for the same architecture.
Building only the root package does not build the DLL.

| Crate | Purpose |
| --- | --- |
| `rusty_sand` | CLI, execution lifecycle, observation, analysis, and reports |
| `rusty_sand_hooks` | Injected Windows DLL and API interceptors |
| `rusty_sand_protocol` | Shared message schemas and operation classification |

Configuration, report handling, scoring, protocol tests, and CLI parsing can run
on non-Windows hosts. Executing a target process requires Windows; the CLI
returns an explicit error rather than substituting a simulated execution.

## Usage

```powershell
.\target\release\rusty_sand.exe C:\Windows\System32\notepad.exe
.\target\release\rusty_sand.exe program.exe --timeout 60 --memory 512
.\target\release\rusty_sand.exe program.exe --format json --output .\reports
.\target\release\rusty_sand.exe program.exe -- --target-option "argument with spaces"
```

| Option | Default | Meaning |
| --- | --- | --- |
| `--internet`, `-i` | Off | Allow connections under the requested policy; also enable DNS |
| `--dns`, `-d` | Off | Allow DNS under the requested policy |
| `--timeout`, `-t` | `300` | Execution deadline in seconds |
| `--memory`, `-m` | `1024` | Process memory limit in MB; zero means unlimited |
| `--workdir`, `-w` | Inherited | Target working directory |
| `--output`, `-o` | `./sandbox_output` | Report directory |
| `--format`, `-f` | `both` | `console`, `json`, or `both` |
| `--verbose`, `-v` | Off | Debug logging |
| `--log-network` | Off | Log observed network endpoints; not packet capture |
| `--no-registry` | Off | Disable registry monitoring and deny intercepted registry requests |
| `--no-interactive` | Off | Make decisions without interactive prompts |
| `--no-behavior-detection` | Off | Disable event-history analysis |

Arguments after `--` belong to the target, not Rusty Sand. Unknown report formats
are rejected. There is no `--no-internet` flag: the internet policy is disabled by
default. Disabling interactive prompts is not the same as disabling hooks.

Policy settings apply only where an implemented interceptor can enforce them.
They are not a firewall, a restricted desktop, or a virtual filesystem. See
[coverage and limitations](FEATURES.md) before interpreting a report.

## Reports and library use

JSON output is saved to `OUTPUT/report.json`. A report includes the executable,
start and end timestamps, duration, exit code, effective configuration, and
ordered events. Hook events describe intercepted requests; observations describe
activity detected separately. Both may refer to the same operation, so event
counts are not counts of unique completed actions.

The Windows library entry point is `execute_sandboxed`. Configuration is built
through `SandboxConfig`; results use `SandboxReport`. Risk categories expose
`ThreatCategory::as_str()` for plain-text labels; the unused decorative
`color_code()` helper has been removed. See the compiling examples:

- [Basic usage](examples/basic_usage.rs): launch Notepad and save a report.
- [Advanced monitoring](examples/advanced_monitoring.rs): observe a benign
  PowerShell process listing with hooks explicitly disabled through the library.

Run examples manually on Windows after building the workspace. They launch real
programs and are not substitutes for unit tests.

## Development

```sh
cargo fmt --all -- --check
cargo check --locked --workspace --all-targets
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace --all-targets
```

Run these on Windows to cover the platform implementation. Portable tests on
Linux exercise domain logic and protocol behavior but do not validate Win32
calls, DLL injection, or interception. The CI configuration checks both surfaces.
It also runs the portable hook-boundary tests under Miri.

Tests live in `tests/unit/`, `rusty_sand_hooks/tests/unit/`, and
`crates/protocol/tests/`. Implementation files contain test-module references,
not embedded test bodies. Keep new tests in those dedicated directories.

Use descriptive names, explicit ownership, and focused modules. Comments should
explain non-obvious protocol, lifetime, or operating-system constraints in coherent
blocks; avoid narrating individual statements. Keep formatting changes separate
from behavior changes when reviewing a patch. Tests should observe behavior,
including error and cleanup paths, without relying on fixed sleeps.

The implementation map and lifecycle constraints are in
[EXECUTION_FLOW.md](EXECUTION_FLOW.md).

## License

[MIT](LICENSE).
