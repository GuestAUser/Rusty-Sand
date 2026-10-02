# Rusty Sand

<img src="logo.png" alt="Rusty Sand crab building a sandcastle" width="240">

Rusty Sand is an analyst workbench written in Rust. It provides portable,
no-execution file inspection, Windows monitored execution, native debugger
evidence, and an interactive analyst shell. Findings are review signals, not
universal virus detection or a clean/malicious verdict. There is no external
reputation lookup or malware signature database.

It is not a security boundary. User-mode hooks and Windows Job Objects do not
provide complete filesystem, network, or privilege isolation. Analyze untrusted
programs in a disposable Windows VM.

| Mode | Host | Target execution | Evidence |
| --- | --- | --- | --- |
| `--static` | Windows or non-Windows | Never | Hash, strings, conservative PE metadata, bounded findings |
| Ordinary invocation | Native x64 Windows | Yes | Selected API requests, policy decisions, observations, behavior assessment |
| `--debug` | Native x64 Windows | Yes, without hooks | Process/thread/module events, debug strings, exceptions and bounded context/memory reads |
| `--shell` | Native x64 Windows | Only after `run` | File inspection and owned monitored execution controls |

## In-place WSL launch

From this checkout in your existing WSL terminal:

```sh
cargo build --locked --release --workspace --target x86_64-pc-windows-gnu
./rusty-sand --help
./rusty-sand /mnt/c/Windows/System32/notepad.exe
./rusty-sand --static /mnt/c/Windows/System32/notepad.exe
./rusty-sand --debug /mnt/c/Windows/System32/cmd.exe -- /d /c echo hello
```

These examples use Windows system programs; ordinary and debug modes execute
them. The launcher requires Python 3, WSL
interop, and `wslpath`; the build requires the Windows GNU Rust target and an x64
MinGW compiler/linker already configured. It uses the release executable and DLL
in `target/x86_64-pc-windows-gnu/release` in place: no copy, Windows terminal tab,
or automatic build is required. Targets still execute as **native x64 Windows
processes**, not Linux programs; WOW64 and ARM emulation are unsupported.

The launcher converts Linux executable, `--workdir`, and `--output` paths using
`wslpath`. Absolute Windows paths and arguments after `--` remain unchanged.
Reports default to this checkout's `sandbox_output/report.json`, even when the
launcher is invoked from another directory for ordinary execution; other modes
use the artifacts described below in the same output directory.
`--launcher-debug` explicitly selects an already-built debug-profile backend;
a missing release build never silently falls back. It does not select analysis
mode: `--debug` selects native debugger analysis and works with either profile.

## Native Windows build

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

Static inspection, configuration, report handling, scoring, protocol tests, and
CLI parsing can run on non-Windows hosts. A native Linux build can inspect bytes
directly, without WSL interop or the hook DLL:

```sh
cargo run --locked -- --static README.md
```

Executing or debugging a target and opening the analyst shell require Windows.
Other modes return an explicit error on non-Windows hosts rather than substituting
simulated execution.

## Usage

```powershell
.\target\release\rusty_sand.exe C:\Windows\System32\notepad.exe
.\target\release\rusty_sand.exe C:\Windows\System32\notepad.exe --timeout 60 --memory 512
.\target\release\rusty_sand.exe C:\Windows\System32\notepad.exe --format json --output .\reports
.\target\release\rusty_sand.exe C:\Windows\System32\cmd.exe -- /d /c echo hello
.\target\release\rusty_sand.exe --static C:\Windows\System32\notepad.exe
.\target\release\rusty_sand.exe --debug C:\Windows\System32\cmd.exe -- /d /c echo hello
.\target\release\rusty_sand.exe --shell C:\Windows\System32\notepad.exe
.\target\release\rusty_sand.exe --restricted C:\Windows\System32\cmd.exe -- /d /c echo hello
```

| Option | Default | Meaning |
| --- | --- | --- |
| `--static` | Off | Inspect bytes without launching the target |
| `--debug` | Off | Collect native Windows debug events; no hook injection or monitoring engine |
| `--shell` | Off | Open the analyst command loop; only `run` launches the target |
| `--restricted` | Off | Require process creation with a restricted primary token; no unrestricted fallback |
| `--internet`, `-i` | Off | Allow connections under the requested policy; also enable DNS |
| `--dns`, `-d` | Off | Allow DNS under the requested policy |
| `--timeout`, `-t` | `300` | Execution deadline in seconds |
| `--memory`, `-m` | `1024` | Process memory limit in MB; zero means unlimited |
| `--workdir`, `-w` | Inherited | Target working directory |
| `--output`, `-o` | `./sandbox_output` | Report directory |
| `--format`, `-f` | `both` | `console`, `json`, or `both` |
| `--verbose`, `-v` | Off | Debug logging unless overridden by `RUST_LOG` |
| `--color` | `auto` | `auto`, `always`, or `never`; `never` also disables effects |
| `--plain` | Off | Disable colors and effects, including with `--color always` |
| `--reduced-motion` | Off | Disable activity animation but retain semantic colors |
| `--log-network` | Off | Log observed network endpoints; not packet capture |
| `--no-registry` | Off | Disable registry monitoring and deny intercepted registry requests |
| `--no-interactive` | Off | Make decisions without interactive prompts |
| `--no-behavior-detection` | Off | Disable live behavior analysis and the ordinary CLI companion assessment; shell `report` still assesses its saved events |

Arguments after `--` belong to the target, not Rusty Sand. Unknown report formats
are rejected. There is no `--no-internet` flag: the internet policy is disabled by
default. Disabling interactive prompts is not the same as disabling hooks.

`--static`, `--debug`, and `--shell` are mutually exclusive. `--restricted`
cannot accompany `--static`; it applies to ordinary execution, debug execution,
and shell `run`. It removes privileges except `SeChangeNotifyPrivilege` and
makes non-basic groups deny-only. Token creation or application failure stops
startup. This is least privilege, not low integrity, AppContainer, or isolation.

Policy settings apply only where an implemented interceptor can enforce them.
They are not a firewall, a restricted desktop, or a virtual filesystem. See
[coverage and limitations](FEATURES.md) before interpreting a report.

## Analyst workflows

Start with `--static` for inspection without execution. It accepts regular files,
including non-PE inputs. Inspect `coverage.pe_status`, truncation flags, and
limitations rather than treating missing findings as a clean result. PE32 and
PE32+ decoding includes sections, regular imports/exports, TLS callbacks,
certificate-table structure, and overlay ranges. It does not unpack, decrypt,
disassemble, verify signatures, or contact extracted URLs.

Use `--debug` for native event evidence instead of API interception. Startup
requires `Y` unless `--no-interactive` is set. Hook-based internet, DNS, registry,
and filesystem policy is not enforced in this mode, and behavior assessment is
unavailable. Job limits and an optional restricted token still apply. Exception
records include chance, code, address, parameters, best-effort AMD64 registers,
and bounded instruction bytes; these are not a complete instruction trace.

The shell is not an operating-system command processor and cannot attach to an
arbitrary PID. It supports only:

| Command | Effect |
| --- | --- |
| `help` | Show available commands |
| `info`, `analysis` | Inspect the configured file without execution |
| `run` | Start one owned monitored execution asynchronously |
| `status` | Show state, PID, active ownership, last error, and completed-report availability |
| `events [count]` | Show latest retained events; default 20, permitted range 1-100 |
| `pause` | Suspend one snapshot of root-process threads |
| `resume` | Release only this controller's retained suspend increments |
| `stop` | Terminate the owned Job and join monitoring |
| `report` | Save the last completed execution report and its assessment |
| `quit` | Stop owned execution and close input |

Shell `run` uses automatic hook policy, not interactive startup or per-operation
approval: configured network/DNS/registry denials still apply, while other
intercepted requests are allowed. The shell owns stdin. A returned PID means
suspended creation and Job assignment succeeded, not that hook startup finished;
use `status` to distinguish `Starting` from `Running`.

Pause is not an atomic or Job-wide freeze: new threads and descendants may
continue, and nothing is undone. The execution deadline continues while paused.
For a benign Notepad session, enter commands individually:

```text
analysis
run
status
events 20
stop
report
quit
```

`report` needs a successfully returned execution report, including one obtained
after a checked `stop`. It does not save an in-progress snapshot or manufacture
a report after failure. A later run does not erase the previous completed report.

## Terminal decisions and cancellation

Configuration, initialization, running, cleanup, risk reviews, and results share
one scrolling presentation on stderr. stdout is not used for runtime human
output; JSON remains a file, so diagnostics never mix into the report. Narrow
terminals wrap fields. Activity indicators show real ongoing work, not estimated
completion percentages, and pause while a prompt owns the terminal. Diagnostics
are buffered during decisions and flushed afterwards; oversized bursts are
bounded and report how many entries were omitted.

Automatic color requires a terminal and respects `NO_COLOR` and `TERM=dumb`.
Redirected output has no animation or automatic colors. `--color always` explicitly
forces colors; `--plain` wins over that choice. `--reduced-motion` preserves color
without animation. WSL forwards terminal width and display hints, while native
Windows queries its stderr console. `RUST_LOG` accepts env_logger level, module,
and regex directives and overrides the `info` default (`debug` with `--verbose`).

Startup accepts only `Y`. Hook decisions use `Y` (once), `A` (this type), `N`
(deny once), `D` (deny this type), or `T` (terminate); empty and unknown keys deny.
Post-event reviews use `A` (accept), `B` (flag suspicious), `C` (continue), or `T`;
these reviews cannot undo observed activity and the target keeps running.
Answers typed before a prompt is armed are discarded, so do not pre-feed approval
scripts. Native input is rendered by Rusty Sand; WSL keeps the caller terminal's
normal echo and the backend does not echo pipe input a second time.

Ctrl-C cancels execution/debug sessions even with `--no-interactive`.
Interactive input EOF cancels during
startup, injection, or execution, not just during prompts. With `--no-interactive`
before `--`, the WSL launcher leaves its backend pipe open after ordinary stdin
EOF, so redirected runs such as
`./rusty-sand /mnt/c/Windows/System32/cmd.exe --no-interactive -- /d /c echo hello < /dev/null`
can complete normally. Target arguments after `--` do not select this behavior.
SIGINT and SIGTERM still close the backend pipe in either mode, and the launcher
waits for cleanup. The launcher explicitly marks its owned stdin control pipe;
closure of that pipe remains a cancellation signal. Noninteractive library calls
ignore ambient stdin, including closed CI pipes, unless the caller opts into
`SandboxConfig::cancel_on_stdin_eof`. This runtime setting is not serialized.
Cancellation terminates the target Job and joins owned workers before returning.
Debug cancellation waits for debugger cleanup and can retain partial evidence.
Shell EOF, Ctrl-C, and `quit` stop owned execution and close input; they do not
automatically save a shell report. When using the shell through WSL, leave
`--no-interactive` unset if ordinary stdin EOF should close the shell, since that
launcher option otherwise keeps the backend control pipe open.

## Reports and library use

`--format json` and `--format both` save mode-specific artifacts under `OUTPUT`;
`--format console` does not save these automatic JSON artifacts. Shell `report`
is an explicit save command independent of that selection.

| Artifact | Contents |
| --- | --- |
| `analysis.json` | All modes: schema version, mode, static evidence, execution status, requested configuration where applicable, and ordinary execution's returned events/behavior assessment |
| `report.json` | Ordinary execution: unchanged `SandboxReport`, with configuration, timestamps, duration, exit code, and ordered retained events |
| `debug.json` | Debug mode: `collected`, `failed`, or `unavailable` evidence wrapper; collected data contains native events, exit outcome, cancellation/timeout flags, counters, and limitations |
| `shell-report-<host-pid>-<start-microseconds>-<index>.json` | Shell `report`: last completed `SandboxReport` under `report`, plus report-only `assessment`; exclusive creation avoids overwriting previous saves |

The companion evidence statuses are `collected`, `failed`, and `unavailable`.
Collected does not mean complete. `pending` execution is not evidence of launch;
shell `shell_closed` does not establish that `run` happened. Shell run events
belong to its explicit report artifacts, not the outer `analysis.json`.
Behavior assessment is unavailable in static/debug mode and in ordinary
execution when disabled.

Static inspection precedes Windows execution but is not a launch gate: an
inspection error can coexist with later execution evidence and makes the CLI
result fail. Malformed, unsupported, or parser-limited PE metadata instead
remains an explicit coverage status alongside basic byte analysis. Read/open
failures are not clean results. Pre-execution bytes are not an atomic snapshot
of the image Windows later loads.

Automatic artifacts use fixed names; use separate output directories for
separate sessions. `analysis.json` is saved before and after the Windows backend,
and debug mode replaces its pending evidence with the final result where possible.
A backend error does not promise a partial ordinary `report.json`; an old file
in a reused directory is not evidence of a new successful run.

Configuration records requested policy, not proof of enforcement. An allowed
hook request remains an attempted action, an observation establishes only what
its source observed, and a denial is not a completed operation. The assessment
keeps these statuses separate and references original event indices. Requests
and observations may refer to the same action, so counts are not unique completed
operations. Neither a zero exit code nor absent findings establishes safety.

Portable library entrypoints include
`analysis::static_analysis::{analyze_file, analyze_bytes}`,
`behavior::assessment::assess_events`, and `report::analysis::AnalysisReport`.
Windows entrypoints include `execute_sandboxed`, `analyst::run_debug`,
`debugger::debug_executable`, `shell::run_shell`, and `live::LiveSession`.
Execution configuration uses `SandboxConfig`; ordinary results use
`SandboxReport`. `print_summary()` retains
its stdout library API; `write_summary(writer, policy)` is fallible and supports
the same rendering policy as the CLI. Risk categories expose
`ThreatCategory::as_str()` for plain-text labels. See the examples:

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
