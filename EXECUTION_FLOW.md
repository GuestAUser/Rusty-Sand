# Execution lifecycle

Rusty Sand separates process ownership, hook approval, observation, and reporting.
The executable owns the target's lifetime. The DLL executes inside the target and
asks the executable to approve intercepted operations over a local named pipe.

## Components

| Responsibility | Implementation |
| --- | --- |
| In-place WSL path conversion and cancellation bridge | `rusty-sand` |
| Serialized human output and prompt/activity guards | `src/ui/` |
| CLI parsing and report selection | `src/cli.rs`, `src/main.rs` |
| Public execution entry point | `src/lib.rs`, `src/sandbox/mod.rs` |
| Process, thread, and Job Object ownership | `src/sandbox/process.rs` |
| Command-line encoding and resource limits | `src/sandbox/command_line.rs`, `src/sandbox/resource.rs` |
| Deadline and process-completion waits | `src/sandbox/deadline.rs`, `src/sandbox/wait.rs` |
| DLL loading and exported initialization | `src/injection/` |
| Session orchestration and cleanup | `src/monitor/lifecycle.rs` |
| Cancellable console input | `src/monitor/input.rs` |
| Named-pipe transport and authentication | `src/ipc/` |
| Shared wire schema and classification | `crates/protocol/` |
| Hook registration and callbacks | `rusty_sand_hooks/src/` |
| Observations and event analysis | `src/monitor/`, `src/behavior/` |
| Report schema and projections | `src/report/` |

## Presentation and input ownership

The CLI resolves explicit display flags and launcher/native terminal capabilities
once, then routes human output and filtered `RUST_LOG` diagnostics through stderr.
Configuration appears before execution. Activity guards cover initialization,
running, and cleanup, and hold no renderer mutex across waits. Prompt guards
suspend activity and queue diagnostics until a decision or cancellation restores
scrolling output. Summary rendering begins only after teardown has stopped all
producers; the library's stdout summary entry point remains available.

WSL translates only launcher-owned paths and preserves target arguments. The
launcher forwards terminal hints and leaves terminal echo to its caller. Native
console edits use renderer input events; pipe bytes are not echoed by the backend.
The reader arms each request before its prompt is displayed and rejects stale
pre-prompt input. Hook and observation reviews share one bounded serial broker.

A biased outer cancellation race observes the input status watch channel and a
native Ctrl-C stream throughout startup, injection, and execution. Release
checkpoints let pending cancellation win before primary-thread resume and hook
replies. Closing the backend pipe cancels the session in either mode. In
interactive mode, the WSL launcher forwards ordinary stdin EOF as pipe closure.
With `--no-interactive` before the target-argument separator, it instead retains
the backend pipe after stdin EOF so redirected execution can finish normally.
SIGINT and SIGTERM always close the pipe and wait for cleanup. Native
noninteractive console sessions retain independent Ctrl-C handling without
needing an approval reader.

## Startup

The target's primary thread is created suspended. Resource handles become owned
immediately, including on errors during Job Object setup. Arguments are encoded
according to Windows command-line quoting rules, with embedded NULs rejected.

Interactive startup approval occurs before injection. Approval permits the remote
loader and hook initializer to execute; it does not mean no target-process code
runs until the primary thread resumes. Noninteractive mode still starts suspended
so it cannot race ahead of required hook initialization.

For hook-enabled execution, the application creates the target-PID-specific pipe
before injection. DLL loading and explicit initialization are distinct operations.
`DllMain` must not perform blocking IPC, logging, or hook installation under the
Windows loader lock. The injector calls the exported `RustySandInitialize` after
loading the DLL.

The executable requires both a successful initialization result and a validated
readiness message before resuming the primary thread. A missing DLL, failed hook,
wrong client identity, or invalid readiness message is a startup error rather
than permission to continue without requested hooks.

## Approval protocol

The pipe name is `\\.\pipe\rusty_sand_hooks_<pid>`. The server rejects remote
clients and authenticates the connected process through Windows, independently
of the PID written into JSON. Messages are bounded by `MAX_MESSAGE_SIZE`.

The first message is `HookReady`, containing the protocol version, process ID,
and installed-hook count. Normal requests then use `HookRequest { operation, pid,
tid }`; responses use `HookResponse { allowed, reason }`. Operation variants retain
the tagged JSON representation with `type` and `data` fields.

The DLL serializes each request/response exchange. Helpers avoid recursive
interception while formatting and transmitting a request, but this internal
bypass must end before calling the original API. Denial returns the appropriate
Win32 failure result. Communication failure is not approval.

Read-only classification is separate from policy enforcement. A request's name
alone does not establish that it is harmless: registry-open access rights must be
examined, and a write must be scored using the authenticated request's process
identity rather than the monitor's PID.

## Observation and deadlines

Filesystem, network, registry, and process monitors collect observations alongside
hook requests. Their findings are not proof of complete coverage or prevention.
See [FEATURES.md](FEATURES.md) for attribution and coverage limits.

The execution deadline uses a monotonic clock and covers startup and execution.
CPU-time limits belong to the Job Object and are a separate control. Completion
is observed through the process handle rather than a fixed readiness delay.
Console input has an explicit cancellation path so an unanswered prompt cannot
leave a blocking stdin task behind after the session ends.

## Teardown and reporting

The session owns the pipe, console reader, observation tasks, and target process.
Normal exit, denial, startup failure, deadline expiry, and external cancellation
must release that ownership. Cleanup terminates remaining target execution,
closes communication, cancels or joins workers, and closes process resources.
Cleanup errors retain context rather than being silently discarded.

Reports record configuration, timestamps, events, and the process outcome. A
startup failure returns an error rather than a successful protection report.
Hook requests and later observations may describe the same action; projections
and summaries count recorded evidence, not unique completed operations.

## Validation

Portable tests exercise protocol serialization, permission classification,
argument parsing, scoring, and report behavior. Windows tests additionally cover
platform handles, pipe exchange, notification behavior, and lifecycle helpers.
Build and test the complete workspace so the executable and DLL cannot silently
drift apart.

A passing unit suite is not a containment guarantee. End-to-end analysis of
untrusted targets belongs in a disposable Windows VM, not on the development host.
