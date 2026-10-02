# Execution lifecycle

Rusty Sand separates portable file inspection, process ownership, hook approval,
observation, native debugging, and reporting. Static inspection never creates a
target process. Windows execution owns the target's lifetime; only hook-enabled
execution loads a DLL that requests operation approval over a local named pipe.

## Components

| Responsibility | Implementation |
| --- | --- |
| In-place WSL path conversion and cancellation bridge | `rusty-sand` |
| Serialized human output and prompt/activity guards | `src/ui/` |
| CLI parsing, mode dispatch, and report selection | `src/cli.rs`, `src/main.rs`, `src/commands/` |
| Portable bounded file inspection | `src/analysis/static_analysis/` |
| Report-only behavior assessment | `src/behavior/assessment/` |
| Companion evidence schema | `src/report/analysis.rs` |
| Public execution entry point | `src/lib.rs`, `src/sandbox/mod.rs` |
| Process, thread, and Job Object ownership | `src/sandbox/process.rs` |
| Restricted primary-token creation | `src/sandbox/isolation.rs` |
| Command-line encoding and resource limits | `src/sandbox/command_line.rs`, `src/sandbox/resource.rs` |
| Deadline and process-completion waits | `src/sandbox/deadline.rs`, `src/sandbox/wait.rs` |
| DLL loading and exported initialization | `src/injection/` |
| Session orchestration and cleanup | `src/monitor/lifecycle.rs` |
| Cancellable console input | `src/monitor/input.rs` |
| Named-pipe transport and authentication | `src/ipc/` |
| Shared wire schema and classification | `crates/protocol/` |
| Hook registration and callbacks | `rusty_sand_hooks/src/` |
| Observations and event analysis | `src/monitor/`, `src/behavior/` |
| Debugger approval and asynchronous cancellation frontend | `src/analyst/mod.rs` |
| Dedicated native debugger thread and bounded evidence | `src/debugger/` |
| Owned live execution and completed-report saving | `src/live/` |
| Analyst command parsing, dispatch, and input ownership | `src/shell/` |
| Report schema and projections | `src/report/` |

## Mode dispatch and initial evidence

`Args::mode()` selects ordinary execution unless `--static`, `--debug`, or
`--shell` is present. Those modes are mutually exclusive. `--restricted` is
rejected with static mode and otherwise sets the creation policy.
`--launcher-debug` belongs to the WSL launcher and selects a build profile;
it is not the backend's `--debug` analysis mode.

On non-Windows hosts, `commands::run_portable` supports static inspection and
returns an explicit error for execution/debug/shell. Windows static mode also
takes the no-execution path before runtime logging or process startup.
`AnalysisReport::inspect` calls portable `analyze_file`, preserving collected
static evidence or an explicit failure. `analyze_bytes` provides the same
bounded analysis for library-owned bytes.

Static parsing retains basic hash/entropy/string analysis if PE decoding is
malformed, unsupported, or parser-limited. Coverage and findings describe these
conditions; they do not translate into a clean verdict. Detailed bounds are in
[FEATURES.md](FEATURES.md).

For Windows execution/debug/shell, the CLI collects static evidence, records
requested configuration, and saves pending `analysis.json` when JSON output is
selected. This pending artifact does not prove process creation. An inspection
failure is not a launch veto: the backend can still run, with both outcomes
reported and the inspection failure retained in the final CLI result.

Dispatch then calls `execute_sandboxed`, `analyst::run_debug`, or
`shell::run_shell`. Debug configuration disables API hooks and behavior analysis.
Shell closing does not supply an ordinary execution report to the outer command;
its live reports are owned and saved separately.

## Presentation and input ownership

The CLI resolves explicit display flags and launcher/native terminal capabilities
once, then routes human output and filtered `RUST_LOG` diagnostics through stderr.
Configuration appears before Windows execution/debug/shell. Activity guards cover initialization,
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

## Monitored execution startup

The target's primary thread is created suspended. Resource handles become owned
immediately, including on errors during Job Object setup. Arguments are encoded
according to Windows command-line quoting rules, with embedded NULs rejected.

Creation first configures the Job's lifetime and resource limits. With
`SandboxConfig::restricted_token`, the source primary token is restricted and
passed to `CreateProcessAsUserW`; otherwise creation uses `CreateProcessW`.
The restricted branch removes privileges except `SeChangeNotifyPrivilege` and
makes non-basic groups deny-only. Failure to create or apply the token is fatal,
not permission to retry unrestricted. The local token handle is closed after
creation, and the suspended process is assigned to the owned Job before release.
This reduces privilege but does not install filesystem/network isolation,
low integrity, or AppContainer.

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

## Native debugger lifecycle

`analyst::run_debug` owns startup approval, input status, Ctrl-C, and a blocking
worker. Interactive approval occurs before process creation. Approval is bounded
by the configured timeout; after approval, `debugger::debug_executable` establishes
its own monotonic execution deadline. Noninteractive library callers do not read
ambient stdin unless `cancel_on_stdin_eof` is enabled.

The debugger entrypoint runs its thread-affine attachment and event queue on a
fresh dedicated OS thread. It reuses suspended process creation, restricted-token
application when requested, and Job assignment. WOW64 is rejected before release.
It attaches only to that owned root PID, enables kill-on-debugger-exit, then
releases the primary thread. No hook DLL or monitoring engine is involved.

Each retained event records sequence, elapsed microseconds, PID/TID, and its
native event payload. Process/module paths are queried from event file handles
before those handles close. Exceptions collect chance, code, address, parameters,
best-effort AMD64 control/integer context, and bounded instruction bytes. Missing
or truncated evidence has explicit fields/counters rather than fabricated values.
The single initialization breakpoint is consumed; application exceptions,
including later breakpoints, use normal exception delivery.

The event retention limit stops diagnostic collection, not event continuation
or cleanup. Explicit cancellation signals the worker and awaits its completion.
Shutdown terminates the owned Job, releases pending debug events and their file
handles, drains exit events, attempts detach if needed, reaps the root, and closes
owned handles. Operational and cleanup errors retain context together.
Descendants are covered by Job cleanup, not debugger evidence.

## Analyst shell and live ownership

`shell::run_shell` creates a `LiveSession` without launching the target and owns
the command reader. `info`/`analysis` invoke static inspection; they do not execute.
Only `run` launches the configured target. It preserves caller policy, including
restricted-token selection, but disables execution-side interactive approval and
stdin EOF handling so the shell remains the sole input owner.

`LiveSession::run` creates an independently owned worker/runtime and returns after
suspended creation and Job assignment. State remains `Starting` until monitored
startup signals readiness. Thus a returned PID is not evidence that injection
succeeded. Automatic hook policy denies configured network/DNS/registry requests
and permits other intercepted operations without prompts.

`status` exposes ownership and state; `events` returns the latest retained
records. `pause` and `resume` are available after monitored startup and manage
only this controller's suspend increments from a root-thread snapshot. They do
not atomically freeze the process, stop descendants, or pause its deadline.
There is no arbitrary-PID attachment or host-command execution path.

`stop` signals the owned execution and joins its monitor. Normal completion is
collected on refresh; a successful result becomes the last completed report.
A later active or failed run does not replace it with invented evidence.
`report` saves that completed report and a report-only assessment using exclusive
artifact creation. Repeated saves do not overwrite existing files.

`quit`, reader EOF, Ctrl-C, and outer shell failures all traverse owner cleanup:
request stop, close input, and await stopped execution. Dropping active ownership
also signals stop and joins its worker. Shell closure does not automatically
save a live report. The WSL launcher's `--no-interactive` ordinary-EOF exception
still applies at the transport layer, even for shell mode.

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

Configured denials take precedence over approval. In automatic mode, other
requests are permitted without prompting. The decision event is retained before
the reply can release the target thread. An allowed request is still only an
attempt; the protocol does not report the original API's eventual result.

## Observation and deadlines

Filesystem, network, registry, and process monitors collect observations alongside
hook requests. Their findings are not proof of complete coverage or prevention.
See [FEATURES.md](FEATURES.md) for attribution and coverage limits.

The execution deadline uses a monotonic clock and covers startup and execution.
CPU-time limits belong to the Job Object and are a separate control. Completion
is observed through the process handle rather than a fixed readiness delay.
Console input has an explicit cancellation path so an unanswered prompt cannot
leave a blocking stdin task behind after the session ends.

Monitoring periodically discards oldest events beyond its 10,000-record retained
history and trims again after producers stop. Report-only `assess_events` examines
only supplied records, independently of live scoring or review state. It groups
findings by rule and attempted/observed/denied status and preserves original
event indices. Its bounded correlations do not infer API success or writer
identity from neighboring events.

## Teardown and reporting

The session owns the pipe, console reader, observation tasks, and target process.
Normal exit, denial, startup failure, deadline expiry, and external cancellation
must release that ownership. Cleanup terminates remaining target execution,
closes communication, cancels or joins workers, and closes process resources.
Cleanup errors retain context rather than being silently discarded.

When JSON output is selected, ordinary execution preserves `report.json` with
the existing `SandboxReport` schema. The companion `analysis.json` records static
evidence, requested policy, execution status, and returned events. It assesses
those events only when behavior detection is enabled. Backend failure is recorded
explicitly; missing events are not reconstructed into a successful report.

Debug mode writes `debug.json` as an evidence wrapper, initially unavailable,
then collected or failed. A returned report can contain partial events after
timeout or cancellation. Nonzero debug exits, unhandled exceptions, timeout,
and cancellation fail the CLI; ordinary target exit codes remain report evidence.
Static mode records execution as not requested. Shell closure records
`shell_closed`, not proof of a target run.

Shell `report` writes
`shell-report-<host-pid>-<start-microseconds>-<index>.json`, containing `report`
and `assessment`, independently of automatic CLI format selection. It assesses
the saved events even when live behavior detection was disabled. Fixed automatic
artifact names can replace previous sessions' files; shell artifacts instead use
exclusive creation.

The final companion artifact is persisted before presentation, including error
states when writing succeeds. Static/backend/save/display failures are combined
without silently discarding earlier errors. An old artifact in a reused output
directory is not evidence of a new successful run.

Hook requests and later observations may describe the same action; projections
and summaries count retained evidence, not unique completed operations. Policy
configuration is requested behavior, allowed calls are attempts, observations
have source-specific attribution limits, and denied requests are not completed
actions. Collection status and target exit status are not safety verdicts.

## Validation

Portable tests exercise protocol serialization, permission classification,
argument parsing, scoring, and report behavior. Windows tests additionally cover
platform handles, pipe exchange, notification behavior, and lifecycle helpers.
Build and test the complete workspace so the executable and DLL cannot silently
drift apart.

A passing unit suite is not a containment guarantee. End-to-end analysis of
untrusted targets belongs in a disposable Windows VM, not on the development host.
