# Coverage and limitations

Rusty Sand combines selected API interception with observational monitoring.
Neither mechanism provides complete host isolation or complete activity coverage.

## API interception

The hook DLL uses MinHook to intercept the following Windows entry points:

| Area | Intercepted APIs |
| --- | --- |
| Files | `CreateFileW`, `DeleteFileW` |
| Directories | `CreateDirectoryW`, `RemoveDirectoryW` |
| Network | `connect` |
| Registry | `RegSetValueExW`, `RegDeleteKeyW`, `RegQueryValueExW`, `RegOpenKeyExW` |
| Processes and threads | `CreateProcessW`, `CreateThread`, `CreateRemoteThread` |
| Memory and DLL loading | `VirtualAlloc`, `VirtualProtect`, `WriteProcessMemory`, `LoadLibraryW`, `LoadLibraryExW` |

An intercepted call can be denied before invoking its original API. Approval does
not guarantee that the original call succeeds. A hook event records the request,
not the API's eventual result.

The protocol represents more operations than this table intercepts. In particular,
a `FileWrite` message does not prove that every `WriteFile` call is hooked, and
network message variants do not imply coverage of `send`, `recv`, UDP traffic,
or every Windows networking API. Alternate entry points and direct system calls
can bypass these hooks. Child processes do not automatically inherit interception.

## Observational monitoring

| Monitor | Evidence | Important limit |
| --- | --- | --- |
| Filesystem | Notifications for watched directories | Activity is not reliably attributable to the target PID |
| Network | Target-PID TCP/UDP table snapshots | Polling misses short-lived activity and does not block traffic |
| Registry | Change notifications on watched keys | A notification does not identify the writing process or full operation |
| Process | Resource and process snapshots | Sampling is not a complete execution trace |

A post-event decision cannot undo the observed action. Network or registry
observation alone must not be interpreted as prevention. Registry notifications
are not an ETW trace, despite the historical source filename.

## Analysis

Operation scoring produces a heuristic value from 0 to 100. The categories are
low (0-30), medium (31-60), high (61-85), and critical (86-100). Inputs include
paths, access flags, registry locations, ports, process arguments, and memory
protections. Overlapping indicators saturate rather than wrap.

Behavioral analysis examines recorded activity for indicators such as unusual
file volume, startup-key access, suspicious process arguments, or selected remote
ports. Counts describe an execution history, not a measured activity rate. These
are review signals, not malware verdicts. Legitimate programs can trigger them,
and malicious activity can remain undetected.

Read-only classification checks registry access rights, including view modifiers.
A registry-open request containing write, generic, maximal, or unknown rights
must not bypass approval merely because its operation is named "open."

## Resources and output

Windows Job Objects provide process resource limits and lifetime management.
They do not isolate filesystem paths, credentials, the registry, or the network.
Wall-clock deadlines and Job Object CPU-time limits are different controls.

The library rejects nonempty `allowed_file_patterns`: filesystem allowlist
enforcement is not implemented. Silently accepting those patterns would suggest
a protection the observational filesystem monitor cannot provide.

Console and JSON reports preserve both observations and hook requests. File and
network projections include their corresponding hook variants. A network hook
request is not counted as a denial simply because it was intercepted. A denied
request is recorded separately; human-readable details are not a typed result
schema.

## Terminal and input surfaces

The WSL launcher runs the x64 Windows backend in place and forwards input over a
cancellable UTF-8 pipe. Native Windows uses cancellable console events.
Interactive EOF, Ctrl-C, transport failure, and session deadlines fail closed.
For WSL `--no-interactive` runs, ordinary stdin EOF leaves the backend pipe open;
SIGINT and SIGTERM still close it and request cleanup. Cancellation is checked
before startup resume and approval replies. Input queued before a prompt cannot
authorize a later request. No new APIs are intercepted by this interface.

Human output uses a synchronized stderr renderer with semantic colors, bounded
prompt-time diagnostic buffering, narrow-terminal wrapping, and real-work activity
indicators. `--color auto|always|never`, `--plain`, and `--reduced-motion` select
presentation without changing policy. Redirected/dumb terminals and `NO_COLOR`
receive conservative defaults. JSON serialization remains unchanged; human report
counts describe retained events, not a verdict that the target is safe.

## Validation boundary

Portable tests cover schemas, classification, scoring, report projections, and
argument handling. Windows-specific tests and builds cover code hidden behind
platform guards. A passing build is not evidence of complete interception,
containment, or correctness against adversarial targets.

Use a disposable Windows VM for end-to-end analysis of untrusted programs. The
prebuilt executable under `test/` is not part of the automated test suite.
