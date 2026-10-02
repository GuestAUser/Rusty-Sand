# Coverage and limitations

Rusty Sand combines portable static inspection with Windows interception,
observation, native debugger evidence, and an analyst shell. See
[README.md](README.md) for commands and report artifacts. None of these modes
provides complete host isolation, universal virus detection, or a clean verdict.

## Static inspection

`--static` reads a regular file without executing or modifying it. Portable
analysis reports SHA-256, size, Shannon entropy, extracted strings, evidence
offsets, and conservative PE32/PE32+ metadata. The PE report includes headers,
sections and permissions/entropy, regular imports and exports, entry-point
mapping, TLS callback addresses, certificate-table records, and overlay ranges.

| Boundary | Limit |
| --- | --- |
| Input file | 32 MiB; larger inputs are rejected, not sampled |
| String scan | First 4 MiB; ASCII first, then ASCII-range UTF-16LE at both alignments |
| Retained strings | 1,024; minimum run 4 characters, retained value at most 512 characters |
| Findings | 256; import capability evidence at most 8 matches per category |
| PE sections / data directories | 96 / 16 |
| Import libraries / imports | 128 / 4,096 |
| Exports / export names | 4,096 / 4,096 |
| PE name byte bound | 256 |
| TLS callbacks / certificate records | 128 / 64 |
| Serialized static report | 8 MiB; this is not a bound on every companion or execution artifact |

Coverage reports `not_pe`, `parsed`, `malformed`, `limited`, or `unsupported`,
plus limits and truncation flags. A failed PE parse omits PE metadata but preserves
basic byte analysis. The decoder is not a Windows loader validator and does not
decode DOS/NE/LE images. Delay/bound imports, resources, relocations, debug data,
and load configuration have directory metadata only. Ordinal imports remain
unresolved; certificates are structural records, not verified signatures,
publisher identity, or trust.

Strings omit other encodings and non-ASCII UTF-16. URL extraction retains the
first HTTP(S) candidate per retained string and never contacts it. File reads
are not atomic snapshots. There is no unpacking, decryption, disassembly,
external reputation service, or malware signature database. The exact EICAR
test-content check is informational test recognition, not real-malware detection.

### Meaning of packing and obfuscation findings

Exact packer-like section names produce a marker finding; names can be imitated
and packing can be benign. Executable sections with at least 1,024 raw bytes and
entropy at least 7.2 bits per byte produce a low-confidence packing signal.
High entropy can also be ordinary data or encryption. Writable/executable
sections and unusual entry points are structural observations, not verdicts.

The encoded-PowerShell indicator recognizes only complete retained strings
starting with bare `powershell`, `powershell.exe`, `pwsh`, or `pwsh.exe`, optional
`-NoProfile`, `-NonInteractive`, or `-NoLogo` switches, then `-EncodedCommand`
or `-enc` and one plausible 8-256-character Base64 argument. It does not interpret
paths, quoting, shell composition, trailing arguments, or other obfuscation.
It neither decodes nor executes the content and excludes truncated strings.

Import-name matches suggest injection, credential, persistence, networking, or
anti-debug capabilities. They neither resolve API identities nor demonstrate
calls. Finding confidence concerns the stated observation, not malicious intent.

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

Automatic policy denies intercepted registry requests when `--no-registry` is
set. Network requests for port 53 use the DNS setting; other ports use the
internet setting. There is no resolver hook or general DNS/DoH enforcement.
`--no-interactive` and shell `run` allow other intercepted requests without
approval prompts; they do not disable the hooks.

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

The separate report-only assessment groups ransomware-like filenames, persistence,
credential-access, process-injection, suspicious-execution, defense-impairment,
and network indicators by rule and action status:

| Status | Meaning |
| --- | --- |
| `attempted` | Intercepted request, including an allowed request; API success is unknown |
| `observed` | Only the source event's stated observation; no additional attribution or success is inferred |
| `denied` | Recorded refusal; not a completed action |

The assessment inspects at most the first 16,384 supplied events, skips whole
descriptions larger than 4,096 bytes, removes exact duplicate records, and keeps
at most 16 evidence references per finding. Coverage counts omitted, duplicate,
oversized, unclassified-denial, and uncorrelatable-injection records. References
are zero-based indices into the original supplied event list.

Ransomware-like filename aggregation requires three distinct suspicious-suffix
paths per action status, not a measured encryption rate. Memory-write followed
by remote-thread correlation requires explicit matching caller/target PIDs,
non-denied requests in order, at most 32 event positions apart and within 30
seconds. It does not establish PID lifetime, payload execution, or API success.
Generic denial records do not acquire an inferred technique.

Matching uses descriptive text, not canonical paths or a Windows command-line
interpreter. File contents, registry value data, memory payloads, and process
snapshot command lines are unavailable. Network records do not prove successful
connections, traffic transfer, command-and-control, or exfiltration.

## Native debugger

`--debug` creates one owned native x64 Windows target, assigns its Job while
suspended, and attaches on a dedicated debugger thread before release. It does
not inject the DLL, start observational monitors, or apply hook-based network,
DNS, registry, filesystem, or behavioral policy. It has no arbitrary-PID attach
interface, breakpoint-management interface, stepping, symbols, or disassembly.
WOW64 targets are rejected before release; descendants are owned for Job cleanup
but are not debugged.

Events cover process/thread creation and exit, module load/unload, debug strings,
exceptions, and native RIP/unknown events. Process/module image paths are
best-effort opened DOS-volume paths queried from debug file handles, not verified
file identities or reconstructed images. Missing handles, query errors, lossy
text, and oversized paths are explicit.

Exception evidence includes code, flags, address, first/second chance,
initialization-breakpoint marker, declared parameters, and best-effort AMD64
control/integer registers. Memory evidence records the address, requested length,
actual bytes, and any read error. It excludes stack walks, floating-point/vector
state, debug registers, and extended processor state.

| Debug evidence | Bound |
| --- | --- |
| Retained events | 2,048; further events increment the dropped counter without additional diagnostic reads |
| Debug string read | 2,048 bytes |
| Instruction-byte read | 32 bytes at RIP, or exception address if context is unavailable |
| Image-path query | 4,096 UTF-16 units including terminator |

Counters expose dropped events, truncated strings/parameters/paths, unavailable
contexts/paths, and incomplete memory reads. Event processing and cleanup continue
after the retention limit. Only the initial Windows attach breakpoint is consumed;
other exceptions are passed to normal Windows/application exception delivery.
A first-chance exception alone is not an unhandled crash.

Debugging changes process behavior. Cancellation/timeout can leave useful partial
evidence, but not a complete trace. Debug mode reports a nonzero exit, unhandled
exception, timeout, or cancellation as CLI failure; ordinary execution retains
the target exit code as evidence rather than automatically failing the CLI.
An exit code alone does not establish which resource limit caused termination.

## Resources and output

Windows Job Objects provide process resource limits and lifetime management.
They do not isolate filesystem paths, credentials, the registry, or the network.
Wall-clock deadlines and Job Object CPU-time limits are different controls.

Process creation applies a Job active-process limit of 10. The default per-process
memory limit is 1,024 MiB and the default per-process user CPU-time limit is 300
seconds; zero disables the corresponding memory/CPU limit. `--timeout` changes
the wall-clock deadline, not `SandboxConfig::max_cpu_time`. Cleanup and blocking
OS calls can extend elapsed wall time beyond a deadline.

`--restricted` applies a restricted primary token through `CreateProcessAsUserW`
in ordinary execution, debug mode, and shell `run`. It removes all privileges
except `SeChangeNotifyPrivilege`. Everyone, Authenticated Users, Builtin Users,
Interactive, logon, and integrity SIDs are retained; other groups, including
administrator/domain/custom groups, become deny-only. Failure is fatal, with no
unrestricted fallback. Resources granted only through custom groups may become
inaccessible. The user SID, integrity level, desktop, and environment are not
isolated; no low-integrity or AppContainer policy is installed.

The library rejects nonempty `allowed_file_patterns`: filesystem allowlist
enforcement is not implemented. Silently accepting those patterns would suggest
a protection the observational filesystem monitor cannot provide.

Console and JSON reports preserve both observations and hook requests. File and
network projections include their corresponding hook variants. A network hook
request is not counted as a denial simply because it was intercepted. A denied
request is recorded separately; human-readable details are not a typed result
schema.

Monitoring periodically trims oldest history to 10,000 events and applies the
same bound after teardown. This is retained history, not a complete trace or a
strict instantaneous allocation bound. Assessment limits do not recover events
already discarded by collection.

The shell keeps one active execution and its last successfully returned report.
`events` shows at most 100 retained records; command input is bounded to 64 UTF-16
units and each command's display to 16,384 characters. Display truncation does
not truncate saved artifacts. `report` saves completed evidence and assessment
with exclusive filenames; it never substitutes an active or failed run.
Pause holds suspend increments from one root-thread snapshot, not an atomic
freeze of new threads or descendants.

## Terminal and input surfaces

The WSL launcher runs the x64 Windows backend in place and forwards input over a
cancellable UTF-8 pipe. Native Windows uses cancellable console events.
Interactive EOF, Ctrl-C, transport failure, and session deadlines trigger owned
cleanup rather than permit execution to continue unattended.
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

Portable tests cover schemas, static parsing and findings, report-only assessment,
classification, scoring, report projections, and argument handling.
Windows-specific tests and builds exercise code hidden behind platform guards.
A passing build is not evidence of complete interception, containment, or
correctness against adversarial targets.

Use a disposable Windows VM for end-to-end analysis of untrusted programs. The
prebuilt executable under `test/` is not part of the automated test suite.
