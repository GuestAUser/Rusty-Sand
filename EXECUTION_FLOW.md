# Rusty Sand - Complete Execution Flow

This document details the **complete technical execution flow** of Rusty Sand, showing how the two-process architecture works with API hooking and IPC.

---

## 🎯 High-Level Architecture

```php
┌────────────────────────────────────────────────────────┐
│                   Main Process                         │
│                (rusty_sand.exe)                        │
│                                                        │
│  ┌──────────────┐        ┌─────────────────────────┐   │
│  │   Monitor    │◄──────►│  Interactive Controller │   │
│  │   Engine     │        │   (HIPS Prompts)        │   │
│  └──────┬───────┘        └───────────▲─────────────┘   │
│         │                            │                 │
│         │                            │                 │
│  ┌──────▼────────────────────────────┴───────────┐     │
│  │          IPC Server (Named Pipe)              │     │
│  │       \\.\pipe\rusty_sand_hooks               │     │
│  └──────────────────────┬────────────────────────┘     │
└─────────────────────────┼──────────────────────────────┘
                          │
                    [JSON Protocol]
                          │
┌─────────────────────────▼───────────────────────────┐
│              Target Process (suspended)             │
│                                                     │
│  ┌─────────────────────────────────────────────┐    │
│  │      rusty_sand_hooks.dll (injected)        │    │
│  │                                             │    │
│  │  ┌─────────────┐  ┌──────────────────────┐  │    │
│  │  │ CreateFileW │  │  RemoveDirectoryW    │  │    │
│  │  │    Hook     │  │       Hook           │  │    │
│  │  └──────┬──────┘  └──────┬───────────────┘  │    │
│  │         │                │                  │    │
│  │  ┌──────▼────────────────▼──────────────┐   │    │
│  │  │        request_approval()            │   │    │
│  │  │  (Sends HookRequest via named pipe)  │   │    │
│  │  └──────────────────────────────────────┘   │    │
│  └─────────────────────────────────────────────┘    │
│                                                     │
│  Windows APIs (called via MinHook trampolines)      │
└─────────────────────────────────────────────────────┘
```

---

## 📊 Complete Flow: Stage by Stage

### STAGE 1: INITIALIZATION

**Location**: [src/main.rs:97](src/main.rs), [src/monitor/mod.rs:58-73](src/monitor/mod.rs)

```php
1.1 User executes: rusty_sand.exe suspicious.exe

1.2 Parse CLI arguments
    ├─ Executable path
    ├─ Arguments to pass
    └─ Configuration flags

1.3 Build SandboxConfig
    ├─ allow_internet: false (DEFAULT - security)
    ├─ interactive_mode: true (DEFAULT - HIPS on)
    ├─ enable_api_hooks: true (DEFAULT - real prevention)
    ├─ timeout: 300 seconds
    └─ max_memory_mb: 1024 MB

1.4 Create process in SUSPENDED state
    ├─ Flags: CREATE_SUSPENDED | CREATE_NEW_CONSOLE
    ├─ Process created but NO code executed yet
    ├─ Main thread suspended
    └─ Returns process handle + main thread handle

1.5 Start IPC server BEFORE injection
    ├─ Create named pipe: \\.\pipe\rusty_sand_hooks
    ├─ Pipe mode: PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE
    ├─ Buffer size: 8192 bytes
    ├─ Listen for connections
    └─ Server runs on background tokio task

1.6 Inject hook DLL
    ├─ Find rusty_sand_hooks.dll in same directory
    ├─ VirtualAllocEx in target process (allocate memory)
    ├─ WriteProcessMemory (write DLL path)
    ├─ GetProcAddress(LoadLibraryW) from kernel32.dll
    ├─ CreateRemoteThread → calls LoadLibraryW(dll_path)
    └─ Wait for DLL to load (thread completion)

1.7 Hook DLL initialization (DllMain in target)
    ├─ DLL_PROCESS_ATTACH received
    ├─ Connect to IPC server (\\.\pipe\rusty_sand_hooks)
    ├─ Initialize MinHook library (MH_Initialize)
    ├─ Install API hooks:
    │   ├─ MH_CreateHook(CreateFileW, hooked_create_file_w)
    │   ├─ MH_CreateHook(RemoveDirectoryW, hooked_remove_directory_w)
    │   ├─ MH_CreateHook(connect, hooked_connect)
    │   ├─ MH_CreateHook(RegSetValueExW, hooked_reg_set_value_ex_w)
    │   ├─ MH_CreateHook(RegDeleteKeyW, hooked_reg_delete_key_w)
    │   ├─ MH_CreateHook(RegQueryValueExW, hooked_reg_query_value_ex_w)
    │   └─ MH_CreateHook(RegOpenKeyExW, hooked_reg_open_key_ex_w)
    ├─ MH_EnableHook(MH_ALL_HOOKS)
    └─ Store original function pointers in static variables
```

**Critical Timing**: IPC server MUST be listening BEFORE DLL connects. Otherwise, DLL connection fails and hooks cannot communicate.

---

### STAGE 2: INITIAL EXECUTION APPROVAL

**Location**: [src/monitor/mod.rs:213-243](src/monitor/mod.rs)

```php
2.1 Process is SUSPENDED (has not executed any code yet)

2.2 Display configuration summary
    ├─ Executable path
    ├─ Internet status (OFF by default)
    ├─ Interactive mode (HIPS)
    ├─ Memory/timeout limits
    └─ Security settings

2.3 Inform user about dual console windows
    ├─ Main window: Monitoring & prompts
    └─ Second window: Target process output

2.4 Prompt user: "Allow process to start?"
    ┌────────────────────────────────────────────┐
    │ ⚠️  INITIAL EXECUTION APPROVAL ⚠️
    ├────────────────────────────────────────────┤
    │ Process: suspicious.exe                    │
    │ Status: SUSPENDED (no code executed)       │
    │                                            │
    │ [Y] Allow execution                        │
    │ [N] Terminate immediately                  │
    └────────────────────────────────────────────┘

2.5 User decision:
    ├─ [Y] → Resume process (ResumeThread on main thread)
    │        → Go to STAGE 3 (process now executing)
    │
    └─ [N] → TerminateProcess immediately
             → Go to STAGE 5 (cleanup and exit)
```

---

### STAGE 3: REAL-TIME API INTERCEPTION

**Location**: [rusty_sand_hooks/src/lib.rs](rusty_sand_hooks/src/lib.rs), [src/monitor/mod.rs:439-539](src/monitor/mod.rs)

Process is now running. For **every API call** to a hooked function:

#### Example: File Creation via CreateFileW

```php
3.1 Target calls: CreateFileW(L"C:\\malware.exe", ...)
    ↓
3.2 MinHook intercepts (inline hook)
    ├─ JMP at function prologue redirects to hooked_create_file_w
    └─ Original function backed up in trampoline

3.3 Hook function executes (rusty_sand_hooks.dll)
    ├─ Extract parameters:
    │   ├─ lpfilename: PCWSTR (wide string pointer)
    │   ├─ dwdesiredaccess: u32 (access flags)
    │   ├─ dwcreationdisposition: u32 (CREATE_NEW, OPEN_EXISTING, etc.)
    │   └─ dwflagsandattributes: u32 (FILE_ATTRIBUTE_DIRECTORY, etc.)
    │
    ├─ Convert PCWSTR → Rust String (UTF-16 to UTF-8)
    │
    ├─ Determine operation type:
    │   ├─ Is it a directory? (FILE_ATTRIBUTE_DIRECTORY bit set)
    │   ├─ Is it folder access? (FILE_FLAG_BACKUP_SEMANTICS)
    │   ├─ CREATE_NEW/CREATE_ALWAYS → Creation
    │   ├─ OPEN_EXISTING → Modification/Read
    │   └─ TRUNCATE_EXISTING → Deletion
    │
    └─ Build HookRequest:
        {
          "operation": "FolderCreate" | "FileCreate" | "FileWrite" | ...
          "path": "C:\\malware.exe"
        }

3.4 Send IPC request (blocking)
    ├─ Serialize HookRequest to JSON
    ├─ WriteFile to named pipe (\\.\pipe\rusty_sand_hooks)
    ├─ Wait for response (BLOCKS target execution here!)
    └─ ReadFile from named pipe (HookResponse)

    [Target thread is FROZEN waiting for user decision]

3.5 Main process receives IPC request
    ├─ IPC server loop reads from named pipe
    ├─ Deserialize JSON → HookRequest
    ├─ Extract operation details
    └─ Forward to Interactive Controller

3.6 Interactive Controller prompts user
    ┌───────────────────────────────────────────────────┐
    │         🔍 OPERATION DETECTED 🔍
    ├───────────────────────────────────────────────────┤
    │                                                   │
    │ 📁 Operation: FolderCreate
    │    Target:    C:\ProgramData\Malware              │
    │    Risk:      MEDIUM                              │
    │    Time:      14:32:15 UTC                        │
    │                                                   │
    │ Session Stats: 5 prompts | 3 allowed | 1 blocked  │
    │                                                   │
    ├───────────────────────────────────────────────────┤
    │ [A]  Allow this operation                         │
    │ [AA] Allow ALL FolderCreate (no more prompts)     │
    │ [B]  Block this operation                         │
    │ [BB] Block ALL FolderCreate (auto-block)          │
    │ [T]  Terminate process immediately                │
    │ [C]  Continue without prompting                   │
    └───────────────────────────────────────────────────┘

3.7 User makes decision:
    ├─ [A] Allow → allowed = true
    ├─ [AA] Allow All → allowed = true, store in auto_allowed map
    ├─ [B] Block → allowed = false
    ├─ [BB] Block All → allowed = false, store in auto_blocked map
    ├─ [T] Terminate → terminate process, allowed = false
    └─ [C] Continue → allowed = true, skip future prompts

3.8 Main process sends response
    ├─ Create HookResponse { allowed: true/false }
    ├─ Serialize to JSON
    └─ WriteFile to named pipe

3.9 Hook DLL receives response
    ├─ ReadFile from named pipe
    ├─ Deserialize JSON → HookResponse
    └─ Check response.allowed

3.10 Hook DLL acts on decision:

    If allowed == TRUE:
        ├─ Call original API via trampoline:
        │   ORIG_CREATE_FILE_W(lpfilename, dwdesiredaccess, ...)
        │
        ├─ Return result handle to target
        └─ Target continues execution

    If allowed == FALSE:
        ├─ DO NOT call original API
        ├─ Return error handle: INVALID_HANDLE_VALUE
        │   (target sees ERROR_ACCESS_DENIED)
        │
        └─ Target continues with error

3.11 Target continues execution
    ├─ Either succeeds (if allowed) or fails (if blocked)
    └─ Next API call → repeat from 3.1
```

#### Example: Folder Deletion via RemoveDirectoryW

```
3.1 Target calls: RemoveDirectoryW(L"C:\\FolderToDelete")
    ↓
3.2 MinHook intercepts → hooked_remove_directory_w
    ↓
3.3 Extract folder path from PCWSTR
    ↓
3.4 Build HookRequest:
    { "operation": "FolderDelete", "path": "C:\\FolderToDelete" }
    ↓
3.5 Send IPC request (blocks target)
    ↓
3.6 User prompted (same UI as above)
    ↓
3.7 Response: allowed = true/false
    ↓
3.8 If allowed:
    ├─ Call ORIG_REMOVE_DIRECTORY_W(lppathname)
    └─ Return BOOL(1) on success

    If denied:
    ├─ DO NOT call original API
    └─ Return BOOL(0) (failure)
```

---

### STAGE 4: BEHAVIORAL ANALYSIS (Parallel to Stage 3)

**Location**: [src/behavior/mod.rs](src/behavior/mod.rs), [src/monitor/mod.rs:252-391](src/monitor/mod.rs)

While the target executes, background monitoring runs:

```php
4.1 Monitoring tasks (spawn in parallel):
    ├─ File system monitor (directory watching)
    ├─ Network monitor (TCP/UDP table polling, 100ms)
    ├─ Registry monitor (RegNotifyChangeKeyValue)
    └─ Process monitor (Toolhelp32 snapshots, 50ms)

4.2 Behavioral analysis loop (100ms polling)
    ├─ Check for new events in shared event list
    ├─ For each new event:
    │   ├─ Skip internal events (SandboxStarted, etc.)
    │   ├─ Match event type:
    │   │   ├─ FileCreated → analyze_file_creation()
    │   │   ├─ FolderCreated → analyze_folder_creation() [NEW]
    │   │   ├─ FolderDeleted → analyze_folder_deletion() [NEW]
    │   │   ├─ NetworkConnection → analyze_network_activity()
    │   │   ├─ RegistryAccess → analyze_registry_access()
    │   │   └─ ProcessCreated → analyze_process_creation()
    │   │
    │   └─ Check for threat patterns:
    │       ├─ Ransomware: >50 rapid file creations
    │       ├─ Persistence: Registry Run keys
    │       ├─ Folder threats: ProgramData creation, System32 deletion
    │       ├─ UAC bypass: windir manipulation
    │       └─ C2 communication: ports 4444, 8080

4.3 If threat detected:
    ├─ Create ThreatDetection object
    ├─ Suspend process (if interactive mode ON)
    ├─ Prompt user with threat details
    ├─ User decides: Allow/Block/Terminate/Continue
    └─ Resume process (if not terminated)

4.4 Log all events to report.events Vec
```

**Note**: When `enable_api_hooks: true`, behavioral analysis is **informational only** - real prevention happens via API hooks in Stage 3.

---

### STAGE 5: PROCESS COMPLETION

**Location**: [src/monitor/mod.rs:195-207](src/monitor/mod.rs)

```php
5.1 Process exits (normal termination or user termination)
    ├─ Exit code captured
    ├─ End timestamp recorded
    └─ Duration calculated

5.2 Shutdown signal sent
    ├─ shutdown.store(true, Ordering::SeqCst)
    └─ All background tasks check this flag

5.3 Monitoring tasks stop (500ms grace period)
    ├─ File system monitor: stops watching
    ├─ Network monitor: stops polling
    ├─ Registry monitor: stops listening
    ├─ Process monitor: stops snapshots
    └─ Behavioral analysis: final event processing

5.4 IPC server shutdown
    ├─ Close named pipe
    └─ Hook DLL in target may disconnect (target exited)

5.5 Final event collection
    ├─ Flush any pending events
    └─ Behavior analyzer processes remaining events

5.6 If tasks don't stop in 500ms:
    └─ Abort all tasks forcefully (JoinHandle::abort)
```

---

### STAGE 6: REPORT GENERATION

**Location**: [src/report/mod.rs](src/report/mod.rs), [src/main.rs:195-221](src/main.rs)

```php
6.1 Build SandboxReport
    ├─ executable: String
    ├─ start_time: String (ISO 8601 UTC)
    ├─ end_time: String
    ├─ duration_seconds: u64
    ├─ exit_code: i32
    ├─ events: Vec<Event> (all captured events)
    └─ config: SandboxConfig (for reproducibility)

6.2 Generate statistics
    ├─ Total events
    ├─ File operations (created/modified/deleted)
    ├─ Folder operations (created/deleted) [NEW]
    ├─ Network connections
    ├─ Network blocked
    ├─ Registry operations
    ├─ Process creations
    └─ Suspicious/threat events

6.3 Output based on format:

    If format == "console" or "both":
        ├─ Print colored summary to terminal
        ├─ Show execution details
        ├─ Show security configuration
        ├─ Show event summary
        ├─ Show detected threats
        └─ Show last 100 events (chronological)

    If format == "json" or "both":
        ├─ Serialize SandboxReport to JSON
        ├─ Create output directory if needed
        ├─ Write to: {output_dir}/report.json
        └─ Pretty-print with 2-space indent

6.4 Return control to user
    └─ Program exits with exit code 0
```

---

## 🔐 Security Guarantees

### ✅ What IS Prevented (Real-Time via API Hooks)

| Operation | Hook Function | Prevention Method |
|-----------|--------------|-------------------|
| **File Creation** | `CreateFileW` | Hook intercepts, user approval required BEFORE file created |
| **File Modification** | `CreateFileW` | Hook intercepts OPEN_EXISTING, approval before handle returned |
| **Folder Creation** | `CreateFileW` | Detects FILE_ATTRIBUTE_DIRECTORY, approval before creation |
| **Folder Deletion** | `RemoveDirectoryW` | Hook intercepts, approval before deletion |
| **Network Connection** | `connect()` | Hook intercepts, approval before socket connects |
| **Registry Write** | `RegSetValueExW` | Hook intercepts, approval before value written |
| **Registry Delete** | `RegDeleteKeyW` | Hook intercepts, approval before key deleted |

**Prevention Mechanism**: Hook returns **error handle/status** WITHOUT calling original API.

### ⚠️ What is Monitored (Post-Execution)

| Operation | Monitor | Detection Method |
|-----------|---------|------------------|
| **File System Changes** | Directory watcher | `notify` crate, detects changes after they occur |
| **Network Activity** | TCP/UDP table polling | Detects connections after establishment |
| **Process Creation** | Toolhelp32 | Detects child processes after creation |
| **Registry Reads** | `RegQueryValueExW` hook | Monitored but not blocked (informational) |

**Note**: These are detected after-the-fact and logged for analysis.

---

## 🎮 User Interaction Points

You have control at **5 critical decision points**:

| Stage | Decision Point | Impact |
|-------|---------------|--------|
| **Stage 2** | Initial approval | Process never executes if denied |
| **Stage 3** | Per-operation approval | Each API call requires approval |
| **Stage 3** | Auto-allow/block | Set policy for operation types |
| **Stage 4** | Threat response | React to behavioral patterns |
| **Any time** | Terminate [T] | Immediate process kill |

---

## 🏗️ Technical Implementation Details

### MinHook Inline Hooking

```rs
Original Function (CreateFileW):
┌─────────────────────────────┐
│ 0x7FF8A000: mov rax, rcx    │ ← Original prologue
│ 0x7FF8A003: push rbp        │
│ ...                         │
└─────────────────────────────┘

After MH_CreateHook:
┌─────────────────────────────┐
│ 0x7FF8A000: jmp 0x1234ABCD  │ ← JMP to our hook
│ 0x7FF8A005: [trampolined]   │
│ ...                         │
└─────────────────────────────┘

Trampoline (for calling original):
┌─────────────────────────────┐
│ 0x5678DCBA: mov rax, rcx    │ ← Backed-up prologue
│ 0x5678DCBD: push rbp        │
│ 0x5678DCBE: jmp 0x7FF8A005  │ ← JMP to rest of original
└─────────────────────────────┘

Our Hook Function:
hooked_create_file_w() {
    // Extract params
    // Send IPC request
    // Wait for approval
    if (approved) {
        return ORIG_CREATE_FILE_W(...); // Calls trampoline
    } else {
        return INVALID_HANDLE_VALUE;   // Block operation
    }
}
```

### IPC Protocol Flow

```php
Hook DLL                             Main Process
(Client)                             (Server)

  │                                       │
  ├─ CreateFileW intercepted              │
  ├─ Build HookRequest JSON               │
  │  {                                    │
  │    "operation": "FileCreate",         │
  │    "path": "C:\\file.txt"             │
  │  }                                    │
  │                                       │
  ├────────[WriteFile to pipe]──────────→ │
  │                                       │
  │                           [ReadFile from pipe]
  │                           ├─ Deserialize JSON
  │                           ├─ Prompt user
  │                           ├─ User: [A] Allow
  │                           ├─ Build HookResponse
  │                           │  { "allowed": true }
  │                           └─ Serialize JSON
  │                                       │
  ├←──────[WriteFile to pipe]─────────────┤
  │                                       │
  ├─ ReadFile from pipe                   │
  ├─ Deserialize JSON                     │
  ├─ Check: allowed == true               │
  ├─ Call ORIG_CREATE_FILE_W(...)         │
  ├─ Return handle to target              │
  │                                       │
```

**Buffer Size**: 8192 bytes per message (adequate for long paths + JSON overhead)

**Timeout**: None (blocking I/O) - user must make decision

**Error Handling**: Any IPC failure = deny operation (fail-secure)

---

## 📝 Key Code Locations

| Component | File | Lines | Purpose |
|-----------|------|-------|---------|
| **Process Creation** | [src/sandbox/process.rs](src/sandbox/process.rs) | 50-120 | CREATE_SUSPENDED flag, Job Objects |
| **DLL Injection** | [src/injection/mod.rs](src/injection/mod.rs) | 20-150 | CreateRemoteThread + LoadLibraryW |
| **IPC Server** | [src/monitor/mod.rs](src/monitor/mod.rs) | 439-539 | Named pipe server loop |
| **Hook DLL** | [rusty_sand_hooks/src/lib.rs](rusty_sand_hooks/src/lib.rs) | ALL | MinHook hooks + IPC client |
| **Interactive Prompts** | [src/control/interactive.rs](src/control/interactive.rs) | 100-250 | User decision UI |
| **Behavioral Analyzer** | [src/behavior/mod.rs](src/behavior/mod.rs) | 150-600 | Threat pattern detection |
| **Report Generation** | [src/report/mod.rs](src/report/mod.rs) | 100-300 | Console + JSON output |

---

## 🔧 Debugging Tips

### "Hook DLL not found" error
```bash
# Ensure DLL was built
cargo build --release --package rusty_sand_hooks

# Check DLL exists in same directory
ls target/release/*.dll

# DLL MUST be in same directory as rusty_sand.exe
```

### "IPC connection failed"
- IPC server starts before DLL injection (check [src/monitor/mod.rs:58-73](src/monitor/mod.rs))
- Named pipe name: `\\.\pipe\rusty_sand_hooks` (must match in DLL)
- Check for port conflicts (other instances running?)

### "No prompts appearing"
- Check `interactive_mode: true` in config
- If `enable_api_hooks: false`, no real-time prompts (passive mode)
- Look for "IPC server listening" message in verbose output

### "Process hangs on exit"
- Shutdown flag not checked in monitoring loops
- 500ms grace period before abort (see [src/monitor/mod.rs:195-207](src/monitor/mod.rs))
- Check for blocking registry API calls (currently disabled)

---

## 🎯 Design Philosophy

### Maximum Control
Every potentially dangerous operation requires **explicit user approval** via IPC.

### Defense in Depth
Multiple confirmation layers:
1. Initial execution approval (Stage 2)
2. Per-operation approval (Stage 3)
3. Behavioral threat prompts (Stage 4)

### Transparency
User sees **exactly what** the process is attempting **before it happens**.

### Fail Secure
- All errors → deny operation
- IPC failure → deny operation
- Unknown operation → deny operation
- No response → deny operation (timeout in future)

### Separation of Concerns
- **Main process**: Monitoring, control, UI, reporting
- **Hook DLL**: API interception, IPC client, parameter extraction
- **IPC**: Clean protocol boundary between processes

---

## 📊 Performance Characteristics

| Operation | Latency | Overhead |
|-----------|---------|----------|
| **Hook interception** | ~5 µs | MinHook trampoline |
| **IPC round-trip** | ~2-5 ms | Named pipe + JSON serialization |
| **User prompt** | ~2-60 seconds | Human decision time |
| **File monitor** | ~50-500 ms | Directory watcher notification |
| **Network monitor** | ~100 ms | TCP/UDP table polling interval |
| **Process monitor** | ~50 ms | Toolhelp32 snapshot interval |

**Total overhead per API call (interactive mode)**: 2-60 seconds (dominated by user decision)

**Total overhead per API call (passive mode)**: 5-10 µs (hook overhead only, no IPC)

---

**This is a true Host Intrusion Prevention System with real-time API interception! 🛡️**
