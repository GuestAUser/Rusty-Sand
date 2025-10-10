# 🏖️ Rusty Sand

[![Windows](https://img.shields.io/badge/Platform-Windows-blue.svg)](https://www.microsoft.com/windows)
[![Rust](https://img.shields.io/badge/Language-Rust-orange.svg)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**Advanced Windows Sandbox with Real-Time Host Intrusion Prevention System (HIPS)**

Rusty Sand is a executable sandbox for Windows security research that i've made providing **real-time API interception**, behavioral threat detection, and interactive control over every operation a program performs. Unlike passive sandboxes that monitor after-the-fact, Rusty Sand implements a true HIPS that **intercepts operations BEFORE execution** using DLL injection and API hooking.

⚠️ **For defensive security research only.** Run on isolated VMs, never on production systems.

---

## 🌟 Key Features

### 🛡️ Real-Time API Interception (HIPS)
- **DLL Injection**: Injects hook DLL into target process using `CreateRemoteThread`
- **MinHook Integration**: Inline API hooking for Windows functions
- **Pre-Execution Blocking**: Operations intercepted BEFORE they execute
- **Named Pipe IPC**: Secure communication between main process and hook DLL
- **Hooked APIs**:
  - `CreateFileW` - File/folder creation and modification
  - `RemoveDirectoryW` - Folder deletion
  - `connect` - Network connections
  - `RegSetValueExW` - Registry value writes
  - `RegDeleteKeyW` - Registry key deletion
  - `RegQueryValueExW` - Registry reads
  - `RegOpenKeyExW` - Registry key opens

### 🔍 Comprehensive Monitoring
- **File System**: File/folder creation, modification, deletion (real-time via API hooks)
- **Network**: TCP/UDP connections (intercepted before connect)
- **Registry**: Registry operations (intercepted before modification)
- **Processes**: Complete process tree tracking with Toolhelp32

### 🚨 Behavioral Threat Detection
Automatically detects:
- **Ransomware**: Rapid file encryption, suspicious extensions (`.encrypted`, `.locked`)
- **Persistence**: Registry Run keys, startup folders, scheduled tasks
- **UAC Bypass**: Environment variable manipulation, `ms-settings` abuse
- **Security Tampering**: Windows Defender/firewall modifications
- **C2 Communications**: Suspicious ports (4444, 8080, 31337)
- **PowerShell Abuse**: Encoded commands, download cradles
- **Folder Operations**: Suspicious folder creation/deletion (ProgramData, System32)

### 🔒 Process Isolation
- **Windows Job Objects**: Hard resource limits (memory, CPU)
- **CREATE_SUSPENDED**: Process starts suspended until user approval
- **Process Tree Control**: Suspend/resume using Toolhelp32 + threading APIs
- **Network Isolation**: Internet access OFF by default
- **Dual Console**: Target runs in separate window (clean monitoring UI)

### 📊 Professional Reporting
- **Color-coded Console Output**: Events with icons and risk levels
- **JSON Exports**: Comprehensive machine-readable reports
- **Event Statistics**: Breakdown by operation type
- **Threat Summaries**: Detected behavioral patterns

---

## 🏗️ Architecture

### Two-Process Design

Rusty Sand uses a sophisticated two-process architecture for real-time prevention:

```ps1
┌───────────────────────────────────────────────────────────┐
│                    Main Process                           │
│                  (rusty_sand.exe)                         │
│                                                           │
│  ┌─────────────┐    ┌──────────────┐   ┌──────────────┐   │
│  │   Process   │    │  Monitoring  │   │  Behavioral  │   │
│  │  Controller │    │    Engine    │   │   Analyzer   │   │
│  └─────────────┘    └──────────────┘   └──────────────┘   │
│          │                  │                   │         │
│          └──────────────────┼───────────────────┘         │
│                             │                             │
│                    ┌────────▼────────┐                    │
│                    │   IPC Server    │                    │
│                    │  (Named Pipe)   │                    │
│                    └────────┬────────┘                    │
└─────────────────────────────┼─────────────────────────────┘
                              │
                   \\.\pipe\rusty_sand_hooks
                              │
┌─────────────────────────────▼──────────────────────────────┐
│                   Target Process                           │
│                   (suspended.exe)                          │
│                                                            │
│  ┌─────────────────────────────────────────────────────┐   │
│  │          rusty_sand_hooks.dll (injected)            │   │
│  │                                                     │   │
│  │  ┌─────────────┐  ┌──────────────┐  ┌───────────┐   │   │
│  │  │  CreateFileW│  │   connect()  │  │RegSetValue│   │   │
│  │  │    Hook     │  │     Hook     │  │   Hook    │   │   │
│  │  └─────────────┘  └──────────────┘  └───────────┘   │   │
│  │         │                 │                │        │   │
│  │         └─────────────────┼────────────────┘        │   │
│  │                           │                         │   │
│  │                  ┌────────▼────────┐                │   │
│  │                  │   IPC Client    │                │   │
│  │                  │(request_approval)                │   │
│  │                  └─────────────────┘                │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                            │
│  Original Windows APIs (via MinHook trampolines)           │
└────────────────────────────────────────────────────────────┘
```

### Execution Flow

1. **Initialization**
   - Main process creates target in `CREATE_SUSPENDED` state
   - IPC server starts on named pipe `\\.\pipe\rusty_sand_hooks`
   - Hook DLL (`rusty_sand_hooks.dll`) injected via `CreateRemoteThread`
   - DLL connects to IPC server and installs MinHook hooks

2. **Initial Approval**
   - User prompted to allow initial execution
   - If approved: process resumes, hooks are active
   - If denied: process terminated immediately

3. **Real-Time Interception**
   - Target calls `CreateFileW()` → hook intercepts
   - Hook extracts parameters (file path, flags, attributes)
   - Hook sends `HookRequest` to main process via named pipe
   - Main process prompts user: Allow/Deny/Terminate
   - Response sent back to hook DLL
   - If allowed: call original API via trampoline
   - If denied: return error handle WITHOUT calling original API

4. **Shutdown**
   - Process exits (normally or terminated)
   - Shutdown signal sent to all monitoring tasks
   - 500ms grace period for cleanup
   - Report generated

### Workspace Structure

This is a **Cargo workspace** with two crates:

- **rusty_sand** - Main executable (binary crate)
- **rusty_sand_hooks** - Hook DLL (cdylib crate) → compiles to `rusty_sand_hooks.dll`

Both must be built for full functionality. The DLL must be in the same directory as the executable.

---

## 🚀 Quick Start

### Prerequisites
- Windows 10/11 (x64)
- Rust toolchain (1.70+)
- Administrator privileges (recommended for full functionality)

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/rusty_sand.git
cd rusty_sand

# Build both main executable AND hook DLL (REQUIRED)
cargo build --release --workspace

# Binaries will be at:
#   target\release\rusty_sand.exe
#   target\release\rusty_sand_hooks.dll (must be in same directory!)
```

**Important**: You must build the entire workspace. The hook DLL is required for API interception to work.

### Basic Usage

```bash
# Run with interactive HIPS mode (default)
.\target\release\rusty_sand.exe suspicious.exe

# Run in passive monitoring mode (no prompts, post-execution analysis only)
.\target\release\rusty_sand.exe --no-interactive malware.exe

# Enable internet access (⚠️ use with extreme caution!)
.\target\release\rusty_sand.exe --internet suspicious.exe

# Custom timeout and memory limits
.\target\release\rusty_sand.exe -t 60 -m 512 program.exe

# Pass arguments to sandboxed program
.\target\release\rusty_sand.exe program.exe -- arg1 arg2 arg3

# Verbose debug output
.\target\release\rusty_sand.exe -v suspicious.exe

# Disable API hooks (passive monitoring only)
.\target\release\rusty_sand.exe --no-interactive suspicious.exe
```

---

## 📖 Command-Line Options

### Required
- `EXECUTABLE` - Path to executable to sandbox (absolute or relative)

### Optional Flags
- `-i, --internet` - Enable internet access (⚠️ **DEFAULT: DISABLED**)
- `-d, --dns` - Enable DNS resolution
- `-t, --timeout <SECONDS>` - Execution timeout (default: 300)
- `-m, --memory <MB>` - Memory limit in MB (default: 1024)
- `-w, --workdir <PATH>` - Working directory for process
- `-o, --output <DIR>` - Output directory (default: ./sandbox_output)
- `-f, --format <FORMAT>` - Output format: `console`, `json`, `both` (default: both)
- `-v, --verbose` - Enable verbose debug output
- `--log-network` - Enable detailed network packet logging
- `--no-registry` - Disable registry monitoring
- `--no-interactive` - Disable HIPS mode (passive monitoring only)
- `--no-behavior-detection` - Disable behavioral threat detection

### View Full Help
```bash
rusty_sand.exe --help
```

---

## 🎯 Interactive Mode (HIPS)

When running with API hooks enabled (default), Rusty Sand intercepts operations **before execution** and prompts in real-time:

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
⚠️  INTERCEPTED OPERATION #5
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  ACTION: CREATE FOLDER
  TARGET: C:\ProgramData\SuspiciousApp

  🛑 BLOCKED - Waiting for your decision...

  [Y]es / [A]llow All / [N]o / [D]eny All / [T]erminate >
```

### Decision Options

When an operation is intercepted:

- **[Y]es** - Allow this single operation (calls original API)
- **[A]llow All** - Auto-allow ALL future operations of this type (no more prompts)
- **[N]o** - Block this single operation (returns error to target)
- **[D]eny All** - Auto-block ALL future operations of this type (no more prompts)
- **[T]erminate** - Immediately kill the entire process

**If you choose [N]o**, you'll see a follow-up prompt:

```
  🚫 BLOCKED

  [C]ontinue / [T]erminate >
```

- **[C]ontinue** - Continue monitoring the process
- **[T]erminate** - Kill the process immediately

---

## 📊 Report Example

### Console Output
```
═══════════════════════════════════════════════════
           SANDBOX EXECUTION REPORT
═══════════════════════════════════════════════════

📋 EXECUTION DETAILS
  Executable:     suspicious.exe
  Start Time:     2025-10-10 14:30:00 UTC
  End Time:       2025-10-10 14:32:15 UTC
  Duration:       135 seconds
  Exit Code:      0

🔐 SECURITY CONFIGURATION
  Internet:       DISABLED ✓
  API Hooks:      ENABLED (7 hooks active)
  Interactive:    ENABLED (HIPS mode)
  Memory Limit:   1024 MB

📊 EVENT SUMMARY
  Total Events:        47
  File Operations:     12
  Folder Operations:   3 (NEW)
  Network Blocked:     2 ⚠️
  Registry Operations: 26

🚨 THREATS DETECTED
  [MEDIUM] Suspicious Folder Creation in ProgramData
  [HIGH]   Attempted connection to C2 port 4444

📝 RECENT EVENTS (last 100)
  📁 [14:30:05] FolderCreated: C:\ProgramData\Malware
  📄 [14:30:08] FileCreated: C:\temp\output.txt
  🌐 [14:30:12] NetworkBlocked: TCP 192.168.1.100:4444
  ...
```

### JSON Report
Saved to `sandbox_output/report.json` with complete event details, timestamps, user decisions, and configuration.

---

## 🔧 Library Usage

Rusty Sand can be used as a Rust library:

```rust
use rusty_sand::{execute_sandboxed, SandboxConfig};
use std::time::Duration;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut config = SandboxConfig::new()
        .with_internet(false)
        .with_timeout(Duration::from_secs(60))
        .with_memory_limit(512)
        .with_verbose(true);

    // Enable API hooks for real-time prevention
    config.enable_api_hooks = true;
    config.interactive_mode = true;

    let report = execute_sandboxed(
        "suspicious.exe",
        &["arg1".to_string(), "arg2".to_string()],
        config
    ).await?;

    println!("Total events: {}", report.events.len());
    println!("Exit code: {}", report.exit_code);

    // Access specific event types
    let file_events = report.get_file_events();
    let network_events = report.get_network_events();

    // Analyze threats
    for event in report.events {
        if event.event_type == rusty_sand::report::EventType::FolderDeleted {
            println!("Folder deleted: {}", event.details);
        }
    }

    Ok(())
}
```

See [examples/basic_usage.rs](examples/basic_usage.rs) and [examples/advanced_monitoring.rs](examples/advanced_monitoring.rs).

---

## 🔬 Detection Capabilities

### Ransomware Detection
- Rapid file creation patterns (>50 files in short time)
- Suspicious file extensions (`.encrypted`, `.locked`, `.crypto`)
- Mass file deletion in user directories

### Persistence Detection
- Registry Run key modifications (`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`)
- Startup folder access
- Scheduled task creation
- Service installation

### Folder-Based Threats (NEW)
- Suspicious folder creation in `ProgramData` (persistence)
- Hidden folder creation (names starting with `.`)
- Critical system folder deletion (`System32`, `Program Files`)
- User data folder deletion (`Documents`, `Desktop`, `Downloads`)

### UAC Bypass Detection
- `HKCU\Environment\windir` manipulation
- `ms-settings` protocol abuse
- DLL hijacking patterns

### Network Threats
- C2 server communication (ports 4444, 8080, 31337)
- Blocked connections when internet disabled
- Unusual connection patterns

---

## ⚙️ Component Architecture

### Main Process Components

| Component | File | Purpose |
|-----------|------|---------|
| **Process Controller** | [src/control/mod.rs](src/control/mod.rs) | Suspend/resume threads via Toolhelp32 |
| **Interactive Controller** | [src/control/interactive.rs](src/control/interactive.rs) | HIPS prompts and user decisions |
| **Monitoring Engine** | [src/monitor/mod.rs](src/monitor/mod.rs) | Event collection, IPC server loop |
| **File Monitor** | [src/monitor/filesystem.rs](src/monitor/filesystem.rs) | Directory watching (notify crate) |
| **Network Monitor** | [src/monitor/network.rs](src/monitor/network.rs) | TCP/UDP table polling |
| **Process Monitor** | [src/monitor/process.rs](src/monitor/process.rs) | Process tree tracking |
| **Behavioral Analyzer** | [src/behavior/mod.rs](src/behavior/mod.rs) | Threat pattern detection |
| **Sandbox** | [src/sandbox/process.rs](src/sandbox/process.rs) | Job objects, process creation |
| **IPC Protocol** | [src/ipc/mod.rs](src/ipc/mod.rs) | Named pipe communication |
| **DLL Injection** | [src/injection/mod.rs](src/injection/mod.rs) | DLL injection via remote thread |

### Hook DLL Components

| Component | File | Purpose |
|-----------|------|---------|
| **Hook DLL** | [rusty_sand_hooks/src/lib.rs](rusty_sand_hooks/src/lib.rs) | MinHook API interception |

**Hooked Functions**:
- `CreateFileW` - Detects file/folder creation, modification, deletion
- `RemoveDirectoryW` - Intercepts folder deletion
- `connect` - Blocks network connections
- `RegSetValueExW`, `RegDeleteKeyW`, `RegQueryValueExW`, `RegOpenKeyExW` - Registry operations

---

## 🛠️ Development

### Building from Source

```bash
# Build main executable only
cargo build --release

# Build hook DLL only
cargo build --release --package rusty_sand_hooks

# Build entire workspace (recommended)
cargo build --release --workspace

# Debug build (faster compilation)
cargo build --workspace

# Check code without building
cargo check --workspace

# Run clippy linter
cargo clippy --workspace -- -D warnings

# Format code
cargo fmt --all
```

### Project Structure
```
rusty_sand/
├── src/                      # Main executable crate
│   ├── behavior/             # Threat detection engine
│   ├── control/              # Process control & HIPS
│   ├── monitor/              # Monitoring subsystems
│   ├── report/               # Reporting and output
│   ├── sandbox/              # Process isolation
│   ├── ipc/                  # Named pipe IPC
│   ├── injection/            # DLL injection
│   ├── config.rs             # Configuration
│   ├── lib.rs                # Library entry point
│   └── main.rs               # CLI entry point
├── rusty_sand_hooks/         # Hook DLL crate
│   ├── src/
│   │   └── lib.rs            # MinHook implementation
│   └── Cargo.toml            # DLL dependencies
├── examples/                 # Usage examples
├── Cargo.toml                # Workspace config
└── README.md
```

### Running Examples

```bash
cargo run --release --example basic_usage
cargo run --release --example advanced_monitoring
```

---

## ⚠️ Limitations

- **Windows Only**: Uses Win32 APIs exclusively (Job Objects, Toolhelp32, Named Pipes)
- **User-Mode**: Cannot intercept kernel-level operations or drivers
- **Evasion**: Sophisticated malware can detect hooks (MinHook inline hooking)
- **Performance**: HIPS mode significantly slows execution due to user prompts
- **Admin Privileges**: Some features require elevation
- **Hook DLL Dependency**: API interception requires successful DLL injection

---

## 🤝 Contributing

Contributions welcome for:
- Additional API hooks (`CreateProcessW`, `WriteFile`, etc.)
- Behavioral detection patterns
- Performance optimizations
- Better Windows API integration
- Bug fixes and stability improvements

**Please ensure all contributions are for defensive security purposes only.**

---

## 📝 License

MIT License - See LICENSE file for details.

**For defensive security research only. The authors are not responsible for misuse.**

---

## 👥 Authors

- **GuestAUser** - Creator and primary developer

## 🙏 Acknowledgments

- [MinHook](https://github.com/TsudaKageyu/minhook) - x86/x64 API hooking library
- Windows API documentation and community
- Rust security community
- Malware analysis research community

---

## 📚 Related Projects

- [Cuckoo Sandbox](https://cuckoosandbox.org/) - Automated malware analysis
- [CAPE Sandbox](https://capesandbox.com/) - Advanced malware analysis
- [Sandboxie](https://github.com/sandboxie-plus/Sandboxie) - Application sandboxing
- [Any.Run](https://any.run/) - Interactive malware analysis service

---

**Stay safe and sandbox everything! 🏖️**
