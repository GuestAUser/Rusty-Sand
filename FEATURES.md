# 🚀 Rusty Sand - Complete Feature List

## Core Architecture

### Two-Process Design
- **Main Process** (`rusty_sand.exe`) - Monitoring, control, and user interaction
- **Hook DLL** (`rusty_sand_hooks.dll`) - Injected into target for real-time API interception
- **Named Pipe IPC** - Secure communication channel (`\\.\pipe\rusty_sand_hooks`)
- **Cargo Workspace** - Two separate crates for clean separation of concerns

---

## 🛡️ Real-Time API Interception (TRUE HIPS)

### DLL Injection
- **CreateRemoteThread technique** - Classic DLL injection into target process
- **LoadLibraryW** - Loads hook DLL into target's address space
- **Suspended process creation** - Target created with `CREATE_SUSPENDED` flag
- **Pre-execution injection** - Hooks installed before ANY code executes
- **Automatic DLL discovery** - Finds `rusty_sand_hooks.dll` in same directory as executable

### MinHook Integration
- **Inline API hooking** - Modifies function prologue with JMP to detour
- **Trampoline creation** - Preserves original function for conditional execution
- **x64 support** - Works on modern 64-bit Windows systems
- **Hook installation** - All hooks installed in `DllMain` during injection
- **Thread-safe** - Proper synchronization for hook operations

### Hooked Windows APIs

#### File System Operations
- **CreateFileW**
  - File creation detection
  - File modification (OPEN_EXISTING)
  - Folder creation (FILE_ATTRIBUTE_DIRECTORY)
  - Folder access with backup semantics (FILE_FLAG_BACKUP_SEMANTICS)
  - Extracts full file path from PCWSTR
  - Detects creation disposition (CREATE_NEW, CREATE_ALWAYS, etc.)

- **RemoveDirectoryW** (NEW)
  - Folder deletion interception
  - Full path extraction
  - Pre-deletion blocking capability

#### Network Operations
- **connect**
  - TCP connection interception
  - IP address and port extraction
  - Socket address parsing (sockaddr_in)
  - Blocks connections BEFORE establishment

#### Registry Operations
- **RegSetValueExW**
  - Registry value write interception
  - Key and value name extraction
  - Persistence detection (Run keys)

- **RegDeleteKeyW**
  - Registry key deletion detection
  - Security tampering detection

- **RegQueryValueExW**
  - Registry read monitoring
  - Sensitive data access tracking

- **RegOpenKeyExW**
  - Registry key open tracking
  - Access pattern analysis

### IPC Protocol

#### Request Structure (HookRequest)
```json
{
  "operation": {
    "FileCreate": { "path": "C:\\file.txt" },
    "FileWrite": { "path": "C:\\file.txt" },
    "FileDelete": { "path": "C:\\file.txt" },
    "FolderCreate": { "path": "C:\\folder" },
    "FolderDelete": { "path": "C:\\folder" },
    "NetworkConnect": { "address": "192.168.1.1", "port": 80 },
    "RegistrySet": { "key": "...", "value": "..." },
    "RegistryDelete": { "key": "..." },
    "RegistryQuery": { "key": "...", "value": "..." }
  }
}
```

#### Response Structure (HookResponse)
```json
{
  "allowed": true/false
}
```

#### IPC Features
- **JSON serialization** - Human-readable protocol
- **Blocking calls** - Hook waits for user decision
- **8KB buffer** - Adequate for long paths
- **Error handling** - IPC failure = deny operation
- **Timeout handling** - Prevents infinite waits

---

## 🔍 Comprehensive Monitoring

### File System Monitoring
- **Directory watching** - Uses `notify` crate for inotify-like behavior
- **Recursive monitoring** - Watches all subdirectories
- **Event types**:
  - File created
  - File modified
  - File deleted
  - Folder created (NEW)
  - Folder deleted (NEW)
- **Real-time detection** - Sub-second latency
- **Path resolution** - Full absolute paths in events

### Network Monitoring
- **TCP table polling** - 100ms interval for active connections
- **UDP table polling** - Tracks UDP endpoints
- **Connection tracking**:
  - Local address and port
  - Remote address and port
  - Connection state (ESTABLISHED, LISTEN, etc.)
- **New connection detection** - Differential analysis vs previous poll
- **Port filtering** - Identifies suspicious ports (4444, 8080, 31337)

### Registry Monitoring
- **RegNotifyChangeKeyValue** - Real-time registry change notifications
- **Monitored keys**:
  - `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
  - `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
  - Security-related keys
- **Read-only monitoring** - No modification prevention (hooks handle writes)
- **Async notifications** - Non-blocking event handling

### Process Monitoring
- **Process tree tracking** - Complete hierarchy (parent → children → descendants)
- **Toolhelp32 API** - CreateToolhelp32Snapshot for enumeration
- **50ms polling** - Fast detection of new processes
- **Process metadata**:
  - Process ID (PID)
  - Parent PID
  - Executable path
  - Creation time
- **Child process detection** - Tracks entire process family

---

## 🚨 Behavioral Threat Detection

### Ransomware Detection
- **Rapid file creation** - >50 files in short window (configurable)
- **Suspicious extensions**:
  - `.encrypted`
  - `.locked`
  - `.crypto`
  - `.crypt`
  - `.enc`
- **Ransom note detection** - Filenames like `README`, `DECRYPT`, `RECOVER`
- **Mass deletion** - Large-scale file deletion patterns
- **Document targeting** - `.docx`, `.xlsx`, `.pdf`, `.jpg` modification

### Persistence Detection
- **Registry Run keys**:
  - `HKLM\...\Run`
  - `HKLM\...\RunOnce`
  - `HKLM\...\RunServices`
  - `HKCU\...\Run`
  - `HKCU\...\RunOnce`
- **Startup folder** - `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`
- **Scheduled tasks** - `schtasks.exe` execution
- **Service creation** - Registry `Services` key modifications

### Folder-Based Threat Detection (NEW)

#### Suspicious Folder Creation
- **ProgramData folders** - `C:\ProgramData\{non-Microsoft}` (persistence)
- **Hidden folders** - Folder names starting with `.`
- **System folder abuse** - Creation in `System32`, `Windows`
- **Temp folder patterns** - Unusual temp directory usage

#### Suspicious Folder Deletion
- **Critical system folders**:
  - `C:\Windows\System32`
  - `C:\Program Files`
  - `C:\Program Files (x86)`
- **User data folders**:
  - `Documents`
  - `Desktop`
  - `Downloads`
  - `Pictures`
- **Backup folders** - Deletion of backup locations

### UAC Bypass Detection
- **Environment variable manipulation**:
  - `HKCU\Environment\windir` - Hijacks Windows directory
  - `HKCU\Environment\SystemRoot`
- **ms-settings abuse** - `ms-settings:` protocol hijacking
- **DLL hijacking** - Suspicious DLL placement in system paths

### Security Tampering Detection
- **Windows Defender**:
  - `DisableAntiSpyware` registry value
  - `Real-Time Protection` modifications
- **Firewall tampering**:
  - `EnableFirewall` modifications
  - Rule deletions
- **Security Center** - Security health notifications disabled

### Network Threat Detection
- **C2 communication**:
  - Port 4444 (Metasploit)
  - Port 8080 (common HTTP proxy/C2)
  - Port 31337 (elite/Back Orifice)
- **Unusual ports** - Connections outside standard services
- **High connection volume** - Rapid connection attempts
- **Blocked connection attempts** - Internet disabled but process tries network

### PowerShell Abuse Detection
- **Encoded commands**:
  - `-enc` flag
  - `-e` flag
  - `-EncodedCommand`
- **Download cradles**:
  - `downloadstring`
  - `invoke-webrequest`
  - `iex` (Invoke-Expression)
  - `curl`, `wget`
- **Process creation** - `Start-Process` in scripts

### Threat Severity Levels
- **Low** - Informational, may be benign
- **Medium** - Suspicious, warrants attention
- **High** - Likely malicious, strong indicators
- **Critical** - Definite threat, immediate action recommended

---

## 🔒 Process Isolation & Control

### Windows Job Objects
- **Process grouping** - All child processes in same Job
- **Memory limits** - Hard caps in MB (default: 1024 MB)
- **CPU time limits** - Maximum CPU seconds (default: 300s)
- **Kill on job close** - Automatic cleanup of entire process tree
- **Resource accounting** - Tracks CPU and memory usage

### Process Suspension/Resumption
- **Thread enumeration** - CreateToolhelp32Snapshot for thread list
- **SuspendThread** - Suspends individual threads
- **ResumeThread** - Resumes suspended threads
- **Process-wide suspension** - Suspends ALL threads in target
- **Interactive control** - User can suspend/resume during execution

### Initial Suspension
- **CREATE_SUSPENDED** - Process created in suspended state
- **Pre-execution approval** - User decides if process runs at all
- **Hook DLL injection** - Happens while suspended
- **Safe resumption** - Only resumes after hooks installed

### Termination
- **Graceful termination** - Attempts clean exit first
- **Forced termination** - TerminateProcess as fallback
- **Job termination** - Kills entire process tree
- **Cleanup** - Ensures no orphaned processes

### Network Isolation
- **Internet OFF by default** - Maximum security
- **DNS disabled by default** - No name resolution
- **Connection blocking** - `connect()` hook denies all connections
- **Optional internet** - `--internet` flag to enable (⚠️ dangerous)

### Dual Console Windows
- **Separate consoles** - Target runs in own window
- **CREATE_NEW_CONSOLE** - Windows flag for separation
- **Clean UI** - Monitoring prompts don't mix with target output
- **User experience** - Watch target output in second window

---

## 🎮 Interactive Control (HIPS)

### User Decision System
- **Real-time prompts** - Pause execution for user input
- **Operation details** - Shows exactly what is being attempted
- **Risk assessment** - Color-coded risk levels
- **Session statistics** - Tracks allowed/blocked/prompt counts

### Decision Options
1. **[A] Allow** - Allow this specific operation
2. **[AA] Allow All** - Auto-allow all future operations of this type
3. **[B] Block** - Block this specific operation
4. **[BB] Block All** - Auto-block all future operations of this type
5. **[T] Terminate** - Kill process immediately
6. **[C] Continue** - Skip prompts for this event type

### Fast-Path Optimization
- **Auto-allow cache** - Operations marked [AA] don't prompt again
- **Auto-block cache** - Operations marked [BB] auto-denied
- **Per-event-type tracking** - Separate allow/block state for each operation type
- **Performance** - Reduces prompt fatigue for repetitive operations

### Prompt Information Display
- **Operation icon** - Visual indicator (📄 📁 🌐 📝)
- **Event type** - Human-readable operation name
- **Risk level** - LOW / MEDIUM / HIGH / CRITICAL
- **Target details** - File path, IP:port, registry key
- **Timestamp** - Exact time of operation (UTC)
- **Statistics** - Running count of prompts/allowed/blocked

### Interactive vs Passive Mode
- **Interactive (default)** - Prompts for every operation
- **Passive mode** - No prompts, post-execution analysis only
- **`--no-interactive` flag** - Switches to passive mode
- **Behavioral detection** - Still runs in passive mode

---

## 📊 Reporting & Output

### Console Output
- **Color-coded events** - Uses `colored` crate for visual feedback
- **Event icons** - Emoji for quick identification
- **Risk highlighting** - Red for high/critical, yellow for medium, green for low
- **Summary statistics** - Event counts by type
- **Recent events** - Last 100 events displayed (configurable)
- **Threat summary** - Lists all detected threats with severity

### JSON Reports
- **Machine-readable** - Standard JSON format
- **Complete event log** - Every event with full details
- **Timestamps** - ISO 8601 format (UTC)
- **Configuration dump** - Shows sandbox settings used
- **Metadata**:
  - Executable path
  - Start/end times
  - Duration
  - Exit code
- **Threat analysis** - Detected patterns and evidence

### Report Formats
- **console** - Terminal output only
- **json** - JSON file only (`report.json`)
- **both** (default) - Console + JSON file

### Event Statistics
- Total events
- File operations
- Folder operations (NEW)
- Network connections
- Network blocked
- Registry operations
- Process creations
- Suspicious events

### Output Directory
- **Configurable** - `-o` / `--output` flag
- **Default** - `./sandbox_output`
- **Auto-creation** - Creates directory if doesn't exist
- **Report naming** - `report.json` (overwritten per run)

---

## ⚙️ Configuration

### SandboxConfig Structure
```rust
pub struct SandboxConfig {
    pub allow_internet: bool,              // Default: false
    pub allow_dns: bool,                   // Default: false
    pub allow_registry: bool,              // Default: true (monitored)
    pub timeout: Duration,                 // Default: 300s
    pub working_dir: Option<PathBuf>,      // Default: None (inherit)
    pub allowed_file_patterns: Vec<String>, // Default: [] (all allowed)
    pub max_memory_mb: u64,                // Default: 1024 MB
    pub max_cpu_time: u64,                 // Default: 300s
    pub verbose: bool,                     // Default: false
    pub log_network_packets: bool,         // Default: false
    pub enable_api_hooks: bool,            // Default: true
    pub interactive_mode: bool,            // Default: true
    pub enable_behavior_detection: bool,   // Default: true
    pub auto_terminate_on_critical: bool,  // Default: false
    pub output_dir: PathBuf,               // Default: ./sandbox_output
}
```

### Builder Pattern
```rust
let config = SandboxConfig::new()
    .with_internet(false)
    .with_timeout(Duration::from_secs(60))
    .with_memory_limit(512)
    .with_verbose(true)
    .with_output_dir(PathBuf::from("./reports"));
```

### CLI to Config Mapping
- `--internet` → `allow_internet: true`
- `--dns` → `allow_dns: true`
- `-t 60` → `timeout: 60s`
- `-m 512` → `max_memory_mb: 512`
- `--no-interactive` → `interactive_mode: false`
- `--no-behavior-detection` → `enable_behavior_detection: false`
- `-v` → `verbose: true`

---

## 🛠️ Library API

### Main Entry Point
```rust
pub async fn execute_sandboxed(
    executable: &str,
    args: &[String],
    config: SandboxConfig
) -> Result<SandboxReport>
```

### Report Structure
```rust
pub struct SandboxReport {
    pub executable: String,
    pub start_time: String,
    pub end_time: String,
    pub duration_seconds: u64,
    pub exit_code: i32,
    pub events: Vec<Event>,
    pub config: SandboxConfig,
}
```

### Event Structure
```rust
pub struct Event {
    pub timestamp: String,
    pub event_type: EventType,
    pub details: String,
    pub risk_level: RiskLevel,
}

pub enum EventType {
    SandboxStarted,
    SandboxStopped,
    FileCreated,
    FileModified,
    FileDeleted,
    FolderCreated,        // NEW
    FolderDeleted,        // NEW
    NetworkConnection,
    NetworkBlocked,
    RegistryAccess,
    ProcessCreated,
    ProcessTerminated,
    SuspiciousBehavior,
    ThreatDetected,
}
```

### Helper Methods
```rust
impl SandboxReport {
    pub fn get_file_events(&self) -> Vec<&Event>;
    pub fn get_network_events(&self) -> Vec<&Event>;
    pub fn get_suspicious_events(&self) -> Vec<&Event>;
    pub fn print_summary(&self);
    pub fn save_json(&self, path: &Path) -> Result<()>;
}
```

---

## 🧪 Examples

### Basic Usage
- [examples/basic_usage.rs](examples/basic_usage.rs) - Simple sandbox execution with notepad.exe
- Shows library integration
- Demonstrates report analysis

### Advanced Monitoring
- [examples/advanced_monitoring.rs](examples/advanced_monitoring.rs) - Strict security config
- PowerShell script analysis
- Custom risk scoring
- Suspicious keyword detection

---

## 🚧 Known Limitations

### Technical Constraints
- **Windows only** - Uses Win32 APIs exclusively
- **User-mode** - Cannot intercept kernel operations
- **x64 only** - MinHook and architecture assumptions
- **Single target** - One process at a time
- **Admin recommended** - Some APIs require elevation

### Security Limitations
- **Hook detection** - Sophisticated malware can detect MinHook
- **NTDLL bypass** - Direct syscalls bypass user-mode hooks
- **Kernel operations** - Drivers and kernel code not monitored
- **Timing attacks** - Malware can detect delays from prompts
- **Self-debugging** - Process can detect debugger/hooks

### Performance Impact
- **Interactive mode** - Significant slowdown from prompts
- **Hook overhead** - MinHook trampolines add microseconds per call
- **IPC latency** - Named pipe round-trips add milliseconds
- **Monitoring overhead** - Polling loops consume CPU

### Current Gaps
- No `CreateProcessW` hook - Child processes not blocked pre-execution
- No `WriteFile` hook - File content not analyzed
- No memory monitoring - No memory dump/scan capability
- No YARA integration - No signature-based detection
- No ETW for file operations - Relies on directory watching

---

## 🔮 Future Enhancements

### Planned Features
- [ ] Additional API hooks (CreateProcessW, WriteFile, LoadLibrary)
- [ ] Full ETW integration for zero-latency monitoring
- [ ] Memory dump on suspicious allocation patterns
- [ ] YARA rule integration for signature-based detection
- [ ] Machine learning threat scoring
- [ ] Automated C2 traffic analysis
- [ ] Direct syscall detection
- [ ] Anti-hook detection and alerts

### Potential Improvements
- [ ] Multi-process support (sandbox multiple targets)
- [ ] Remote monitoring (network-based control)
- [ ] Automated report analysis (ML-based)
- [ ] Browser integration (JS execution monitoring)
- [ ] Container integration (Docker/Kubernetes)

---

**Rusty Sand is my clean HIPS for defensive security research! 🎉**
> GuestAUser
