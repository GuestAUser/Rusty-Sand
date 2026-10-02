use clap::{Parser, ValueEnum};
use rusty_sand::report::analysis::AnalysisMode;
use rusty_sand::ui::{ColorMode, OutputPolicy};
use std::io::IsTerminal;
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub(crate) enum ColorChoice {
    Auto,
    Always,
    Never,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub(crate) enum ReportFormat {
    Console,
    Json,
    Both,
}

#[derive(Parser, Debug)]
#[command(name = "rusty_sand", author, version)]
#[command(about = "Inspect files and analyze Windows executable behavior")]
#[command(
    after_help = "Monitoring and API hooks do not provide complete host isolation or guaranteed network blocking. Use a disposable Windows VM for untrusted programs. Pass target arguments after --."
)]
pub(crate) struct Args {
    /// Executable path, absolute or relative
    #[arg(value_name = "EXECUTABLE")]
    pub executable: String,

    /// Arguments forwarded unchanged to the executable after --
    #[arg(value_name = "ARGS", last = true)]
    pub args: Vec<String>,

    /// Inspect the file without executing it (also supported on non-Windows hosts)
    #[arg(long = "static", conflicts_with_all = ["debug_mode", "shell_mode", "restricted"])]
    pub static_only: bool,

    /// Trace native Windows debug events instead of injecting API hooks
    #[arg(long = "debug", conflicts_with = "shell_mode")]
    pub debug_mode: bool,

    /// Open an analyst shell with inspection and live execution controls
    #[arg(long = "shell")]
    pub shell_mode: bool,

    /// Launch with a restricted Windows token; fail if it cannot be applied
    #[arg(long)]
    pub restricted: bool,

    /// Allow internet in the requested policy; also enables DNS
    #[arg(short = 'i', long = "internet")]
    pub internet: bool,

    /// Allow DNS in the requested policy
    #[arg(short = 'd', long = "dns")]
    pub dns: bool,

    /// Requested execution timeout in seconds
    #[arg(short = 't', long = "timeout", default_value = "300")]
    pub timeout: u64,

    /// Working directory for the target process
    #[arg(short = 'w', long = "workdir")]
    pub working_dir: Option<PathBuf>,

    /// Directory for reports and monitoring artifacts
    #[arg(short = 'o', long = "output", default_value = "./sandbox_output")]
    pub output_dir: PathBuf,

    /// Output selection; JSON artifacts are saved inside OUTPUT
    #[arg(short = 'f', long = "format", value_enum, default_value = "both")]
    pub format: ReportFormat,

    /// Requested memory limit in megabytes (0 means unlimited)
    #[arg(short = 'm', long = "memory", default_value = "1024")]
    pub max_memory: u64,

    /// Color policy; never also disables terminal effects
    #[arg(long, value_enum, default_value = "auto")]
    pub color: ColorChoice,

    /// Disable colors and terminal effects
    #[arg(long)]
    pub plain: bool,

    /// Disable animation while retaining semantic colors
    #[arg(long)]
    pub reduced_motion: bool,

    /// Enable debug logging
    #[arg(short = 'v', long = "verbose")]
    pub verbose: bool,

    /// Log observed network endpoints, not packet payloads
    #[arg(long = "log-network")]
    pub log_network: bool,

    /// Disable registry monitoring and deny intercepted registry access
    #[arg(long = "no-registry")]
    pub no_registry: bool,

    /// Disable interactive operation approval
    #[arg(long = "no-interactive")]
    pub no_interactive: bool,

    /// Disable behavioral analysis
    #[arg(long = "no-behavior-detection")]
    pub no_behavior_detection: bool,
}

impl Args {
    pub(crate) fn mode(&self) -> AnalysisMode {
        if self.static_only {
            AnalysisMode::Static
        } else if self.debug_mode {
            AnalysisMode::Debug
        } else if self.shell_mode {
            AnalysisMode::Shell
        } else {
            AnalysisMode::Execute
        }
    }

    #[cfg(any(windows, test))]
    pub(crate) fn sandbox_config(&self) -> rusty_sand::SandboxConfig {
        use rusty_sand::SandboxConfig;
        use std::time::Duration;

        let mut config = SandboxConfig::new()
            .with_internet(self.internet)
            .with_timeout(Duration::from_secs(self.timeout))
            .with_output_dir(self.output_dir.clone())
            .with_memory_limit(self.max_memory)
            .with_verbose(self.verbose);

        config.working_dir = self.working_dir.clone();
        config.allow_dns = self.dns || self.internet;
        config.log_network_packets = self.log_network;
        config.allow_registry = !self.no_registry;
        config.interactive_mode = !self.no_interactive;
        config.cancel_on_stdin_eof =
            std::env::var("RUSTY_SAND_STDIN_CONTROL").as_deref() == Ok("1");
        config.restricted_token = self.restricted;
        config.enable_api_hooks = !self.debug_mode;
        config.enable_behavior_detection = !self.no_behavior_detection && !self.debug_mode;

        config
    }

    pub(crate) fn output_policy(&self) -> OutputPolicy {
        let tty = match std::env::var("RUSTY_SAND_STDERR_TTY").as_deref() {
            Ok("1") => true,
            Ok("0") => false,
            _ => std::io::stderr().is_terminal(),
        };
        let columns = std::env::var("RUSTY_SAND_COLUMNS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or_else(native_columns);

        OutputPolicy {
            color: match self.color {
                ColorChoice::Auto => ColorMode::Auto,
                ColorChoice::Always => ColorMode::Always,
                ColorChoice::Never => ColorMode::Never,
            },
            plain: self.plain,
            reduced_motion: self.reduced_motion,
            tty,
            columns,
        }
    }
}

#[cfg(not(windows))]
fn native_columns() -> usize {
    80
}

#[cfg(windows)]
fn native_columns() -> usize {
    use windows::Win32::System::Console::{
        GetConsoleScreenBufferInfo, GetStdHandle, CONSOLE_SCREEN_BUFFER_INFO, STD_ERROR_HANDLE,
    };

    /* SAFETY: These calls only query the borrowed standard output handle and
     * write into an initialized, correctly sized console-info structure. A
     * redirected stream has no native console dimensions, so use 80 columns. */
    let Ok(handle) = (unsafe { GetStdHandle(STD_ERROR_HANDLE) }) else {
        return 80;
    };
    let mut info = CONSOLE_SCREEN_BUFFER_INFO::default();
    if unsafe { GetConsoleScreenBufferInfo(handle, &mut info) }.is_err() {
        return 80;
    }
    usize::try_from(i32::from(info.srWindow.Right) - i32::from(info.srWindow.Left) + 1)
        .unwrap_or(80)
}

#[cfg(test)]
#[path = "../tests/unit/domain/cli.rs"]
mod tests;
