//! Comprehensive error logging system for hook DLL
//!
//! This module provides thread-safe logging to a file with timestamps,
//! thread IDs, and log levels. Useful for debugging IPC issues and hook failures.

use once_cell::sync::Lazy;
use parking_lot::Mutex;
use std::fs::{create_dir_all, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;

/// Log levels for filtering
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    Error = 0,
    Warn = 1,
    Info = 2,
    Debug = 3,
    Trace = 4,
}

impl LogLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            LogLevel::Error => "ERROR",
            LogLevel::Warn => "WARN",
            LogLevel::Info => "INFO",
            LogLevel::Debug => "DEBUG",
            LogLevel::Trace => "TRACE",
        }
    }

    pub fn from_env() -> LogLevel {
        if let Ok(level_str) = std::env::var("RUSTY_SAND_LOG_LEVEL") {
            match level_str.to_uppercase().as_str() {
                "ERROR" => LogLevel::Error,
                "WARN" => LogLevel::Warn,
                "INFO" => LogLevel::Info,
                "DEBUG" => LogLevel::Debug,
                "TRACE" => LogLevel::Trace,
                _ => LogLevel::Info, // Default
            }
        } else {
            LogLevel::Info // Default log level
        }
    }
}

/// Global logger instance
pub struct HookLogger {
    file: Option<std::fs::File>,
    enabled: bool,
    log_level: LogLevel,
}

impl HookLogger {
    pub fn new() -> Self {
        // Check if logging is enabled via environment variable
        let enabled = std::env::var("RUSTY_SAND_DEBUG")
            .map(|v| v == "1" || v.to_lowercase() == "true")
            .unwrap_or(false);

        let log_level = LogLevel::from_env();

        if !enabled {
            return Self {
                file: None,
                enabled: false,
                log_level,
            };
        }

        // Create log directory
        let log_dir = PathBuf::from(r"C:\ProgramData\RustySand");
        if let Err(_e) = create_dir_all(&log_dir) {
            // Failed to create directory - disable logging
            return Self {
                file: None,
                enabled: false,
                log_level,
            };
        }

        // Open log file (append mode)
        let log_path = log_dir.join("hook_debug.log");
        match OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
        {
            Ok(file) => Self {
                file: Some(file),
                enabled: true,
                log_level,
            },
            Err(_e) => Self {
                file: None,
                enabled: false,
                log_level,
            },
        }
    }

    pub fn log(&mut self, level: LogLevel, message: &str) {
        if !self.enabled || level > self.log_level {
            return;
        }

        if let Some(file) = &mut self.file {
            // Get timestamp
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default();

            // Get current thread ID
            let tid = unsafe { windows::Win32::System::Threading::GetCurrentThreadId() };

            // Format log entry
            let log_entry = format!(
                "[{:>5}] [{}.{:03}] [TID:{}] {}\n",
                level.as_str(),
                now.as_secs(),
                now.subsec_millis(),
                tid,
                message
            );

            // Write to file (ignore errors - don't want logging to crash the DLL)
            let _ = file.write_all(log_entry.as_bytes());
            let _ = file.flush(); // Immediate flush for debugging
        }
    }
}

/// Global logger instance (thread-safe)
static LOGGER: Lazy<Arc<Mutex<HookLogger>>> = Lazy::new(|| Arc::new(Mutex::new(HookLogger::new())));

/// Log a message with the specified level
pub fn log(level: LogLevel, message: &str) {
    LOGGER.lock().log(level, message);
}

/// Convenience macro for logging
///
/// Usage:
/// ```
/// hook_log!(ERROR, "IPC connection failed: {}", error);
/// hook_log!(INFO, "Hook installed successfully");
/// hook_log!(DEBUG, "Processing request: {:?}", request);
/// ```
#[macro_export]
macro_rules! hook_log {
    ($level:ident, $($arg:tt)*) => {{
        let level = $crate::logging::LogLevel::$level;
        let message = format!($($arg)*);
        $crate::logging::log(level, &message);
    }};
}

/// Initialize logger (call this early in DLL_PROCESS_ATTACH)
pub fn init() {
    // Force initialization of lazy static
    let _ = &*LOGGER;
    log(LogLevel::Info, "Hook logger initialized");
}

/// Log hook statistics (useful for debugging)
///
/// This structure is kept for future telemetry features (Phase 4)
#[allow(dead_code)]
pub struct HookStatistics {
    pub total_calls: u64,
    pub allowed_calls: u64,
    pub denied_calls: u64,
    pub ipc_errors: u64,
}

#[allow(dead_code)]
impl HookStatistics {
    pub fn new() -> Self {
        Self {
            total_calls: 0,
            allowed_calls: 0,
            denied_calls: 0,
            ipc_errors: 0,
        }
    }

    pub fn log_summary(&self, hook_name: &str) {
        log(
            LogLevel::Info,
            &format!(
                "[{}] Stats: Total={} Allowed={} Denied={} IPC_Errors={}",
                hook_name,
                self.total_calls,
                self.allowed_calls,
                self.denied_calls,
                self.ipc_errors
            ),
        );
    }
}

/// Performance measurement helper
///
/// This structure is kept for future performance monitoring (Phase 4)
#[allow(dead_code)]
pub struct PerfTimer {
    start: std::time::Instant,
    name: String,
}

#[allow(dead_code)]
impl PerfTimer {
    pub fn new(name: &str) -> Self {
        Self {
            start: std::time::Instant::now(),
            name: name.to_string(),
        }
    }
}

impl Drop for PerfTimer {
    fn drop(&mut self) {
        let elapsed = self.start.elapsed();
        log(
            LogLevel::Debug,
            &format!("[PERF] {} took {:?}", self.name, elapsed),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_level_ordering() {
        assert!(LogLevel::Error < LogLevel::Warn);
        assert!(LogLevel::Warn < LogLevel::Info);
        assert!(LogLevel::Info < LogLevel::Debug);
        assert!(LogLevel::Debug < LogLevel::Trace);
    }

    #[test]
    fn test_log_level_from_env() {
        std::env::set_var("RUSTY_SAND_LOG_LEVEL", "DEBUG");
        assert_eq!(LogLevel::from_env(), LogLevel::Debug);

        std::env::set_var("RUSTY_SAND_LOG_LEVEL", "ERROR");
        assert_eq!(LogLevel::from_env(), LogLevel::Error);
    }
}
