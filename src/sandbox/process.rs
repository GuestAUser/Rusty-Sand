use crate::config::SandboxConfig;
use anyhow::{anyhow, Result};
use log::{debug, info};
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, SetInformationJobObject,
    JobObjectExtendedLimitInformation, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_ACTIVE_PROCESS, JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_LIMIT_PROCESS_MEMORY,
    JOB_OBJECT_LIMIT_PROCESS_TIME,
};
use windows::Win32::System::Threading::{
    CreateProcessW, TerminateProcess, WaitForSingleObject,
    CREATE_SUSPENDED, CREATE_NEW_CONSOLE, PROCESS_INFORMATION, STARTUPINFOW,
};

pub struct ProcessHandle {
    pub process_handle: HANDLE,
    pub thread_handle: HANDLE,
    pub process_id: u32,
    pub thread_id: u32,
    pub job_handle: Option<HANDLE>,
    pub is_suspended: bool,  // Track if process is currently suspended
}

impl Drop for ProcessHandle {
    fn drop(&mut self) {
        unsafe {
            if !self.process_handle.is_invalid() {
                let _ = CloseHandle(self.process_handle);
            }
            if !self.thread_handle.is_invalid() {
                let _ = CloseHandle(self.thread_handle);
            }
            if let Some(job) = self.job_handle {
                if !job.is_invalid() {
                    let _ = CloseHandle(job);
                }
            }
        }
    }
}

pub fn create_sandboxed_process(
    executable: &str,
    args: &[String],
    config: &SandboxConfig,
) -> Result<ProcessHandle> {
    info!("Creating sandboxed process: {}", executable);

    // Build command line
    let mut cmd_line = format!("\"{}\"", executable);
    for arg in args {
        cmd_line.push_str(&format!(" \"{}\"", arg));
    }

    debug!("Command line: {}", cmd_line);

    // Convert to wide string (mutable for PWSTR)
    let mut cmd_line_wide: Vec<u16> = OsStr::new(&cmd_line)
        .encode_wide()
        .chain(Some(0))
        .collect();

    let working_dir_wide: Option<Vec<u16>> = config.working_dir.as_ref().map(|dir| {
        dir.as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect()
    });

    let mut startup_info: STARTUPINFOW = unsafe { std::mem::zeroed() };
    startup_info.cb = std::mem::size_of::<STARTUPINFOW>() as u32;

    let mut process_info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    // Create process in suspended state
    let success = unsafe {
        let working_dir_ptr = match &working_dir_wide {
            Some(v) => PCWSTR(v.as_ptr()),
            None => PCWSTR::null(),
        };

        CreateProcessW(
            PCWSTR::null(),
            PWSTR(cmd_line_wide.as_mut_ptr()),
            None,
            None,
            false,
            CREATE_SUSPENDED | CREATE_NEW_CONSOLE,  // Open in separate window + suspended
            None,
            working_dir_ptr,
            &startup_info,
            &mut process_info,
        )
    };

    if success.is_err() {
        return Err(anyhow!("Failed to create process: {:?}", success));
    }

    info!(
        "Process created with PID: {} (suspended)",
        process_info.dwProcessId
    );

    // Create job object for resource limits
    let job_handle = unsafe { CreateJobObjectW(None, PCWSTR::null())? };

    // Set job limits
    let mut job_info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };

    // Kill all processes when job handle closes
    job_info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION
        | JOB_OBJECT_LIMIT_ACTIVE_PROCESS;

    // Set memory limit if specified
    if config.max_memory_mb > 0 {
        job_info.ProcessMemoryLimit = (config.max_memory_mb * 1024 * 1024) as usize;
        job_info.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_PROCESS_MEMORY;
    }

    // Set CPU time limit if specified
    if config.max_cpu_time > 0 {
        job_info.BasicLimitInformation.PerProcessUserTimeLimit =
            (config.max_cpu_time as i64) * 10_000_000; // Convert to 100-nanosecond intervals
        job_info.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_PROCESS_TIME;
    }

    job_info.BasicLimitInformation.ActiveProcessLimit = 10; // Max 10 child processes

    unsafe {
        SetInformationJobObject(
            job_handle,
            JobObjectExtendedLimitInformation,
            &job_info as *const _ as *const _,
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )?;
    }

    // Assign process to job
    unsafe {
        AssignProcessToJobObject(job_handle, process_info.hProcess)?;
    }

    info!("Process assigned to job object with resource limits");

    // Only auto-resume if interactive mode is disabled
    // If interactive mode is ON, keep suspended until user approves
    let should_auto_resume = !config.interactive_mode;

    if should_auto_resume {
        unsafe {
            windows::Win32::System::Threading::ResumeThread(process_info.hThread);
        }
        info!("Process resumed and executing in sandbox");
    } else {
        info!("Process kept SUSPENDED - waiting for user approval (HIPS mode)");
    }

    Ok(ProcessHandle {
        process_handle: process_info.hProcess,
        thread_handle: process_info.hThread,
        process_id: process_info.dwProcessId,
        thread_id: process_info.dwThreadId,
        job_handle: Some(job_handle),
        is_suspended: !should_auto_resume,
    })
}

impl ProcessHandle {
    /// Resume the initial thread if process is suspended
    pub fn resume_initial_thread(&mut self) -> Result<()> {
        if self.is_suspended {
            unsafe {
                windows::Win32::System::Threading::ResumeThread(self.thread_handle);
            }
            self.is_suspended = false;
            info!("Initial thread resumed - process now executing");
        }
        Ok(())
    }
}

pub fn terminate_process(handle: &ProcessHandle) -> Result<()> {
    unsafe {
        TerminateProcess(handle.process_handle, 1)?;
    }
    Ok(())
}

pub fn wait_for_process(handle: &ProcessHandle, timeout_ms: u32) -> Result<u32> {
    unsafe {
        let result = WaitForSingleObject(handle.process_handle, timeout_ms);
        Ok(result.0)
    }
}
