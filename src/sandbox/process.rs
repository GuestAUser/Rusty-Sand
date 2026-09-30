use super::command_line::command_line;
use super::resource::{close_handle, with_cleanup, OwnedHandle};
use crate::config::SandboxConfig;
use anyhow::{bail, Context, Result};
use std::os::windows::ffi::OsStrExt;
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{HANDLE, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
    SetInformationJobObject, TerminateJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_ACTIVE_PROCESS, JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_LIMIT_PROCESS_MEMORY,
    JOB_OBJECT_LIMIT_PROCESS_TIME,
};
use windows::Win32::System::Threading::{
    CreateProcessW, GetExitCodeProcess, QueryFullProcessImageNameW, ResumeThread, TerminateProcess,
    WaitForSingleObject, CREATE_NO_WINDOW, CREATE_SUSPENDED, PROCESS_INFORMATION,
    PROCESS_NAME_WIN32, STARTUPINFOW,
};

pub struct ProcessHandle {
    pub process_handle: HANDLE,
    pub thread_handle: HANDLE,
    pub process_id: u32,
    pub thread_id: u32,
    pub job_handle: Option<HANDLE>,
    pub is_suspended: bool,
    image_path: String,
}

impl ProcessHandle {
    pub fn resume_initial_thread(&mut self) -> Result<()> {
        if self.is_suspended {
            /* SAFETY: This object owns the primary thread returned by
            CreateProcessW; startup has not resumed it elsewhere. */
            let previous = unsafe { ResumeThread(self.thread_handle) };
            if previous == u32::MAX {
                return Err(windows::core::Error::from_win32()).context("resume initial thread");
            }
            if previous != 1 {
                bail!("unexpected initial thread suspension count: {previous}");
            }
            self.is_suspended = false;
        }
        Ok(())
    }

    /**
    The image identity is captured while creation still owns a suspended process.
    Windows may stop serving image queries after exit, even while a handle remains.
    */
    pub fn executable(&self) -> &str {
        &self.image_path
    }

    pub(crate) fn exit_code(&self) -> Result<Option<u32>> {
        const STILL_ACTIVE: u32 = 259;
        let mut code = 0;

        /* SAFETY: The owned handle remains valid throughout both queries.
        Exit status may become available before the final process signal,
        while Windows is closing the target's pipe and other resources. */
        unsafe { GetExitCodeProcess(self.process_handle, &mut code) }
            .context("query process exit code")?;
        if code != STILL_ACTIVE {
            return Ok(Some(code));
        }

        /* A real exit code of 259 is ambiguous until the process signals. */
        match unsafe { WaitForSingleObject(self.process_handle, 0) } {
            WAIT_TIMEOUT => Ok(None),
            WAIT_OBJECT_0 => {
                /* The process may have exited between the status and wait
                queries, so read the now-final status rather than reusing 259. */
                unsafe { GetExitCodeProcess(self.process_handle, &mut code) }
                    .context("query final process exit code")?;
                Ok(Some(code))
            }
            _ => Err(windows::core::Error::from_win32()).context("query process completion"),
        }
    }

    pub(crate) fn terminate(&self, code: u32) -> Result<()> {
        let mut result = Ok(());
        if let Some(job) = self.job_handle {
            /* SAFETY: The job is owned here and contains only this execution's
            processes. Termination also covers surviving descendants. */
            match unsafe { TerminateJobObject(job, code) } {
                Ok(()) => return Ok(()),
                Err(error) => result = Err(error).context("terminate process job"),
            }
        }
        if !self.process_handle.is_invalid() {
            match self.exit_code() {
                Ok(Some(_)) => {}
                Ok(None) => {
                    /* SAFETY: This object owns the process. A process not yet
                    assigned to its job must also die on assignment failure. */
                    if let Err(error) = unsafe { TerminateProcess(self.process_handle, code) } {
                        /* A racing natural exit is not a termination failure. */
                        match self.exit_code() {
                            Ok(Some(_)) => {}
                            Ok(None) => {
                                result = with_cleanup(
                                    result,
                                    Err(error).context("terminate target process"),
                                )
                            }
                            Err(query) => {
                                result = with_cleanup(
                                    with_cleanup(result, Err(error.into())),
                                    Err(query),
                                )
                            }
                        }
                    }
                }
                Err(error) => result = with_cleanup(result, Err(error)),
            }
        }
        result
    }

    pub(crate) fn close(&mut self) -> Result<()> {
        let mut result = Ok(());
        if let Some(job) = self.job_handle.as_mut() {
            result = with_cleanup(result, close_handle(job));
            if job.is_invalid() {
                self.job_handle = None;
            }
        }
        result = with_cleanup(result, close_handle(&mut self.thread_handle));
        with_cleanup(result, close_handle(&mut self.process_handle))
    }
}

impl Drop for ProcessHandle {
    fn drop(&mut self) {
        if !self.process_handle.is_invalid()
            || !self.thread_handle.is_invalid()
            || self.job_handle.is_some()
        {
            let termination = self.terminate(1);
            let cleanup = self.close();
            if let Err(error) = with_cleanup(termination, cleanup) {
                log::error!("Process cleanup failed: {error:#}");
            }
        }
    }
}

pub fn create_sandboxed_process(
    executable: &str,
    args: &[String],
    config: &SandboxConfig,
) -> Result<ProcessHandle> {
    let mut command = command_line(executable, args)?;
    let application: Vec<u16> = executable.encode_utf16().chain(Some(0)).collect();
    let directory = config
        .working_dir
        .as_ref()
        .map(|path| {
            let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
            if wide.contains(&0) {
                bail!("working directory contains NUL");
            }
            wide.push(0);
            Ok(wide)
        })
        .transpose()?;
    let limits = job_limits(config)?;

    /* SAFETY: The unnamed job takes no borrowed pointers beyond the call. */
    let mut job = OwnedHandle::new(
        unsafe { CreateJobObjectW(None, PCWSTR::null()) }.context("create process job")?,
    );
    /* SAFETY: Windows copies the correctly sized job-information structure. */
    let configured = unsafe {
        SetInformationJobObject(
            job.raw(),
            JobObjectExtendedLimitInformation,
            (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            std::mem::size_of_val(&limits) as u32,
        )
    }
    .context("configure process job");
    if let Err(error) = configured {
        return with_cleanup(Err(error), job.close());
    }

    let startup = STARTUPINFOW {
        cb: std::mem::size_of::<STARTUPINFOW>() as u32,
        ..Default::default()
    };
    let mut information = PROCESS_INFORMATION::default();
    /* SAFETY: All strings are NUL-terminated and the command line is mutable.
    No handles are inherited. Output handles are owned immediately on success.
    The explicit application path avoids command-line executable ambiguity. */
    let created = unsafe {
        CreateProcessW(
            PCWSTR(application.as_ptr()),
            PWSTR(command.as_mut_ptr()),
            None,
            None,
            false,
            CREATE_SUSPENDED | CREATE_NO_WINDOW,
            None,
            directory
                .as_ref()
                .map_or(PCWSTR::null(), |path| PCWSTR(path.as_ptr())),
            &startup,
            &mut information,
        )
    }
    .context("create suspended process");
    if let Err(error) = created {
        return with_cleanup(Err(error), job.close());
    }

    let mut process = ProcessHandle {
        process_handle: information.hProcess,
        thread_handle: information.hThread,
        process_id: information.dwProcessId,
        thread_id: information.dwThreadId,
        job_handle: None,
        is_suspended: true,
        image_path: String::new(),
    };
    /* SAFETY: Both kernel handles are owned above. The primary thread has never
    run, so no target-created children can escape this assignment. */
    let assigned = unsafe { AssignProcessToJobObject(job.raw(), process.process_handle) }
        .context("assign suspended process to job");
    if let Err(error) = assigned {
        let terminated = process.terminate(1);
        let closed = process.close();
        return with_cleanup(
            with_cleanup(with_cleanup(Err(error), terminated), closed),
            job.close(),
        );
    }

    /*
     * A stored job handle proves membership. Successful job termination then
     * owns shutdown; a second TerminateProcess can fail while Windows is
     * already dismantling the process but has not signaled its handle yet.
     */
    process.job_handle = Some(job.into_raw());

    let mut buffer = vec![0u16; 32_768];
    let mut length = buffer.len() as u32;
    /* SAFETY: The process remains suspended and owned. The UTF-16 buffer and
    length storage remain writable for the synchronous image query. */
    let image_path = unsafe {
        QueryFullProcessImageNameW(
            process.process_handle,
            PROCESS_NAME_WIN32,
            PWSTR(buffer.as_mut_ptr()),
            &mut length,
        )
    }
    .context("query executable path")
    .and_then(|()| {
        String::from_utf16(&buffer[..length as usize]).context("executable path is not Unicode")
    });

    match image_path {
        Ok(path) => process.image_path = path,
        Err(error) => {
            let terminated = process.terminate(1);
            let closed = process.close();
            return with_cleanup(with_cleanup(Err(error), terminated), closed);
        }
    }

    Ok(process)
}

fn job_limits(config: &SandboxConfig) -> Result<JOBOBJECT_EXTENDED_LIMIT_INFORMATION> {
    let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION
        | JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
    limits.BasicLimitInformation.ActiveProcessLimit = 10;
    if config.max_memory_mb != 0 {
        limits.ProcessMemoryLimit = usize::try_from(config.max_memory_mb)
            .ok()
            .and_then(|megabytes| megabytes.checked_mul(1024 * 1024))
            .context("memory limit is outside this architecture's address range")?;
        limits.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_PROCESS_MEMORY;
    }
    if config.max_cpu_time != 0 {
        limits.BasicLimitInformation.PerProcessUserTimeLimit = i64::try_from(config.max_cpu_time)
            .ok()
            .and_then(|seconds| seconds.checked_mul(10_000_000))
            .context("CPU time limit overflows Windows 100-nanosecond units")?;
        limits.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_PROCESS_TIME;
    }
    Ok(limits)
}

pub fn terminate_process(handle: &ProcessHandle) -> Result<()> {
    handle.terminate(1)
}

pub fn wait_for_process(handle: &ProcessHandle, timeout_ms: u32) -> Result<u32> {
    /* SAFETY: The process handle is borrowed from its owner for this call. */
    let result = unsafe { WaitForSingleObject(handle.process_handle, timeout_ms) };
    if result == WAIT_FAILED {
        return Err(windows::core::Error::from_win32()).context("wait for process");
    }
    Ok(result.0)
}

#[cfg(test)]
#[path = "../../tests/unit/windows/sandbox_process.rs"]
mod tests;
