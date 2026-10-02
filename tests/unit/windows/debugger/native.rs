use super::*;
use crate::config::SandboxConfig;
use crate::debugger::diagnostic::{image_path, read_memory};
use crate::debugger::*;
use crate::sandbox::process::create_sandboxed_process;
use crate::sandbox::wait::HandleWait;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use windows::core::PCWSTR;
use windows::Win32::System::Threading::{
    CreateEventW, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
};

const HANDLED_EXCEPTION: u32 = 0xE042_1001;
const UNHANDLED_EXCEPTION: u32 = 0xE042_1002;

#[test]
fn debugger_rip_serialization_preserves_discriminator_and_native_type() -> Result<()> {
    /* Given RIP evidence, including an unrecognized native type value. */
    let event = DebugEventKind::Rip {
        error: 5,
        kind: u32::MAX,
    };

    /* When the event crosses the serialized report boundary. */
    let encoded = serde_json::to_value(&event)?;
    let decoded: DebugEventKind = serde_json::from_value(encoded.clone())?;

    /* Then the discriminator and numeric RIP type remain separate fields. */
    assert_eq!(
        encoded,
        serde_json::json!({
            "kind": "rip",
            "error": 5,
            "rip_type": u32::MAX,
        })
    );
    assert_eq!(decoded, event);
    Ok(())
}

fn fixture() -> Result<(tempfile::TempDir, String)> {
    /*
     * Build-time inclusion makes a missing fixture a build error. Each test
     * owns a Windows-local copy, independent of the Cargo profile directory,
     * WSL source paths, other tests, and other concurrent Cargo invocations.
     */
    let directory = tempfile::tempdir()?;
    let fixture = directory.path().join("debugger_benign.exe");
    std::fs::write(
        &fixture,
        include_bytes!(concat!(env!("OUT_DIR"), "/debugger_benign.exe")),
    )?;

    let executable = fixture
        .to_str()
        .map(str::to_owned)
        .context("debugger fixture path is not Unicode")?;

    Ok((directory, executable))
}

fn config() -> SandboxConfig {
    SandboxConfig {
        timeout: Duration::from_secs(30),
        interactive_mode: false,
        /*
         * Intentionally retain the default enable_api_hooks=true setting:
         * debugger mode must not use the hook-injection execution path.
         */
        ..SandboxConfig::default()
    }
}

fn run_fixture(mode: &str) -> Result<DebugReport> {
    let (_directory, executable) = fixture()?;

    debug_executable(
        &executable,
        &[mode.into()],
        &config(),
        &AtomicBool::new(false),
    )
}

fn has_debug_string(report: &DebugReport, expected: &str) -> bool {
    report.events.iter().any(|event| {
        matches!(
            &event.event,
            DebugEventKind::DebugString { data } if data.text == expected
        )
    })
}

#[test]
fn debugger_debug_strings_use_native_byte_counts_and_preserve_raw_payloads() -> Result<()> {
    /* Given the fixture's known ANSI and UTF-16 debug strings. */
    let expected_strings = [(false, "debugger-ascii"), (true, "debugger-wide-\u{03a9}")];

    /* When actual Windows debug-string events are recorded. */
    let report = run_fixture("normal")?;

    /* Then each read is exactly the declared byte payload, including its NUL. */
    for (unicode, text) in expected_strings {
        let expected: Vec<u8> = if unicode {
            text.encode_utf16()
                .chain(Some(0))
                .flat_map(u16::to_le_bytes)
                .collect()
        } else {
            text.as_bytes().iter().copied().chain(Some(0)).collect()
        };

        let data = report
            .events
            .iter()
            .find_map(|event| match &event.event {
                DebugEventKind::DebugString { data } if data.text == text => Some(data),
                _ => None,
            })
            .context("missing fixture debug string")?;

        assert_eq!(data.unicode, unicode);
        assert_eq!(usize::from(data.declared_units), expected.len());
        assert_eq!(data.memory.requested_bytes as usize, expected.len());
        assert_eq!(data.memory.bytes, expected);
        assert!(data.memory.error.is_none());
        assert!(!data.truncated);
    }

    Ok(())
}

#[test]
fn debugger_records_native_events_and_preserves_handled_exceptions() -> Result<()> {
    let report = run_fixture("normal")?;
    assert_eq!(report.exit, ExitOutcome::Exited { code: 7 });
    assert!(!report.cancelled);
    assert!(!report.timed_out);
    assert_ne!(report.target_pid, 0);
    assert_eq!(report.counters.dropped_events, 0);

    assert!(matches!(
        report.events.first().map(|event| &event.event),
        Some(DebugEventKind::ProcessCreated { .. })
    ));
    assert!(matches!(
        report.events.last().map(|event| &event.event),
        Some(DebugEventKind::ProcessExited { code: 7 })
    ));
    assert!(report
        .events
        .iter()
        .all(|event| event.process_id == report.target_pid));
    assert!(report.events.windows(2).all(|events| {
        events[0].sequence < events[1].sequence
            && events[0].elapsed_micros <= events[1].elapsed_micros
    }));
    assert!(report
        .events
        .iter()
        .any(|event| matches!(&event.event, DebugEventKind::ThreadCreated { .. })));
    assert!(report
        .events
        .iter()
        .any(|event| matches!(&event.event, DebugEventKind::ThreadExited { code: 9 })));
    assert!(report
        .events
        .iter()
        .any(|event| matches!(&event.event, DebugEventKind::ModuleLoaded { .. })));
    assert!(report
        .events
        .iter()
        .any(|event| matches!(&event.event, DebugEventKind::ModuleUnloaded { .. })));

    assert!(has_debug_string(&report, "debugger-ascii"));
    assert!(has_debug_string(&report, "debugger-wide-\u{03a9}"));
    assert!(has_debug_string(&report, "handled-breakpoint"));

    let exceptions: Vec<&ExceptionDetails> = report
        .events
        .iter()
        .filter_map(|event| match &event.event {
            DebugEventKind::Exception { details } => Some(details.as_ref()),
            _ => None,
        })
        .collect();

    assert_eq!(
        exceptions
            .iter()
            .filter(|exception| exception.initialization_breakpoint)
            .count(),
        1
    );
    assert!(exceptions.iter().any(|exception| {
        exception.code == STATUS_BREAKPOINT.0 as u32
            && !exception.initialization_breakpoint
            && exception.first_chance
    }));

    let handled = exceptions
        .iter()
        .find(|exception| exception.code == HANDLED_EXCEPTION)
        .context("missing native handled exception")?;
    assert!(handled.first_chance);
    assert_eq!(handled.parameters, [0x1122, 0x3344, 0x5566]);
    let context = handled
        .context
        .as_ref()
        .context("native AMD64 context was not captured")?;
    assert_ne!(context.rip, 0);
    assert_ne!(context.rsp, 0);
    assert!(handled.context_error.is_none());
    assert!(!handled.instruction_bytes.bytes.is_empty());
    assert!(handled.instruction_bytes.bytes.len() <= MAX_INSTRUCTION_BYTES);
    assert!(exceptions.iter().all(|exception| exception.first_chance));

    let serialized = serde_json::to_string(&report)?;
    let decoded: DebugReport = serde_json::from_str(&serialized)?;
    assert_eq!(decoded, report);
    Ok(())
}

#[test]
fn debugger_records_native_image_and_module_paths_before_closing_files() -> Result<()> {
    /* Given a private, Cargo-built benign executable. */
    let (_directory, executable) = fixture()?;
    let expected_image = std::fs::canonicalize(&executable)?;

    /* When the actual Windows debugger receives image and DLL load events. */
    let report = debug_executable(
        &executable,
        &["normal".into()],
        &config(),
        &AtomicBool::new(false),
    )?;

    /* Then path evidence identifies the image and the fixture's loaded DLL. */
    assert_eq!(report.exit, ExitOutcome::Exited { code: 7 });

    let image = report
        .events
        .iter()
        .find_map(|event| match &event.event {
            DebugEventKind::ProcessCreated {
                image_path: ImagePath::Available { path, lossy: false },
                ..
            } => Some(path),
            _ => None,
        })
        .context("native process image path was not captured")?;

    assert_eq!(std::fs::canonicalize(image)?, expected_image);
    assert!(image.encode_utf16().count() < MAX_IMAGE_PATH_UNITS);

    let module = report
        .events
        .iter()
        .find_map(|event| match &event.event {
            DebugEventKind::ModuleLoaded {
                image_path: ImagePath::Available { path, lossy: false },
                ..
            } if std::path::Path::new(path)
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.eq_ignore_ascii_case("version.dll")) =>
            {
                Some(path)
            }
            _ => None,
        })
        .context("native version.dll path was not captured")?;

    assert!(std::path::Path::new(module).is_absolute());
    assert!(module.encode_utf16().count() < MAX_IMAGE_PATH_UNITS);
    assert_eq!(report.counters.truncated_image_paths, 0);
    Ok(())
}

#[test]
fn debugger_image_path_absence_is_explicit() {
    /* Given an event for which Windows supplied no image file handle. */
    let mut counters = DebugCounters::default();

    /* When diagnostic recording attempts to obtain image path evidence. */
    let evidence = image_path(HANDLE::default(), &mut counters);

    /* Then absence is retained, without a failing debugger operation. */
    assert_eq!(evidence, ImagePath::MissingHandle);
    assert_eq!(counters.unavailable_image_paths, 1);
    assert_eq!(counters.truncated_image_paths, 0);
}

#[test]
fn debugger_image_path_query_failure_retains_the_native_error() -> Result<()> {
    /* Given a valid kernel object which cannot provide a file path. */
    let (mut event, _) = named_event("path-query-error")?;
    let mut counters = DebugCounters::default();

    /* When Windows rejects the diagnostic path query. */
    let evidence = image_path(event.raw(), &mut counters);
    event.close()?;

    /* Then the error remains evidence, rather than an operational failure. */
    assert!(matches!(
        evidence,
        ImagePath::Unavailable {
            win32_error: Some(win32_error)
        } if win32_error != 0
    ));
    assert_eq!(counters.unavailable_image_paths, 1);
    assert_eq!(counters.truncated_image_paths, 0);
    Ok(())
}

#[test]
fn debugger_delivers_both_chances_of_an_unhandled_exception() -> Result<()> {
    let report = run_fixture("unhandled")?;
    assert_eq!(
        report.exit,
        ExitOutcome::UnhandledException {
            code: UNHANDLED_EXCEPTION,
            exception_code: UNHANDLED_EXCEPTION,
        }
    );

    let chances: Vec<bool> = report
        .events
        .iter()
        .filter_map(|event| match &event.event {
            DebugEventKind::Exception { details } if details.code == UNHANDLED_EXCEPTION => {
                Some(details.first_chance)
            }
            _ => None,
        })
        .collect();

    assert_eq!(chances, [true, false]);
    assert!(matches!(
        report.events.last().map(|event| &event.event),
        Some(DebugEventKind::ProcessExited {
            code: UNHANDLED_EXCEPTION
        })
    ));
    Ok(())
}

#[test]
fn debugger_bounds_payloads_and_keeps_driving_after_event_capacity() -> Result<()> {
    let report = run_fixture("flood")?;
    assert_eq!(report.exit, ExitOutcome::Exited { code: 7 });
    assert_eq!(report.events.len(), MAX_EVENTS);
    assert!(report.counters.dropped_events > 0);
    assert!(report.counters.truncated_debug_strings > 0);

    for event in &report.events {
        match &event.event {
            DebugEventKind::DebugString { data } => {
                assert!(data.memory.bytes.len() <= MAX_DEBUG_STRING_BYTES);
                assert!(data.memory.requested_bytes as usize <= MAX_DEBUG_STRING_BYTES);
            }
            DebugEventKind::Exception { details } => {
                assert!(details.parameters.len() <= 15);
                assert!(details.instruction_bytes.bytes.len() <= MAX_INSTRUCTION_BYTES);
            }
            DebugEventKind::ProcessCreated { image_path, .. }
            | DebugEventKind::ModuleLoaded { image_path, .. } => match image_path {
                ImagePath::Available { path, .. } => {
                    assert!(path.encode_utf16().count() < MAX_IMAGE_PATH_UNITS);
                }
                ImagePath::Truncated {
                    required_buffer_units,
                } => {
                    assert!(*required_buffer_units as usize >= MAX_IMAGE_PATH_UNITS);
                }
                ImagePath::MissingHandle | ImagePath::Unavailable { .. } => {}
            },
            _ => {}
        }
    }

    Ok(())
}

fn named_event(label: &str) -> Result<(OwnedHandle, String)> {
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);

    let name = format!(
        "Local\\RustySandDebuggerTest-{}-{}-{label}",
        std::process::id(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    );
    let wide: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();

    /* SAFETY: The terminated name lives through creation; the handle is owned. */
    let event =
        OwnedHandle::new(unsafe { CreateEventW(None, true, false, PCWSTR(wide.as_ptr()))? });

    Ok((event, name))
}

async fn stopped_fixture(cancel_requested: bool) -> Result<DebugReport> {
    let (directory, executable) = fixture()?;
    let pid_path = directory.path().join("target.pid");
    let (mut ready, ready_name) = named_event("ready")?;
    let (mut gate, gate_name) = named_event("gate")?;
    let mut ready_wait = HandleWait::new(ready.raw())?;
    let cancel = Arc::new(AtomicBool::new(false));
    let worker_cancel = Arc::clone(&cancel);
    let mut policy = config();

    if !cancel_requested {
        /* Time itself is under test in this case. The target waits on an event,
         * not a sleep or a polling loop, until the debugger deadline kills it. */
        policy.timeout = Duration::from_secs(10);
    }

    let args = vec![
        "wait".into(),
        ready_name,
        gate_name,
        pid_path
            .to_str()
            .context("fixture PID path is not Unicode")?
            .to_owned(),
    ];

    /*
     * Register readiness before launching. After readiness, retain an OS wait
     * on this exact process object before requesting cancellation. This avoids
     * using process enumeration, PID disappearance, sleeps, or timing luck as
     * the completion assertion.
     */
    let worker = tokio::task::spawn_blocking(move || {
        debug_executable(&executable, &args, &policy, &worker_cancel)
    });

    let observed: Result<(u32, HandleWait)> = async {
        tokio::time::timeout(Duration::from_secs(20), ready_wait.wait())
            .await
            .context("fixture did not signal native readiness")??;

        let pid: u32 = std::fs::read_to_string(&pid_path)?.trim().parse()?;
        /* SAFETY: Readiness publishes this fixture's PID. Only query/wait access
         * is requested; the debugger retains its original owned process handle. */
        let process = OwnedHandle::new(unsafe {
            OpenProcess(
                PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
                false,
                pid,
            )?
        });
        let completion = HandleWait::new(process.raw())?;
        Ok((pid, completion))
    }
    .await;

    if cancel_requested || observed.is_err() {
        cancel.store(true, Ordering::Release);
    }

    /*
     * Join even when readiness failed, rather than leaving a detached debugger
     * task behind. The backend's termination and cleanup waits are bounded.
     */
    let joined = tokio::time::timeout(Duration::from_secs(60), worker)
        .await
        .context("debugger worker did not finish")?
        .context("debugger blocking task panicked")?;
    let report = with_cleanup(joined, ready_wait.close())?;
    let (pid, mut completion) = observed?;

    tokio::time::timeout(Duration::from_secs(5), completion.wait())
        .await
        .context("debugger returned with an orphaned owned target")??;
    completion.close()?;
    ready.close()?;
    gate.close()?;

    assert_eq!(pid, report.target_pid);
    assert!(matches!(
        report.events.last().map(|event| &event.event),
        Some(DebugEventKind::ProcessExited { .. })
    ));
    assert!(matches!(
        report.exit,
        ExitOutcome::Terminated {
            code: STOP_EXIT_CODE
        }
    ));
    Ok(report)
}

#[tokio::test]
async fn debugger_cancellation_reaps_the_exact_owned_process() -> Result<()> {
    let report = stopped_fixture(true).await?;
    assert!(report.cancelled);
    assert!(!report.timed_out);
    Ok(())
}

#[tokio::test]
async fn debugger_timeout_reaps_the_exact_owned_process() -> Result<()> {
    let report = stopped_fixture(false).await?;
    assert!(report.timed_out);
    assert!(!report.cancelled);
    Ok(())
}

#[test]
fn debugger_preexisting_cancellation_never_releases_the_target() -> Result<()> {
    let (_directory, executable) = fixture()?;

    let report = debug_executable(
        &executable,
        &["normal".into()],
        &config(),
        &AtomicBool::new(true),
    )?;

    assert!(report.cancelled);
    assert!(!report.timed_out);
    assert!(report.events.is_empty());
    assert_eq!(
        report.exit,
        ExitOutcome::Terminated {
            code: STOP_EXIT_CODE
        }
    );
    Ok(())
}

#[test]
fn debugger_pre_attach_failure_closes_and_reaps_the_suspended_target() -> Result<()> {
    let (_directory, executable) = fixture()?;
    let process = create_sandboxed_process(&executable, &["normal".into()], &config())?;
    assert!(process.is_suspended);
    let mut completion = OwnedHandle::duplicate(process.process_handle)?;
    let mut session = Session::new(process);

    let unreadable = read_memory(&session.process, 0, MAX_INSTRUCTION_BYTES);
    assert!(unreadable.bytes.is_empty());
    assert!(unreadable.error.is_some());
    assert_eq!(unreadable.requested_bytes as usize, MAX_INSTRUCTION_BYTES);

    let result = session.finish(Err(anyhow!("test setup failure")));
    assert!(result.is_err());
    assert!(session.process.process_handle.is_invalid());
    assert!(session.process.thread_handle.is_invalid());
    assert!(session.process.job_handle.is_none());

    /* SAFETY: This duplicate keeps the exact process object alive after cleanup.
     * A zero-duration query is an assertion, not a polling or timing wait. */
    assert_eq!(
        unsafe { WaitForSingleObject(completion.raw(), 0) },
        WAIT_OBJECT_0
    );
    completion.close()?;
    Ok(())
}
