#![cfg(any(unix, windows))]

use serde_json::Value;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Output, Stdio};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::{Child, Command};
use tokio::time::timeout;

const CLI_TIMEOUT: Duration = Duration::from_secs(120);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(10);

fn output(command: &mut Command) -> io::Result<Output> {
    let invocation = format!("{command:?}");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    runtime
        .block_on(async {
            let mut child = command
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .kill_on_drop(true)
                .spawn()?;

            wait_for_output(&mut child, CLI_TIMEOUT).await
        })
        .map_err(|error| io::Error::new(error.kind(), format!("{invocation}: {error}")))
}

async fn drain(reader: &mut (impl AsyncRead + Unpin), bytes: &mut Vec<u8>) -> io::Result<()> {
    loop {
        let count = reader.read_buf(bytes).await?;

        if count == 0 {
            return Ok(());
        }
    }
}

async fn wait_for_output(child: &mut Child, limit: Duration) -> io::Result<Output> {
    let mut stdout_pipe = child.stdout.take().expect("piped stdout");
    let mut stderr_pipe = child.stderr.take().expect("piped stderr");
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    // These futures borrow the child and buffers; cancellation loses neither.
    let completion = timeout(limit, async {
        tokio::try_join!(
            child.wait(),
            drain(&mut stdout_pipe, &mut stdout),
            drain(&mut stderr_pipe, &mut stderr),
        )
    })
    .await;

    let error = match completion {
        Ok(Ok((status, (), ()))) => {
            return Ok(Output {
                status,
                stdout,
                stderr,
            });
        }
        Ok(Err(error)) => error,
        Err(_) => io::Error::new(
            io::ErrorKind::TimedOut,
            format!("child completion exceeded {limit:?}"),
        ),
    };

    // Only this child is terminated. Inherited pipes must not extend cleanup
    // indefinitely, and no reader task or thread survives this scope.
    let kill = child.start_kill();
    let mut reaped = None;
    let cleanup = timeout(CLEANUP_TIMEOUT, async {
        tokio::join!(
            async {
                reaped = Some(child.wait().await);
            },
            drain(&mut stdout_pipe, &mut stdout),
            drain(&mut stderr_pipe, &mut stderr),
        )
    })
    .await;

    Err(io::Error::new(
        error.kind(),
        format!(
            "{error}; kill={kill:?}; reap={reaped:?}; cleanup={cleanup:?}; stdout={}; stderr={}",
            String::from_utf8_lossy(&stdout),
            String::from_utf8_lossy(&stderr),
        ),
    ))
}

#[cfg(unix)]
#[tokio::test]
async fn timeout_reaps_owned_child_and_retains_stderr() {
    let mut child = Command::new("/bin/sh")
        .args([
            "-c",
            "printf CLI_TIMEOUT_STDERR >&2; printf R; read -r ignored",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();

    // Keep stdin open outside Child so wait() cannot release the read gate.
    let input = child.stdin.take().unwrap();
    let mut ready = [0];
    let readiness = timeout(
        CLI_TIMEOUT,
        child.stdout.as_mut().unwrap().read_exact(&mut ready),
    )
    .await;

    // The shell cannot finish while its stdin gate remains open. An expired
    // deadline tests cancellation without a race against a fast child exit.
    let result = wait_for_output(&mut child, Duration::ZERO).await;
    drop(input);

    readiness.unwrap().unwrap();
    assert_eq!(ready, *b"R");

    let error = result.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert!(error.to_string().contains("CLI_TIMEOUT_STDERR"));
    assert!(child.id().is_none(), "timeout returned before reaping");
    assert!(!child.try_wait().unwrap().unwrap().success());
}

fn command(output: &Path, format: &str) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_rusty_sand"));
    command
        .args([
            "--plain",
            "--no-interactive",
            "--format",
            format,
            "--output",
        ])
        .arg(output)
        .env_remove("RUSTY_SAND_STDIN_CONTROL");

    command
}

fn json(path: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "status={:?}; stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(output.stdout.is_empty());
}

#[cfg(windows)]
fn command_processor() -> PathBuf {
    std::env::var_os("COMSPEC")
        .map(PathBuf::from)
        .expect("Windows command processor")
}

fn executable_fixture(directory: &Path) -> (PathBuf, Vec<String>, PathBuf) {
    let marker = directory.join("executed");

    #[cfg(unix)]
    let (target, arguments) = {
        use std::os::unix::fs::PermissionsExt;

        let target = directory.join("target.sh");
        std::fs::write(&target, b"#!/bin/sh\nprintf executed > \"$1\"\n").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o700)).unwrap();

        (target, vec![marker.to_str().unwrap().to_owned()])
    };

    #[cfg(windows)]
    let (target, arguments) = (
        command_processor(),
        vec![
            "/D".into(),
            "/C".into(),
            format!("echo executed > \"{}\"", marker.display()),
        ],
    );

    (target, arguments, marker)
}

#[test]
fn static_inspection_never_executes_input_and_honors_all_formats() {
    let directory = tempfile::tempdir().unwrap();
    let (target, arguments, marker) = executable_fixture(directory.path());
    let original = std::fs::read(&target).unwrap();

    for format in ["console", "json", "both"] {
        let output_dir = directory.path().join(format);
        let output = output(
            command(&output_dir, format)
                .arg("--static")
                .arg(&target)
                .arg("--")
                .args(&arguments),
        )
        .unwrap();

        assert_success(&output);
        assert!(!marker.exists(), "static inspection executed its input");
        assert_eq!(std::fs::read(&target).unwrap(), original);
        assert!(!output_dir.join("report.json").exists());
        assert!(!output_dir.join("debug.json").exists());

        if format == "console" {
            assert!(!output_dir.join("analysis.json").exists());
            assert!(!output.stderr.is_empty());
        } else {
            let value = json(&output_dir.join("analysis.json"));

            assert_eq!(value["mode"], "static");
            assert_eq!(value["execution"]["status"], "not_requested");
            assert_eq!(value["static_analysis"]["status"], "collected");
            assert_eq!(
                value["static_analysis"]["report"]["size_bytes"],
                original.len()
            );
            assert_eq!(value["behavior"]["status"], "unavailable");
            assert!(value["events"].as_array().unwrap().is_empty());

            if format == "json" {
                assert!(output.stderr.is_empty());
            } else {
                assert!(!output.stderr.is_empty());
            }
        }
    }
}

#[test]
fn failed_static_inspection_returns_failure_and_parseable_artifacts() {
    let directory = tempfile::tempdir().unwrap();
    let missing = directory.path().join("missing.exe");

    for (index, target) in [missing.as_path(), directory.path()]
        .into_iter()
        .enumerate()
    {
        let output_dir = directory.path().join(format!("failure-{index}"));
        let output = output(command(&output_dir, "json").arg("--static").arg(target)).unwrap();

        assert!(!output.status.success());
        assert!(output.stdout.is_empty());

        let value = json(&output_dir.join("analysis.json"));

        assert_eq!(value["execution"]["status"], "not_requested");
        assert_eq!(value["static_analysis"]["status"], "failed");
        assert!(value["static_analysis"].get("report").is_none());
        assert!(!output_dir.join("report.json").exists());
        assert!(!output_dir.join("debug.json").exists());
    }
}

#[test]
fn malformed_pe_is_explicitly_partial_not_an_execution_failure() {
    let directory = tempfile::tempdir().unwrap();
    let target = directory.path().join("malformed.exe");
    let output_dir = directory.path().join("output");
    std::fs::write(&target, b"MZ").unwrap();

    let output = output(command(&output_dir, "json").arg("--static").arg(&target)).unwrap();

    assert_success(&output);

    let value = json(&output_dir.join("analysis.json"));

    assert_eq!(value["execution"]["status"], "not_requested");
    assert_eq!(value["static_analysis"]["status"], "collected");
    assert_eq!(
        value["static_analysis"]["report"]["coverage"]["pe_status"],
        "malformed"
    );
    assert!(value["static_analysis"]["report"]["pe"].is_null());
}

#[cfg(not(windows))]
#[test]
fn execution_modes_do_not_silently_fall_back_to_static_inspection() {
    let directory = tempfile::tempdir().unwrap();
    let (target, arguments, marker) = executable_fixture(directory.path());

    for mode in [None, Some("--debug"), Some("--shell")] {
        let output_dir = directory.path().join(mode.unwrap_or("execute"));
        let mut invocation = command(&output_dir, "json");

        if let Some(mode) = mode {
            invocation.arg(mode);
        }

        let output = output(invocation.arg(&target).arg("--").args(&arguments)).unwrap();

        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(!marker.exists());
        assert!(!output_dir.join("analysis.json").exists());
    }
}

#[cfg(windows)]
#[test]
fn native_debug_mode_writes_debug_events_without_an_ordinary_report() {
    let directory = tempfile::tempdir().unwrap();
    let output = output(
        command(directory.path(), "json")
            .arg("--debug")
            .arg(command_processor())
            .args(["--", "/D", "/C", "exit", "/B", "7"]),
    )
    .unwrap();

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());

    let debug = json(&directory.path().join("debug.json"));
    let analysis = json(&directory.path().join("analysis.json"));

    assert_eq!(debug["status"], "collected");
    assert_eq!(debug["report"]["exit"]["kind"], "exited");
    assert_eq!(debug["report"]["exit"]["code"], 7);
    assert!(!debug["report"]["events"].as_array().unwrap().is_empty());
    assert_eq!(analysis["mode"], "debug");
    assert_eq!(analysis["execution"]["status"], "exited");
    assert_eq!(analysis["execution"]["code"], 7);
    assert_eq!(analysis["requested_config"]["enable_api_hooks"], false);
    assert_eq!(analysis["behavior"]["status"], "unavailable");
    assert!(!directory.path().join("report.json").exists());
}

#[cfg(windows)]
#[test]
fn failed_execution_keeps_static_evidence_without_claiming_success() {
    let directory = tempfile::tempdir().unwrap();
    let target = directory.path().join("not-an-executable.exe");
    let output_dir = directory.path().join("output");
    std::fs::write(&target, b"benign non-executable fixture").unwrap();

    let output = output(
        command(&output_dir, "json")
            .arg("--restricted")
            .arg(&target),
    )
    .unwrap();

    assert!(!output.status.success());

    let analysis = json(&output_dir.join("analysis.json"));

    assert_eq!(analysis["mode"], "execute");
    assert_eq!(analysis["execution"]["status"], "failed");
    assert_eq!(analysis["static_analysis"]["status"], "collected");
    assert_eq!(analysis["behavior"]["status"], "unavailable");
    assert_eq!(analysis["requested_config"]["restricted_token"], true);
    assert!(!output_dir.join("report.json").exists());
}
