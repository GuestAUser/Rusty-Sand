use super::*;
use std::time::Duration;
use windows::Win32::Storage::FileSystem::WriteFile;
use windows::Win32::System::Pipes::{
    CreatePipe, GetNamedPipeHandleStateW, NAMED_PIPE_MODE, PIPE_NOWAIT,
};

fn pipe() -> Result<(OwnedHandle, OwnedHandle)> {
    let mut read = HANDLE::default();
    let mut write = HANDLE::default();
    /* SAFETY: Both handle outputs are immediately owned, with no inheritance. */
    unsafe { CreatePipe(&mut read, &mut write, None, 4096) }?;
    Ok((OwnedHandle::new(read), OwnedHandle::new(write)))
}

fn write(handle: &OwnedHandle, bytes: &[u8]) -> Result<()> {
    let mut count = 0;
    /* Test messages fit the empty pipe buffer and never need timing delays. */
    unsafe { WriteFile(handle.raw(), Some(bytes), Some(&mut count), None) }?;
    assert_eq!(count as usize, bytes.len());
    Ok(())
}

fn mode(handle: &OwnedHandle) -> Result<NAMED_PIPE_MODE> {
    let mut mode = NAMED_PIPE_MODE::default();
    unsafe { GetNamedPipeHandleStateW(handle.raw(), Some(&mut mode), None, None, None, None) }
        .ok()?;
    Ok(mode)
}

fn arm(input: &ConsoleInput) -> Result<oneshot::Receiver<Result<String>>> {
    let (reply, response) = oneshot::channel();
    let (armed, ready) = mpsc::channel();
    input.queue_request(Request {
        boundary: 0,
        ready: Arc::new(AtomicBool::new(true)),
        reply,
        armed: Some(armed),
    })?;
    ready
        .recv_timeout(Duration::from_secs(5))
        .context("input request did not arm")?;
    Ok(response)
}

async fn ended(status: &mut watch::Receiver<Option<InputEnd>>) -> Result<InputEnd> {
    tokio::time::timeout(Duration::from_secs(5), status.wait_for(|end| end.is_some()))
        .await
        .context("input did not publish completion")?
        .map(|end| end.as_ref().unwrap().clone())
        .context("input status sender disappeared")
}

async fn answer(response: oneshot::Receiver<Result<String>>) -> Result<String> {
    tokio::time::timeout(Duration::from_secs(5), response)
        .await
        .context("input answer did not complete")?
        .context("input answer sender disappeared")?
}

#[tokio::test]
async fn idle_pipe_eof_is_observable_and_joinable() -> Result<()> {
    let (read, mut write) = pipe()?;
    let mut input = ConsoleInput::from_handle(read.raw())?;
    let mut status = input.status();
    write.close()?;
    assert!(matches!(ended(&mut status).await?, InputEnd::Eof));
    input.close()?;
    input.close()?;
    Ok(())
}

#[tokio::test]
async fn idle_cancellation_joins_and_restores_shared_pipe_mode() -> Result<()> {
    let (read, _write) = pipe()?;
    let original = mode(&read)?;
    let mut input = ConsoleInput::from_handle(read.raw())?;
    let mut status = input.status();
    assert_ne!(mode(&read)?.0 & PIPE_NOWAIT.0, 0);
    input.close()?;
    assert!(matches!(ended(&mut status).await?, InputEnd::Cancelled));
    assert_eq!(mode(&read)?, original);
    Ok(())
}

#[tokio::test]
async fn empty_open_pipe_is_not_eof_and_accepts_fragmented_utf8() -> Result<()> {
    let (read, write_end) = pipe()?;
    let mut input = ConsoleInput::from_handle(read.raw())?;
    let response = arm(&input)?;
    assert!(input.status().borrow().is_none());
    for byte in "Y\u{1f600}\r\n".as_bytes() {
        write(&write_end, &[*byte])?;
    }
    assert_eq!(answer(response).await?, "Y\u{1f600}");
    input.close()?;
    Ok(())
}

#[tokio::test]
async fn read_line_arms_before_returning_its_future() -> Result<()> {
    let (read, write_end) = pipe()?;
    let mut input = ConsoleInput::from_handle(read.raw())?;
    let response = input.read_line();

    // Rendering the prompt belongs here: the future is not polled yet, but a
    // response must already be owned by this request rather than discarded.
    write(&write_end, b"Y\n")?;
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), response).await??,
        "Y"
    );
    input.close()?;
    Ok(())
}

#[tokio::test]
async fn input_after_queueing_is_retained_without_waiting_for_worker_readiness() -> Result<()> {
    let (read, write_end) = pipe()?;
    let mut input = ConsoleInput::from_handle(read.raw())?;
    let (reply, response) = oneshot::channel();
    {
        /*
         * Hold the reader's boundary until the answer is buffered, modeling a
         * worker not yet scheduled. Release it before awaiting the response.
         */
        let cursor = input
            .cursor
            .lock()
            .map_err(|_| anyhow!("input cursor poisoned"))?;
        input.requests.try_send(Request {
            boundary: *cursor + u64::from(input.backend.available()?),
            ready: Arc::new(AtomicBool::new(true)),
            reply,
            armed: None,
        })?;
        write(&write_end, b"Y\n")?;
        unsafe { SetEvent(input.request.raw()) }?;
    }
    assert_eq!(answer(response).await?, "Y");
    input.close()?;
    Ok(())
}

#[tokio::test]
async fn prequeued_answers_do_not_approve_a_future_prompt() -> Result<()> {
    let (read, write_end) = pipe()?;
    write(&write_end, b"Y\r\nY\n")?;
    let mut input = ConsoleInput::from_handle(read.raw())?;
    let response = arm(&input)?;
    write(&write_end, b"N\n")?;
    assert_eq!(answer(response).await?, "N");
    input.close()?;
    Ok(())
}

#[tokio::test]
async fn unsolicited_partial_line_is_discarded_through_its_terminator() -> Result<()> {
    let (read, write_end) = pipe()?;
    write(&write_end, b"Y")?;
    let mut input = ConsoleInput::from_handle(read.raw())?;
    let response = arm(&input)?;
    write(&write_end, b"\nN\n")?;
    assert_eq!(answer(response).await?, "N");
    input.close()?;
    Ok(())
}

#[tokio::test]
async fn cancelled_prompt_cannot_lend_queued_input_to_the_next_prompt() -> Result<()> {
    let (read, write_end) = pipe()?;
    let mut input = ConsoleInput::from_handle(read.raw())?;
    let abandoned = arm(&input)?;
    drop(abandoned);
    write(&write_end, b"Y\n")?;
    let response = arm(&input)?;
    write(&write_end, b"N\n")?;
    assert_eq!(answer(response).await?, "N");
    input.close()?;
    Ok(())
}

#[tokio::test]
async fn outstanding_prompt_cancellation_and_deadline_can_join() -> Result<()> {
    let (read, _write) = pipe()?;
    let mut input = ConsoleInput::from_handle(read.raw())?;
    let response = arm(&input)?;
    let mut status = input.status();
    // Dropping the receiver models a deadline's select branch cancelling input.
    drop(response);
    input.close()?;
    assert!(matches!(ended(&mut status).await?, InputEnd::Cancelled));
    Ok(())
}

#[tokio::test]
async fn invalid_utf8_overflow_and_incomplete_eof_fail_closed() -> Result<()> {
    for bytes in [vec![0xff], vec![b'Y'; 65], vec![0xf0, 0x9f], b"Y".to_vec()] {
        let (read, mut write_end) = pipe()?;
        let mut input = ConsoleInput::from_handle(read.raw())?;
        let mut status = input.status();
        let response = arm(&input)?;
        write(&write_end, &bytes)?;
        write_end.close()?;
        let end = ended(&mut status).await?;
        assert!(matches!(end, InputEnd::Failed(message) if !message.is_empty()));
        assert!(answer(response).await.is_err());
        assert!(input.close().is_err());
    }
    Ok(())
}

#[test]
fn native_unicode_backspace_removes_one_scalar_not_one_surrogate() -> Result<()> {
    let mut line = Line::default();
    assert!(matches!(line.unit('Y' as u16)?, Some(Edit::Append('Y'))));
    assert!(line.unit(0xd83d)?.is_none());
    assert!(matches!(
        line.unit(0xde00)?,
        Some(Edit::Append('\u{1f600}'))
    ));
    assert!(matches!(line.unit(8)?, Some(Edit::Backspace)));
    assert!(matches!(line.unit(13)?, Some(Edit::Line(text)) if text == "Y"));
    assert!(line.unit(10)?.is_none());
    Ok(())
}

#[test]
fn incomplete_native_surrogates_never_echo_replacement_characters() -> Result<()> {
    let mut line = Line::default();
    assert!(line.unit(0xd83d)?.is_none());
    assert!(line.unit(8)?.is_none());
    assert!(matches!(line.unit(13)?, Some(Edit::Line(text)) if text.is_empty()));
    assert!(line.unit(0xde00).is_err());
    let mut line = Line::default();
    line.unit(0xd83d)?;
    assert!(line.unit(13).is_err());
    Ok(())
}

#[test]
fn limit_counts_utf16_units_for_both_transports() -> Result<()> {
    for pipe in [false, true] {
        let mut line = Line::default();
        if pipe {
            for byte in "\u{1f600}".repeat(32).bytes() {
                line.byte(byte)?;
            }
            assert!(line.byte(b'Y').is_err());
        } else {
            for _ in 0..32 {
                line.unit(0xd83d)?;
                line.unit(0xde00)?;
            }
            assert!(line.unit('Y' as u16).is_err());
        }
    }
    Ok(())
}

#[test]
fn pipe_decoder_preserves_crlf_and_scalar_backspace() -> Result<()> {
    let mut line = Line::default();
    let mut answers = Vec::new();
    for byte in "Y\u{1f600}\u{7f}\r\nN\n".bytes() {
        if let Some(Edit::Line(answer)) = line.byte(byte)? {
            answers.push(answer);
        }
    }
    assert_eq!(answers, ["Y", "N"]);
    line.end()?;
    Ok(())
}

#[tokio::test]
async fn dropping_an_unpolled_answer_releases_the_input_gate() -> Result<()> {
    let (read, mut write_end) = pipe()?;
    let mut input = ConsoleInput::from_handle(read.raw())?;
    let mut status = input.status();
    let response = input.read_line();
    drop(response);
    write_end.close()?;

    assert!(matches!(ended(&mut status).await?, InputEnd::Eof));
    input.close()?;
    Ok(())
}

/** This is also the explicit child entry point used by the WSL launcher probe.
Without the child flag, the ordinary test run exercises the same code through an
owned Windows anonymous pipe. Neither role skips or substitutes the real reader. */
#[tokio::test]
async fn real_prompt_ordering() -> Result<()> {
    use crate::sandbox::wait::HandleWait;
    use std::io::BufRead;
    use std::os::windows::io::{AsRawHandle, FromRawHandle};
    use std::process::{Command, Stdio};

    if std::env::var_os("RUSTY_SAND_TEST_PROMPT_CHILD").is_some() {
        return prompt_child().await;
    }

    // Rust's Stdio::piped read handle lacks FILE_WRITE_ATTRIBUTES. CreatePipe
    // retains the mode-setting access required by this explicit transport.
    let (read, mut input_write) = pipe()?;
    let stdin =
        unsafe { std::os::windows::io::OwnedHandle::from_raw_handle(read.into_raw().0 as _) };
    let mut child = Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            "monitor::input::tests::real_prompt_ordering",
            "--nocapture",
        ])
        .env("RUSTY_SAND_TEST_PROMPT_CHILD", "1")
        .stdin(Stdio::from(stdin))
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()?;
    let stdout = child.stdout.take().context("fixture stdout unavailable")?;
    let (lines, mut received) = tokio::sync::mpsc::unbounded_channel();
    let reader = std::thread::spawn(move || {
        for line in std::io::BufReader::new(stdout).lines() {
            if lines.send(line).is_err() {
                break;
            }
        }
    });
    let mut completion = HandleWait::new(HANDLE(child.as_raw_handle() as isize))?;
    let result = async {
        let mut answers = 0;
        let mut completed = false;
        while let Some(line) = received.recv().await {
            let line = line?;
            if line == "RS_INPUT_ARMED" {
                write(&input_write, b"Y\n")?;
                answers += 1;
            }
            if line == "RS_CMD_EXIT=0" {
                completed = true;
            }
        }
        completion.wait().await?;
        assert_eq!(answers, 1);
        assert!(completed);
        assert!(child.wait()?.success());
        Ok(())
    };
    let result: Result<()> = match tokio::time::timeout(Duration::from_secs(10), result).await {
        Ok(result) => result,
        Err(error) => Err(error).context("prompt-ordering child exceeded its bound"),
    };

    // EOF releases the real reader even if an assertion path failed. The child
    // bounds its own answer wait; there is no timeout kill of a target host.
    input_write.close()?;
    child.wait()?;
    reader
        .join()
        .map_err(|_| anyhow!("fixture output reader panicked"))?;
    with_cleanup(result, completion.close())
}

async fn prompt_child() -> Result<()> {
    use crate::config::SandboxConfig;
    use crate::sandbox::process::create_sandboxed_process;
    use crate::sandbox::wait::HandleWait;
    use crate::ui::{ColorMode, OutputPolicy, Panel, PromptEnd, Tone};
    use std::io::Write;

    crate::ui::configure(OutputPolicy {
        color: ColorMode::Never,
        plain: true,
        reduced_motion: true,
        tty: false,
        columns: 80,
    })?;
    let executable = format!("{}\\System32\\cmd.exe", std::env::var("SystemRoot")?);
    let config = SandboxConfig {
        interactive_mode: true,
        enable_api_hooks: false,
        working_dir: Some(std::path::PathBuf::from(std::env::var("SystemRoot")?)),
        ..SandboxConfig::default()
    };
    let mut process = create_sandboxed_process(
        &executable,
        &["/D".into(), "/C".into(), "exit 0".into()],
        &config,
    )?;
    let mut input = ConsoleInput::new()?;

    // The ordering is the behavior under test: reserve input, render the real
    // panel, publish a machine synchronization token, then poll the answer.
    let answer = input.read_line();
    let prompt = crate::ui::terminal().begin_prompt(&Panel {
        title: "Benign cmd fixture startup".into(),
        tone: Tone::Warning,
        fields: vec![("Executable".into(), executable)],
        notes: vec!["Allow startup? [Y/N]".into()],
    })?;
    println!("RS_INPUT_ARMED");
    std::io::stdout().flush()?;
    let answer = tokio::time::timeout(Duration::from_secs(5), answer).await??;
    assert_eq!(answer, "Y");
    prompt.finish(PromptEnd::Answered)?;

    let mut completion = HandleWait::new(process.process_handle)?;
    process.resume_initial_thread()?;
    tokio::time::timeout(Duration::from_secs(5), completion.wait()).await??;
    assert_eq!(process.exit_code()?, Some(0));
    completion.close()?;
    process.close()?;
    input.close()?;
    println!("RS_CMD_EXIT=0");
    Ok(())
}
