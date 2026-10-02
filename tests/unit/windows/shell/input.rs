use super::*;
use crate::live::shell_tests::fixture::{process_completion, Fixture, UI_LOCK};
use crate::live::RunState;
use crate::monitor::input::InputEnd;
use crate::sandbox::resource::OwnedHandle;
use command::Command;
use std::time::Duration;
use tokio::sync::mpsc;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Storage::FileSystem::WriteFile;
use windows::Win32::System::Pipes::{CreatePipe, GetNamedPipeHandleStateW, NAMED_PIPE_MODE};

#[path = "completion.rs"]
mod completion;

fn pipe() -> Result<(OwnedHandle, OwnedHandle)> {
    let mut read = HANDLE::default();
    let mut write = HANDLE::default();

    /* SAFETY: Both output handles immediately receive checked ownership. */
    unsafe { CreatePipe(&mut read, &mut write, None, 4096) }?;
    Ok((OwnedHandle::new(read), OwnedHandle::new(write)))
}

fn write(handle: &OwnedHandle, bytes: &[u8]) -> Result<()> {
    let mut written = 0;

    /* SAFETY: The bounded test message fits the empty pipe buffer and its
    bytes outlive this synchronous write. */
    unsafe { WriteFile(handle.raw(), Some(bytes), Some(&mut written), None) }?;

    assert_eq!(written as usize, bytes.len());
    Ok(())
}

fn mode(handle: &OwnedHandle) -> Result<NAMED_PIPE_MODE> {
    let mut mode = NAMED_PIPE_MODE::default();

    /* SAFETY: The test retains the pipe and writable output storage. */
    unsafe { GetNamedPipeHandleStateW(handle.raw(), Some(&mut mode), None, None, None, None) }
        .ok()?;

    Ok(mode)
}

async fn armed(ready: &mut mpsc::Receiver<()>) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(10), ready.recv())
        .await
        .context("shell did not arm its next input request")?
        .context("shell readiness channel closed")
}

#[tokio::test]
async fn shell_commands_remain_responsive_then_stop_report_and_quit() -> Result<()> {
    let _ui = UI_LOCK.lock().await;
    let fixture = Fixture::new()?;
    let mut session = fixture.session()?;
    session.run().await?;
    fixture.running(&session).await?;

    let mut completion = process_completion(&session)?;
    let (read, write_end) = pipe()?;
    let original_mode = mode(&read)?;
    let mut input = ConsoleInput::from_handle(read.raw())?;
    let (send, mut ready) = mpsc::channel(1);
    let mut shell = Shell {
        session,
        armed: Some(send),
    };

    let driver = async {
        /*
         * Each next-prompt signal proves that the previous command completed
         * while the target's release event remains unsignaled.
         */
        for command in [
            b"status\n".as_slice(),
            b"events 1\n",
            b"run\n",
            b"attach 1\n",
            b"help\n",
            b"stop\n",
            b"report\n",
            b"quit\n",
        ] {
            armed(&mut ready).await?;
            write(&write_end, command)?;
        }

        Ok::<(), anyhow::Error>(())
    };

    let (served, driven) = tokio::time::timeout(Duration::from_secs(20), async {
        tokio::join!(shell.serve(&mut input), driver)
    })
    .await?;

    served?;
    driven?;
    tokio::time::timeout(Duration::from_secs(5), completion.wait()).await??;
    completion.close()?;

    assert_eq!(mode(&read)?, original_mode);
    assert_eq!(shell.session.state(), RunState::Completed);
    assert!(!shell.session.has_active_run());

    let artifacts = std::fs::read_dir(fixture.output())?.collect::<std::io::Result<Vec<_>>>()?;
    assert_eq!(artifacts.len(), 1);

    let saved: serde_json::Value = serde_json::from_slice(&std::fs::read(artifacts[0].path())?)?;
    let report = shell
        .session
        .completed_report()
        .context("shell lost completed report")?;

    assert_eq!(saved["report"], serde_json::to_value(report)?);
    assert_eq!(
        saved["assessment"],
        serde_json::to_value(crate::behavior::assessment::assess_events(&report.events))?,
    );

    Ok(())
}

#[derive(Clone, Copy)]
enum End {
    Quit,
    Eof,
    Cancel,
    InvalidUtf8,
}

#[tokio::test]
async fn shell_quit_eof_cancel_and_error_stop_join_and_close_reader() -> Result<()> {
    let _ui = UI_LOCK.lock().await;

    for end in [End::Quit, End::Eof, End::Cancel, End::InvalidUtf8] {
        let fixture = Fixture::new()?;
        let mut session = fixture.session()?;
        session.run().await?;
        fixture.running(&session).await?;

        let mut completion = process_completion(&session)?;
        let (read, mut write_end) = pipe()?;
        let original_mode = mode(&read)?;
        let mut input = ConsoleInput::from_handle(read.raw())?;
        let mut input_status = input.status();
        let (send, mut ready) = mpsc::channel(1);
        let mut shell = Shell {
            session,
            armed: Some(send),
        };

        let driver = async {
            armed(&mut ready).await?;

            match end {
                End::Quit => write(&write_end, b"quit\n"),
                End::Eof => write_end.close(),
                End::Cancel => write(&write_end, b"\x03"),
                End::InvalidUtf8 => write(&write_end, b"\xff"),
            }
        };

        let (served, driven) = tokio::time::timeout(Duration::from_secs(20), async {
            tokio::join!(shell.serve(&mut input), driver)
        })
        .await?;

        driven?;

        if matches!(end, End::InvalidUtf8) {
            assert!(served.is_err());
        } else {
            served?;
        }

        tokio::time::timeout(Duration::from_secs(5), completion.wait()).await??;
        completion.close()?;
        tokio::time::timeout(
            Duration::from_secs(5),
            input_status.wait_for(|end| end.is_some()),
        )
        .await??;

        assert_eq!(mode(&read)?, original_mode);
        assert!(!shell.session.has_active_run());
        assert!(shell.session.completed_report().is_some());

        match (&end, input_status.borrow().as_ref()) {
            (End::Eof, Some(InputEnd::Eof))
            | (End::Quit | End::Cancel, Some(InputEnd::Cancelled))
            | (End::InvalidUtf8, Some(InputEnd::Failed(_))) => {}
            _ => panic!("input worker published the wrong completion state"),
        }

        input.close()?;
    }

    Ok(())
}

#[tokio::test]
async fn shell_dispatch_run_returns_while_the_target_is_active() -> Result<()> {
    let _ui = UI_LOCK.lock().await;
    let fixture = Fixture::new()?;
    let mut shell = Shell {
        session: fixture.session()?,
        armed: None,
    };

    tokio::time::timeout(Duration::from_secs(10), shell.dispatch(Command::Run)).await??;
    fixture.running(&shell.session).await?;

    let status = shell
        .dispatch(Command::Status)
        .await?
        .context("status returned quit")?;
    let status: serde_json::Value = serde_json::from_str(&status)?;
    assert_eq!(status["state"], serde_json::to_value(RunState::Running)?);
    assert!(status["pid"].as_u64().is_some());

    let events = shell
        .dispatch(Command::Events(100))
        .await?
        .context("events returned quit")?;
    let events: Vec<crate::report::Event> = serde_json::from_str(&events)?;
    assert!(events
        .iter()
        .any(|event| event.event_type == crate::report::EventType::SandboxStarted));

    assert!(shell.dispatch(Command::Run).await.is_err());
    assert_eq!(shell.session.state(), RunState::Running);

    shell.dispatch(Command::Stop).await?;
    assert!(shell.session.completed_report().is_some());
    Ok(())
}
