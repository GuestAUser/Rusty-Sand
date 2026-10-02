use super::*;
use std::future::{poll_fn, Future};
use std::task::Poll;

#[tokio::test]
async fn shell_collects_completion_without_rearming_or_losing_the_answer() -> Result<()> {
    let _ui = UI_LOCK.lock().await;
    let fixture = Fixture::new()?;
    let mut session = fixture.session()?;
    session.run().await?;
    fixture.running(&session).await?;

    let mut state = session.subscribe().context("missing state subscription")?;
    let (read, write_end) = pipe()?;
    let mut input = ConsoleInput::from_handle(read.raw())?;
    let (send, mut ready) = mpsc::channel(1);
    let mut shell = Shell {
        session,
        armed: Some(send),
    };
    let mut answer = Box::pin(shell.read_command(&mut input));

    /*
     * Poll once to arm the actual reader, then trigger target completion.
     * No readiness delay or alternate input implementation is involved.
     */
    poll_fn(|context| {
        assert!(answer.as_mut().poll(context).is_pending());
        Poll::Ready(())
    })
    .await;
    armed(&mut ready).await?;

    write(&write_end, b"sta")?;
    fixture.release()?;

    tokio::time::timeout(
        Duration::from_secs(10),
        state.wait_for(|state| state.is_finished()),
    )
    .await??;

    /*
     * A poll processes the already-published completion and joins the worker.
     * It must remain pending on the same partially entered command.
     */
    poll_fn(|context| {
        assert!(answer.as_mut().poll(context).is_pending());
        Poll::Ready(())
    })
    .await;

    write(&write_end, b"tus\n")?;
    let line = tokio::time::timeout(Duration::from_secs(5), &mut answer).await??;
    assert_eq!(line.as_deref(), Some("status"));
    drop(answer);

    assert!(!shell.session.has_active_run());
    assert!(shell.session.completed_report().is_some());
    assert!(matches!(
        ready.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));

    input.close()?;
    Ok(())
}

#[tokio::test]
async fn shell_line_read_handles_termination_without_the_outer_status_select() -> Result<()> {
    let _ui = UI_LOCK.lock().await;

    for end in [End::Eof, End::Cancel, End::InvalidUtf8] {
        let executable = std::env::current_exe()?;
        let session = LiveSession::new(
            executable
                .to_str()
                .context("test executable path is not Unicode")?,
            &[],
            SandboxConfig::default(),
        )?;
        let (read, mut write_end) = pipe()?;
        let original_mode = mode(&read)?;
        let mut input = ConsoleInput::from_handle(read.raw())?;
        let status = input.status();
        let mut shell = Shell {
            session,
            armed: None,
        };
        let mut answer = Box::pin(shell.read_command(&mut input));

        /*
         * Arm the real reader before triggering its termination. Deliberately
         * omit serve's outer status select: the line-read path must independently
         * distinguish clean termination from the worker's actual failure.
         */
        poll_fn(|context| {
            assert!(answer.as_mut().poll(context).is_pending());
            Poll::Ready(())
        })
        .await;

        match end {
            End::Eof => write_end.close()?,
            End::Cancel => write(&write_end, b"\x03")?,
            End::InvalidUtf8 => write(&write_end, b"\xff")?,
            End::Quit => unreachable!(),
        }

        let result = tokio::time::timeout(Duration::from_secs(5), &mut answer).await?;
        drop(answer);

        match end {
            End::Eof => {
                assert_eq!(result?, None);
                assert!(matches!(status.borrow().as_ref(), Some(InputEnd::Eof)));
                input.close()?;
            }
            End::Cancel => {
                assert_eq!(result?, None);
                assert!(matches!(
                    status.borrow().as_ref(),
                    Some(InputEnd::Cancelled)
                ));
                input.close()?;
            }
            End::InvalidUtf8 => {
                assert!(result.is_err());
                assert!(matches!(
                    status.borrow().as_ref(),
                    Some(InputEnd::Failed(_))
                ));
                assert!(input.close().is_err());
            }
            End::Quit => unreachable!(),
        }

        assert_eq!(mode(&read)?, original_mode);
        assert!(!shell.session.has_active_run());
    }

    Ok(())
}
