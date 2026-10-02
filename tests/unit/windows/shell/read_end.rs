use super::*;
use std::future::{poll_fn, Future};
use std::io::{Error, ErrorKind};
use std::task::Poll;
use std::time::Duration;

#[tokio::test]
async fn shell_reply_closure_after_status_poll_waits_for_publication() -> Result<()> {
    for end in [
        InputEnd::Eof,
        InputEnd::Cancelled,
        InputEnd::Failed("native-input-failure".into()),
    ] {
        let (reply, mut receive) = oneshot::channel::<Result<String>>();
        let (publish, mut status) = watch::channel(None);
        let mut outer_status = status.clone();
        let mut read = Box::pin(async {
            tokio::select! {
                biased;
                result = line_ended(&mut outer_status) => result,
                result = async {
                    /*
                     * Force the reported interleaving: the first branch has
                     * already polled status as pending before the reply closes.
                     * The publisher remains alive but has not sent its reason.
                     */
                    drop(reply);
                    receive_line(&mut receive, &mut status).await
                } => result,
            }
        });

        poll_fn(|context| {
            assert!(read.as_mut().poll(context).is_pending());
            Poll::Ready(())
        })
        .await;

        publish.send_replace(Some(end.clone()));
        let result = tokio::time::timeout(Duration::from_secs(5), read).await??;

        match (end, result) {
            (InputEnd::Eof, LineRead::End(InputEnd::Eof))
            | (InputEnd::Cancelled, LineRead::End(InputEnd::Cancelled)) => {}
            (InputEnd::Failed(expected), LineRead::End(InputEnd::Failed(actual))) => {
                assert_eq!(actual, expected);
            }
            _ => panic!("line read did not preserve the published termination reason"),
        }
    }

    Ok(())
}

#[tokio::test]
async fn shell_missing_termination_publication_remains_an_error() -> Result<()> {
    let (reply, mut receive) = oneshot::channel::<Result<String>>();
    let (publish, mut status) = watch::channel(None);

    drop(reply);
    drop(publish);

    let result = tokio::time::timeout(
        Duration::from_secs(5),
        receive_line(&mut receive, &mut status),
    )
    .await?;

    assert!(result.is_err());
    Ok(())
}

#[tokio::test]
async fn shell_explicit_line_failure_is_not_reclassified_as_clean_eof() -> Result<()> {
    let (reply, mut receive) = oneshot::channel::<Result<String>>();
    let (_publish, mut status) = watch::channel(Some(InputEnd::Eof));

    assert!(reply
        .send(Err(Error::new(ErrorKind::InvalidData, "fixture").into()))
        .is_ok());

    let result = tokio::time::timeout(
        Duration::from_secs(5),
        receive_line(&mut receive, &mut status),
    )
    .await?;
    let error = result.err().context("explicit line error was discarded")?;

    assert_eq!(
        error
            .downcast_ref::<Error>()
            .context("line error type was lost")?
            .kind(),
        ErrorKind::InvalidData,
    );

    Ok(())
}
