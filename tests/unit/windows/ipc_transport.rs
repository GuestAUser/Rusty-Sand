use super::*;
use crate::ipc::HookOperation;
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

fn isolated_pair(expected_pid: u32) -> Result<(HookIpcServer, HookIpcClient)> {
    static NEXT_PIPE: AtomicU64 = AtomicU64::new(0);

    /*
     * Tokio may retain an overlapped-I/O handle while retiring its completion.
     * Each scenario therefore owns a unique name rather than assuming that a
     * dropped server's name is synchronously available for reuse.
     */
    let name = format!(
        "{}-test-{}",
        pipe_name(std::process::id()),
        NEXT_PIPE.fetch_add(1, Ordering::Relaxed),
    );
    let server = HookIpcServer::bind(expected_pid, &name)?;
    let client = HookIpcClient {
        pipe: ClientOptions::new()
            .pipe_mode(PipeMode::Message)
            .open(&name)?,
    };

    Ok((server, client))
}

fn ready(pid: u32) -> HookReady {
    HookReady {
        pid,
        version: PROTOCOL_VERSION,
        installed_hooks: EXPECTED_HOOK_COUNT,
    }
}

#[test]
fn handshake_rejects_wrong_pid_version_or_partial_installation() {
    assert!(validate_ready(42, &ready(42)).is_ok());
    assert!(validate_ready(41, &ready(42)).is_err());
    assert!(validate_ready(
        42,
        &HookReady {
            version: PROTOCOL_VERSION + 1,
            ..ready(42)
        }
    )
    .is_err());
    assert!(validate_ready(
        42,
        &HookReady {
            installed_hooks: EXPECTED_HOOK_COUNT - 1,
            ..ready(42)
        }
    )
    .is_err());
    assert!(validate_ready(
        42,
        &HookReady {
            installed_hooks: EXPECTED_HOOK_COUNT + 1,
            ..ready(42)
        }
    )
    .is_err());
    let operation = HookRequest {
        operation: HookOperation::FileRead { path: "x".into() },
        pid: 42,
        tid: 1,
    };
    assert!(serde_json::from_slice::<HookReady>(&serde_json::to_vec(&operation).unwrap()).is_err());
}

#[tokio::test]
async fn named_pipe_authenticates_handshake_and_transports_requests() -> Result<()> {
    tokio::time::timeout(Duration::from_secs(10), async {
        let pid = std::process::id();
        let readiness = ready(pid);
        let mut server =
            HookIpcServer::for_process(pid).context("bind initial authenticated server")?;
        assert!(HookIpcServer::for_process(pid).is_err());
        assert!(server.read_request().await.is_err());
        /* Connecting before accept exercises ERROR_PIPE_CONNECTED without a
        scheduling assumption or a readiness delay. */
        let mut client = HookIpcClient::connect_to(pid)?;
        let (accepted, sent) = tokio::join!(server.handshake(), client.send_ready(&readiness));
        accepted?;
        sent?;
        let request = HookRequest {
            operation: HookOperation::FileRead {
                path: "x".repeat(6000),
            },
            pid,
            tid: 1,
        };
        let exchange = async {
            assert_eq!(server.read_request().await?, request);
            server
                .send_response(&HookResponse {
                    allowed: false,
                    reason: Some("policy".into()),
                })
                .await
        };
        let (response, served) = tokio::join!(client.request_approval(&request), exchange);
        assert!(!response?.allowed);
        served?;
        let invalid = HookRequest {
            pid: pid.wrapping_add(1),
            ..request
        };
        let (sent, rejected) = tokio::join!(
            messages::write(&mut client.pipe, &invalid),
            server.read_request()
        );
        sent?;
        assert!(rejected.is_err());
        server.disconnect()?;
        drop(client);
        drop(server);
        Ok::<(), anyhow::Error>(())
    })
    .await
    .context("named-pipe exchange deadline")?
}

#[tokio::test]
async fn named_pipe_rejects_a_different_process_identity() -> Result<()> {
    tokio::time::timeout(Duration::from_secs(10), async {
        let wrong_pid = std::process::id().wrapping_add(1);
        let (mut server, client) = isolated_pair(wrong_pid)?;
        assert!(server.wait_for_connection().await.is_err());
        assert!(server.read_ready().await.is_err());
        server.disconnect()?;
        drop(client);
        drop(server);
        Ok::<(), anyhow::Error>(())
    })
    .await
    .context("named-pipe identity deadline")?
}

#[tokio::test]
async fn pending_pipe_read_can_be_cancelled_and_disconnected() -> Result<()> {
    tokio::time::timeout(Duration::from_secs(10), async {
        let pid = std::process::id();
        let readiness = ready(pid);
        let (mut server, mut client) = isolated_pair(pid)?;
        let (accepted, sent) = tokio::join!(server.handshake(), client.send_ready(&readiness));
        accepted?;
        sent?;
        /* Poll the read once to register I/O before cancelling its future. */
        let mut pending_read = Box::pin(server.read_request());
        std::future::poll_fn(|cx| {
            assert!(pending_read.as_mut().poll(cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        drop(pending_read);
        server.disconnect()?;
        Ok::<(), anyhow::Error>(())
    })
    .await
    .context("named-pipe cancellation deadline")?
}
