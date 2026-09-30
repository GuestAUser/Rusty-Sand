use super::*;
use crate::ipc::{HookOperation, HookRequest};

#[tokio::test]
async fn rejects_oversized_truncated_and_invalid_utf8_messages() -> Result<()> {
    let oversized = serde_json::to_vec(&HookRequest {
        operation: HookOperation::FileRead {
            path: "x".repeat(MAX_MESSAGE_SIZE),
        },
        pid: 1,
        tid: 1,
    })?;
    assert!(read::<HookRequest>(&mut &oversized[..]).await.is_err());
    assert!(read::<HookRequest>(&mut &b"{\"pid\":1"[..]).await.is_err());
    assert!(read::<HookRequest>(&mut &[0xffu8][..]).await.is_err());
    Ok(())
}
