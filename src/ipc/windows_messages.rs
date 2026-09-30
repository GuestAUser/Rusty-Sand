use super::MAX_MESSAGE_SIZE;
use anyhow::{bail, Context, Result};
use serde::{de::DeserializeOwned, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub(super) async fn read<T: DeserializeOwned>(pipe: &mut (impl AsyncRead + Unpin)) -> Result<T> {
    let mut bytes = Vec::with_capacity(MAX_MESSAGE_SIZE);
    loop {
        if bytes.len() == MAX_MESSAGE_SIZE {
            bail!("hook message exceeds {MAX_MESSAGE_SIZE} bytes");
        }
        let mut chunk = [0u8; 4096];
        let capacity = chunk.len().min(MAX_MESSAGE_SIZE - bytes.len());
        let count = pipe
            .read(&mut chunk[..capacity])
            .await
            .context("read hook message")?;
        if count == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "hook pipe disconnected before a complete message",
            )
            .into());
        }
        bytes.extend_from_slice(&chunk[..count]);
        match serde_json::from_slice(&bytes) {
            Ok(message) => return Ok(message),
            /* Mio buffers reads in 4 KiB chunks even for message-mode pipes.
            A JSON object may span chunks; never decode lossy UTF-8 or accept
            a truncated object as a valid request. */
            Err(error) if error.is_eof() => {}
            Err(error) => return Err(error).context("decode hook message"),
        }
    }
}

pub(super) async fn write(
    pipe: &mut (impl AsyncWrite + Unpin),
    message: &impl Serialize,
) -> Result<()> {
    let bytes = serde_json::to_vec(message).context("encode hook message")?;
    if bytes.len() > MAX_MESSAGE_SIZE {
        bail!("hook message exceeds {MAX_MESSAGE_SIZE} bytes");
    }
    pipe.write_all(&bytes).await.context("write hook message")?;
    pipe.flush().await.context("flush hook message")
}

#[cfg(test)]
#[path = "../../tests/unit/windows/ipc_windows_messages.rs"]
mod tests;
