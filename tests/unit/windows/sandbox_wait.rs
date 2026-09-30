use super::*;
use anyhow::anyhow;
use std::time::Duration;
use windows::Win32::System::Threading::{CreateEventW, SetEvent};

#[tokio::test]
async fn notification_is_registered_before_signal_and_is_cancellable() -> Result<()> {
    /* SAFETY: The event is unnamed, owned here, and contains no pointers. */
    let event = OwnedHandle::new(unsafe { CreateEventW(None, true, false, None)? });
    let mut cancelled = HandleWait::new(event.raw())?;
    cancelled.close()?;
    let mut wait = HandleWait::new(event.raw())?;
    /* SAFETY: The event owner is live throughout signaling and waiting. */
    unsafe { SetEvent(event.raw())? };
    tokio::time::timeout(Duration::from_secs(5), wait.wait())
        .await
        .map_err(|_| anyhow!("event notification did not arrive"))??;
    wait.close()?;
    Ok(())
}
