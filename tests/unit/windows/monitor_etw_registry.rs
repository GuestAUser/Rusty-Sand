use super::*;

#[test]
fn cancellation_guard_requests_worker_shutdown() {
    let cancelled = Arc::new(AtomicBool::new(false));
    let guard = CancelOnDrop(cancelled.clone());
    drop(guard);
    assert!(cancelled.load(Ordering::Acquire));
}

#[test]
fn notification_is_consumed_once_and_can_be_rearmed() -> Result<()> {
    use std::sync::atomic::AtomicU64;
    use windows::Win32::System::Registry::{
        RegCreateKeyExW, RegDeleteKeyW, RegSetValueExW, KEY_SET_VALUE, REG_DWORD,
        REG_OPTION_VOLATILE,
    };
    use windows::Win32::System::Threading::WaitForSingleObject;

    static NEXT_KEY: AtomicU64 = AtomicU64::new(0);
    let path = format!(
        "Software\\RustySandMonitorTest-{}-{}",
        std::process::id(),
        NEXT_KEY.fetch_add(1, Ordering::Relaxed)
    );
    let wide: Vec<u16> = path.encode_utf16().chain(Some(0)).collect();
    let mut key = HKEY::default();

    /* SAFETY: The path is a private NUL-terminated test key, and key is
    writable output. The returned handle is immediately owned below. */
    unsafe {
        RegCreateKeyExW(
            HKEY_CURRENT_USER,
            PCWSTR(wide.as_ptr()),
            0,
            PCWSTR::null(),
            REG_OPTION_VOLATILE,
            KEY_SET_VALUE,
            None,
            &mut key,
            None,
        )
    }?;

    struct TestKey {
        key: OwnedKey,
        path: Vec<u16>,
    }
    impl Drop for TestKey {
        fn drop(&mut self) {
            /* SAFETY: This path names only this test's private key and
            remains NUL-terminated and live throughout deletion. */
            if let Err(error) =
                unsafe { RegDeleteKeyW(HKEY_CURRENT_USER, PCWSTR(self.path.as_ptr())) }
            {
                panic!("test registry cleanup failed: {error}");
            }
        }
    }

    let key = TestKey {
        key: OwnedKey(key),
        path: wide,
    };
    let watch = KeyWatch::open(HKEY_CURRENT_USER, "HKCU", &path)?;

    for value in [1u32, 2] {
        if value == 2 {
            watch.arm()?;
        }

        /* SAFETY: The key has KEY_SET_VALUE access; the DWORD bytes live
        for this synchronous call. A null value name selects default. */
        unsafe {
            RegSetValueExW(
                key.key.0,
                PCWSTR::null(),
                0,
                REG_DWORD,
                Some(&value.to_ne_bytes()),
            )
        }?;

        /* SAFETY: The registered event is owned by watch. Wait for the
        exact notification with a deadline, then inspect auto-reset. */
        assert_eq!(
            unsafe { WaitForSingleObject(watch.event.0, 2000) },
            WAIT_OBJECT_0
        );
        assert_eq!(
            unsafe { WaitForSingleObject(watch.event.0, 0) },
            WAIT_TIMEOUT
        );
    }

    Ok(())
}

#[tokio::test]
async fn already_stopped_monitor_joins_without_events() -> Result<()> {
    let events = Arc::new(Mutex::new(Vec::new()));
    let shutdown = Arc::new(AtomicBool::new(true));
    RealRegistryMonitor::new(events.clone(), shutdown)
        .monitor()
        .await?;
    assert!(events.lock().await.is_empty());
    Ok(())
}
