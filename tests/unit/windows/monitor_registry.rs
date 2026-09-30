use super::*;

#[tokio::test]
async fn constructing_disabled_policy_does_not_create_a_blocked_event() -> Result<()> {
    let events = Arc::new(Mutex::new(Vec::new()));
    let config = SandboxConfig {
        allow_registry: false,
        ..SandboxConfig::default()
    };
    let _monitor = RegistryMonitor::new(config, events.clone())?;

    assert!(events.lock().await.is_empty());
    Ok(())
}
