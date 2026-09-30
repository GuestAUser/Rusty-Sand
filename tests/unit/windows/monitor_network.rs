use super::*;

#[test]
fn decodes_network_byte_order() {
    assert_eq!(
        address(u32::from_ne_bytes([127, 0, 0, 1])),
        Ipv4Addr::LOCALHOST
    );
    assert_eq!(port(u16::to_be(443) as u32), 443);
}

#[tokio::test]
async fn policy_does_not_fabricate_block_events() -> Result<()> {
    let events = Arc::new(Mutex::new(Vec::new()));
    let config = SandboxConfig {
        allow_internet: false,
        ..SandboxConfig::default()
    };
    let monitor = NetworkMonitor::new(config, events.clone(), std::process::id())?;
    let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let _connection = std::net::TcpStream::connect(listener.local_addr()?)?;
    let _udp = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
    let observed = snapshot(monitor.target_pid)?;
    assert!(!observed.is_empty());

    monitor.record_snapshot(&observed, &HashSet::new()).await;
    let count = events.lock().await.len();
    assert!(count > 0);
    assert!(events
        .lock()
        .await
        .iter()
        .all(|event| matches!(event.event_type, EventType::NetworkConnection)));

    monitor.record_snapshot(&observed, &observed).await;
    assert_eq!(events.lock().await.len(), count);

    Ok(())
}
