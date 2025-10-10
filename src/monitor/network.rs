use crate::config::SandboxConfig;
use crate::report::{Event, EventType};
use anyhow::Result;
use log::{debug, info, warn};
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::Mutex;

#[cfg(windows)]
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCPTABLE_OWNER_PID,
    MIB_UDPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
};
#[cfg(windows)]
use windows::Win32::Networking::WinSock::AF_INET;

pub struct NetworkMonitor {
    config: SandboxConfig,
    events: Arc<Mutex<Vec<Event>>>,
    target_pid: u32,
    seen_connections: Arc<Mutex<HashSet<String>>>,
}

impl NetworkMonitor {
    pub fn new(
        config: SandboxConfig,
        events: Arc<Mutex<Vec<Event>>>,
        target_pid: u32,
    ) -> Result<Self> {
        Ok(Self {
            config,
            events,
            target_pid,
            seen_connections: Arc::new(Mutex::new(HashSet::new())),
        })
    }

    pub async fn monitor(self) -> Result<()> {
        debug!("Starting network monitor for PID {}", self.target_pid);

        if !self.config.allow_internet {
            debug!("🔒 Network access is BLOCKED for this process");
            // NOTE: We don't log this as an event - it's just a configuration status,
            // not an actual blocked connection attempt. Only real network blocks are logged.
        }

        // Monitor network connections periodically - poll fast to catch everything
        loop {
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

            if let Err(e) = self.check_connections().await {
                debug!("Network check error: {}", e);
            }
        }
    }

    async fn check_connections(&self) -> Result<()> {
        // Check TCP connections
        self.check_tcp_connections().await?;

        // Check UDP connections
        self.check_udp_connections().await?;

        Ok(())
    }

    #[cfg(windows)]
    async fn check_tcp_connections(&self) -> Result<()> {
        // Extract connection data synchronously first
        let connections: Vec<String> = unsafe {
            let mut size: u32 = 0;

            // First call to get size
            let _ = GetExtendedTcpTable(
                None,
                &mut size,
                false,
                AF_INET.0 as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            );

            if size == 0 {
                Vec::new()
            } else {
                let mut buffer = vec![0u8; size as usize];

                // Second call to get data
                let result = GetExtendedTcpTable(
                    Some(buffer.as_mut_ptr() as *mut _),
                    &mut size,
                    false,
                    AF_INET.0 as u32,
                    TCP_TABLE_OWNER_PID_ALL,
                    0,
                );

                if result != 0 {
                    Vec::new()
                } else {
                    let table = buffer.as_ptr() as *const MIB_TCPTABLE_OWNER_PID;
                    let num_entries = (*table).dwNumEntries;
                    let mut connections = Vec::new();

                    // Use pointer arithmetic to access flexible array members safely
                    let table_start = (*table).table.as_ptr();

                    for i in 0..num_entries {
                        let row = &*table_start.add(i as usize);

                        if row.dwOwningPid == self.target_pid {
                            let local_addr = u32::from_be(row.dwLocalAddr);
                            let local_port = u16::from_be((row.dwLocalPort & 0xFFFF) as u16);
                            let remote_addr = u32::from_be(row.dwRemoteAddr);
                            let remote_port = u16::from_be((row.dwRemotePort & 0xFFFF) as u16);

                            if remote_addr != 0 {
                                let connection = format!(
                                    "TCP: {}.{}.{}.{}:{} -> {}.{}.{}.{}:{}",
                                    (local_addr >> 24) & 0xFF,
                                    (local_addr >> 16) & 0xFF,
                                    (local_addr >> 8) & 0xFF,
                                    local_addr & 0xFF,
                                    local_port,
                                    (remote_addr >> 24) & 0xFF,
                                    (remote_addr >> 16) & 0xFF,
                                    (remote_addr >> 8) & 0xFF,
                                    remote_addr & 0xFF,
                                    remote_port
                                );
                                connections.push(connection);
                            }
                        }
                    }

                    connections
                }
            }
        };

        // Now handle async operations
        for connection in connections {
            let mut seen = self.seen_connections.lock().await;
            if !seen.contains(&connection) {
                seen.insert(connection.clone());
                drop(seen);

                if !self.config.allow_internet {
                    warn!("⚠️  BLOCKED network connection: {}", connection);
                    self.log_event(EventType::NetworkBlocked, connection.clone())
                        .await;
                } else {
                    info!("Network connection: {}", connection);
                    self.log_event(EventType::NetworkConnection, connection)
                        .await;
                }
            }
        }

        Ok(())
    }

    #[cfg(windows)]
    async fn check_udp_connections(&self) -> Result<()> {
        // Extract connection data synchronously first
        let connections: Vec<String> = unsafe {
            let mut size: u32 = 0;

            let _ = GetExtendedUdpTable(
                None,
                &mut size,
                false,
                AF_INET.0 as u32,
                UDP_TABLE_OWNER_PID,
                0,
            );

            if size == 0 {
                Vec::new()
            } else {
                let mut buffer = vec![0u8; size as usize];

                let result = GetExtendedUdpTable(
                    Some(buffer.as_mut_ptr() as *mut _),
                    &mut size,
                    false,
                    AF_INET.0 as u32,
                    UDP_TABLE_OWNER_PID,
                    0,
                );

                if result != 0 {
                    Vec::new()
                } else {
                    let table = buffer.as_ptr() as *const MIB_UDPTABLE_OWNER_PID;
                    let num_entries = (*table).dwNumEntries;
                    let mut connections = Vec::new();

                    // Use pointer arithmetic to access flexible array members safely
                    let table_start = (*table).table.as_ptr();

                    for i in 0..num_entries {
                        let row = &*table_start.add(i as usize);

                        if row.dwOwningPid == self.target_pid {
                            let local_addr = u32::from_be(row.dwLocalAddr);
                            let local_port = u16::from_be((row.dwLocalPort & 0xFFFF) as u16);

                            let connection = format!(
                                "UDP: {}.{}.{}.{}:{}",
                                (local_addr >> 24) & 0xFF,
                                (local_addr >> 16) & 0xFF,
                                (local_addr >> 8) & 0xFF,
                                local_addr & 0xFF,
                                local_port
                            );
                            connections.push(connection);
                        }
                    }

                    connections
                }
            }
        };

        // Now handle async operations
        for connection in connections {
            let mut seen = self.seen_connections.lock().await;
            if !seen.contains(&connection) {
                seen.insert(connection.clone());
                drop(seen);

                if !self.config.allow_internet {
                    warn!("⚠️  BLOCKED UDP socket: {}", connection);
                    self.log_event(EventType::NetworkBlocked, connection.clone())
                        .await;
                } else {
                    self.log_event(EventType::NetworkConnection, connection)
                        .await;
                }
            }
        }

        Ok(())
    }

    #[cfg(not(windows))]
    async fn check_tcp_connections(&self) -> Result<()> {
        // Placeholder for non-Windows platforms
        Ok(())
    }

    #[cfg(not(windows))]
    async fn check_udp_connections(&self) -> Result<()> {
        // Placeholder for non-Windows platforms
        Ok(())
    }

    async fn log_event(&self, event_type: EventType, details: String) {
        let event = Event {
            timestamp: chrono::Utc::now(),
            event_type,
            details,
        };

        self.events.lock().await.push(event);
    }
}
