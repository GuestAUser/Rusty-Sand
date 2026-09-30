use crate::config::SandboxConfig;
use crate::report::{Event, EventType};
use anyhow::{bail, Context, Result};
use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use windows::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER;
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCPROW_OWNER_PID, MIB_UDPROW_OWNER_PID,
    TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
};
use windows::Win32::Networking::WinSock::AF_INET;

#[path = "observations/ip_table.rs"]
mod ip_table;

pub struct NetworkMonitor {
    events: Arc<Mutex<Vec<Event>>>,
    target_pid: u32,
    log_connections: bool,
}

impl NetworkMonitor {
    pub fn new(
        config: SandboxConfig,
        events: Arc<Mutex<Vec<Event>>>,
        target_pid: u32,
    ) -> Result<Self> {
        Ok(Self {
            events,
            target_pid,
            log_connections: config.log_network_packets,
        })
    }

    pub async fn monitor(self) -> Result<()> {
        let mut previous = HashSet::new();
        let mut interval = tokio::time::interval(Duration::from_millis(100));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            interval.tick().await;

            let pid = self.target_pid;
            let current = tokio::task::spawn_blocking(move || snapshot(pid)).await??;

            if self.log_connections {
                for connection in current.difference(&previous) {
                    log::info!(
                        target: "rusty_sand::network",
                        "Network observation: pid={pid}, endpoint={connection}"
                    );
                }
            }

            self.record_snapshot(&current, &previous).await;

            /* Retain only the last snapshot, not every endpoint ever observed.
            Policy belongs to hooks; an observed socket is not a denied request. */
            previous = current;
        }
    }

    async fn record_snapshot(&self, current: &HashSet<String>, previous: &HashSet<String>) {
        let mut events = self.events.lock().await;

        for connection in current.difference(previous) {
            events.push(Event {
                timestamp: chrono::Utc::now(),
                event_type: EventType::NetworkConnection,
                details: connection.clone(),
            });
        }
    }
}

fn snapshot(pid: u32) -> Result<HashSet<String>> {
    let mut connections = HashSet::new();

    for tcp in [true, false] {
        let (words, byte_len) = read_table(tcp)?;
        let row_words = if tcp { 6 } else { 3 };

        for row in ip_table::rows(&words, byte_len, row_words)?.chunks_exact(row_words) {
            if tcp && row[5] == pid && row[3] != 0 {
                connections.insert(format!(
                    "Observed TCP endpoint for PID {pid}: {}:{} -> {}:{} (state {})",
                    address(row[1]),
                    port(row[2]),
                    address(row[3]),
                    port(row[4]),
                    row[0]
                ));
            } else if !tcp && row[2] == pid {
                connections.insert(format!(
                    "Observed UDP bound socket for PID {pid}: {}:{} (traffic not established)",
                    address(row[0]),
                    port(row[1])
                ));
            }
        }
    }

    Ok(connections)
}

fn address(value: u32) -> Ipv4Addr {
    Ipv4Addr::from(value.to_ne_bytes())
}

fn port(value: u32) -> u16 {
    u16::from_be(value as u16)
}

fn read_table(tcp: bool) -> Result<(Vec<u32>, usize)> {
    /* These ABI assertions justify DWORD-aligned storage and word decoding.
    All fields in both IPv4 row types are DWORDs with no internal padding. */
    const _: () = assert!(std::mem::size_of::<MIB_TCPROW_OWNER_PID>() == 24);
    const _: () = assert!(std::mem::size_of::<MIB_UDPROW_OWNER_PID>() == 12);
    const _: () = assert!(std::mem::align_of::<MIB_TCPROW_OWNER_PID>() == 4);
    const _: () = assert!(std::mem::align_of::<MIB_UDPROW_OWNER_PID>() == 4);
    const MAX_BYTES: usize = 16 * 1024 * 1024;

    let mut words = Vec::<u32>::new();
    let mut size = 0u32;

    for _ in 0..4 {
        let buffer = if words.is_empty() {
            None
        } else {
            Some(words.as_mut_ptr().cast())
        };

        /* SAFETY: The optional pointer owns at least `size` writable bytes,
        aligned for DWORD-only tables. The size pointer remains live for
        the synchronous call; Windows retains neither pointer. */
        let status = unsafe {
            if tcp {
                GetExtendedTcpTable(
                    buffer,
                    &mut size,
                    false,
                    AF_INET.0 as u32,
                    TCP_TABLE_OWNER_PID_ALL,
                    0,
                )
            } else {
                GetExtendedUdpTable(
                    buffer,
                    &mut size,
                    false,
                    AF_INET.0 as u32,
                    UDP_TABLE_OWNER_PID,
                    0,
                )
            }
        };

        if status == 0 {
            return Ok((words, size as usize));
        }

        if status != ERROR_INSUFFICIENT_BUFFER.0 {
            return Err(std::io::Error::from_raw_os_error(status as i32))
                .context("query IPv4 owner-PID table");
        }

        if size < 4 || size as usize > MAX_BYTES {
            bail!("IP table size outside supported bounds: {size}");
        }

        words.resize((size as usize).div_ceil(4), 0);
        size = (words.len() * 4) as u32;
    }

    bail!("IP table continued growing during four snapshot attempts")
}

#[cfg(test)]
#[path = "../../tests/unit/windows/monitor_network.rs"]
mod tests;
