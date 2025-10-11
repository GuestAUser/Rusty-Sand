//! Network operation hooks (connect, send, recv)

use crate::hooks::file_hooks::IPC_CLIENT;
use crate::types::{HookOperation, HookRequest, NetworkProtocol};
use minhook::MinHook;
use windows::Win32::Networking::WinSock::{SOCKADDR, SOCKET};
use windows::Win32::System::Threading::{GetCurrentProcessId, GetCurrentThreadId};

// Original function pointers
static mut ORIG_CONNECT: Option<FnConnect> = None;

// Function type definitions
type FnConnect = unsafe extern "system" fn(SOCKET, *const SOCKADDR, i32) -> i32;

/// Request approval from main process via IPC
fn request_approval(operation: HookOperation) -> bool {
    let client_guard = IPC_CLIENT.lock();

    if let Some(client) = client_guard.as_ref() {
        let request = HookRequest {
            operation,
            pid: unsafe { GetCurrentProcessId() },
            tid: unsafe { GetCurrentThreadId() },
        };

        match client.request_approval(&request) {
            Ok(response) => response.allowed,
            Err(_) => false,
        }
    } else {
        false
    }
}

/// Hooked connect - intercepts network connections BEFORE execution
unsafe extern "system" fn hooked_connect(s: SOCKET, name: *const SOCKADDR, namelen: i32) -> i32 {
    // Extract IP and port from sockaddr structure
    let (addr, port, protocol) = if !name.is_null() && namelen >= 16 {
        let sockaddr = &*name;

        // Extract address family (AF_INET = 2, AF_INET6 = 23)
        let family_bytes = std::slice::from_raw_parts(sockaddr as *const _ as *const u8, 2);
        let family = u16::from_le_bytes([family_bytes[0], family_bytes[1]]);

        // Extract port (big-endian at offset 2)
        let port_bytes = std::slice::from_raw_parts((sockaddr as *const _ as *const u8).offset(2), 2);
        let port = u16::from_be_bytes([port_bytes[0], port_bytes[1]]);

        // Extract IP address based on family
        let (addr, protocol) = if family == 2 {
            // AF_INET (IPv4)
            let ip_bytes = std::slice::from_raw_parts((sockaddr as *const _ as *const u8).offset(4), 4);
            let addr = format!("{}.{}.{}.{}", ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]);
            (addr, NetworkProtocol::Tcp)
        } else if family == 23 {
            // AF_INET6 (IPv6)
            let ip_bytes = std::slice::from_raw_parts((sockaddr as *const _ as *const u8).offset(8), 16);
            let addr = format!(
                "{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
                ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3],
                ip_bytes[4], ip_bytes[5], ip_bytes[6], ip_bytes[7],
                ip_bytes[8], ip_bytes[9], ip_bytes[10], ip_bytes[11],
                ip_bytes[12], ip_bytes[13], ip_bytes[14], ip_bytes[15]
            );
            (addr, NetworkProtocol::Tcp6)
        } else {
            ("unknown".to_string(), NetworkProtocol::Tcp)
        };

        (addr, port, protocol)
    } else {
        ("unknown".to_string(), 0, NetworkProtocol::Tcp)
    };

    let operation = HookOperation::NetworkConnect {
        remote_addr: addr,
        port,
        protocol,
    };

    // REQUEST APPROVAL
    if !request_approval(operation) {
        // DENIED - return error
        return -1; // SOCKET_ERROR
    }

    // ALLOWED - call original
    if let Some(orig) = ORIG_CONNECT {
        orig(s, name, namelen)
    } else {
        -1
    }
}

/// Install network operation hooks
pub unsafe fn install_network_hooks() -> Result<(), String> {
    // Load ws2_32.dll
    let ws2_32 = windows::Win32::System::LibraryLoader::LoadLibraryA(
        windows::core::PCSTR(c"ws2_32.dll".as_ptr() as *const u8),
    )
    .map_err(|e| format!("Failed to load ws2_32: {}", e))?;

    // Hook connect
    let connect_addr = windows::Win32::System::LibraryLoader::GetProcAddress(
        ws2_32,
        windows::core::PCSTR(c"connect".as_ptr() as *const u8),
    )
    .ok_or("connect not found")?;

    let orig_connect = MinHook::create_hook(
        connect_addr as *mut _,
        hooked_connect as *mut _,
    )
    .map_err(|e| format!("Failed to hook connect: {:?}", e))?;

    ORIG_CONNECT = Some(std::mem::transmute::<*mut std::ffi::c_void, FnConnect>(orig_connect));

    MinHook::enable_hook(connect_addr as *mut _)
        .map_err(|e| format!("Failed to enable connect hook: {:?}", e))?;

    Ok(())
}
