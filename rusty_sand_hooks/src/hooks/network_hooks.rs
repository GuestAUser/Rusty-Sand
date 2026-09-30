use crate::approval::approve;
use crate::buffers::{self, BufferError};
use crate::installation::{InitializationError, Installation};
use crate::types::{HookOperation, NetworkProtocol};
use crate::utils::{copy_caller_bytes, InspectionError};
use std::sync::OnceLock;
use windows::core::PSTR;
use windows::Win32::Networking::WinSock::{
    getsockopt, WSAGetLastError, WSASetLastError, SOCKADDR, SOCKET, SOCKET_ERROR, SOCK_DGRAM,
    SOCK_STREAM, SOL_SOCKET, SO_TYPE, WSAEACCES,
};

type Connect = unsafe extern "system" fn(SOCKET, *const SOCKADDR, i32) -> i32;
static CONNECT: OnceLock<Connect> = OnceLock::new();

unsafe extern "system" fn connect(socket: SOCKET, name: *const SOCKADDR, length: i32) -> i32 {
    /* SAFETY: WSAGetLastError reads only the calling thread's socket error. */
    let saved_error = unsafe { WSAGetLastError() };
    let Some(original) = CONNECT.get() else {
        return denied();
    };
    if !approve(|| {
        let length = usize::try_from(length).map_err(|_| BufferError::InvalidLength)?;
        if length < 2 {
            return Err(BufferError::InvalidLength.into());
        }
        let mut address = [0; 28];
        copy_caller_bytes(name.cast(), &mut address[..2])?;
        let required =
            buffers::socket_address_length(u16::from_le_bytes([address[0], address[1]]))?;
        if length < required {
            return Err(BufferError::InvalidLength.into());
        }
        copy_caller_bytes(name.cast(), &mut address[..required])?;
        let (remote_addr, port, ipv6) = buffers::socket_address(&address[..required])?;
        let mut kind = 0_i32;
        let mut kind_length = size_of::<i32>() as i32;
        /* SAFETY: getsockopt validates the borrowed socket. Its output points
        to an aligned local i32, with the exact capacity supplied separately. */
        let result = unsafe {
            getsockopt(
                socket,
                SOL_SOCKET,
                SO_TYPE,
                PSTR((&mut kind as *mut i32).cast()),
                &mut kind_length,
            )
        };
        if result == SOCKET_ERROR {
            return Err(windows::core::Error::from_win32().into());
        }
        if kind_length != size_of::<i32>() as i32 {
            return Err(BufferError::InvalidLength.into());
        }
        let protocol = match (kind, ipv6) {
            (kind, false) if kind == SOCK_STREAM.0 => NetworkProtocol::Tcp,
            (kind, true) if kind == SOCK_STREAM.0 => NetworkProtocol::Tcp6,
            (kind, false) if kind == SOCK_DGRAM.0 => NetworkProtocol::Udp,
            (kind, true) if kind == SOCK_DGRAM.0 => NetworkProtocol::Udp6,
            _ => return Err(InspectionError::UnsupportedSocketType(kind)),
        };
        Ok(HookOperation::NetworkConnect {
            remote_addr,
            port,
            protocol,
        })
    }) {
        return denied();
    }
    /* SAFETY: Restore only this thread's socket error before calling the
    process-lifetime connect trampoline with its unchanged borrowed buffer. */
    unsafe {
        WSASetLastError(saved_error.0);
        original(socket, name, length)
    }
}

fn denied() -> i32 {
    /* SAFETY: Winsock denials use its thread-local error slot, not errno. */
    unsafe { WSASetLastError(WSAEACCES.0) };
    SOCKET_ERROR
}

pub fn install(installation: &mut Installation) -> Result<(), InitializationError> {
    let module = installation.module(c"ws2_32.dll")?;
    install_hook!(installation, module, c"connect", connect, CONNECT, Connect);
    Ok(())
}
