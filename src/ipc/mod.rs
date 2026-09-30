/*! Portable hook protocol with Windows-only named-pipe transport. */

pub use rusty_sand_protocol::{
    pipe_name, HookOperation, HookReady, HookRequest, HookResponse, NetworkProtocol,
    OperationCriticality, EXPECTED_HOOK_COUNT, MAX_MESSAGE_SIZE, PROTOCOL_VERSION,
};

#[cfg(windows)]
mod transport;
#[cfg(windows)]
pub use transport::{HookIpcClient, HookIpcServer};
