/*! Portable wire contract for the executable and hook DLL. */

mod description;
mod messages;
mod operation;
mod policy;

pub use messages::{HookReady, HookRequest, HookResponse};
pub use operation::{HookOperation, NetworkProtocol};
pub use policy::OperationCriticality;

pub const PROTOCOL_VERSION: u32 = 1;
pub const EXPECTED_HOOK_COUNT: u32 = 17;
pub const MAX_MESSAGE_SIZE: usize = 8192;

pub fn pipe_name(pid: u32) -> String {
    format!(r"\\.\pipe\rusty_sand_hooks_{pid}")
}
