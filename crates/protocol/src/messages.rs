use serde::{Deserialize, Serialize};

use crate::HookOperation;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HookRequest {
    pub operation: HookOperation,
    pub pid: u32,
    pub tid: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HookResponse {
    pub allowed: bool,
    pub reason: Option<String>,
}

/**
The first pipe message, sent only after all required hooks are active.
Operation requests retain their original representation and follow this message.
*/
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HookReady {
    pub version: u32,
    pub pid: u32,
    pub installed_hooks: u32,
}
