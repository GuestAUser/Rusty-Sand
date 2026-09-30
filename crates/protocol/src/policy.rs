use crate::HookOperation;

/*
KEY_READ combines READ_CONTROL, QUERY_VALUE, ENUMERATE_SUB_KEYS and NOTIFY.
Use an allowlist: generic, maximal, mutation and unknown rights must never
bypass approval. WOW64 flags select a view, not an access right; selecting both
views is invalid. A view modifier alone is not a read-access request.
*/
const KEY_READ: u32 = 0x0002_0019;
const KEY_WOW64_64KEY: u32 = 0x0100;
const KEY_WOW64_32KEY: u32 = 0x0200;
const VIEW_MASK: u32 = KEY_WOW64_64KEY | KEY_WOW64_32KEY;

fn registry_access_is_read_only(access_rights: u32) -> bool {
    let has_read_access = access_rights & KEY_READ != 0;
    let has_only_read_rights = access_rights & !(KEY_READ | VIEW_MASK) == 0;
    let has_valid_view = access_rights & VIEW_MASK != VIEW_MASK;

    has_read_access && has_only_read_rights && has_valid_view
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum OperationCriticality {
    Low = 0,
    Medium = 1,
    High = 2,
    Critical = 3,
}

impl HookOperation {
    pub fn criticality(&self) -> OperationCriticality {
        match self {
            HookOperation::FileRead { .. } => OperationCriticality::Low,
            HookOperation::RegistryRead { .. } => OperationCriticality::Low,
            HookOperation::RegistryOpen { access_rights, .. } => {
                if registry_access_is_read_only(*access_rights) {
                    OperationCriticality::Low
                } else {
                    OperationCriticality::Medium
                }
            }
            HookOperation::NetworkReceive { .. } => OperationCriticality::Low,

            HookOperation::FileWrite { .. } => OperationCriticality::Medium,
            HookOperation::FileCreate { .. } => OperationCriticality::Medium,
            HookOperation::FolderCreate { .. } => OperationCriticality::Medium,
            HookOperation::FileCopy { .. } => OperationCriticality::Medium,
            HookOperation::RegistrySet { .. } => OperationCriticality::Medium,
            HookOperation::NetworkConnect { .. } => OperationCriticality::Medium,
            HookOperation::NetworkSend { .. } => OperationCriticality::Medium,

            HookOperation::FileDelete { .. } => OperationCriticality::High,
            HookOperation::FolderDelete { .. } => OperationCriticality::High,
            HookOperation::FileMove { .. } => OperationCriticality::High,
            HookOperation::FileAttributeChange { .. } => OperationCriticality::High,
            HookOperation::RegistryDelete { .. } => OperationCriticality::High,
            HookOperation::MemoryProtect { .. } => OperationCriticality::High,

            HookOperation::ProcessCreate { .. } => OperationCriticality::Critical,
            HookOperation::ThreadCreate { .. } => OperationCriticality::Critical,
            HookOperation::ThreadCreateRemote { .. } => OperationCriticality::Critical,
            HookOperation::DllLoad { .. } => OperationCriticality::Critical,
            HookOperation::MemoryAllocate { .. } => OperationCriticality::Critical,
            HookOperation::MemoryWrite { .. } => OperationCriticality::Critical,
        }
    }

    pub fn is_read_only(&self) -> bool {
        matches!(self.criticality(), OperationCriticality::Low)
    }
}
