use super::EventType;

impl EventType {
    pub(super) fn is_file(&self) -> bool {
        matches!(
            self,
            Self::FileCreated
                | Self::FileModified
                | Self::FileDeleted
                | Self::HookFileCreate
                | Self::HookFileWrite
                | Self::HookFileDelete
                | Self::HookFileRead
                | Self::HookFileMove
                | Self::HookFileCopy
                | Self::HookFileAttributeChange
        )
    }

    pub(super) fn is_network(&self) -> bool {
        matches!(
            self,
            Self::NetworkConnection
                | Self::NetworkBlocked
                | Self::DnsQuery
                | Self::HookNetworkConnect
                | Self::HookNetworkSend
                | Self::HookNetworkReceive
        )
    }
}
