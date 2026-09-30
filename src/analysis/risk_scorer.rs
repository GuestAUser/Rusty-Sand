//! Risk scoring system for security operations
//!
//! Analyzes hooked operations and assigns risk scores (0-100) based on
//! multiple factors including operation type, target, and context.

use crate::ipc::{HookOperation, HookRequest};

mod files;
mod network;
mod process;
mod registry;

use files::*;
use network::*;
use process::*;
use registry::*;

/// Heuristic risk from 0 (lowest) to 100 (highest), not a malware verdict.
#[derive(Debug, Clone, Copy)]
pub struct RiskScore {
    pub score: u8,
    pub category: ThreatCategory,
}

/// Threat category classification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreatCategory {
    /// 0-30: Low risk, normal operations
    Low,
    /// 31-60: Medium risk, potentially suspicious
    Medium,
    /// 61-85: High heuristic risk
    High,
    /// 86-100: Critical heuristic risk
    Critical,
}

impl ThreatCategory {
    pub fn from_score(score: u8) -> Self {
        match score {
            0..=30 => ThreatCategory::Low,
            31..=60 => ThreatCategory::Medium,
            61..=85 => ThreatCategory::High,
            _ => ThreatCategory::Critical,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            ThreatCategory::Low => "LOW",
            ThreatCategory::Medium => "MEDIUM",
            ThreatCategory::High => "HIGH",
            ThreatCategory::Critical => "CRITICAL",
        }
    }
}

/**
Scores a request using its originating process rather than the monitor's PID.

The caller must authenticate the request before using its PID as identity.
Only an identified self-write receives the lower memory-write score.
*/
pub fn analyze_request(request: &HookRequest) -> RiskScore {
    if let HookOperation::MemoryWrite {
        target_process_id, ..
    } = &request.operation
    {
        if request.pid != 0 && *target_process_id == request.pid {
            return RiskScore {
                score: 35,
                category: ThreatCategory::from_score(35),
            };
        }
    }

    analyze_operation(&request.operation)
}

/**
Scores an operation without assuming which process originated it.

Memory writes remain high risk when origin is unavailable. IPC callers should
use `analyze_request` after authenticating the sender.
*/
pub fn analyze_operation(operation: &HookOperation) -> RiskScore {
    let score = match operation {
        HookOperation::FileCreate {
            path,
            flags_and_attributes,
            ..
        } => analyze_file_create(path, *flags_and_attributes),
        HookOperation::FileWrite { path, .. } => analyze_file_write(path),
        HookOperation::FileDelete { path } => analyze_file_delete(path),
        HookOperation::FileRead { .. } => 5,
        HookOperation::FileMove {
            source,
            destination,
        } => analyze_file_move(source, destination),
        HookOperation::FileCopy {
            source,
            destination,
        } => analyze_file_copy(source, destination),
        HookOperation::FileAttributeChange { path, .. } => analyze_file_attribute_change(path),

        HookOperation::FolderCreate { path } => analyze_folder_create(path),
        HookOperation::FolderDelete { path } => analyze_folder_delete(path),

        HookOperation::RegistrySet { key, data_type, .. } => analyze_registry_set(key, *data_type),
        HookOperation::RegistryDelete { key } => analyze_registry_delete(key),
        HookOperation::RegistryRead { .. } => 5,
        HookOperation::RegistryOpen { key, access_rights } => {
            analyze_registry_open(key, *access_rights)
        }

        HookOperation::NetworkConnect {
            remote_addr, port, ..
        } => analyze_network_connect(remote_addr, *port),
        HookOperation::NetworkSend {
            port,
            bytes_to_send,
            ..
        } => analyze_network_send(*port, *bytes_to_send),
        HookOperation::NetworkReceive { .. } => 10,

        HookOperation::ProcessCreate {
            executable, args, ..
        } => analyze_process_create(executable, args),
        HookOperation::ThreadCreate { .. } => 40,
        HookOperation::ThreadCreateRemote { .. } => 95,

        HookOperation::DllLoad { dll_path, .. } => analyze_dll_load(dll_path),
        HookOperation::MemoryAllocate {
            protection, size, ..
        } => analyze_memory_allocate(*protection, *size),
        HookOperation::MemoryProtect {
            new_protection,
            old_protection,
            ..
        } => analyze_memory_protect(*old_protection, *new_protection),
        HookOperation::MemoryWrite { .. } => 85,
    };

    /*
     * Indicators can overlap. Helpers saturate before this domain clamp so
     * release and debug builds produce the same monotonic score.
     */
    let clamped_score = score.min(100);
    RiskScore {
        score: clamped_score,
        category: ThreatCategory::from_score(clamped_score),
    }
}

#[cfg(test)]
#[path = "../../tests/unit/domain/risk_scorer.rs"]
mod tests;
