//! Bounded event collection, deduplication and ordered request correlation.

use super::matching::{
    command_parts, credential_file, defense_command, file_target, hook_text, injection_target,
    startup_registry, suspicious_execution,
};
use super::presentation::finding;
use super::schema::{
    ActionStatus, BehaviorAssessment, Coverage, RuleId, MAX_CORRELATION_EVENT_GAP,
    MAX_CORRELATION_SECONDS, MAX_DETAIL_BYTES, MAX_EVENTS, RANSOMWARE_PATH_THRESHOLD,
};
use crate::report::{Event, EventType};
use chrono::Duration;
use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};

type Hits = BTreeMap<(RuleId, ActionStatus), BTreeSet<usize>>;

struct MemoryRequest {
    index: usize,
    caller: u32,
    target: u32,
}

/**
Assess a bounded prefix without modifying events or live analyzer state.

Findings are grouped by rule and action status. Exact duplicate records have
the same type, timestamp and details; only their first input index is used.
Repeated paths do not satisfy the ransomware count threshold. Other counts
describe supporting event records, never rates or completed operations.
*/
pub fn assess_events(events: &[Event]) -> BehaviorAssessment {
    let mut coverage = Coverage::for_events(events.len());

    let mut seen = HashSet::new();
    let mut hits = Hits::new();
    let mut ransomware_paths = BTreeMap::<ActionStatus, BTreeMap<String, usize>>::new();
    let mut writes = VecDeque::<MemoryRequest>::new();

    for (index, event) in events.iter().take(MAX_EVENTS).enumerate() {
        while writes
            .front()
            .is_some_and(|write| index - write.index > MAX_CORRELATION_EVENT_GAP)
        {
            writes.pop_front();
        }

        if event.details.len() > MAX_DETAIL_BYTES {
            coverage.oversized_events += 1;
            continue;
        }

        if !seen.insert((&event.event_type, event.timestamp, event.details.as_str())) {
            coverage.duplicate_events += 1;
            continue;
        }

        if matches!(
            event.event_type,
            EventType::HookBlocked | EventType::RegistryBlocked
        ) {
            coverage.unclassified_denial_records += 1;
            continue;
        }

        let details = event.details.to_ascii_lowercase();
        let request = hook_text(&details);

        let network_status = match event.event_type {
            EventType::HookNetworkConnect
            | EventType::HookNetworkSend
            | EventType::HookNetworkReceive => Some(request.status),
            EventType::NetworkConnection | EventType::DnsQuery => Some(ActionStatus::Observed),
            EventType::NetworkBlocked => Some(ActionStatus::Denied),
            _ => None,
        };

        if let Some(status) = network_status {
            record(&mut hits, RuleId::NetworkActivity, status, &[index]);
        }

        if let Some((status, path)) = file_target(&event.event_type, &details, &request) {
            let path = path.trim_matches('"').replace('/', "\\");
            let name = path.rsplit('\\').next().unwrap_or_default();

            if [".locked", ".encrypted", ".crypt"]
                .iter()
                .any(|extension| name.ends_with(extension))
            {
                ransomware_paths
                    .entry(status)
                    .or_default()
                    .entry(path.clone())
                    .or_insert(index);
            }

            if matches!(
                name,
                "readme_decrypt.txt" | "how_to_decrypt.txt" | "decrypt_instructions.txt"
            ) {
                record(&mut hits, RuleId::RansomNoteName, status, &[index]);
            }

            if path.contains("\\start menu\\programs\\startup\\")
                && [".exe", ".lnk", ".bat", ".cmd", ".ps1", ".vbs", ".js"]
                    .iter()
                    .any(|extension| name.ends_with(extension))
            {
                record(&mut hits, RuleId::StartupFolder, status, &[index]);
            }
        }

        let registry = match event.event_type {
            EventType::HookRegistrySet => request
                .description
                .strip_prefix("set registry: ")
                .map(|path| (request.status, path)),
            EventType::RegistryAccess => Some((
                ActionStatus::Observed,
                details
                    .strip_prefix(
                        "observed registry subtree change \
                         (process unattributed; operation unspecified): ",
                    )
                    .unwrap_or(&details),
            )),
            _ => None,
        };

        if let Some((status, path)) = registry {
            /*
             * Native hooks may render key::value::value because the key helper
             * already includes the value. The first separator ends the key.
             * No setting value or successful mutation is present in this text.
             */
            let mut fields = path.split("::");
            let key = fields.next().unwrap_or_default();
            let value = fields.next().unwrap_or_default();

            if startup_registry(key) {
                record(&mut hits, RuleId::StartupRegistry, status, &[index]);
            }

            if event.event_type == EventType::HookRegistrySet
                && key.split('\\').any(|part| part == "windows defender")
                && matches!(value, "disableantispyware" | "disablerealtimemonitoring")
            {
                record(&mut hits, RuleId::DefenseImpairment, status, &[index]);
            }
        }

        let credential_read = match event.event_type {
            EventType::HookFileRead => request
                .description
                .strip_prefix("read file: ")
                .is_some_and(credential_file),
            EventType::HookRegistryRead => request
                .description
                .strip_prefix("read registry: ")
                .is_some_and(|path| {
                    let key = path.split("::").next().unwrap_or_default();

                    ["hklm\\sam", "hklm\\security"].iter().any(|root| {
                        key == *root
                            || key
                                .strip_prefix(root)
                                .is_some_and(|suffix| suffix.starts_with('\\'))
                    })
                }),
            _ => false,
        };

        if credential_read {
            record(
                &mut hits,
                RuleId::CredentialStoreRead,
                request.status,
                &[index],
            );
        }

        if event.event_type == EventType::HookProcessCreate {
            if let Some((executable, arguments)) = command_parts(request.description) {
                if suspicious_execution(executable, arguments) {
                    record(
                        &mut hits,
                        RuleId::SuspiciousExecution,
                        request.status,
                        &[index],
                    );
                }

                if defense_command(executable, arguments) {
                    record(
                        &mut hits,
                        RuleId::DefenseImpairment,
                        request.status,
                        &[index],
                    );
                }
            }
        }

        if matches!(
            event.event_type,
            EventType::HookMemoryWrite | EventType::HookThreadCreateRemote
        ) {
            let target = injection_target(&event.event_type, request.description);
            let (Some(caller), Some(target)) = (request.caller, target) else {
                coverage.uncorrelatable_injection_events += 1;
                continue;
            };

            if caller == target {
                continue;
            }

            if event.event_type == EventType::HookMemoryWrite {
                record(
                    &mut hits,
                    RuleId::RemoteMemoryWrite,
                    request.status,
                    &[index],
                );

                if request.status == ActionStatus::Attempted {
                    writes.push_back(MemoryRequest {
                        index,
                        caller,
                        target,
                    });
                }
            } else {
                record(&mut hits, RuleId::RemoteThread, request.status, &[index]);

                if request.status == ActionStatus::Attempted {
                    let previous = writes.iter().rev().find(|write| {
                        let timestamp = events[write.index].timestamp;

                        write.caller == caller
                            && write.target == target
                            && event.timestamp >= timestamp
                            && event.timestamp.signed_duration_since(timestamp)
                                <= Duration::seconds(MAX_CORRELATION_SECONDS)
                    });

                    if let Some(write) = previous {
                        record(
                            &mut hits,
                            RuleId::WriteThenRemoteThread,
                            ActionStatus::Attempted,
                            &[write.index, index],
                        );
                    }
                }
            }
        }
    }

    for (status, paths) in ransomware_paths {
        if paths.len() >= RANSOMWARE_PATH_THRESHOLD {
            hits.entry((RuleId::RansomwareLikeFileNames, status))
                .or_default()
                .extend(paths.into_values());
        }
    }

    let findings = hits
        .into_iter()
        .map(|((rule, status), indices)| finding(events, rule, status, indices))
        .collect();

    BehaviorAssessment { findings, coverage }
}

fn record(hits: &mut Hits, rule: RuleId, status: ActionStatus, indices: &[usize]) {
    hits.entry((rule, status))
        .or_default()
        .extend(indices.iter().copied());
}
