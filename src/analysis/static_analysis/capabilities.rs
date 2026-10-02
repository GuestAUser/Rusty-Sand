use super::model::*;
use super::push_finding;

pub(super) fn import_findings(metadata: &PeMetadata, report: &mut StaticReport) {
    for category in [
        "injection",
        "credentials",
        "persistence",
        "networking",
        "anti_debug",
    ] {
        let evidence: Vec<Evidence> = metadata
            .imports
            .iter()
            .filter(|import| import.name.as_deref().and_then(import_capability) == Some(category))
            .take(8)
            .map(|import| Evidence {
                offset: Some(import.thunk_offset),
                length: Some(match metadata.kind {
                    PeKind::Pe32 => 4,
                    PeKind::Pe32Plus => 8,
                }),
                detail: format!(
                    "{}!{}",
                    import.library,
                    import.name.as_deref().unwrap_or_default()
                ),
            })
            .collect();

        if !evidence.is_empty() {
            push_finding(
                report,
                Finding {
                    id: format!("capability.{category}"),
                    category: FindingCategory::Capability,
                    severity: Severity::Low,
                    confidence: Confidence::Medium,
                    summary: format!(
                        "Imported names associated with {category}; capability is not observed behavior"
                    ),
                    evidence,
                },
            );
        }
    }
}

fn import_capability(name: &str) -> Option<&'static str> {
    match name.to_ascii_lowercase().as_str() {
        "writeprocessmemory"
        | "virtualallocex"
        | "createremotethread"
        | "createremotethreadex"
        | "ntcreatethreadex"
        | "queueuserapc"
        | "setthreadcontext" => Some("injection"),
        "credreada"
        | "credreadw"
        | "credenumeratea"
        | "credenumeratew"
        | "lsaretrieveprivatedata"
        | "vaultgetitem" => Some("credentials"),
        "regsetvalueexa"
        | "regsetvalueexw"
        | "createservicea"
        | "createservicew"
        | "changeserviceconfiga"
        | "changeserviceconfigw" => Some("persistence"),
        "connect" | "wsaconnect" | "internetopena" | "internetopenw" | "internetconnecta"
        | "internetconnectw" | "httpsendrequesta" | "httpsendrequestw" | "winhttpconnect"
        | "winhttpsendrequest" | "urldownloadtofilea" | "urldownloadtofilew" => Some("networking"),
        "isdebuggerpresent" | "checkremotedebuggerpresent" | "ntqueryinformationprocess" => {
            Some("anti_debug")
        }
        _ => None,
    }
}
