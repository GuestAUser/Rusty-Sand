use super::model::*;
use super::push_finding;

pub(super) fn url_findings(report: &mut StaticReport) {
    /*
     * Keep the borrow of each retained string separate from report mutation.
     * Each candidate is bounded by the maximum retained string length.
     */
    for index in 0..report.strings.len() {
        let string = &report.strings[index];
        let lowercase = string.value.to_ascii_lowercase();
        let candidate = lowercase.match_indices("http").find_map(|(start, _)| {
            let tail = &lowercase[start..];
            let prefix_length = if tail.starts_with("https://") {
                8
            } else if tail.starts_with("http://") {
                7
            } else {
                return None;
            };
            let end = string.value[start..]
                .find(|character: char| {
                    character.is_ascii_whitespace() || matches!(character, '"' | '\'' | '<' | '>')
                })
                .map_or(string.value.len(), |relative| start + relative);

            (end > start + prefix_length).then_some((start, end))
        });
        let Some((start, end)) = candidate else {
            continue;
        };
        let stride = match string.encoding {
            StringEncoding::Ascii => 1,
            StringEncoding::Utf16Le => 2,
        };
        let finding = Finding {
            id: "indicator.embedded_url".into(),
            category: FindingCategory::EmbeddedIndicator,
            severity: Severity::Informational,
            confidence: Confidence::Medium,
            summary: "Embedded HTTP(S) URL candidate; not a reputation or connectivity result"
                .into(),
            evidence: vec![Evidence {
                offset: Some(string.offset + (start * stride) as u64),
                length: Some(((end - start) * stride) as u64),
                detail: string.value[start..end].to_owned(),
            }],
        };

        push_finding(report, finding);
    }
}
