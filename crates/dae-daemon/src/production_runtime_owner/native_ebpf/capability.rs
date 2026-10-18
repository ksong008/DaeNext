use super::*;

pub(super) fn probe_report_json(report: &dae_ebpf_support::AyaUserspaceLoadReport) -> Value {
    report.capability_probe.map_or(Value::Null, |probe| {
        json!({
            "diagnosticOnly": true,
            "cachedPerProcess": true,
            "elapsedMicros": probe.elapsed_micros as u64,
            "entries": probe.entries.iter().map(|entry| json!({
                "kind": entry.kind,
                "name": entry.name,
                "programType": entry.program_type,
                "status": entry.outcome.status(),
                "error": entry.outcome.error(),
            })).collect::<Vec<_>>(),
        })
    })
}

// Supplemental metadata never controls link deletion or backend selection.
pub(super) fn link_metadata_json(
    report: &dae_ebpf_support::aya_loader::AyaLinkMetadataReport,
) -> Value {
    json!({
        "diagnosticOnly": true,
        "links": report.links.iter().map(|link| json!({
            "id": link.id,
            "programId": link.program_id,
            "type": link.link_type,
        })).collect::<Vec<_>>(),
        "errors": report.errors,
    })
}
