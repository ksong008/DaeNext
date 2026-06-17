use super::*;
pub(super) fn compact_start_report_for_runtime(start_report: &Value) -> Value {
    let attach_backend = actual_resident_attach_backend(start_report).or_else(|| {
        start_report
            .pointer("/resident_interface_backend_policy/effective_backend")
            .and_then(Value::as_str)
            .map(str::to_owned)
    });
    let netns_link_mode = selected_netns_link_mode(start_report).or_else(|| {
        start_report
            .pointer("/topology_values/requested_netns_link_mode")
            .and_then(Value::as_str)
            .map(str::to_owned)
    });
    let startup_evidence = startup_evidence_from_report(start_report);
    json!({
        "name": start_report["name"].clone(),
        "status": start_report["status"].clone(),
        "artifact_dir": start_report["artifact_dir"].clone(),
        "start_file": start_report["start_file"].clone(),
        "cleanup_file": start_report["cleanup_file"].clone(),
        "tproxy_port": start_report["tproxy_port"].clone(),
        "resident_runtime_started": start_report["resident_runtime_started"].clone(),
        "resident_dataplane": start_report["resident_dataplane"].clone(),
        "resident_interface_monitor": start_report["resident_interface_monitor"].clone(),
        "attachBackend": attach_backend,
        "netnsLinkMode": netns_link_mode,
        "startupEvidence": startup_evidence,
        "stored_summary_only": true,
        "full_start_report_file": start_report["start_file"].clone(),
    })
}
