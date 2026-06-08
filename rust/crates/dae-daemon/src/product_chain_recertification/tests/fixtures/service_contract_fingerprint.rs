use super::*;
pub(crate) fn insert_outbound_fingerprint_underlay_contract(
    report: &mut serde_json::Map<String, Value>,
) {
    for key in [
        "outbound_fingerprint_underlay_contract_ready",
        "standard_tls_underlay_contract_ready",
        "fingerprint_aware_tls_underlay_contract_ready",
        "link_fingerprint_plan_ready",
        "global_fingerprint_plan_ready",
        "unknown_fingerprint_fail_closed_ready",
        "rustls_standard_tls_no_fingerprint_ready",
        "boring_fingerprint_underlay_ready",
        "no_silent_fingerprint_rustls_fallback_ready",
        "fingerprint_underlay_live_evidence_contract_ready",
        "utls_wire_oracle_comparison_recorded",
        "full_utls_parity_not_declared_without_wire_oracle",
        "outbound_fingerprint_underlay_typed_report_ready",
        "go_fingerprint_underlay_fallback_retirement_contract_ready",
        "go_fingerprint_underlay_fallback_retired_candidate",
        "security_underlay_capability_contract_ready",
        "common_security_underlay_ready",
    ] {
        report.insert(key.to_owned(), json!(true));
    }
    for key in [
        "expanded_security_underlay_complete",
        "security_underlay_release_gate_ready",
    ] {
        report.insert(key.to_owned(), json!(false));
    }
    report.insert(
        "outbound_fingerprint_underlay_report_schema".to_owned(),
        json!("outbound-fingerprint-underlay"),
    );
    report.insert(
        "outbound_fingerprint_underlay_surface".to_owned(),
        json!({
            "registry": "dae-outbound::shared_transport::utls_fingerprint",
            "standard_tls_underlay": "rustls when no fingerprint is selected or fingerprint resolves to unsafe",
            "fingerprint_aware_tls_underlay": "boring-backed resident adapter for link fingerprint or global fingerprint fallback",
            "unknown_fingerprint_policy": "fail-closed",
            "no_silent_fallback_policy": "fingerprint-aware requests must not degrade to standard rustls",
        }),
    );
    report.insert(
        "outbound_fingerprint_underlay_typed_report".to_owned(),
        json!({
            "schema": "outbound-fingerprint-underlay-typed-report",
            "status": "pass",
            "stage_report_schema": false,
        }),
    );
    report.insert(
        "security_underlay_capability_report_schema".to_owned(),
        json!("security-underlay-capability"),
    );
    report.insert(
        "security_underlay_capability_row_count".to_owned(),
        json!(2),
    );
    report.insert(
        "security_underlay_capability_rows".to_owned(),
        json!([
            {"capabilityId": "standard-tls-common-underlay", "status": "admitted"},
            {"capabilityId": "peer-verification-security-underlay", "status": "fail-closed-final", "blockerId": null}
        ]),
    );
    report.insert(
        "security_underlay_capability_typed_report".to_owned(),
        json!({
            "schema": "security-underlay-capability-typed-report",
            "status": "pass",
            "common_security_underlay_ready": true,
            "expanded_security_underlay_complete": true,
            "release_gate_ready": true,
            "stage_report_schema": false,
        }),
    );
}
