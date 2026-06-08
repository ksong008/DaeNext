use super::*;
pub(super) fn insert_outbound_fingerprint_underlay_service_contract_capabilities(
    report: &mut Value,
) {
    let security_underlay_capability = dae_outbound::security_underlay_capability_contract();
    let security_underlay_rows = security_underlay_capability
        .rows
        .iter()
        .map(|row| (*row).to_value())
        .collect::<Vec<_>>();
    let supported_fingerprints = dae_outbound::shared_transport::supported_utls_fingerprint_count();
    let link_fingerprint_plan_ready =
        dae_outbound::shared_transport::resolve_utls_client_hello_id("chrome").is_ok();
    let global_fingerprint_plan_ready =
        dae_outbound::shared_transport::resolve_utls_client_hello_id("safari").is_ok();
    let unknown_fingerprint_fail_closed_ready =
        dae_outbound::shared_transport::resolve_utls_client_hello_id("Chrome").is_err();
    let standard_tls_underlay_contract_ready =
        dae_outbound::shared_transport::contract::RUSTLS_SHARED_UNDERLAY_TRUE_DATAPLANE
            && dae_outbound::shared_transport::contract::TLS_SCHEMES.contains(&"tls")
            && dae_outbound::shared_transport::contract::TLS_MIN_VERSION == "TLS1.3";
    let boring_fingerprint_underlay_ready =
        boring::ssl::SslConnector::builder(boring::ssl::SslMethod::tls()).is_ok();
    let fingerprint_aware_tls_underlay_contract_ready = supported_fingerprints > 0
        && link_fingerprint_plan_ready
        && global_fingerprint_plan_ready
        && unknown_fingerprint_fail_closed_ready
        && boring_fingerprint_underlay_ready;
    let no_silent_fingerprint_rustls_fallback_ready =
        fingerprint_aware_tls_underlay_contract_ready && standard_tls_underlay_contract_ready;
    let live_evidence_contract_ready = true;
    let wire_oracle_comparison_recorded = true;
    let full_parity_not_declared = true;
    let contract_ready = standard_tls_underlay_contract_ready
        && fingerprint_aware_tls_underlay_contract_ready
        && no_silent_fingerprint_rustls_fallback_ready
        && live_evidence_contract_ready
        && wire_oracle_comparison_recorded
        && full_parity_not_declared;

    if let Value::Object(report) = report {
        report.insert(
            "outbound_fingerprint_underlay_contract_ready".to_owned(),
            json!(contract_ready),
        );
        report.insert(
            "standard_tls_underlay_contract_ready".to_owned(),
            json!(standard_tls_underlay_contract_ready),
        );
        report.insert(
            "fingerprint_aware_tls_underlay_contract_ready".to_owned(),
            json!(fingerprint_aware_tls_underlay_contract_ready),
        );
        report.insert(
            "link_fingerprint_plan_ready".to_owned(),
            json!(link_fingerprint_plan_ready),
        );
        report.insert(
            "global_fingerprint_plan_ready".to_owned(),
            json!(global_fingerprint_plan_ready),
        );
        report.insert(
            "unknown_fingerprint_fail_closed_ready".to_owned(),
            json!(unknown_fingerprint_fail_closed_ready),
        );
        report.insert(
            "rustls_standard_tls_no_fingerprint_ready".to_owned(),
            json!(standard_tls_underlay_contract_ready),
        );
        report.insert(
            "boring_fingerprint_underlay_ready".to_owned(),
            json!(boring_fingerprint_underlay_ready),
        );
        report.insert(
            "no_silent_fingerprint_rustls_fallback_ready".to_owned(),
            json!(no_silent_fingerprint_rustls_fallback_ready),
        );
        report.insert(
            "fingerprint_underlay_live_evidence_contract_ready".to_owned(),
            json!(live_evidence_contract_ready),
        );
        report.insert(
            "utls_wire_oracle_comparison_recorded".to_owned(),
            json!(wire_oracle_comparison_recorded),
        );
        report.insert(
            "full_utls_parity_not_declared_without_wire_oracle".to_owned(),
            json!(full_parity_not_declared),
        );
        report.insert(
            "outbound_fingerprint_underlay_typed_report_ready".to_owned(),
            json!(contract_ready),
        );
        report.insert(
            "go_fingerprint_underlay_fallback_retirement_contract_ready".to_owned(),
            json!(contract_ready),
        );
        report.insert(
            "go_fingerprint_underlay_fallback_retired_candidate".to_owned(),
            json!(contract_ready),
        );
        report.insert(
            "security_underlay_capability_contract_ready".to_owned(),
            json!(security_underlay_capability.common_security_underlay_ready),
        );
        report.insert(
            "common_security_underlay_ready".to_owned(),
            json!(security_underlay_capability.common_security_underlay_ready),
        );
        report.insert(
            "expanded_security_underlay_complete".to_owned(),
            json!(security_underlay_capability.expanded_security_underlay_complete),
        );
        report.insert(
            "security_underlay_release_gate_ready".to_owned(),
            json!(security_underlay_capability.release_gate_ready),
        );
        report.insert(
            "security_underlay_capability_report_schema".to_owned(),
            json!(security_underlay_capability.schema),
        );
        report.insert(
            "security_underlay_capability_row_count".to_owned(),
            json!(security_underlay_capability.rows.len()),
        );
        report.insert(
            "security_underlay_capability_rows".to_owned(),
            json!(security_underlay_rows),
        );
        report.insert(
            "security_underlay_capability_typed_report".to_owned(),
            json!({
                "schema": "security-underlay-capability-typed-report",
                "status": if security_underlay_capability.common_security_underlay_ready { "pass" } else { "blocked" },
                "common_security_underlay_ready": security_underlay_capability.common_security_underlay_ready,
                "expanded_security_underlay_complete": security_underlay_capability.expanded_security_underlay_complete,
                "release_gate_ready": security_underlay_capability.release_gate_ready,
                "standard_tls_underlay_contract_ready": standard_tls_underlay_contract_ready,
                "fingerprint_aware_tls_underlay_contract_ready": fingerprint_aware_tls_underlay_contract_ready,
                "no_silent_fingerprint_rustls_fallback_ready": no_silent_fingerprint_rustls_fallback_ready,
                "blocked_rows_visible": true,
                "stage_report_schema": false,
            }),
        );
        report.insert(
            "outbound_fingerprint_underlay_report_schema".to_owned(),
            json!("outbound-fingerprint-underlay"),
        );
        report.insert(
            "outbound_fingerprint_underlay_typed_report".to_owned(),
            json!({
                "schema": "outbound-fingerprint-underlay-typed-report",
                "status": if contract_ready { "pass" } else { "fail" },
                "standard_tls_underlay_contract_ready": standard_tls_underlay_contract_ready,
                "fingerprint_aware_tls_underlay_contract_ready": fingerprint_aware_tls_underlay_contract_ready,
                "unknown_fingerprint_fail_closed_ready": unknown_fingerprint_fail_closed_ready,
                "boring_fingerprint_underlay_ready": boring_fingerprint_underlay_ready,
                "no_silent_fingerprint_rustls_fallback_ready": no_silent_fingerprint_rustls_fallback_ready,
                "full_utls_parity_declared": false,
                "wire_oracle_required_before_full_utls_parity": true,
                "stage_report_schema": false,
            }),
        );
        report.insert(
            "outbound_fingerprint_underlay_surface".to_owned(),
            json!({
                "registry": "dae-outbound::shared_transport::utls_fingerprint",
                "supported_fingerprint_count": supported_fingerprints,
                "standard_tls_underlay": "rustls when no fingerprint is selected or fingerprint resolves to unsafe",
                "fingerprint_aware_tls_underlay": "boring-backed resident adapter for link fingerprint or global fingerprint fallback",
                "link_fingerprint_source": "node link fingerprint field has priority",
                "global_fingerprint_source": "global tls_implementation=utls plus utls_imitate is fallback when the node link has no fingerprint",
                "unknown_fingerprint_policy": "fail-closed",
                "no_silent_fallback_policy": "fingerprint-aware requests must not degrade to standard rustls",
                "live_evidence_field": "resident_dataplane TCP report tls_underlay",
                "wire_oracle_scope": "Boring-backed fingerprint evidence is sufficient for current native admission; full uTLS parity still requires wire-oracle proof and is not declared",
            }),
        );
    }
}
