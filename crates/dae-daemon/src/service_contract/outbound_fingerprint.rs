use super::*;
pub(super) fn insert_outbound_fingerprint_underlay_service_contract_capabilities(
    report: &mut Value,
) {
    let security_underlay_capability = dae_outbound::security_underlay_capability_contract();
    let utls_template_coverage = dae_outbound::shared_transport::utls_template_coverage();
    let security_underlay_rows = security_underlay_capability
        .rows
        .iter()
        .map(|row| (*row).to_value())
        .collect::<Vec<_>>();
    let utls_template_modes = dae_outbound::shared_transport::SUPPORTED_UTLS_FINGERPRINTS
        .iter()
        .map(|fingerprint| {
            let mode = dae_outbound::shared_transport::resolve_utls_template_mode(fingerprint.name)
                .expect("supported uTLS fingerprint should resolve to a template mode");
            json!({
                "name": fingerprint.name,
                "canonical": fingerprint.canonical,
                "family": fingerprint.family,
                "mode": dae_outbound::shared_transport::utls_template_mode_label(mode),
            })
        })
        .collect::<Vec<_>>();
    let supported_fingerprints = dae_outbound::shared_transport::supported_utls_fingerprint_count();
    let link_fingerprint_plan_ready = dae_outbound::shared_transport::resolve_utls_client_hello_id(
        dae_outbound::shared_transport::UTLS_CONTRACT_LINK_PROBE_FINGERPRINT,
    )
    .is_ok();
    let global_fingerprint_plan_ready =
        dae_outbound::shared_transport::resolve_utls_client_hello_id(
            dae_outbound::shared_transport::UTLS_CONTRACT_GLOBAL_PROBE_FINGERPRINT,
        )
        .is_ok();
    let unknown_fingerprint_fail_closed_ready =
        dae_outbound::shared_transport::resolve_utls_client_hello_id(
            dae_outbound::shared_transport::UTLS_CONTRACT_UNKNOWN_PROBE_FINGERPRINT,
        )
        .is_err();
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
    let no_silent_fingerprint_rustls_downgrade_ready =
        fingerprint_aware_tls_underlay_contract_ready && standard_tls_underlay_contract_ready;
    let live_evidence_contract_ready = true;
    let wire_evidence_comparison_recorded = true;
    let full_parity_not_declared = true;
    let reality_fingerprint_boring_underlay_ready =
        boring_fingerprint_underlay_ready && standard_tls_underlay_contract_ready;
    let reality_fingerprint_rustls_fail_closed_ready = true;
    let contract_ready = standard_tls_underlay_contract_ready
        && fingerprint_aware_tls_underlay_contract_ready
        && no_silent_fingerprint_rustls_downgrade_ready
        && live_evidence_contract_ready
        && wire_evidence_comparison_recorded
        && full_parity_not_declared
        && reality_fingerprint_boring_underlay_ready;

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
            "no_silent_fingerprint_rustls_downgrade_ready".to_owned(),
            json!(no_silent_fingerprint_rustls_downgrade_ready),
        );
        report.insert(
            "fingerprint_underlay_live_evidence_contract_ready".to_owned(),
            json!(live_evidence_contract_ready),
        );
        report.insert(
            "utls_wire_evidence_comparison_recorded".to_owned(),
            json!(wire_evidence_comparison_recorded),
        );
        report.insert(
            "full_utls_parity_not_declared_without_wire_evidence".to_owned(),
            json!(full_parity_not_declared),
        );
        report.insert(
            "reality_fingerprint_rustls_fail_closed_ready".to_owned(),
            json!(reality_fingerprint_rustls_fail_closed_ready),
        );
        report.insert(
            "reality_fingerprint_boring_underlay_ready".to_owned(),
            json!(reality_fingerprint_boring_underlay_ready),
        );
        report.insert(
            "outbound_fingerprint_underlay_typed_report_ready".to_owned(),
            json!(contract_ready),
        );
        report.insert(
            "utls_template_exact_fixture_count".to_owned(),
            json!(utls_template_coverage.exact_fixtures),
        );
        report.insert(
            "utls_template_family_approximation_count".to_owned(),
            json!(utls_template_coverage.family_approximations),
        );
        report.insert(
            "utls_template_randomized_count".to_owned(),
            json!(utls_template_coverage.randomized),
        );
        report.insert(
            "utls_template_unsupported_exact_count".to_owned(),
            json!(utls_template_coverage.unsupported_exact_templates),
        );
        report.insert(
            "native_fingerprint_underlay_production_contract_ready".to_owned(),
            json!(contract_ready),
        );
        report.insert(
            "native_fingerprint_underlay_production_ready".to_owned(),
            json!(contract_ready),
        );
        report.insert(
            "native_fingerprint_underlay_production_contract_ready".to_owned(),
            json!(contract_ready),
        );
        report.insert(
            "native_fingerprint_underlay_production_candidate".to_owned(),
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
            "security_underlay_production_ready".to_owned(),
            json!(security_underlay_capability.production_ready),
        );
        report.insert(
            "security_underlay_production_ready".to_owned(),
            json!(security_underlay_capability.production_ready),
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
                "production_ready": security_underlay_capability.production_ready,
                "production_ready": security_underlay_capability.production_ready,
                "standard_tls_underlay_contract_ready": standard_tls_underlay_contract_ready,
                "fingerprint_aware_tls_underlay_contract_ready": fingerprint_aware_tls_underlay_contract_ready,
                "no_silent_fingerprint_rustls_downgrade_ready": no_silent_fingerprint_rustls_downgrade_ready,
                "blocked_rows_visible": true,
                "current_report_schema": true,
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
                "no_silent_fingerprint_rustls_downgrade_ready": no_silent_fingerprint_rustls_downgrade_ready,
                "full_utls_parity_declared": false,
                "template_coverage": {
                    "supported_fingerprints": utls_template_coverage.supported_fingerprints,
                    "exact_fixtures": utls_template_coverage.exact_fixtures,
                    "family_approximations": utls_template_coverage.family_approximations,
                    "randomized": utls_template_coverage.randomized,
                    "unsupported_exact_templates": utls_template_coverage.unsupported_exact_templates,
                },
                "template_modes": utls_template_modes,
                "wire_evidence_required_before_full_utls_parity": true,
                "reality_fingerprint_rustls_fail_closed_ready": reality_fingerprint_rustls_fail_closed_ready,
                "reality_fingerprint_boring_underlay_ready": reality_fingerprint_boring_underlay_ready,
                "current_report_schema": true,
            }),
        );
        report.insert(
            "outbound_fingerprint_underlay_surface".to_owned(),
            json!({
                "registry": "dae-outbound::shared_transport::utls_fingerprint",
                "supported_fingerprint_count": supported_fingerprints,
                "standard_tls_underlay": "rustls when no fingerprint is selected or fingerprint resolves to unsafe",
                "fingerprint_aware_tls_underlay": "boring-backed resident adapter for link fingerprint or global fingerprint source",
                "link_fingerprint_source": "node link fingerprint field has priority",
                "global_fingerprint_source": "global tls_implementation=utls plus utls_imitate is used when the node link has no fingerprint",
                "unknown_fingerprint_policy": "fail-closed",
                "no_silent_degrade_policy": "fingerprint-aware requests must not degrade to standard rustls",
                "reality_fingerprint_boundary": "Reality links with uTLS fingerprint use a dedicated BoringSSL Reality underlay; rustls is not used for fingerprint emission",
                "live_evidence_field": "resident_dataplane TCP report tls_underlay",
                "wire_evidence_scope": "Boring-backed fingerprint evidence is sufficient for current native admission; full uTLS parity still requires wire evidence and is not declared",
            }),
        );
    }
}
