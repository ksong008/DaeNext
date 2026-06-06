use serde_json::{Value, json};

use super::{ProductChainAdmissionEvidence, ProductChainRecertificationOptions, path_string};

#[derive(Debug, Clone)]
pub(super) struct OutboundFingerprintUnderlayGateReport {
    pub(super) report: Value,
    pub(super) blockers: Vec<String>,
}

pub(super) fn outbound_fingerprint_underlay_gate_json(
    executed: bool,
    options: &ProductChainRecertificationOptions,
    datapath_core_gate: &Value,
    resident_default_daemon_switch_gate: &Value,
    admission: ProductChainAdmissionEvidence,
) -> OutboundFingerprintUnderlayGateReport {
    if !executed {
        return OutboundFingerprintUnderlayGateReport {
            report: json!({
                "name": "outbound-fingerprint-underlay",
                "status": "not-executed",
                "requested": false,
                "outbound_fingerprint_underlay_ready": false,
                "go_fingerprint_underlay_fallback_retired_candidate": false,
                "outbound_fingerprint_underlay_default_switch_admission_ready": false,
                "blockers": [],
            }),
            blockers: Vec::new(),
        };
    }

    let requested = true;
    let datapath_core_ready = datapath_core_gate["datapath_core_ready"]
        .as_bool()
        .unwrap_or(false);
    let binary_source_provided = resident_default_daemon_switch_gate["binary_source_provided"]
        .as_bool()
        .unwrap_or(false);
    let binary_source_exists = resident_default_daemon_switch_gate["binary_source_exists"]
        .as_bool()
        .unwrap_or(false);
    let binary_source = resident_default_daemon_switch_gate["binary_source"].clone();
    let candidate_service_contract =
        resident_default_daemon_switch_gate["candidate_service_contract"].clone();
    let candidate_executed = candidate_service_contract["executed"]
        .as_bool()
        .unwrap_or(false);
    let candidate_passed = candidate_service_contract["passed"]
        .as_bool()
        .unwrap_or(false);

    let contract_ready = candidate_service_contract["outbound_fingerprint_underlay_contract_ready"]
        .as_bool()
        .unwrap_or(false);
    let standard_tls_underlay_contract_ready =
        candidate_service_contract["standard_tls_underlay_contract_ready"]
            .as_bool()
            .unwrap_or(false);
    let fingerprint_aware_tls_underlay_contract_ready =
        candidate_service_contract["fingerprint_aware_tls_underlay_contract_ready"]
            .as_bool()
            .unwrap_or(false);
    let link_fingerprint_plan_ready = candidate_service_contract["link_fingerprint_plan_ready"]
        .as_bool()
        .unwrap_or(false);
    let global_fingerprint_plan_ready = candidate_service_contract["global_fingerprint_plan_ready"]
        .as_bool()
        .unwrap_or(false);
    let unknown_fingerprint_fail_closed_ready =
        candidate_service_contract["unknown_fingerprint_fail_closed_ready"]
            .as_bool()
            .unwrap_or(false);
    let rustls_standard_tls_no_fingerprint_ready =
        candidate_service_contract["rustls_standard_tls_no_fingerprint_ready"]
            .as_bool()
            .unwrap_or(false);
    let boring_fingerprint_underlay_ready =
        candidate_service_contract["boring_fingerprint_underlay_ready"]
            .as_bool()
            .unwrap_or(false);
    let no_silent_fingerprint_rustls_fallback_ready =
        candidate_service_contract["no_silent_fingerprint_rustls_fallback_ready"]
            .as_bool()
            .unwrap_or(false);
    let live_evidence_contract_ready =
        candidate_service_contract["fingerprint_underlay_live_evidence_contract_ready"]
            .as_bool()
            .unwrap_or(false);
    let wire_oracle_comparison_recorded =
        candidate_service_contract["utls_wire_oracle_comparison_recorded"]
            .as_bool()
            .unwrap_or(false);
    let full_parity_not_declared =
        candidate_service_contract["full_utls_parity_not_declared_without_wire_oracle"]
            .as_bool()
            .unwrap_or(false);
    let typed_report_ready =
        candidate_service_contract["outbound_fingerprint_underlay_typed_report_ready"]
            .as_bool()
            .unwrap_or(false);
    let fallback_retirement_contract_ready =
        candidate_service_contract["go_fingerprint_underlay_fallback_retirement_contract_ready"]
            .as_bool()
            .unwrap_or(false);
    let candidate_fallback_retired =
        candidate_service_contract["go_fingerprint_underlay_fallback_retired_candidate"]
            .as_bool()
            .unwrap_or(false);
    let underlay_surface =
        candidate_service_contract["outbound_fingerprint_underlay_surface"].clone();
    let typed_report =
        candidate_service_contract["outbound_fingerprint_underlay_typed_report"].clone();

    let outbound_fingerprint_underlay_ready = requested
        && datapath_core_ready
        && binary_source_provided
        && binary_source_exists
        && candidate_executed
        && candidate_passed
        && contract_ready
        && standard_tls_underlay_contract_ready
        && fingerprint_aware_tls_underlay_contract_ready
        && link_fingerprint_plan_ready
        && global_fingerprint_plan_ready
        && unknown_fingerprint_fail_closed_ready
        && rustls_standard_tls_no_fingerprint_ready
        && boring_fingerprint_underlay_ready
        && no_silent_fingerprint_rustls_fallback_ready
        && live_evidence_contract_ready
        && wire_oracle_comparison_recorded
        && full_parity_not_declared
        && typed_report_ready
        && fallback_retirement_contract_ready
        && candidate_fallback_retired;
    let go_fingerprint_underlay_fallback_retired_candidate = outbound_fingerprint_underlay_ready;
    let outbound_fingerprint_underlay_default_switch_admission_ready =
        outbound_fingerprint_underlay_ready
            && admission.production_dataplane_admitted
            && admission.reload_runtime_parity_admitted
            && admission.matched_benchmark_recorded;

    let mut blockers = Vec::new();
    if !datapath_core_ready {
        blockers.push("C7 requires C6 datapath-core readiness".to_owned());
    }
    if !binary_source_provided {
        blockers.push("C7 fingerprint-underlay candidate binary source is not provided".to_owned());
    } else if !binary_source_exists {
        blockers.push("C7 fingerprint-underlay candidate binary source is absent".to_owned());
    }
    if binary_source_provided && binary_source_exists && !candidate_executed {
        blockers
            .push("C7 fingerprint-underlay candidate service-contract was not executed".to_owned());
    }
    if candidate_executed && !candidate_passed {
        blockers.push(
            "C7 fingerprint-underlay candidate service-contract command did not pass".to_owned(),
        );
    }
    if !contract_ready {
        blockers.push("C7 fingerprint-aware underlay contract is not declared".to_owned());
    }
    if !standard_tls_underlay_contract_ready {
        blockers.push("C7 standard TLS underlay contract is not ready".to_owned());
    }
    if !fingerprint_aware_tls_underlay_contract_ready {
        blockers.push("C7 fingerprint-aware TLS underlay contract is not ready".to_owned());
    }
    if !link_fingerprint_plan_ready {
        blockers.push("C7 link fingerprint plan is not ready".to_owned());
    }
    if !global_fingerprint_plan_ready {
        blockers.push("C7 global fingerprint plan is not ready".to_owned());
    }
    if !unknown_fingerprint_fail_closed_ready {
        blockers.push("C7 unknown fingerprint fail-closed contract is not ready".to_owned());
    }
    if !rustls_standard_tls_no_fingerprint_ready {
        blockers.push("C7 standard rustls no-fingerprint path is not ready".to_owned());
    }
    if !boring_fingerprint_underlay_ready {
        blockers.push("C7 Boring-backed fingerprint underlay is not ready".to_owned());
    }
    if !no_silent_fingerprint_rustls_fallback_ready {
        blockers.push("C7 fingerprint path can still silently fall back to rustls".to_owned());
    }
    if !live_evidence_contract_ready {
        blockers.push("C7 fingerprint underlay live evidence contract is not ready".to_owned());
    }
    if !wire_oracle_comparison_recorded {
        blockers.push("C7 fingerprint underlay wire oracle comparison is not recorded".to_owned());
    }
    if !full_parity_not_declared {
        blockers.push("C7 full uTLS parity boundary is not declared".to_owned());
    }
    if !typed_report_ready {
        blockers.push("C7 fingerprint underlay typed report is not ready".to_owned());
    }
    if !fallback_retirement_contract_ready {
        blockers.push(
            "C7 Go fingerprint-underlay fallback retirement contract is not ready".to_owned(),
        );
    }
    if !candidate_fallback_retired {
        blockers.push(
            "C7 Go fingerprint-underlay fallback retired candidate is not declared".to_owned(),
        );
    }

    OutboundFingerprintUnderlayGateReport {
        report: json!({
            "name": "outbound-fingerprint-underlay",
            "status": if outbound_fingerprint_underlay_ready { "pass" } else { "blocked" },
            "requested": requested,
            "outbound_fingerprint_underlay_ready": outbound_fingerprint_underlay_ready,
            "go_fingerprint_underlay_fallback_retired_candidate": go_fingerprint_underlay_fallback_retired_candidate,
            "outbound_fingerprint_underlay_default_switch_admission_ready": outbound_fingerprint_underlay_default_switch_admission_ready,
            "datapath_core_ready": datapath_core_ready,
            "binary_source": binary_source,
            "binary_source_provided": binary_source_provided,
            "binary_source_exists": binary_source_exists,
            "candidate_service_contract": candidate_service_contract,
            "outbound_fingerprint_underlay_contract_ready": contract_ready,
            "standard_tls_underlay_contract_ready": standard_tls_underlay_contract_ready,
            "fingerprint_aware_tls_underlay_contract_ready": fingerprint_aware_tls_underlay_contract_ready,
            "link_fingerprint_plan_ready": link_fingerprint_plan_ready,
            "global_fingerprint_plan_ready": global_fingerprint_plan_ready,
            "unknown_fingerprint_fail_closed_ready": unknown_fingerprint_fail_closed_ready,
            "rustls_standard_tls_no_fingerprint_ready": rustls_standard_tls_no_fingerprint_ready,
            "boring_fingerprint_underlay_ready": boring_fingerprint_underlay_ready,
            "no_silent_fingerprint_rustls_fallback_ready": no_silent_fingerprint_rustls_fallback_ready,
            "fingerprint_underlay_live_evidence_contract_ready": live_evidence_contract_ready,
            "utls_wire_oracle_comparison_recorded": wire_oracle_comparison_recorded,
            "full_utls_parity_not_declared_without_wire_oracle": full_parity_not_declared,
            "outbound_fingerprint_underlay_typed_report_ready": typed_report_ready,
            "go_fingerprint_underlay_fallback_retirement_contract_ready": fallback_retirement_contract_ready,
            "candidate_go_fingerprint_underlay_fallback_retired": candidate_fallback_retired,
            "admission_production_dataplane_admitted": admission.production_dataplane_admitted,
            "admission_reload_runtime_parity_admitted": admission.reload_runtime_parity_admitted,
            "admission_matched_go_rust_default_daemon_benchmark_recorded": admission.matched_benchmark_recorded,
            "outbound_fingerprint_underlay_surface": underlay_surface,
            "outbound_fingerprint_underlay_typed_report": typed_report,
            "requires_candidate_binary": true,
            "candidate_binary_source_hint": options.resident_default_daemon_binary_source.as_ref().map(|path| path_string(path)),
            "blockers": blockers,
        }),
        blockers,
    }
}
