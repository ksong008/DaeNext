use serde_json::{Value, json};

use super::{ProductChainAdmissionEvidence, ProductChainRecertificationOptions, path_string};

#[derive(Debug, Clone)]
pub(super) struct OutboundProductionMatrixGateReport {
    pub(super) report: Value,
    pub(super) blockers: Vec<String>,
}

pub(super) fn outbound_production_matrix_gate_json(
    executed: bool,
    options: &ProductChainRecertificationOptions,
    outbound_fingerprint_underlay_gate: &Value,
    resident_default_daemon_switch_gate: &Value,
    admission: ProductChainAdmissionEvidence,
) -> OutboundProductionMatrixGateReport {
    if !executed {
        return OutboundProductionMatrixGateReport {
            report: json!({
                "name": "outbound-production-matrix",
                "status": "not-executed",
                "requested": false,
                "outbound_production_matrix_ready": false,
                "go_outbound_fallback_retired_candidate": false,
                "outbound_production_matrix_default_switch_admission_ready": false,
                "blockers": [],
            }),
            blockers: Vec::new(),
        };
    }

    let requested = true;
    let outbound_fingerprint_underlay_ready =
        outbound_fingerprint_underlay_gate["outbound_fingerprint_underlay_ready"]
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

    let contract_ready = candidate_service_contract["outbound_production_matrix_contract_ready"]
        .as_bool()
        .unwrap_or(false);
    let runtime_state_ready =
        candidate_service_contract["outbound_production_matrix_runtime_state_ready"]
            .as_bool()
            .unwrap_or(false);
    let matrix_entries_ready = candidate_service_contract["outbound_matrix_entries_ready"]
        .as_bool()
        .unwrap_or(false);
    let parser_export_metadata_ready =
        candidate_service_contract["parser_export_metadata_matrix_ready"]
            .as_bool()
            .unwrap_or(false);
    let tcp_udp_dataplane_ready = candidate_service_contract["tcp_udp_dataplane_matrix_ready"]
        .as_bool()
        .unwrap_or(false);
    let transport_underlay_ready = candidate_service_contract["transport_underlay_matrix_ready"]
        .as_bool()
        .unwrap_or(false);
    let route_group_connectivity_ready =
        candidate_service_contract["route_group_connectivity_matrix_ready"]
            .as_bool()
            .unwrap_or(false);
    let reload_behavior_ready = candidate_service_contract["reload_behavior_matrix_ready"]
        .as_bool()
        .unwrap_or(false);
    let live_smoke_ready = candidate_service_contract["live_smoke_matrix_ready"]
        .as_bool()
        .unwrap_or(false);
    let fallback_retirement_matrix_ready =
        candidate_service_contract["go_outbound_fallback_retirement_matrix_ready"]
            .as_bool()
            .unwrap_or(false);
    let typed_report_ready =
        candidate_service_contract["outbound_production_matrix_typed_report_ready"]
            .as_bool()
            .unwrap_or(false);
    let fallback_retired_candidate =
        candidate_service_contract["go_outbound_fallback_retired_candidate"]
            .as_bool()
            .unwrap_or(false);
    let live_adapter_contract_ready =
        candidate_service_contract["resident_live_adapter_matrix_contract_ready"]
            .as_bool()
            .unwrap_or(false);
    let live_adapter_matrix_ready =
        candidate_service_contract["resident_live_adapter_matrix_ready"]
            .as_bool()
            .unwrap_or(false);
    let live_adapter_runtime_state_ready =
        candidate_service_contract["resident_live_adapter_matrix_runtime_state_ready"]
            .as_bool()
            .unwrap_or(false);
    let live_adapter_wired_matrix_ready =
        candidate_service_contract["resident_live_adapter_wired_matrix_ready"]
            .as_bool()
            .unwrap_or(false);
    let live_adapter_remote_live_matrix_ready =
        candidate_service_contract["resident_live_adapter_remote_live_matrix_ready"]
            .as_bool()
            .unwrap_or(false);
    let live_adapter_typed_report_ready =
        candidate_service_contract["resident_live_adapter_matrix_typed_report_ready"]
            .as_bool()
            .unwrap_or(false);
    let matrix_entries = candidate_service_contract["outbound_production_matrix_entries"].clone();
    let typed_report =
        candidate_service_contract["outbound_production_matrix_typed_report"].clone();
    let live_adapter_entries =
        candidate_service_contract["resident_live_adapter_matrix_entries"].clone();
    let live_adapter_typed_report =
        candidate_service_contract["resident_live_adapter_matrix_typed_report"].clone();

    let outbound_production_matrix_ready = requested
        && outbound_fingerprint_underlay_ready
        && binary_source_provided
        && binary_source_exists
        && candidate_executed
        && candidate_passed
        && contract_ready
        && runtime_state_ready
        && matrix_entries_ready
        && parser_export_metadata_ready
        && tcp_udp_dataplane_ready
        && transport_underlay_ready
        && route_group_connectivity_ready
        && reload_behavior_ready
        && live_smoke_ready
        && fallback_retirement_matrix_ready
        && typed_report_ready
        && fallback_retired_candidate
        && live_adapter_contract_ready
        && live_adapter_matrix_ready
        && live_adapter_runtime_state_ready
        && live_adapter_wired_matrix_ready
        && live_adapter_remote_live_matrix_ready
        && live_adapter_typed_report_ready;
    let go_outbound_fallback_retired_candidate = outbound_production_matrix_ready;
    let outbound_production_matrix_default_switch_admission_ready = outbound_production_matrix_ready
        && admission.production_dataplane_admitted
        && admission.reload_runtime_parity_admitted
        && admission.matched_benchmark_recorded;

    let mut blockers = Vec::new();
    if !outbound_fingerprint_underlay_ready {
        blockers.push("C8 requires C7 outbound fingerprint underlay readiness".to_owned());
    }
    if !binary_source_provided {
        blockers.push(
            "C8 outbound production matrix candidate binary source is not provided".to_owned(),
        );
    } else if !binary_source_exists {
        blockers.push("C8 outbound production matrix candidate binary source is absent".to_owned());
    }
    if binary_source_provided && binary_source_exists && !candidate_executed {
        blockers.push(
            "C8 outbound production matrix candidate service-contract was not executed".to_owned(),
        );
    }
    if candidate_executed && !candidate_passed {
        blockers.push(
            "C8 outbound production matrix candidate service-contract command did not pass"
                .to_owned(),
        );
    }
    if !contract_ready {
        blockers.push("C8 outbound production matrix contract is not declared".to_owned());
    }
    if !runtime_state_ready {
        blockers.push("C8 outbound production matrix runtime state is not ready".to_owned());
    }
    if !matrix_entries_ready {
        blockers.push("C8 outbound matrix entries are not ready".to_owned());
    }
    if !parser_export_metadata_ready {
        blockers.push("C8 parser/export/metadata matrix is not ready".to_owned());
    }
    if !tcp_udp_dataplane_ready {
        blockers.push("C8 TCP/UDP dataplane matrix is not ready".to_owned());
    }
    if !transport_underlay_ready {
        blockers.push("C8 transport underlay matrix is not ready".to_owned());
    }
    if !route_group_connectivity_ready {
        blockers.push("C8 route/group/connectivity matrix is not ready".to_owned());
    }
    if !reload_behavior_ready {
        blockers.push("C8 reload behavior matrix is not ready".to_owned());
    }
    if !live_smoke_ready {
        blockers.push("C8 live smoke matrix is not ready".to_owned());
    }
    if !fallback_retirement_matrix_ready {
        blockers.push("C8 Go outbound fallback retirement matrix is not ready".to_owned());
    }
    if !typed_report_ready {
        blockers.push("C8 outbound production matrix typed report is not ready".to_owned());
    }
    if !fallback_retired_candidate {
        blockers.push("C8 Go outbound fallback retired candidate is not declared".to_owned());
    }
    if !live_adapter_contract_ready {
        blockers.push("C8 resident live adapter matrix contract is not declared".to_owned());
    }
    if !live_adapter_matrix_ready {
        blockers.push("C8 resident live adapter matrix is not ready".to_owned());
    }
    if !live_adapter_runtime_state_ready {
        blockers.push("C8 resident live adapter runtime state is not ready".to_owned());
    }
    if !live_adapter_wired_matrix_ready {
        blockers.push("C8 resident live adapter wired matrix is not ready".to_owned());
    }
    if !live_adapter_remote_live_matrix_ready {
        blockers.push("C8 resident live adapter remote live matrix is not ready".to_owned());
    }
    if !live_adapter_typed_report_ready {
        blockers.push("C8 resident live adapter typed report is not ready".to_owned());
    }

    OutboundProductionMatrixGateReport {
        report: json!({
            "name": "outbound-production-matrix",
            "status": if outbound_production_matrix_ready { "pass" } else { "blocked" },
            "requested": requested,
            "outbound_production_matrix_ready": outbound_production_matrix_ready,
            "go_outbound_fallback_retired_candidate": go_outbound_fallback_retired_candidate,
            "outbound_production_matrix_default_switch_admission_ready": outbound_production_matrix_default_switch_admission_ready,
            "outbound_fingerprint_underlay_ready": outbound_fingerprint_underlay_ready,
            "binary_source": binary_source,
            "binary_source_provided": binary_source_provided,
            "binary_source_exists": binary_source_exists,
            "candidate_service_contract": candidate_service_contract,
            "outbound_production_matrix_contract_ready": contract_ready,
            "outbound_production_matrix_runtime_state_ready": runtime_state_ready,
            "outbound_matrix_entries_ready": matrix_entries_ready,
            "parser_export_metadata_matrix_ready": parser_export_metadata_ready,
            "tcp_udp_dataplane_matrix_ready": tcp_udp_dataplane_ready,
            "transport_underlay_matrix_ready": transport_underlay_ready,
            "route_group_connectivity_matrix_ready": route_group_connectivity_ready,
            "reload_behavior_matrix_ready": reload_behavior_ready,
            "live_smoke_matrix_ready": live_smoke_ready,
            "go_outbound_fallback_retirement_matrix_ready": fallback_retirement_matrix_ready,
            "outbound_production_matrix_typed_report_ready": typed_report_ready,
            "candidate_go_outbound_fallback_retired": fallback_retired_candidate,
            "resident_live_adapter_matrix_contract_ready": live_adapter_contract_ready,
            "resident_live_adapter_matrix_ready": live_adapter_matrix_ready,
            "resident_live_adapter_matrix_runtime_state_ready": live_adapter_runtime_state_ready,
            "resident_live_adapter_wired_matrix_ready": live_adapter_wired_matrix_ready,
            "resident_live_adapter_remote_live_matrix_ready": live_adapter_remote_live_matrix_ready,
            "resident_live_adapter_matrix_typed_report_ready": live_adapter_typed_report_ready,
            "admission_production_dataplane_admitted": admission.production_dataplane_admitted,
            "admission_reload_runtime_parity_admitted": admission.reload_runtime_parity_admitted,
            "admission_matched_go_rust_default_daemon_benchmark_recorded": admission.matched_benchmark_recorded,
            "outbound_production_matrix_entries": matrix_entries,
            "outbound_production_matrix_typed_report": typed_report,
            "resident_live_adapter_matrix_entries": live_adapter_entries,
            "resident_live_adapter_matrix_typed_report": live_adapter_typed_report,
            "requires_candidate_binary": true,
            "candidate_binary_source_hint": options.resident_default_daemon_binary_source.as_ref().map(|path| path_string(path)),
            "blockers": blockers,
        }),
        blockers,
    }
}
