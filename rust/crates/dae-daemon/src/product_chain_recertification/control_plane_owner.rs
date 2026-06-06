use serde_json::{Value, json};

use super::{ProductChainAdmissionEvidence, ProductChainRecertificationOptions, path_string};

#[derive(Debug, Clone)]
pub(super) struct ControlPlaneOwnerGateReport {
    pub(super) report: Value,
    pub(super) blockers: Vec<String>,
}

pub(super) fn control_plane_owner_gate_json(
    executed: bool,
    options: &ProductChainRecertificationOptions,
    resident_runtime_platform_gate: &Value,
    resident_default_daemon_switch_gate: &Value,
    admission: ProductChainAdmissionEvidence,
) -> ControlPlaneOwnerGateReport {
    if !executed {
        return ControlPlaneOwnerGateReport {
            report: json!({
                "name": "control-plane-owner",
                "status": "not-executed",
                "requested": false,
                "control_plane_owner_ready": false,
                "go_control_plane_fallback_retired_candidate": false,
                "control_plane_owner_default_switch_admission_ready": false,
                "blockers": [],
            }),
            blockers: Vec::new(),
        };
    }

    let requested = true;
    let resident_runtime_platform_ready =
        resident_runtime_platform_gate["resident_runtime_platform_ready"]
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
    let control_plane_owner_contract_ready =
        candidate_service_contract["control_plane_owner_contract_ready"]
            .as_bool()
            .unwrap_or(false);
    let control_plane_runtime_state_ready =
        candidate_service_contract["control_plane_runtime_state_ready"]
            .as_bool()
            .unwrap_or(false);
    let routing_map_owner_ready = candidate_service_contract["routing_map_owner_ready"]
        .as_bool()
        .unwrap_or(false);
    let domain_routing_owner_ready = candidate_service_contract["domain_routing_owner_ready"]
        .as_bool()
        .unwrap_or(false);
    let outbound_connectivity_owner_ready =
        candidate_service_contract["outbound_connectivity_owner_ready"]
            .as_bool()
            .unwrap_or(false);
    let runtime_overview_cache_stats_ready =
        candidate_service_contract["runtime_overview_cache_stats_ready"]
            .as_bool()
            .unwrap_or(false);
    let reload_parity_contract_ready =
        candidate_service_contract["control_plane_reload_parity_contract_ready"]
            .as_bool()
            .unwrap_or(false);
    let cleanup_leftovers_gate_ready =
        candidate_service_contract["control_plane_cleanup_leftovers_gate_ready"]
            .as_bool()
            .unwrap_or(false);
    let matched_benchmark_gate_ready =
        candidate_service_contract["matched_go_rust_default_daemon_benchmark_gate_ready"]
            .as_bool()
            .unwrap_or(false);
    let control_plane_typed_report_ready =
        candidate_service_contract["control_plane_typed_report_ready"]
            .as_bool()
            .unwrap_or(false);
    let c_tproxy_oracle_retained =
        candidate_service_contract["control_plane_c_tproxy_oracle_retained_until_datapath_core"]
            .as_bool()
            .unwrap_or(false);
    let go_control_plane_fallback_retirement_contract_ready =
        candidate_service_contract["go_control_plane_fallback_retirement_contract_ready"]
            .as_bool()
            .unwrap_or(false);
    let control_plane_owner_surface =
        candidate_service_contract["control_plane_owner_surface"].clone();
    let runtime_state_report =
        candidate_service_contract["control_plane_runtime_state_report"].clone();
    let control_api_typed_report = candidate_service_contract["control_plane_typed_report"].clone();

    let owner_surface_ready = routing_map_owner_ready
        && domain_routing_owner_ready
        && outbound_connectivity_owner_ready
        && runtime_overview_cache_stats_ready
        && reload_parity_contract_ready
        && cleanup_leftovers_gate_ready
        && matched_benchmark_gate_ready
        && control_plane_typed_report_ready
        && c_tproxy_oracle_retained;
    let control_plane_owner_ready = requested
        && resident_runtime_platform_ready
        && binary_source_provided
        && binary_source_exists
        && candidate_executed
        && candidate_passed
        && control_plane_owner_contract_ready
        && control_plane_runtime_state_ready
        && owner_surface_ready;
    let go_control_plane_fallback_retired_candidate = control_plane_owner_ready
        && go_control_plane_fallback_retirement_contract_ready
        && matched_benchmark_gate_ready
        && c_tproxy_oracle_retained;
    let control_plane_owner_default_switch_admission_ready =
        go_control_plane_fallback_retired_candidate
            && admission.reload_runtime_parity_admitted
            && admission.matched_benchmark_recorded;

    let mut blockers = Vec::new();
    if !resident_runtime_platform_ready {
        blockers.push("C5 requires C4 resident runtime platform readiness".to_owned());
    }
    if !binary_source_provided {
        blockers.push("C5 control-plane owner candidate binary source is not provided".to_owned());
    } else if !binary_source_exists {
        blockers.push("C5 control-plane owner candidate binary source is absent".to_owned());
    }
    if binary_source_provided && binary_source_exists && !candidate_executed {
        blockers
            .push("C5 control-plane owner candidate service-contract was not executed".to_owned());
    }
    if candidate_executed && !candidate_passed {
        blockers.push(
            "C5 control-plane owner candidate service-contract command did not pass".to_owned(),
        );
    }
    if !control_plane_owner_contract_ready {
        blockers.push("C5 control-plane owner contract is not declared".to_owned());
    }
    if !control_plane_runtime_state_ready {
        blockers.push("C5 Rust control-plane runtime state is not ready".to_owned());
    }
    if !routing_map_owner_ready {
        blockers.push("C5 routing map owner is not ready".to_owned());
    }
    if !domain_routing_owner_ready {
        blockers.push("C5 domain routing owner is not ready".to_owned());
    }
    if !outbound_connectivity_owner_ready {
        blockers.push("C5 outbound connectivity owner is not ready".to_owned());
    }
    if !runtime_overview_cache_stats_ready {
        blockers.push("C5 runtime overview/cache/stats surface is not ready".to_owned());
    }
    if !reload_parity_contract_ready {
        blockers.push("C5 reload parity contract is not ready".to_owned());
    }
    if !cleanup_leftovers_gate_ready {
        blockers.push("C5 cleanup leftovers gate is not ready".to_owned());
    }
    if !matched_benchmark_gate_ready {
        blockers.push("C5 matched Go/Rust benchmark gate is not ready".to_owned());
    }
    if !control_plane_typed_report_ready {
        blockers.push("C5 control-plane typed report is not ready".to_owned());
    }
    if !c_tproxy_oracle_retained {
        blockers.push("C5 C tproxy oracle retention is not declared until C6".to_owned());
    }
    if !go_control_plane_fallback_retirement_contract_ready {
        blockers.push("C5 Go control-plane fallback retirement contract is not ready".to_owned());
    }

    ControlPlaneOwnerGateReport {
        report: json!({
            "name": "control-plane-owner",
            "status": if control_plane_owner_ready && go_control_plane_fallback_retired_candidate {
                "pass"
            } else {
                "blocked"
            },
            "requested": requested,
            "control_plane_owner_ready": control_plane_owner_ready,
            "go_control_plane_fallback_retired_candidate": go_control_plane_fallback_retired_candidate,
            "control_plane_owner_default_switch_admission_ready": control_plane_owner_default_switch_admission_ready,
            "resident_runtime_platform_ready": resident_runtime_platform_ready,
            "binary_source": binary_source,
            "binary_source_provided": binary_source_provided,
            "binary_source_exists": binary_source_exists,
            "candidate_service_contract": candidate_service_contract,
            "control_plane_owner_contract_ready": control_plane_owner_contract_ready,
            "control_plane_runtime_state_ready": control_plane_runtime_state_ready,
            "routing_map_owner_ready": routing_map_owner_ready,
            "domain_routing_owner_ready": domain_routing_owner_ready,
            "outbound_connectivity_owner_ready": outbound_connectivity_owner_ready,
            "runtime_overview_cache_stats_ready": runtime_overview_cache_stats_ready,
            "control_plane_reload_parity_contract_ready": reload_parity_contract_ready,
            "control_plane_cleanup_leftovers_gate_ready": cleanup_leftovers_gate_ready,
            "matched_go_rust_default_daemon_benchmark_gate_ready": matched_benchmark_gate_ready,
            "control_plane_typed_report_ready": control_plane_typed_report_ready,
            "control_plane_c_tproxy_oracle_retained_until_datapath_core": c_tproxy_oracle_retained,
            "go_control_plane_fallback_retirement_contract_ready": go_control_plane_fallback_retirement_contract_ready,
            "admission_reload_runtime_parity_admitted": admission.reload_runtime_parity_admitted,
            "admission_matched_go_rust_default_daemon_benchmark_recorded": admission.matched_benchmark_recorded,
            "control_plane_owner_surface": control_plane_owner_surface,
            "control_plane_runtime_state_report": runtime_state_report,
            "control_plane_typed_report": control_api_typed_report,
            "requires_candidate_binary": true,
            "candidate_binary_source_hint": options.resident_default_daemon_binary_source.as_ref().map(|path| path_string(path)),
            "blockers": blockers,
        }),
        blockers,
    }
}
