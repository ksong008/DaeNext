use serde_json::{Value, json};

use super::{ProductChainAdmissionEvidence, ProductChainRecertificationOptions, path_string};

#[derive(Debug, Clone)]
pub(super) struct DatapathCoreGateReport {
    pub(super) report: Value,
    pub(super) blockers: Vec<String>,
}

pub(super) fn datapath_core_gate_json(
    executed: bool,
    options: &ProductChainRecertificationOptions,
    control_plane_owner_gate: &Value,
    resident_default_daemon_switch_gate: &Value,
    admission: ProductChainAdmissionEvidence,
) -> DatapathCoreGateReport {
    if !executed {
        return DatapathCoreGateReport {
            report: json!({
                "name": "datapath-core-v1",
                "status": "not-executed",
                "requested": false,
                "datapath_core_ready": false,
                "go_datapath_core_fallback_retired_candidate": false,
                "datapath_core_default_switch_admission_ready": false,
                "blockers": [],
            }),
            blockers: Vec::new(),
        };
    }

    let requested = true;
    let control_plane_owner_ready = control_plane_owner_gate["control_plane_owner_ready"]
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

    let datapath_core_contract_ready = candidate_service_contract["datapath_core_contract_ready"]
        .as_bool()
        .unwrap_or(false);
    let datapath_core_runtime_state_ready =
        candidate_service_contract["datapath_core_runtime_state_ready"]
            .as_bool()
            .unwrap_or(false);
    let tcp_tproxy_datapath_ready = candidate_service_contract["tcp_tproxy_datapath_ready"]
        .as_bool()
        .unwrap_or(false);
    let tcp_route_sniff_direct_block_proxy_ready =
        candidate_service_contract["tcp_route_sniff_direct_block_proxy_ready"]
            .as_bool()
            .unwrap_or(false);
    let udp_tproxy_datapath_ready = candidate_service_contract["udp_tproxy_datapath_ready"]
        .as_bool()
        .unwrap_or(false);
    let udp_endpoint_pool_ready = candidate_service_contract["udp_endpoint_pool_ready"]
        .as_bool()
        .unwrap_or(false);
    let dns_tproxy_datapath_ready = candidate_service_contract["dns_tproxy_datapath_ready"]
        .as_bool()
        .unwrap_or(false);
    let dns_cache_route_integration_ready =
        candidate_service_contract["dns_cache_route_integration_ready"]
            .as_bool()
            .unwrap_or(false);
    let sniff_result_contract_ready = candidate_service_contract["sniff_result_contract_ready"]
        .as_bool()
        .unwrap_or(false);
    let route_result_contract_ready = candidate_service_contract["route_result_contract_ready"]
        .as_bool()
        .unwrap_or(false);
    let direct_block_proxy_action_contract_ready =
        candidate_service_contract["direct_block_proxy_action_contract_ready"]
            .as_bool()
            .unwrap_or(false);
    let datapath_core_benchmark_gate_ready =
        candidate_service_contract["datapath_core_benchmark_gate_ready"]
            .as_bool()
            .unwrap_or(false);
    let datapath_core_typed_report_ready =
        candidate_service_contract["datapath_core_typed_report_ready"]
            .as_bool()
            .unwrap_or(false);
    let no_go_userspace_datapath_fallback_contract_ready =
        candidate_service_contract["no_go_userspace_datapath_fallback_contract_ready"]
            .as_bool()
            .unwrap_or(false);
    let c_tproxy_oracle_retired_after_datapath_core =
        candidate_service_contract["c_tproxy_oracle_retired_after_datapath_core"]
            .as_bool()
            .unwrap_or(false);
    let go_datapath_core_fallback_retirement_contract_ready =
        candidate_service_contract["go_datapath_core_fallback_retirement_contract_ready"]
            .as_bool()
            .unwrap_or(false);
    let candidate_go_datapath_core_fallback_retired =
        candidate_service_contract["go_datapath_core_fallback_retired_candidate"]
            .as_bool()
            .unwrap_or(false);
    let datapath_core_surface = candidate_service_contract["datapath_core_surface"].clone();
    let datapath_core_typed_report =
        candidate_service_contract["datapath_core_typed_report"].clone();
    let datapath_core_report_schema =
        candidate_service_contract["datapath_core_report_schema"].clone();

    let tcp_core_ready = tcp_tproxy_datapath_ready
        && tcp_route_sniff_direct_block_proxy_ready
        && sniff_result_contract_ready
        && route_result_contract_ready
        && direct_block_proxy_action_contract_ready;
    let udp_core_ready = udp_tproxy_datapath_ready && udp_endpoint_pool_ready;
    let dns_core_ready = dns_tproxy_datapath_ready && dns_cache_route_integration_ready;
    let datapath_core_ready = requested
        && control_plane_owner_ready
        && binary_source_provided
        && binary_source_exists
        && candidate_executed
        && candidate_passed
        && datapath_core_contract_ready
        && datapath_core_runtime_state_ready
        && tcp_core_ready
        && udp_core_ready
        && dns_core_ready
        && datapath_core_benchmark_gate_ready
        && datapath_core_typed_report_ready
        && no_go_userspace_datapath_fallback_contract_ready
        && c_tproxy_oracle_retired_after_datapath_core
        && go_datapath_core_fallback_retirement_contract_ready
        && candidate_go_datapath_core_fallback_retired;
    let go_datapath_core_fallback_retired_candidate = datapath_core_ready;
    let datapath_core_default_switch_admission_ready = datapath_core_ready
        && admission.production_dataplane_admitted
        && admission.reload_runtime_parity_admitted
        && admission.matched_benchmark_recorded;

    let mut blockers = Vec::new();
    if !control_plane_owner_ready {
        blockers.push("C6 requires C5 control-plane owner readiness".to_owned());
    }
    if !binary_source_provided {
        blockers.push("C6 datapath-core candidate binary source is not provided".to_owned());
    } else if !binary_source_exists {
        blockers.push("C6 datapath-core candidate binary source is absent".to_owned());
    }
    if binary_source_provided && binary_source_exists && !candidate_executed {
        blockers.push("C6 datapath-core candidate service-contract was not executed".to_owned());
    }
    if candidate_executed && !candidate_passed {
        blockers
            .push("C6 datapath-core candidate service-contract command did not pass".to_owned());
    }
    if !datapath_core_contract_ready {
        blockers.push("C6 datapath core contract is not declared".to_owned());
    }
    if !datapath_core_runtime_state_ready {
        blockers.push("C6 datapath core runtime state is not ready".to_owned());
    }
    if !tcp_tproxy_datapath_ready {
        blockers.push("C6 TCP tproxy datapath is not ready".to_owned());
    }
    if !tcp_route_sniff_direct_block_proxy_ready {
        blockers.push("C6 TCP route/sniff/direct/block/proxy contract is not ready".to_owned());
    }
    if !udp_tproxy_datapath_ready {
        blockers.push("C6 UDP tproxy datapath is not ready".to_owned());
    }
    if !udp_endpoint_pool_ready {
        blockers.push("C6 UDP endpoint pool is not ready".to_owned());
    }
    if !dns_tproxy_datapath_ready {
        blockers.push("C6 DNS tproxy datapath is not ready".to_owned());
    }
    if !dns_cache_route_integration_ready {
        blockers.push("C6 DNS cache/route integration is not ready".to_owned());
    }
    if !sniff_result_contract_ready {
        blockers.push("C6 sniff result contract is not ready".to_owned());
    }
    if !route_result_contract_ready {
        blockers.push("C6 route result contract is not ready".to_owned());
    }
    if !direct_block_proxy_action_contract_ready {
        blockers.push("C6 direct/block/proxy action contract is not ready".to_owned());
    }
    if !datapath_core_benchmark_gate_ready {
        blockers.push("C6 TCP/UDP/DNS datapath benchmark gate is not ready".to_owned());
    }
    if !datapath_core_typed_report_ready {
        blockers.push("C6 datapath core typed report is not ready".to_owned());
    }
    if !no_go_userspace_datapath_fallback_contract_ready {
        blockers.push("C6 no-Go userspace datapath fallback contract is not ready".to_owned());
    }
    if !c_tproxy_oracle_retired_after_datapath_core {
        blockers
            .push("C6 C tproxy oracle retirement after datapath core is not declared".to_owned());
    }
    if !go_datapath_core_fallback_retirement_contract_ready {
        blockers.push("C6 Go datapath core fallback retirement contract is not ready".to_owned());
    }
    if !candidate_go_datapath_core_fallback_retired {
        blockers.push("C6 Go datapath core fallback retired candidate is not declared".to_owned());
    }

    DatapathCoreGateReport {
        report: json!({
            "name": "datapath-core-v1",
            "status": if datapath_core_ready { "pass" } else { "blocked" },
            "requested": requested,
            "datapath_core_ready": datapath_core_ready,
            "go_datapath_core_fallback_retired_candidate": go_datapath_core_fallback_retired_candidate,
            "datapath_core_default_switch_admission_ready": datapath_core_default_switch_admission_ready,
            "control_plane_owner_ready": control_plane_owner_ready,
            "binary_source": binary_source,
            "binary_source_provided": binary_source_provided,
            "binary_source_exists": binary_source_exists,
            "candidate_service_contract": candidate_service_contract,
            "datapath_core_contract_ready": datapath_core_contract_ready,
            "datapath_core_runtime_state_ready": datapath_core_runtime_state_ready,
            "tcp_datapath_core_ready": tcp_core_ready,
            "udp_datapath_core_ready": udp_core_ready,
            "dns_datapath_core_ready": dns_core_ready,
            "tcp_tproxy_datapath_ready": tcp_tproxy_datapath_ready,
            "tcp_route_sniff_direct_block_proxy_ready": tcp_route_sniff_direct_block_proxy_ready,
            "udp_tproxy_datapath_ready": udp_tproxy_datapath_ready,
            "udp_endpoint_pool_ready": udp_endpoint_pool_ready,
            "dns_tproxy_datapath_ready": dns_tproxy_datapath_ready,
            "dns_cache_route_integration_ready": dns_cache_route_integration_ready,
            "sniff_result_contract_ready": sniff_result_contract_ready,
            "route_result_contract_ready": route_result_contract_ready,
            "direct_block_proxy_action_contract_ready": direct_block_proxy_action_contract_ready,
            "datapath_core_benchmark_gate_ready": datapath_core_benchmark_gate_ready,
            "datapath_core_typed_report_ready": datapath_core_typed_report_ready,
            "no_go_userspace_datapath_fallback_contract_ready": no_go_userspace_datapath_fallback_contract_ready,
            "c_tproxy_oracle_retired_after_datapath_core": c_tproxy_oracle_retired_after_datapath_core,
            "go_datapath_core_fallback_retirement_contract_ready": go_datapath_core_fallback_retirement_contract_ready,
            "candidate_go_datapath_core_fallback_retired": candidate_go_datapath_core_fallback_retired,
            "admission_production_dataplane_admitted": admission.production_dataplane_admitted,
            "admission_reload_runtime_parity_admitted": admission.reload_runtime_parity_admitted,
            "admission_matched_go_rust_default_daemon_benchmark_recorded": admission.matched_benchmark_recorded,
            "datapath_core_report_schema": datapath_core_report_schema,
            "datapath_core_surface": datapath_core_surface,
            "datapath_core_typed_report": datapath_core_typed_report,
            "requires_candidate_binary": true,
            "candidate_binary_source_hint": options.resident_default_daemon_binary_source.as_ref().map(|path| path_string(path)),
            "blockers": blockers,
        }),
        blockers,
    }
}
