use super::*;
#[derive(Debug, Clone)]
pub(crate) struct NativeOwnedEntryGateReport {
    pub(in crate::product_chain_recertification) report: Value,
    pub(in crate::product_chain_recertification) blockers: Vec<String>,
}

pub(crate) fn native_owned_entry_gates_json(
    executed: bool,
    options: &ProductChainRecertificationOptions,
    topology: &Value,
    service: &Value,
    runtime_control_api: &Value,
) -> NativeOwnedEntryGateReport {
    if !executed {
        return NativeOwnedEntryGateReport {
            report: json!({
                "status": "not-executed",
                "product_chain_topology_locked": false,
                "default_bundle_boundary_clean": false,
                "default_runtime_selector_rust_owned": false,
                "explicit_go_rollback_only": false,
                "runtime_selector_matrix_recorded": false,
                "daed_service_contract_ready": false,
                "c0_product_chain_topology_lock": not_executed_gate("product-chain-topology-lock"),
                "c1_default_bundle_boundary": not_executed_gate("default-bundle-boundary"),
                "c2_default_runtime_selector": not_executed_gate("default-runtime-selector"),
                "c3_daed_service_contract": not_executed_gate("daed-service-contract"),
            }),
            blockers: Vec::new(),
        };
    }

    let c0 = c0_product_chain_topology_lock(options, topology);
    let c1 = c1_default_bundle_boundary(options);
    let c2 = c2_default_runtime_selector(options);
    let c3 = c3_daed_service_contract(options, service, runtime_control_api);
    let product_chain_topology_locked = c0["product_chain_topology_locked"]
        .as_bool()
        .unwrap_or(false);
    let default_bundle_boundary_clean = c1["default_bundle_boundary_clean"]
        .as_bool()
        .unwrap_or(false);
    let default_runtime_selector_rust_owned = c2["default_runtime_selector_rust_owned"]
        .as_bool()
        .unwrap_or(false);
    let explicit_go_rollback_only = c2["explicit_go_rollback_only"].as_bool().unwrap_or(false);
    let runtime_selector_matrix_recorded = c2["runtime_selector_matrix_recorded"]
        .as_bool()
        .unwrap_or(false);
    let daed_service_contract_ready = c3["daed_service_contract_ready"].as_bool().unwrap_or(false);
    let status = if product_chain_topology_locked
        && default_bundle_boundary_clean
        && default_runtime_selector_rust_owned
        && explicit_go_rollback_only
        && runtime_selector_matrix_recorded
        && daed_service_contract_ready
    {
        "pass"
    } else {
        "blocked"
    };
    let mut blockers = Vec::new();
    blockers.extend(value_string_array(&c0["blockers"]));
    blockers.extend(value_string_array(&c1["blockers"]));
    blockers.extend(value_string_array(&c2["blockers"]));
    blockers.extend(value_string_array(&c3["blockers"]));
    NativeOwnedEntryGateReport {
        report: json!({
            "status": status,
            "product_chain_topology_locked": product_chain_topology_locked,
            "default_bundle_boundary_clean": default_bundle_boundary_clean,
            "default_runtime_selector_rust_owned": default_runtime_selector_rust_owned,
            "explicit_go_rollback_only": explicit_go_rollback_only,
            "runtime_selector_matrix_recorded": runtime_selector_matrix_recorded,
            "daed_service_contract_ready": daed_service_contract_ready,
            "c0_product_chain_topology_lock": c0,
            "c1_default_bundle_boundary": c1,
            "c2_default_runtime_selector": c2,
            "c3_daed_service_contract": c3,
        }),
        blockers,
    }
}

pub(crate) fn not_executed_gate(name: &str) -> Value {
    json!({
        "name": name,
        "status": "not-executed",
        "blockers": [],
    })
}
