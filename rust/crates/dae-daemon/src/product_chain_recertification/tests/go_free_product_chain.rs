use super::*;

#[test]
fn go_free_product_chain_gate_blocks_current_candidate_until_go_paths_retire() {
    let mut candidate_service_contract = candidate_service_contract_value(true);
    candidate_service_contract["executed"] = json!(true);
    candidate_service_contract["passed"] = json!(true);
    let resident_gate = json!({
        "candidate_service_contract": candidate_service_contract,
    });
    let release_gate = json!({
        "release_default_switch_ready": true,
    });
    let gate = go_free_product_chain::go_free_product_chain_gate_json(
        true,
        &release_gate,
        &resident_gate,
        true,
        true,
    )
    .report;

    assert_eq!(gate["status"].as_str().unwrap(), "blocked");
    assert!(!gate["go_free_product_chain_ready"].as_bool().unwrap());
    assert!(
        gate["go_free_product_chain_contract_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !gate["go_product_shell_retired_from_default_package"]
            .as_bool()
            .unwrap()
    );
    assert!(gate["blockers"].as_array().unwrap().iter().any(|blocker| {
        blocker
            .as_str()
            .unwrap()
            .contains("Go product shell is not retired")
    }));
}

#[test]
fn go_free_product_chain_gate_accepts_complete_final_contract_fixture() {
    let mut candidate_service_contract = candidate_service_contract_value(true);
    candidate_service_contract["executed"] = json!(true);
    candidate_service_contract["passed"] = json!(true);
    for key in [
        "default_product_package_go_free",
        "go_product_shell_retired_from_default_package",
        "go_orchestration_retired_from_default_package",
        "go_control_runtime_api_service_release_retired_from_default_package",
        "go_outbound_dependency_retired_from_default_package",
        "go_compat_oracle_boundary_ready",
        "rust_product_binary_contract_ready",
        "rust_product_lifecycle_contract_ready",
        "rust_product_web_api_package_release_contract_ready",
        "go_free_live_host_contract_ready",
        "go_free_rollback_model_ready",
        "go_free_product_chain_typed_report_ready",
        "go_free_product_chain_ready",
    ] {
        candidate_service_contract[key] = json!(true);
    }
    let resident_gate = json!({
        "candidate_service_contract": candidate_service_contract,
    });
    let release_gate = json!({
        "release_default_switch_ready": true,
    });
    let gate = go_free_product_chain::go_free_product_chain_gate_json(
        true,
        &release_gate,
        &resident_gate,
        true,
        true,
    )
    .report;

    assert_eq!(gate["status"].as_str().unwrap(), "pass");
    assert!(
        gate["go_free_product_chain_admission_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(gate["go_free_product_chain_ready"].as_bool().unwrap());
    assert!(gate["blockers"].as_array().unwrap().is_empty());
}
