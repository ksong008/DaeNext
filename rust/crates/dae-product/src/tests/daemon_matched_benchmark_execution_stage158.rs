use super::*;

#[test]
fn stage158_matched_benchmark_execution_matches_golden_fixture() {
    let fixture =
        load("product/daemon/stage158_matched_default_daemon_benchmark_execution_gate.json");
    let contract = stage158_matched_benchmark_execution_gate_contract();

    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.gate_decision,
        fixture["gate_decision"].as_str().unwrap()
    );
    assert_eq!(
        contract.rows.len(),
        fixture["rows"].as_array().unwrap().len()
    );
    assert_string_vec(&contract.remaining_blockers, &fixture["remaining_blockers"]);
}

#[test]
fn stage158_matched_benchmark_execution_keeps_benchmark_closed() {
    let contract = stage158_matched_benchmark_execution_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.matched_benchmark_execution_gate_recorded);
    assert!(contract.stage156_run_identity_carried);
    assert!(contract.stage157_control_plane_entrypoint_carried);
    assert!(contract.benchmark_corpus_manifest_recorded);
    assert!(contract.same_host_execution_requirements_recorded);
    assert!(contract.benchmark_artifact_requirements_recorded);
    assert!(contract.benchmark_blocker_recorded);

    assert!(!contract.production_listener_bound);
    assert!(!contract.ebpf_attached);
    assert!(!contract.benchmark_executable_now);
    assert!(!contract.matched_go_rust_default_daemon_benchmark_recorded);
    assert!(!contract.true_rust_default_daemon_admitted);
    assert!(!contract.default_switch_allowed);
    assert!(!contract.product_chain_switch_allowed);
}
