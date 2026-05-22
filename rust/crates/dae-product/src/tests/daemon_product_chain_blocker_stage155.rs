use super::*;

#[test]
fn stage155_product_chain_blocker_review_matches_golden_fixture() {
    let fixture =
        load("product/daemon/stage155_product_chain_default_switch_blocker_review_gate.json");
    let contract = stage155_product_chain_blocker_review_gate_contract();

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
fn stage155_product_chain_blocker_review_keeps_switches_closed() {
    let contract = stage155_product_chain_blocker_review_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.product_chain_blocker_review_recorded);
    assert!(contract.benchmark_blocker_carried);
    assert!(contract.default_switch_blockers_recorded);
    assert!(contract.product_chain_switch_blockers_recorded);
    assert!(contract.external_dependency_policy_carried);
    assert!(contract.go_default_path_preserved);
    assert!(contract.go_fallback_required);
    assert!(contract.external_outbound_required);
    assert!(contract.external_quic_go_required);

    assert!(!contract.benchmark_executable_now);
    assert!(!contract.rust_default_run_entrypoint_exists);
    assert!(!contract.rust_default_control_plane_entrypoint_admitted);
    assert!(!contract.production_listener_bound);
    assert!(!contract.ebpf_attached);
    assert!(!contract.matched_go_rust_default_daemon_benchmark_recorded);
    assert!(!contract.true_rust_default_daemon_admitted);
    assert!(!contract.default_switch_allowed);
    assert!(!contract.default_path_mutation_allowed);
    assert!(!contract.product_chain_switch_allowed);
    assert!(!contract.systemd_execstart_switch_allowed);
    assert!(!contract.release_artifact_switch_allowed);
    assert!(!contract.daewing_default_switch_allowed);
    assert!(!contract.daed_default_switch_allowed);
}
