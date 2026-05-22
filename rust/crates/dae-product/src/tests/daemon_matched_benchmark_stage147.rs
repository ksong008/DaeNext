use super::*;

#[test]
fn stage147_matched_benchmark_readiness_gate_matches_golden_fixture() {
    let fixture =
        load("product/daemon/stage147_matched_default_daemon_benchmark_readiness_gate.json");
    let contract = stage147_matched_benchmark_readiness_gate_contract();

    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.gate_decision,
        fixture["gate_decision"].as_str().unwrap()
    );
    assert_string_vec(&contract.remaining_blockers, &fixture["remaining_blockers"]);
}

#[test]
fn stage147_matched_benchmark_readiness_keeps_benchmark_closed() {
    let contract = stage147_matched_benchmark_readiness_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.matched_default_daemon_benchmark_plan_recorded);
    assert!(contract.benchmark_corpus_manifest_recorded);
    assert!(contract.benchmark_blocker_queue_recorded);
    assert!(contract.shared_transport_fallback_aware_recertified);
    assert!(contract.outbound_fallback_aware_recertified);
    assert!(contract.fallback_dependency_policy_recorded);
    assert!(contract.go_default_path_preserved);
    assert!(contract.go_fallback_required);

    assert!(!contract.benchmark_executable_now);
    assert!(!contract.true_rust_daemon_binary_exists);
    assert!(!contract.rust_default_control_plane_entrypoint_admitted);
    assert!(!contract.matched_go_rust_default_daemon_benchmark_recorded);
    assert!(!contract.shared_transport_true_dataplane_admitted);
    assert!(!contract.outbound_true_dataplane_admitted);
    assert!(!contract.true_rust_default_daemon_admitted);
    assert!(!contract.default_switch_allowed);
    assert!(!contract.product_chain_switch_allowed);

    assert_eq!(contract.next_admission_queue[0].stage, "stage148");
    assert_eq!(contract.next_admission_queue[1].stage, "stage149");
}
