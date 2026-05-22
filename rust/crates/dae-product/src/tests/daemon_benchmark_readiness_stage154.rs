use super::*;

#[test]
fn stage154_benchmark_readiness_refresh_matches_golden_fixture() {
    let fixture = load(
        "product/daemon/stage154_matched_default_daemon_benchmark_readiness_refresh_gate.json",
    );
    let contract = stage154_benchmark_readiness_refresh_gate_contract();

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
fn stage154_benchmark_readiness_keeps_benchmark_closed() {
    let contract = stage154_benchmark_readiness_refresh_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.matched_default_daemon_benchmark_plan_recorded);
    assert!(contract.benchmark_corpus_manifest_recorded);
    assert!(contract.benchmark_blocker_queue_recorded);
    assert!(contract.stage153_non_default_wrapper_recorded);
    assert!(contract.go_default_path_preserved);

    assert!(!contract.benchmark_executable_now);
    assert!(!contract.rust_default_run_entrypoint_exists);
    assert!(!contract.rust_default_control_plane_entrypoint_admitted);
    assert!(!contract.production_listener_bound);
    assert!(!contract.ebpf_attached);
    assert!(!contract.matched_go_rust_default_daemon_benchmark_recorded);
    assert!(!contract.true_rust_default_daemon_admitted);
    assert!(!contract.default_switch_allowed);
    assert!(!contract.product_chain_switch_allowed);
}
