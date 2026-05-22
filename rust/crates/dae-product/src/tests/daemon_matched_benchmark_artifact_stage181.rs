use super::*;

#[test]
fn stage181_runtime_blocker_matches_golden_fixture() {
    let fixture = load(
        "product/daemon/stage181_matched_benchmark_reviewed_corpus_runtime_readiness_blocker_gate.json",
    );
    let contract = stage181_matched_benchmark_reviewed_corpus_runtime_blocker_contract();

    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.groups.len(),
        fixture["groups"].as_array().unwrap().len()
    );
    assert_string_vec(&contract.execution_order, &fixture["execution_order"]);
    assert_string_vec(&contract.remaining_blockers, &fixture["remaining_blockers"]);
}

#[test]
fn stage181_runtime_blocker_keeps_benchmark_closed() {
    let contract = stage181_matched_benchmark_reviewed_corpus_runtime_blocker_contract();
    assert!(contract.stage_complete);
    assert!(contract.runtime_readiness_blocker_gate_recorded);
    assert!(contract.stage180_queue_carried);
    assert!(contract.production_command_blocker_recorded);
    assert!(contract.daemon_execution_blocker_recorded);
    assert!(contract.listener_tc_ebpf_blocker_recorded);
    assert!(contract.reload_runtime_parity_blocker_recorded);
    assert!(contract.matched_benchmark_blocker_recorded);
    assert!(contract.default_product_blocker_recorded);

    assert!(!contract.reviewed_real_corpus_ready);
    assert!(!contract.rust_production_dae_run_command_exists);
    assert!(!contract.real_benchmark_corpus_materialized);
    assert!(!contract.go_default_daemon_executed);
    assert!(!contract.rust_optin_daemon_executed);
    assert!(!contract.production_listener_bound);
    assert!(!contract.production_tc_attach_smoke_passed);
    assert!(!contract.ebpf_attached);
    assert!(!contract.benchmark_executable_now);
    assert!(!contract.matched_go_rust_default_daemon_benchmark_recorded);
    assert!(!contract.true_rust_default_daemon_admitted);
    assert!(!contract.default_switch_allowed);
    assert!(!contract.default_path_mutation_allowed);
    assert!(!contract.product_chain_switch_allowed);
}
