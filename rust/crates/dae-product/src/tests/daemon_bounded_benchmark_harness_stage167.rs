use super::*;

#[test]
fn stage167_bounded_benchmark_harness_matches_golden_fixture() {
    let fixture = load("product/daemon/stage167_bounded_listener_ebpf_benchmark_harness_gate.json");
    let contract = stage167_bounded_benchmark_harness_gate_contract();

    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.rows.len(),
        fixture["rows"].as_array().unwrap().len()
    );
    assert_string_vec(&contract.remaining_blockers, &fixture["remaining_blockers"]);
}

#[test]
fn stage167_bounded_benchmark_harness_keeps_default_benchmark_closed() {
    let contract = stage167_bounded_benchmark_harness_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.bounded_production_equivalent_benchmark_harness_executed);
    assert!(contract.bounded_benchmark_executable_now);
    assert!(contract.production_equivalent_listener_ebpf_benchmark_recorded);
    assert!(contract.reload_owner_handoff_benchmark_recorded);
    assert!(contract.benchmark_artifact_summary_recorded);
    assert!(contract.rollback_cleanup_benchmark_recorded);

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
