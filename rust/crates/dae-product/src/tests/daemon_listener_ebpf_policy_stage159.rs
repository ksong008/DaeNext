use super::*;

#[test]
fn stage159_listener_ebpf_policy_matches_golden_fixture() {
    let fixture = load(
        "product/daemon/stage159_production_listener_ebpf_benchmark_preflight_policy_gate.json",
    );
    let contract = stage159_listener_ebpf_policy_gate_contract();

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
fn stage159_listener_ebpf_policy_keeps_execution_closed() {
    let contract = stage159_listener_ebpf_policy_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.production_equivalent_benchmark_policy_recorded);
    assert!(contract.listener_binding_preflight_policy_recorded);
    assert!(contract.ebpf_attach_preflight_policy_recorded);
    assert!(contract.namespace_isolation_required);
    assert!(contract.temporary_bpf_pin_required);
    assert!(contract.capability_preflight_required);
    assert!(contract.rollback_cleanup_required);

    assert!(!contract.production_listener_bound);
    assert!(!contract.ebpf_attached);
    assert!(!contract.isolated_namespace_listener_smoke_passed);
    assert!(!contract.temporary_ebpf_attach_smoke_passed);
    assert!(!contract.benchmark_executable_now);
    assert!(!contract.matched_go_rust_default_daemon_benchmark_recorded);
    assert!(!contract.true_rust_default_daemon_admitted);
    assert!(!contract.default_switch_allowed);
    assert!(!contract.product_chain_switch_allowed);
}
