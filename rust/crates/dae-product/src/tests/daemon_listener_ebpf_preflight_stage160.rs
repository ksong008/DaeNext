use super::*;

#[test]
fn stage160_listener_ebpf_preflight_matches_golden_fixture() {
    let fixture =
        load("product/daemon/stage160_isolated_listener_ebpf_preflight_harness_gate.json");
    let contract = stage160_listener_ebpf_harness_gate_contract();

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
fn stage160_listener_ebpf_preflight_keeps_ebpf_and_defaults_closed() {
    let contract = stage160_listener_ebpf_harness_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.isolated_listener_preflight_harness_available);
    assert!(contract.temporary_port_scope_validated);
    assert!(contract.tcp_udp_loopback_listener_smoke_passed);
    assert!(contract.capability_preflight_executed);
    assert!(contract.temporary_bpf_pin_scope_validated);
    assert!(contract.rollback_cleanup_smoke_passed);
    assert!(contract.listener_fd_map_key_contract_recorded);

    assert!(!contract.production_listener_bound);
    assert!(!contract.isolated_namespace_listener_smoke_passed);
    assert!(!contract.ebpf_attached);
    assert!(!contract.temporary_ebpf_attach_smoke_passed);
    assert!(!contract.benchmark_executable_now);
    assert!(!contract.matched_go_rust_default_daemon_benchmark_recorded);
    assert!(!contract.true_rust_default_daemon_admitted);
    assert!(!contract.default_switch_allowed);
    assert!(!contract.product_chain_switch_allowed);
}
