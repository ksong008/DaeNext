use super::*;

#[test]
fn stage162_temporary_ebpf_program_matches_golden_fixture() {
    let fixture = load("product/daemon/stage162_temporary_ebpf_program_attach_preflight_gate.json");
    let contract = stage162_temporary_ebpf_program_gate_contract();

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
fn stage162_temporary_ebpf_program_keeps_production_attach_and_defaults_closed() {
    let contract = stage162_temporary_ebpf_program_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.temporary_ebpf_program_attach_harness_available);
    assert!(contract.temporary_ebpf_program_load_smoke_passed);
    assert!(contract.temporary_ebpf_socket_attach_smoke_passed);
    assert!(contract.temporary_ebpf_socket_detach_cleanup_smoke_passed);

    assert!(!contract.production_tc_attach_smoke_passed);
    assert!(!contract.production_listener_bound);
    assert!(!contract.ebpf_attached);
    assert!(!contract.benchmark_executable_now);
    assert!(!contract.matched_go_rust_default_daemon_benchmark_recorded);
    assert!(!contract.true_rust_default_daemon_admitted);
    assert!(!contract.default_switch_allowed);
    assert!(!contract.product_chain_switch_allowed);
}
