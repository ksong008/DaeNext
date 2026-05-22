use super::*;

#[test]
fn stage161_temporary_ebpf_map_matches_golden_fixture() {
    let fixture = load("product/daemon/stage161_temporary_ebpf_map_preflight_gate.json");
    let contract = stage161_temporary_ebpf_map_gate_contract();

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
fn stage161_temporary_ebpf_map_keeps_attach_and_defaults_closed() {
    let contract = stage161_temporary_ebpf_map_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.temporary_ebpf_map_preflight_harness_available);
    assert!(contract.bpffs_pin_root_discovery_available);
    assert!(contract.temporary_ebpf_map_create_smoke_passed);
    assert!(contract.temporary_ebpf_map_update_lookup_smoke_passed);
    assert!(contract.temporary_ebpf_pin_reopen_smoke_passed);
    assert!(contract.temporary_ebpf_pin_cleanup_smoke_passed);

    assert!(!contract.temporary_ebpf_attach_smoke_passed);
    assert!(!contract.production_listener_bound);
    assert!(!contract.ebpf_attached);
    assert!(!contract.benchmark_executable_now);
    assert!(!contract.matched_go_rust_default_daemon_benchmark_recorded);
    assert!(!contract.true_rust_default_daemon_admitted);
    assert!(!contract.default_switch_allowed);
    assert!(!contract.product_chain_switch_allowed);
}
