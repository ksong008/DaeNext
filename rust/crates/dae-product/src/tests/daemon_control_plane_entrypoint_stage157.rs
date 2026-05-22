use super::*;

#[test]
fn stage157_control_plane_entrypoint_matches_golden_fixture() {
    let fixture = load("product/daemon/stage157_control_plane_entrypoint_admission_gate.json");
    let contract = stage157_control_plane_entrypoint_gate_contract();

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
fn stage157_control_plane_entrypoint_keeps_production_closed() {
    let contract = stage157_control_plane_entrypoint_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.control_plane_entrypoint_optin_admitted);
    assert!(contract.rust_default_run_entrypoint_exists);
    assert!(contract.rust_default_control_plane_entrypoint_admitted);
    assert!(contract.stage156_run_identity_reused);
    assert!(contract.stage151_owner_preflight_reused);
    assert!(contract.listener_reuse_contract_recorded);
    assert!(contract.bpf_owner_transfer_contract_recorded);
    assert!(contract.dns_cache_migration_guard_recorded);
    assert!(contract.reload_scoped_flush_after_current_swap_recorded);

    assert!(!contract.production_listener_bound);
    assert!(!contract.ebpf_attached);
    assert!(!contract.benchmark_executable_now);
    assert!(!contract.matched_go_rust_default_daemon_benchmark_recorded);
    assert!(!contract.true_rust_default_daemon_admitted);
    assert!(!contract.default_switch_allowed);
    assert!(!contract.product_chain_switch_allowed);
}
