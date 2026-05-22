use super::*;

#[test]
fn stage165_daemon_reload_owner_handoff_matches_golden_fixture() {
    let fixture =
        load("product/daemon/stage165_non_production_daemon_reload_owner_handoff_smoke_gate.json");
    let contract = stage165_daemon_reload_owner_handoff_gate_contract();

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
fn stage165_daemon_reload_owner_handoff_keeps_production_and_defaults_closed() {
    let contract = stage165_daemon_reload_owner_handoff_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.reload_owner_handoff_harness_available);
    assert!(contract.non_production_daemon_reload_owner_transfer_smoke_passed);
    assert!(contract.reload_current_swap_smoke_passed);
    assert!(contract.old_owner_close_smoke_passed);
    assert!(contract.listener_reuse_sequence_smoke_passed);
    assert!(contract.reload_scoped_cleanup_smoke_passed);
    assert!(contract.rollback_blocker_recorded);
    assert!(contract.listen_socket_map_key_handoff_smoke_passed);

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
