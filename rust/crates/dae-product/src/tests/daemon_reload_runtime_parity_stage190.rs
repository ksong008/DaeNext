use super::*;

#[test]
fn stage190_live_reload_runtime_parity_matches_golden_fixture() {
    let fixture =
        load("product/daemon/stage190_live_reload_runtime_parity_execution_evidence_gate.json");
    let contract = stage190_live_reload_runtime_parity_execution_evidence_gate_contract();

    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.stage189_required_files.len(),
        fixture["stage189_required_files"].as_array().unwrap().len()
    );
    assert_eq!(
        contract.stage190_expected_files.len(),
        fixture["stage190_expected_files"].as_array().unwrap().len()
    );
    assert_eq!(
        contract.rows.len(),
        fixture["rows"].as_array().unwrap().len()
    );
    assert_eq!(
        contract.gates.len(),
        fixture["gates"].as_array().unwrap().len()
    );
    assert_string_vec(&contract.remaining_blockers, &fixture["remaining_blockers"]);
}

#[test]
fn stage190_live_reload_runtime_parity_keeps_hard_gates_closed() {
    let contract = stage190_live_reload_runtime_parity_execution_evidence_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.live_reload_runtime_parity_execution_evidence_gate_available);
    assert!(contract.stage189_dataplane_bundle_required);
    assert!(contract.stage189_dataplane_bundle_verified);
    assert!(contract.listener_reuse_gap_available);
    assert!(contract.listener_reuse_gap_written);
    assert!(contract.bpf_owner_transfer_gap_available);
    assert!(contract.bpf_owner_transfer_gap_written);
    assert!(contract.dns_cache_migration_guard_gap_available);
    assert!(contract.dns_cache_migration_guard_gap_written);
    assert!(contract.bounded_close_runtime_overview_gap_available);
    assert!(contract.bounded_close_runtime_overview_gap_written);
    assert!(contract.stage191_bounded_benchmark_input_written);
    assert_eq!(contract.rows.len(), 6);
    assert_eq!(contract.gates.len(), 6);

    assert!(!contract.hard_gates_resolved);
    assert!(!contract.rust_production_dae_run_command_admitted);
    assert!(!contract.production_listener_bound);
    assert!(!contract.listen_socket_map_written);
    assert!(!contract.production_tc_attach_smoke_passed);
    assert!(!contract.ebpf_attached);
    assert!(!contract.netns_setup_executed);
    assert!(!contract.dae0_attach_executed);
    assert!(!contract.bpf_owner_handoff_executed);
    assert!(!contract.production_dataplane_admitted);
    assert!(!contract.live_reload_executed);
    assert!(!contract.production_listener_reused);
    assert!(!contract.production_bpf_owner_transferred);
    assert!(!contract.production_dns_cache_migrated);
    assert!(!contract.dns_cache_migration_guard_verified);
    assert!(!contract.bounded_close_verified);
    assert!(!contract.runtime_overview_parity_verified);
    assert!(!contract.reload_scoped_resources_flushed);
    assert!(!contract.reload_runtime_parity_admitted);
    assert!(!contract.benchmark_readiness_admitted);
    assert!(!contract.benchmark_executable_now);
    assert!(!contract.bounded_benchmark_executed);
    assert!(!contract.matched_go_rust_default_daemon_benchmark_recorded);
    assert!(!contract.true_rust_default_daemon_admitted);
    assert!(!contract.default_switch_allowed);
    assert!(!contract.default_path_mutation_allowed);
    assert!(!contract.product_chain_switch_allowed);
}
