use super::*;

#[test]
fn stage188_bounded_benchmark_hard_gate_matches_golden_fixture() {
    let fixture = load("product/daemon/stage188_bounded_benchmark_hard_gate_resolution.json");
    let contract = stage188_bounded_benchmark_hard_gate_resolution_contract();

    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.stage187_required_files.len(),
        fixture["stage187_required_files"].as_array().unwrap().len()
    );
    assert_eq!(
        contract.stage188_expected_files.len(),
        fixture["stage188_expected_files"].as_array().unwrap().len()
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
fn stage188_bounded_benchmark_hard_gate_keeps_execution_closed() {
    let contract = stage188_bounded_benchmark_hard_gate_resolution_contract();
    assert!(contract.stage_complete);
    assert!(contract.bounded_benchmark_hard_gate_resolution_available);
    assert!(contract.stage187_readiness_bundle_required);
    assert!(contract.stage187_readiness_bundle_verified);
    assert!(contract.production_dataplane_execution_queue_available);
    assert!(contract.production_dataplane_execution_queue_written);
    assert!(contract.reload_runtime_parity_execution_queue_available);
    assert!(contract.reload_runtime_parity_execution_queue_written);
    assert!(contract.benchmark_admission_blocker_queue_available);
    assert!(contract.benchmark_admission_blockers_written);
    assert!(contract.stage189_execution_input_written);
    assert_eq!(contract.rows.len(), 4);
    assert_eq!(contract.gates.len(), 6);

    assert!(!contract.hard_gates_resolved);
    assert!(!contract.rust_production_dae_run_command_admitted);
    assert!(!contract.production_listener_bound);
    assert!(!contract.listen_socket_map_written);
    assert!(!contract.production_tc_attach_smoke_passed);
    assert!(!contract.ebpf_attached);
    assert!(!contract.production_dataplane_admitted);
    assert!(!contract.live_reload_executed);
    assert!(!contract.production_listener_reused);
    assert!(!contract.production_bpf_owner_transferred);
    assert!(!contract.production_dns_cache_migrated);
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
