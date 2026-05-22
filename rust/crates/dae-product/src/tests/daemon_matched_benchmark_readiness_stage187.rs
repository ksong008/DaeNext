use super::*;

#[test]
fn stage187_matched_benchmark_readiness_matches_golden_fixture() {
    let fixture = load("product/daemon/stage187_matched_benchmark_readiness_gate.json");
    let contract = stage187_matched_benchmark_readiness_gate_contract();

    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.stage186_required_files.len(),
        fixture["stage186_required_files"].as_array().unwrap().len()
    );
    assert_eq!(
        contract.stage187_expected_files.len(),
        fixture["stage187_expected_files"].as_array().unwrap().len()
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
fn stage187_matched_benchmark_readiness_keeps_hard_gates_closed() {
    let contract = stage187_matched_benchmark_readiness_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.matched_benchmark_readiness_gate_available);
    assert!(contract.stage186_parity_bundle_required);
    assert!(contract.stage186_parity_bundle_verified);
    assert!(contract.stage184_185_evidence_carried_by_stage186);
    assert!(contract.hard_gate_checklist_available);
    assert!(contract.hard_gate_checklist_written);
    assert!(contract.same_corpus_command_plan_available);
    assert!(contract.same_corpus_command_plan_written);
    assert!(contract.execution_blocker_queue_available);
    assert!(contract.benchmark_execution_blockers_written);
    assert!(contract.stage188_bounded_benchmark_input_written);
    assert_eq!(contract.rows.len(), 4);
    assert_eq!(contract.gates.len(), 6);

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
