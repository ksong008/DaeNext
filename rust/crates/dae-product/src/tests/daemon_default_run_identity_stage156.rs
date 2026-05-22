use super::*;

#[test]
fn stage156_default_run_identity_matches_golden_fixture() {
    let fixture = load("product/daemon/stage156_rust_default_run_identity_admission_gate.json");
    let contract = stage156_default_run_identity_gate_contract();

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
fn stage156_default_run_identity_keeps_default_switch_closed() {
    let contract = stage156_default_run_identity_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.rust_default_run_identity_harness_available);
    assert!(contract.rust_default_run_identity_optin_admitted);
    assert!(contract.rust_default_run_entrypoint_exists);
    assert!(contract.config_corpus_loaded);
    assert!(contract.run_shaped_flags_validated);
    assert!(contract.run_identity_on_ready_contract_validated);
    assert!(contract.isolated_pid_progress_paths_validated);
    assert!(contract.stage153_wrapper_reused);
    assert!(contract.go_default_path_preserved);

    assert!(!contract.production_run_command_replaced);
    assert!(!contract.production_pid_progress_paths_mutated);
    assert!(!contract.production_signal_handler_installed);
    assert!(!contract.rust_default_control_plane_entrypoint_admitted);
    assert!(!contract.production_listener_bound);
    assert!(!contract.ebpf_attached);
    assert!(!contract.benchmark_executable_now);
    assert!(!contract.matched_go_rust_default_daemon_benchmark_recorded);
    assert!(!contract.true_rust_default_daemon_admitted);
    assert!(!contract.default_switch_allowed);
    assert!(!contract.default_path_mutation_allowed);
    assert!(!contract.product_chain_switch_allowed);
}
