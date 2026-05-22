use super::*;

#[test]
fn stage153_run_entrypoint_gate_matches_golden_fixture() {
    let fixture = load("product/daemon/stage153_rust_run_entrypoint_preflight_gate.json");
    let contract = stage153_run_entrypoint_preflight_gate_contract();

    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.gate_decision,
        fixture["gate_decision"].as_str().unwrap()
    );
    assert_string_vec(&contract.remaining_blockers, &fixture["remaining_blockers"]);
}

#[test]
fn stage153_run_entrypoint_keeps_default_closed() {
    let contract = stage153_run_entrypoint_preflight_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.non_default_run_entrypoint_wrapper_available);
    assert!(contract.run_entrypoint_wrapper_composed);
    assert!(contract.run_entrypoint_lifecycle_smoke_reused);
    assert!(contract.run_entrypoint_signal_control_plane_smoke_reused);
    assert!(contract.run_entrypoint_on_ready_contract_recorded);
    assert!(contract.run_entrypoint_flag_contract_recorded);
    assert!(contract.go_default_run_command_preserved);
    assert!(contract.go_default_path_preserved);

    assert!(!contract.production_run_command_replaced);
    assert!(!contract.production_pid_progress_paths_mutated);
    assert!(!contract.production_signal_handler_installed);
    assert!(!contract.production_listener_bound);
    assert!(!contract.ebpf_attached);
    assert!(!contract.rust_default_run_entrypoint_exists);
    assert!(!contract.rust_default_control_plane_entrypoint_admitted);
    assert!(!contract.benchmark_executable_now);
    assert!(!contract.matched_go_rust_default_daemon_benchmark_recorded);
    assert!(!contract.true_rust_default_daemon_admitted);
    assert!(!contract.default_switch_allowed);
    assert!(!contract.product_chain_switch_allowed);
}
