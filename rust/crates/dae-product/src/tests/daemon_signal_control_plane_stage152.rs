use super::*;

#[test]
fn stage152_signal_control_plane_gate_matches_golden_fixture() {
    let fixture = load("product/daemon/stage152_rust_signal_control_plane_smoke_gate.json");
    let contract = stage152_signal_control_plane_smoke_gate_contract();

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
fn stage152_signal_control_plane_keeps_default_closed() {
    let contract = stage152_signal_control_plane_smoke_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.rust_daemon_lifecycle_smoke_passed);
    assert!(contract.rust_control_plane_owner_preflight_recorded);
    assert!(contract.rust_signal_control_plane_smoke_passed);
    assert!(contract.reload_signal_progress_owner_sequence_validated);
    assert!(contract.suspend_signal_progress_sequence_validated);
    assert!(contract.abort_file_one_shot_consumed);
    assert!(contract.isolated_pid_removed_on_stop);
    assert!(contract.stage151_owner_preflight_reused);
    assert!(contract.go_default_path_preserved);

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
