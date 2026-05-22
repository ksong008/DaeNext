use super::*;

#[test]
fn stage150_daemon_lifecycle_smoke_gate_matches_golden_fixture() {
    let fixture = load("product/daemon/stage150_rust_daemon_lifecycle_smoke_gate.json");
    let contract = stage150_daemon_lifecycle_smoke_gate_contract();

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
fn stage150_daemon_lifecycle_smoke_keeps_default_closed() {
    let contract = stage150_daemon_lifecycle_smoke_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.rust_daemon_identity_scaffolded);
    assert!(contract.rust_daemon_lifecycle_smoke_harness_available);
    assert!(contract.rust_daemon_lifecycle_smoke_passed);
    assert!(contract.isolated_pid_progress_paths_validated);
    assert!(!contract.production_paths_mutated);
    assert!(contract.go_default_path_preserved);

    assert!(!contract.rust_default_run_entrypoint_exists);
    assert!(!contract.rust_default_control_plane_entrypoint_admitted);
    assert!(!contract.benchmark_executable_now);
    assert!(!contract.matched_go_rust_default_daemon_benchmark_recorded);
    assert!(!contract.true_rust_default_daemon_admitted);
    assert!(!contract.default_switch_allowed);
    assert!(!contract.product_chain_switch_allowed);
}
