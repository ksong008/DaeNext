use super::*;

#[test]
fn stage148_daemon_identity_preflight_gate_matches_golden_fixture() {
    let fixture = load("product/daemon/stage148_rust_daemon_identity_preflight_gate.json");
    let contract = stage148_daemon_identity_preflight_gate_contract();

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
fn stage148_daemon_identity_preflight_keeps_benchmark_closed() {
    let contract = stage148_daemon_identity_preflight_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.rust_daemon_identity_preflight_recorded);
    assert!(contract.go_default_daemon_identity_preserved);
    assert!(contract.cli_optin_helper_identity_recorded);
    assert!(contract.go_default_path_preserved);
    assert!(contract.go_fallback_required);

    assert!(!contract.rust_daemon_crate_manifest_exists);
    assert!(!contract.rust_default_run_entrypoint_exists);
    assert!(!contract.rust_default_control_plane_entrypoint_admitted);
    assert!(!contract.true_rust_daemon_binary_exists);
    assert!(!contract.benchmark_executable_now);
    assert!(!contract.matched_go_rust_default_daemon_benchmark_recorded);
    assert!(!contract.true_rust_default_daemon_admitted);
    assert!(!contract.default_switch_allowed);
    assert!(!contract.product_chain_switch_allowed);

    assert_eq!(contract.next_admission_queue[0].stage, "stage149");
    assert_eq!(contract.next_admission_queue[1].stage, "stage150");
}
