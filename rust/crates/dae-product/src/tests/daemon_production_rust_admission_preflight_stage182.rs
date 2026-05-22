use super::*;

#[test]
fn stage182_production_rust_daemon_admission_preflight_matches_golden_fixture() {
    let fixture = load("product/daemon/stage182_production_rust_daemon_admission_preflight.json");
    let contract = stage182_production_rust_daemon_admission_preflight_contract();

    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.rows.len(),
        fixture["rows"].as_array().unwrap().len()
    );
    assert_string_vec(
        &contract.admission_requirements,
        &fixture["admission_requirements"],
    );
    assert_string_vec(&contract.remaining_blockers, &fixture["remaining_blockers"]);
}

#[test]
fn stage182_production_rust_daemon_admission_preflight_keeps_admission_closed() {
    let contract = stage182_production_rust_daemon_admission_preflight_contract();
    assert!(contract.stage_complete);
    assert!(contract.production_rust_daemon_admission_preflight_recorded);
    assert!(contract.stage181_runtime_blocker_carried);
    assert!(contract.command_identity_checked);
    assert!(contract.config_corpus_binding_checked);
    assert!(contract.progress_pid_signal_lifecycle_checked);
    assert!(contract.startup_reload_control_plane_requirements_checked);
    assert!(contract.default_path_isolation_checked);
    assert!(contract.benchmark_exclusion_checked);

    assert!(!contract.reviewed_real_corpus_ready);
    assert!(!contract.rust_production_dae_run_command_exists);
    assert!(!contract.rust_production_run_command_admitted);
    assert!(!contract.real_benchmark_corpus_materialized);
    assert!(!contract.go_default_daemon_executed);
    assert!(!contract.rust_optin_daemon_executed);
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
