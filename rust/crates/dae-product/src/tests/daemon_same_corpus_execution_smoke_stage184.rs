use super::*;

#[test]
fn stage184_same_corpus_daemon_execution_smoke_matches_golden_fixture() {
    let fixture = load("product/daemon/stage184_same_corpus_daemon_execution_smoke.json");
    let contract = stage184_same_corpus_daemon_execution_smoke_contract();

    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.stage183_required_files.len(),
        fixture["stage183_required_files"].as_array().unwrap().len()
    );
    assert_eq!(
        contract.stage184_expected_files.len(),
        fixture["stage184_expected_files"].as_array().unwrap().len()
    );
    assert_eq!(
        contract.gates.len(),
        fixture["gates"].as_array().unwrap().len()
    );
    assert_string_vec(&contract.remaining_blockers, &fixture["remaining_blockers"]);
}

#[test]
fn stage184_same_corpus_daemon_execution_smoke_keeps_hard_gates_closed() {
    let contract = stage184_same_corpus_daemon_execution_smoke_contract();
    assert!(contract.stage_complete);
    assert!(contract.same_corpus_daemon_execution_smoke_available);
    assert!(contract.stage183_admission_bundle_required);
    assert!(contract.stage183_bundle_verified);
    assert!(contract.reviewed_corpus_digest_verified);
    assert!(contract.go_command_template_owner_verified);
    assert!(contract.rust_command_template_owner_verified);
    assert!(contract.same_corpus_binding_verified);
    assert!(contract.go_default_identity_smoke_passed);
    assert!(contract.rust_optin_identity_smoke_passed);
    assert!(contract.daemon_execution_gate_identity_smoke_passed);
    assert_eq!(contract.gates.len(), 6);

    assert!(!contract.go_default_production_daemon_executed);
    assert!(!contract.rust_production_dae_run_command_admitted);
    assert!(!contract.production_listener_bound);
    assert!(!contract.production_tc_attach_smoke_passed);
    assert!(!contract.ebpf_attached);
    assert!(!contract.production_dataplane_admitted);
    assert!(!contract.reload_runtime_parity_admitted);
    assert!(!contract.real_benchmark_corpus_materialized);
    assert!(!contract.benchmark_executable_now);
    assert!(!contract.matched_go_rust_default_daemon_benchmark_recorded);
    assert!(!contract.true_rust_default_daemon_admitted);
    assert!(!contract.default_switch_allowed);
    assert!(!contract.default_path_mutation_allowed);
    assert!(!contract.product_chain_switch_allowed);
}
