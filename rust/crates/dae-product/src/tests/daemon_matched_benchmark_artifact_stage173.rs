use super::*;

#[test]
fn stage173_matched_benchmark_command_capture_verifier_matches_golden_fixture() {
    let fixture =
        load("product/daemon/stage173_matched_benchmark_command_capture_artifact_verifier.json");
    let contract = stage173_matched_benchmark_command_capture_verifier_contract();

    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.rows.len(),
        fixture["rows"].as_array().unwrap().len()
    );
    assert_string_vec(
        &contract.required_stage172_files,
        &fixture["required_stage172_files"],
    );
    assert_string_vec(&contract.remaining_blockers, &fixture["remaining_blockers"]);
}

#[test]
fn stage173_matched_benchmark_command_capture_verifier_keeps_daemons_closed() {
    let contract = stage173_matched_benchmark_command_capture_verifier_contract();
    assert!(contract.stage_complete);
    assert!(contract.command_capture_artifact_verifier_available);
    assert!(contract.stage172_command_capture_contract_required);
    assert!(contract.explicit_stage172_root_required);
    assert!(contract.command_template_symmetry_verified);
    assert!(contract.stage171_digest_input_verified);
    assert!(contract.runtime_evidence_contract_verified);
    assert!(contract.rust_optin_blocker_verified);

    assert!(!contract.rust_production_dae_run_command_exists);
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
