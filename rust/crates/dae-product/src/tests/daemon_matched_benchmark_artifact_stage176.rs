use super::*;

#[test]
fn stage176_real_corpus_candidate_verifier_matches_golden_fixture() {
    let fixture = load(
        "product/daemon/stage176_matched_benchmark_real_corpus_candidate_artifact_verifier.json",
    );
    let contract = stage176_matched_benchmark_real_corpus_candidate_verifier_contract();

    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.rows.len(),
        fixture["rows"].as_array().unwrap().len()
    );
    assert_string_vec(
        &contract.required_stage175_files,
        &fixture["required_stage175_files"],
    );
    assert_string_vec(&contract.remaining_blockers, &fixture["remaining_blockers"]);
}

#[test]
fn stage176_real_corpus_candidate_verifier_keeps_materialization_closed() {
    let contract = stage176_matched_benchmark_real_corpus_candidate_verifier_contract();
    assert!(contract.stage_complete);
    assert!(contract.real_corpus_candidate_artifact_verifier_available);
    assert!(contract.stage175_candidate_contract_required);
    assert!(contract.explicit_stage175_root_required);
    assert!(contract.candidate_digest_recompute_required);
    assert!(contract.candidate_review_pending_required);
    assert!(contract.candidate_file_set_verified);
    assert!(contract.candidate_digest_verified);
    assert!(contract.candidate_review_boundary_verified);
    assert!(contract.closed_benchmark_flags_verified);

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
