use super::*;

#[test]
fn stage179_reviewed_corpus_verifier_matches_golden_fixture() {
    let fixture =
        load("product/daemon/stage179_matched_benchmark_reviewed_corpus_artifact_verifier.json");
    let contract = stage179_matched_benchmark_reviewed_corpus_verifier_contract();

    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.rows.len(),
        fixture["rows"].as_array().unwrap().len()
    );
    assert_string_vec(
        &contract.required_stage178_files,
        &fixture["required_stage178_files"],
    );
    assert_string_vec(&contract.remaining_blockers, &fixture["remaining_blockers"]);
}

#[test]
fn stage179_reviewed_corpus_verifier_keeps_benchmark_closed() {
    let contract = stage179_matched_benchmark_reviewed_corpus_verifier_contract();
    assert!(contract.stage_complete);
    assert!(contract.reviewed_corpus_artifact_verifier_available);
    assert!(contract.stage178_reviewed_artifact_contract_required);
    assert!(contract.explicit_stage178_root_required);
    assert!(contract.reviewed_digest_recompute_required);
    assert!(contract.redaction_evidence_required);
    assert!(contract.runtime_evidence_scope_required);
    assert!(contract.command_binding_required);
    assert!(contract.reviewed_file_set_verified);
    assert!(contract.reviewed_digest_verified);
    assert!(contract.redaction_evidence_verified);
    assert!(contract.runtime_evidence_scope_verified);
    assert!(contract.command_binding_verified);
    assert!(contract.closed_benchmark_flags_verified);

    assert!(!contract.reviewed_real_corpus_ready);
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
