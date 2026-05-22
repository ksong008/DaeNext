use super::*;

#[test]
fn stage178_reviewed_corpus_materializer_matches_golden_fixture() {
    let fixture =
        load("product/daemon/stage178_matched_benchmark_reviewed_corpus_materializer_dry_run.json");
    let contract = stage178_matched_benchmark_reviewed_corpus_materializer_contract();

    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.rows.len(),
        fixture["rows"].as_array().unwrap().len()
    );
    assert_string_vec(&contract.reviewed_files, &fixture["reviewed_files"]);
    assert_string_vec(
        &contract.reviewed_artifact_requirements,
        &fixture["reviewed_artifact_requirements"],
    );
    assert_string_vec(&contract.remaining_blockers, &fixture["remaining_blockers"]);
}

#[test]
fn stage178_reviewed_corpus_materializer_keeps_benchmark_closed() {
    let contract = stage178_matched_benchmark_reviewed_corpus_materializer_contract();
    assert!(contract.stage_complete);
    assert!(contract.reviewed_corpus_artifact_dry_run_available);
    assert!(contract.stage177_review_admission_queue_carried);
    assert!(contract.reviewed_config_artifact_available);
    assert!(contract.reviewed_outbound_matrix_artifact_available);
    assert!(contract.reviewed_digest_contract_available);
    assert!(contract.review_admission_evidence_carried);
    assert!(contract.runtime_evidence_scope_carried);
    assert!(contract.command_binding_carried);
    assert!(contract.redaction_evidence_carried);
    assert!(contract.explicit_temp_root_required);
    assert!(contract.reviewed_corpus_artifact_written);
    assert!(contract.reviewed_manifest_written);
    assert!(contract.reviewed_config_written);
    assert!(contract.reviewed_outbound_matrix_written);
    assert!(contract.reviewed_digest_written);
    assert!(contract.review_admission_evidence_written);
    assert!(contract.runtime_evidence_scope_written);
    assert!(contract.command_binding_written);

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
