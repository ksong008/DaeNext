use super::*;

#[test]
fn stage177_real_corpus_review_queue_matches_golden_fixture() {
    let fixture = load(
        "product/daemon/stage177_matched_benchmark_real_corpus_review_admission_queue_gate.json",
    );
    let contract = stage177_matched_benchmark_real_corpus_review_queue_gate_contract();

    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.rows.len(),
        fixture["rows"].as_array().unwrap().len()
    );
    assert_string_vec(
        &contract.review_admission_requirements,
        &fixture["review_admission_requirements"],
    );
    assert_string_vec(&contract.remaining_blockers, &fixture["remaining_blockers"]);
}

#[test]
fn stage177_real_corpus_review_queue_keeps_materialization_closed() {
    let contract = stage177_matched_benchmark_real_corpus_review_queue_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.real_corpus_review_admission_queue_recorded);
    assert!(contract.stage175_candidate_boundary_carried);
    assert!(contract.stage176_candidate_verifier_carried);
    assert!(contract.reviewed_config_input_required);
    assert!(contract.reviewed_outbound_matrix_required);
    assert!(contract.digest_provenance_required);
    assert!(contract.redaction_evidence_required);
    assert!(contract.runtime_evidence_scope_required);
    assert!(contract.command_binding_required);
    assert!(contract.reviewer_signoff_required);

    assert!(!contract.reviewed_real_corpus_ready);
    assert!(!contract.real_benchmark_corpus_materialized);
    assert!(!contract.go_default_daemon_executed);
    assert!(!contract.rust_optin_daemon_executed);
    assert!(!contract.benchmark_executable_now);
    assert!(!contract.default_switch_allowed);
    assert!(!contract.product_chain_switch_allowed);
}
