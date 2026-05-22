use super::*;

#[test]
fn stage180_readiness_queue_matches_golden_fixture() {
    let fixture = load(
        "product/daemon/stage180_matched_benchmark_reviewed_corpus_readiness_admission_queue_gate.json",
    );
    let contract = stage180_matched_benchmark_reviewed_corpus_readiness_queue_contract();

    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.rows.len(),
        fixture["rows"].as_array().unwrap().len()
    );
    assert_string_vec(
        &contract.readiness_requirements,
        &fixture["readiness_requirements"],
    );
    assert_string_vec(&contract.remaining_blockers, &fixture["remaining_blockers"]);
}

#[test]
fn stage180_readiness_queue_keeps_benchmark_closed() {
    let contract = stage180_matched_benchmark_reviewed_corpus_readiness_queue_contract();
    assert!(contract.stage_complete);
    assert!(contract.reviewed_corpus_readiness_admission_queue_recorded);
    assert!(contract.stage178_reviewed_artifact_carried);
    assert!(contract.stage179_verifier_evidence_carried);
    assert!(contract.verified_file_set_required);
    assert!(contract.verified_digest_required);
    assert!(contract.redaction_runtime_command_evidence_required);
    assert!(contract.runtime_readiness_blockers_recorded);
    assert!(contract.benchmark_readiness_blockers_recorded);
    assert!(contract.default_switch_blockers_recorded);

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
