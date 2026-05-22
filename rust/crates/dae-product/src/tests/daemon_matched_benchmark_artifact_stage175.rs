use super::*;

#[test]
fn stage175_matched_benchmark_real_corpus_candidate_matches_golden_fixture() {
    let fixture = load(
        "product/daemon/stage175_matched_benchmark_real_corpus_candidate_materializer_dry_run.json",
    );
    let contract = stage175_matched_benchmark_real_corpus_candidate_materializer_contract();

    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.rows.len(),
        fixture["rows"].as_array().unwrap().len()
    );
    assert_string_vec(&contract.candidate_files, &fixture["candidate_files"]);
    assert_string_vec(&contract.remaining_blockers, &fixture["remaining_blockers"]);
}

#[test]
fn stage175_matched_benchmark_real_corpus_candidate_keeps_real_corpus_closed() {
    let contract = stage175_matched_benchmark_real_corpus_candidate_materializer_contract();
    assert!(contract.stage_complete);
    assert!(contract.real_corpus_candidate_materializer_dry_run_available);
    assert!(contract.stage174_materialization_queue_carried);
    assert!(contract.candidate_digest_contract_available);
    assert!(contract.candidate_manifest_written);
    assert!(contract.candidate_corpus_written);
    assert!(contract.candidate_outbound_matrix_written);
    assert!(contract.candidate_digest_written);
    assert!(contract.candidate_review_contract_written);
    assert!(contract.candidate_review_pending);
    assert_eq!(contract.digest_algorithm, "blake3");

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
