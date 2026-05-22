use super::*;

#[test]
fn stage171_matched_benchmark_metadata_digest_matches_golden_fixture() {
    let fixture =
        load("product/daemon/stage171_matched_benchmark_metadata_corpus_digest_dry_run.json");
    let contract = stage171_matched_benchmark_metadata_digest_contract();

    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.rows.len(),
        fixture["rows"].as_array().unwrap().len()
    );
    assert_string_vec(&contract.dry_run_files, &fixture["dry_run_files"]);
    assert_string_vec(&contract.remaining_blockers, &fixture["remaining_blockers"]);
}

#[test]
fn stage171_matched_benchmark_metadata_digest_keeps_real_benchmark_closed() {
    let contract = stage171_matched_benchmark_metadata_digest_contract();
    assert!(contract.stage_complete);
    assert!(contract.host_metadata_dry_run_available);
    assert!(contract.host_metadata_snapshot_written);
    assert!(contract.corpus_digest_dry_run_available);
    assert!(contract.corpus_digest_written);
    assert!(contract.outbound_matrix_digest_written);
    assert!(contract.dry_run_corpus_placeholder_recorded);
    assert_eq!(contract.digest_algorithm, "blake3");

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
