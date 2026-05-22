use super::*;

#[test]
fn stage168_matched_benchmark_execution_matches_golden_fixture() {
    let fixture =
        load("product/daemon/stage168_matched_default_daemon_benchmark_execution_gate.json");
    let contract = stage168_matched_benchmark_execution_gate_contract();

    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.rows.len(),
        fixture["rows"].as_array().unwrap().len()
    );
    assert_string_vec(&contract.remaining_blockers, &fixture["remaining_blockers"]);
    assert_string_vec(
        &contract.matched_benchmark_corpus,
        &fixture["matched_benchmark_corpus"],
    );
    assert_string_vec(
        &contract.artifact_requirements,
        &fixture["artifact_requirements"],
    );
}

#[test]
fn stage168_matched_benchmark_execution_keeps_default_benchmark_closed() {
    let contract = stage168_matched_benchmark_execution_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.matched_benchmark_execution_gate_refreshed);
    assert!(contract.stage167_bounded_metrics_carried);
    assert!(contract.matched_benchmark_corpus_reconfirmed);
    assert!(contract.go_default_daemon_required);
    assert!(contract.rust_optin_daemon_required);
    assert!(contract.same_host_execution_requirements_reconfirmed);
    assert!(contract.artifact_requirements_reconfirmed);
    assert!(contract.rollback_cleanup_requirements_reconfirmed);
    assert!(contract.go_default_path_preserved);
    assert!(contract.go_fallback_required);

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
