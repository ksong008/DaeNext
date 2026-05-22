use super::*;

#[test]
fn stage174_matched_benchmark_real_corpus_queue_matches_golden_fixture() {
    let fixture = load(
        "product/daemon/stage174_matched_benchmark_real_corpus_materialization_queue_gate.json",
    );
    let contract = stage174_matched_benchmark_real_corpus_queue_gate_contract();

    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.rows.len(),
        fixture["rows"].as_array().unwrap().len()
    );
    assert_string_vec(
        &contract.materialization_requirements,
        &fixture["materialization_requirements"],
    );
    assert_string_vec(&contract.remaining_blockers, &fixture["remaining_blockers"]);
}

#[test]
fn stage174_matched_benchmark_real_corpus_queue_keeps_materialization_closed() {
    let contract = stage174_matched_benchmark_real_corpus_queue_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.real_corpus_materialization_queue_recorded);
    assert!(contract.stage171_placeholder_boundary_carried);
    assert!(contract.stage172_command_templates_carried);
    assert!(contract.stage173_artifact_verifier_carried);
    assert!(contract.same_corpus_review_requirements_recorded);
    assert!(contract.outbound_matrix_review_required);
    assert!(contract.digest_provenance_required);
    assert!(contract.sensitive_material_redaction_required);

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
