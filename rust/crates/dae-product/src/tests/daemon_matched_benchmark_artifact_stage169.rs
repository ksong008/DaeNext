use super::*;

#[test]
fn stage169_matched_benchmark_artifact_matches_golden_fixture() {
    let fixture = load("product/daemon/stage169_matched_benchmark_corpus_artifact_builder.json");
    let contract = stage169_matched_benchmark_artifact_builder_contract();

    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.rows.len(),
        fixture["rows"].as_array().unwrap().len()
    );
    assert_eq!(
        contract.artifact_layout.len(),
        fixture["artifact_layout"].as_array().unwrap().len()
    );
    assert_eq!(
        contract.command_plan.len(),
        fixture["command_plan"].as_array().unwrap().len()
    );
    assert_string_vec(
        &contract.symmetry_requirements,
        &fixture["symmetry_requirements"],
    );
    assert_string_vec(&contract.remaining_blockers, &fixture["remaining_blockers"]);
}

#[test]
fn stage169_matched_benchmark_artifact_keeps_execution_closed() {
    let contract = stage169_matched_benchmark_artifact_builder_contract();
    assert!(contract.stage_complete);
    assert!(contract.matched_benchmark_artifact_layout_materialized);
    assert!(contract.command_plan_recorded);
    assert!(contract.same_corpus_layout_recorded);
    assert!(contract.go_rust_artifact_symmetry_recorded);
    assert!(contract.stage167_bounded_summary_required);
    assert!(contract.host_metadata_required);
    assert!(contract.bpf_dns_runtime_artifacts_required);

    assert!(!contract.artifact_files_written_to_runtime_dir);
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
