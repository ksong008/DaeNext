use super::*;

#[test]
fn stage170_matched_benchmark_artifact_writer_matches_golden_fixture() {
    let fixture = load("product/daemon/stage170_matched_benchmark_artifact_writer_dry_run.json");
    let contract = stage170_matched_benchmark_artifact_writer_contract();

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
        contract.expected_file_count,
        fixture["expected_file_count"].as_u64().unwrap() as usize
    );
    assert_string_vec(&contract.remaining_blockers, &fixture["remaining_blockers"]);
}

#[test]
fn stage170_matched_benchmark_artifact_writer_keeps_daemon_execution_closed() {
    let contract = stage170_matched_benchmark_artifact_writer_contract();
    assert!(contract.stage_complete);
    assert!(contract.artifact_writer_dry_run_available);
    assert!(contract.stage169_layout_reused);
    assert!(contract.explicit_temp_root_required);
    assert!(contract.dry_run_artifact_files_written);
    assert!(contract.dry_run_manifest_written);
    assert!(contract.dry_run_file_count_verified);
    assert!(contract.cleanup_boundary_recorded);
    assert_eq!(contract.expected_file_count, 14);

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
