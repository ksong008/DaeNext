use super::*;

#[test]
fn stage172_matched_benchmark_command_capture_matches_golden_fixture() {
    let fixture = load("product/daemon/stage172_matched_benchmark_command_capture_dry_run.json");
    let contract = stage172_matched_benchmark_command_capture_contract();

    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.rows.len(),
        fixture["rows"].as_array().unwrap().len()
    );
    assert_eq!(
        contract.command_templates.len(),
        fixture["command_templates"].as_array().unwrap().len()
    );
    assert_string_vec(&contract.dry_run_files, &fixture["dry_run_files"]);
    assert_string_vec(&contract.remaining_blockers, &fixture["remaining_blockers"]);
}

#[test]
fn stage172_matched_benchmark_command_capture_keeps_execution_closed() {
    let contract = stage172_matched_benchmark_command_capture_contract();
    assert!(contract.stage_complete);
    assert!(contract.command_capture_dry_run_available);
    assert!(contract.go_default_command_template_written);
    assert!(contract.rust_optin_command_template_written);
    assert!(contract.command_capture_contract_written);
    assert!(contract.stage171_digest_contract_required);
    assert!(contract.stage157_control_plane_evidence_required);
    assert!(contract.command_capture_symmetry_recorded);
    assert!(contract.explicit_temp_root_required);

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
