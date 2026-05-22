use super::*;

#[test]
fn stage183_corpus_command_admission_matches_golden_fixture() {
    let fixture = load("product/daemon/stage183_corpus_command_admission_binding_dry_run.json");
    let contract = stage183_corpus_command_admission_binding_contract();

    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.bundle_files.len(),
        fixture["bundle_files"].as_array().unwrap().len()
    );
    assert_eq!(
        contract.closed_gates.len(),
        fixture["closed_gates"].as_array().unwrap().len()
    );
    assert_eq!(
        contract.command_templates.len(),
        fixture["command_templates"].as_array().unwrap().len()
    );
}

#[test]
fn stage183_corpus_command_admission_keeps_benchmark_closed() {
    let contract = stage183_corpus_command_admission_binding_contract();
    assert!(contract.stage_complete);
    assert!(contract.corpus_command_admission_binding_available);
    assert!(contract.stage178_reviewed_artifact_carried);
    assert!(contract.stage179_verifier_carried);
    assert!(contract.stage182_preflight_carried);
    assert!(contract.go_rust_command_templates_bound);
    assert!(contract.explicit_temp_root_required);
    assert!(contract.admission_bundle_written);

    assert_eq!(contract.closed_gates.len(), 6);
    assert!(!contract.benchmark_executable_now);
    assert!(!contract.matched_go_rust_default_daemon_benchmark_recorded);
    assert!(!contract.default_switch_allowed);
}
