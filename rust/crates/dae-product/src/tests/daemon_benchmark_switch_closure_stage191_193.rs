use super::*;

#[test]
fn stage191_benchmark_admission_input_matches_golden_fixture() {
    let fixture =
        load("product/daemon/stage191_bounded_same_corpus_benchmark_admission_input_gate.json");
    let contract = stage191_bounded_same_corpus_benchmark_admission_input_gate_contract();

    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.stage190_required_files.len(),
        fixture["stage190_required_files"].as_array().unwrap().len()
    );
    assert_eq!(
        contract.stage191_expected_files.len(),
        fixture["stage191_expected_files"].as_array().unwrap().len()
    );
    assert_eq!(
        contract.rows.len(),
        fixture["rows"].as_array().unwrap().len()
    );
    assert_eq!(
        contract.gates.len(),
        fixture["gates"].as_array().unwrap().len()
    );
    assert_string_vec(&contract.remaining_blockers, &fixture["remaining_blockers"]);
}

#[test]
fn stage192_switch_recertification_input_matches_golden_fixture() {
    let fixture =
        load("product/daemon/stage192_default_product_switch_recertification_input_gate.json");
    let contract = stage192_default_product_switch_recertification_input_gate_contract();

    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.stage191_required_files.len(),
        fixture["stage191_required_files"].as_array().unwrap().len()
    );
    assert_eq!(
        contract.stage192_expected_files.len(),
        fixture["stage192_expected_files"].as_array().unwrap().len()
    );
    assert_eq!(
        contract.rows.len(),
        fixture["rows"].as_array().unwrap().len()
    );
    assert_eq!(
        contract.gates.len(),
        fixture["gates"].as_array().unwrap().len()
    );
    assert_string_vec(&contract.remaining_blockers, &fixture["remaining_blockers"]);
}

#[test]
fn stage193_switch_hard_gate_closure_matches_golden_fixture() {
    let fixture = load("product/daemon/stage193_default_product_switch_hard_gate_closure.json");
    let contract = stage193_default_product_switch_hard_gate_closure_contract();

    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.stage192_required_files.len(),
        fixture["stage192_required_files"].as_array().unwrap().len()
    );
    assert_eq!(
        contract.stage193_expected_files.len(),
        fixture["stage193_expected_files"].as_array().unwrap().len()
    );
    assert_eq!(
        contract.rows.len(),
        fixture["rows"].as_array().unwrap().len()
    );
    assert_eq!(
        contract.gates.len(),
        fixture["gates"].as_array().unwrap().len()
    );
    assert_string_vec(&contract.remaining_blockers, &fixture["remaining_blockers"]);
}

#[test]
fn stage191_193_contracts_keep_benchmark_and_switch_gates_closed() {
    let stage191 = stage191_bounded_same_corpus_benchmark_admission_input_gate_contract();
    assert!(stage191.stage_complete);
    assert!(stage191.bounded_same_corpus_benchmark_admission_input_gate_available);
    assert!(stage191.stage190_reload_runtime_bundle_required);
    assert!(stage191.stage190_reload_runtime_bundle_verified);
    assert!(stage191.production_dataplane_blocker_written);
    assert!(stage191.reload_runtime_parity_blocker_written);
    assert!(stage191.matched_benchmark_command_blocker_written);
    assert!(stage191.stage192_default_product_switch_input_written);
    assert!(!stage191.hard_gates_resolved);
    assert!(!stage191.production_dataplane_admitted);
    assert!(!stage191.reload_runtime_parity_admitted);
    assert!(!stage191.benchmark_executable_now);
    assert!(!stage191.matched_go_rust_default_daemon_benchmark_recorded);
    assert!(!stage191.true_rust_default_daemon_admitted);
    assert!(!stage191.default_switch_allowed);
    assert!(!stage191.default_path_mutation_allowed);
    assert!(!stage191.product_chain_switch_allowed);

    let stage192 = stage192_default_product_switch_recertification_input_gate_contract();
    assert!(stage192.stage_complete);
    assert!(stage192.default_product_switch_recertification_input_gate_available);
    assert!(stage192.stage191_benchmark_admission_bundle_required);
    assert!(stage192.stage191_benchmark_admission_bundle_verified);
    assert!(stage192.default_daemon_switch_blocker_written);
    assert!(stage192.product_chain_switch_blocker_written);
    assert!(stage192.rollback_recertification_gap_written);
    assert!(stage192.stage193_hard_gate_input_written);
    assert!(!stage192.hard_gates_resolved);
    assert!(!stage192.production_dataplane_admitted);
    assert!(!stage192.reload_runtime_parity_admitted);
    assert!(!stage192.benchmark_executable_now);
    assert!(!stage192.matched_go_rust_default_daemon_benchmark_recorded);
    assert!(!stage192.true_rust_default_daemon_admitted);
    assert!(!stage192.default_switch_allowed);
    assert!(!stage192.default_path_mutation_allowed);
    assert!(!stage192.product_chain_switch_allowed);

    let stage193 = stage193_default_product_switch_hard_gate_closure_contract();
    assert!(stage193.stage_complete);
    assert!(stage193.default_product_switch_hard_gate_closure_available);
    assert!(stage193.stage192_recertification_bundle_required);
    assert!(stage193.stage192_recertification_bundle_verified);
    assert!(stage193.default_switch_hard_gate_summary_written);
    assert!(stage193.product_chain_hard_gate_summary_written);
    assert!(stage193.benchmark_dataplane_reload_blocker_summary_written);
    assert!(stage193.stage194_true_production_execution_input_written);
    assert!(!stage193.hard_gates_resolved);
    assert!(!stage193.production_dataplane_admitted);
    assert!(!stage193.reload_runtime_parity_admitted);
    assert!(!stage193.benchmark_executable_now);
    assert!(!stage193.matched_go_rust_default_daemon_benchmark_recorded);
    assert!(!stage193.true_rust_default_daemon_admitted);
    assert!(!stage193.default_switch_allowed);
    assert!(!stage193.default_path_mutation_allowed);
    assert!(!stage193.product_chain_switch_allowed);
}
