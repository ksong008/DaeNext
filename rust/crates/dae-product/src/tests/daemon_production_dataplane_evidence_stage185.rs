use super::*;

#[test]
fn stage185_production_dataplane_evidence_matches_golden_fixture() {
    let fixture =
        load("product/daemon/stage185_production_dataplane_listener_tc_ebpf_evidence_gate.json");
    let contract = stage185_production_dataplane_evidence_gate_contract();

    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.stage184_required_files.len(),
        fixture["stage184_required_files"].as_array().unwrap().len()
    );
    assert_eq!(
        contract.stage185_expected_files.len(),
        fixture["stage185_expected_files"].as_array().unwrap().len()
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
fn stage185_production_dataplane_evidence_keeps_hard_gates_closed() {
    let contract = stage185_production_dataplane_evidence_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.production_dataplane_evidence_gate_available);
    assert!(contract.stage184_explicit_smoke_required);
    assert!(contract.stage184_smoke_verified);
    assert!(contract.stage184_daemon_execution_gate_carried);
    assert!(contract.go_rust_identity_smoke_carried);
    assert!(contract.listener_socket_map_contract_available);
    assert!(contract.tc_ebpf_attach_contract_available);
    assert!(contract.bpf_owner_handoff_contract_available);
    assert!(contract.production_dataplane_evidence_contract_written);
    assert!(contract.stage186_reload_runtime_input_written);
    assert_eq!(contract.rows.len(), 4);
    assert_eq!(contract.gates.len(), 6);

    assert!(!contract.rust_production_dae_run_command_admitted);
    assert!(!contract.production_listener_bound);
    assert!(!contract.listen_socket_map_written);
    assert!(!contract.production_tc_attach_smoke_passed);
    assert!(!contract.ebpf_attached);
    assert!(!contract.production_dataplane_admitted);
    assert!(!contract.reload_runtime_parity_admitted);
    assert!(!contract.real_benchmark_corpus_materialized);
    assert!(!contract.benchmark_executable_now);
    assert!(!contract.matched_go_rust_default_daemon_benchmark_recorded);
    assert!(!contract.true_rust_default_daemon_admitted);
    assert!(!contract.default_switch_allowed);
    assert!(!contract.default_path_mutation_allowed);
    assert!(!contract.product_chain_switch_allowed);
}
