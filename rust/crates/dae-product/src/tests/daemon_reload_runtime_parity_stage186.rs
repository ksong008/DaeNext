use super::*;

#[test]
fn stage186_reload_runtime_parity_matches_golden_fixture() {
    let fixture = load("product/daemon/stage186_reload_runtime_parity_evidence_gate.json");
    let contract = stage186_reload_runtime_parity_gate_contract();

    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.stage185_required_files.len(),
        fixture["stage185_required_files"].as_array().unwrap().len()
    );
    assert_eq!(
        contract.stage186_expected_files.len(),
        fixture["stage186_expected_files"].as_array().unwrap().len()
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
fn stage186_reload_runtime_parity_keeps_hard_gates_closed() {
    let contract = stage186_reload_runtime_parity_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.reload_runtime_parity_gate_available);
    assert!(contract.stage185_evidence_bundle_required);
    assert!(contract.stage185_evidence_verified);
    assert!(contract.stage185_dataplane_contract_carried);
    assert!(contract.listener_reuse_contract_available);
    assert!(contract.bpf_owner_transfer_contract_available);
    assert!(contract.dns_cache_migration_guard_available);
    assert!(contract.bounded_close_contract_available);
    assert!(contract.runtime_overview_parity_contract_available);
    assert!(contract.reload_runtime_parity_contract_written);
    assert!(contract.benchmark_readiness_input_written);
    assert_eq!(contract.rows.len(), 5);
    assert_eq!(contract.gates.len(), 6);

    assert!(!contract.live_reload_executed);
    assert!(!contract.production_listener_reused);
    assert!(!contract.production_bpf_owner_transferred);
    assert!(!contract.production_dns_cache_migrated);
    assert!(!contract.runtime_overview_parity_admitted);
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
