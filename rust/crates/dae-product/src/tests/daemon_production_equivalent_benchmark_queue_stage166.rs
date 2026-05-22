use super::*;

#[test]
fn stage166_production_equivalent_benchmark_queue_matches_golden_fixture() {
    let fixture = load(
        "product/daemon/stage166_production_equivalent_listener_ebpf_benchmark_admission_queue_gate.json",
    );
    let contract = stage166_production_equivalent_benchmark_queue_gate_contract();

    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.rows.len(),
        fixture["rows"].as_array().unwrap().len()
    );
    assert_string_vec(&contract.remaining_blockers, &fixture["remaining_blockers"]);
}

#[test]
fn stage166_production_equivalent_benchmark_queue_keeps_benchmark_closed() {
    let contract = stage166_production_equivalent_benchmark_queue_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.production_equivalent_benchmark_queue_recorded);
    assert!(contract.stage160_listener_preflight_carried);
    assert!(contract.stage161_map_preflight_carried);
    assert!(contract.stage162_program_attach_preflight_carried);
    assert!(contract.stage164_listener_handoff_smoke_carried);
    assert!(contract.stage165_reload_owner_handoff_smoke_carried);
    assert!(contract.benchmark_corpus_reconfirmed);

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
