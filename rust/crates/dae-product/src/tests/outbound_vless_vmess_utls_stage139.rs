use super::*;

#[test]
fn stage139_vless_vmess_utls_wire_gate_matches_golden_fixture() {
    let fixture = load("product/daemon/stage139_vless_vmess_utls_wire_baseline_gate.json");
    let contract = stage139_vless_vmess_utls_wire_gate_contract();

    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.stage_complete,
        fixture["stage_complete"].as_bool().unwrap()
    );
    assert_eq!(contract.blocked, fixture["blocked"].as_bool().unwrap());
    assert_eq!(
        contract.fixture_sample_count,
        fixture["fixture_sample_count"].as_u64().unwrap() as usize
    );
    assert_eq!(
        contract.parsed_profile_count,
        fixture["parsed_profile_count"].as_u64().unwrap() as usize
    );
    assert_eq!(
        contract.profile_match_count,
        fixture["profile_match_count"].as_u64().unwrap() as usize
    );
    assert_eq!(
        contract.gate_decision,
        fixture["gate_decision"].as_str().unwrap()
    );
    assert_string_vec(&contract.benchmark_record, &fixture["benchmark_record"]);
    assert_string_vec(&contract.remaining_blockers, &fixture["remaining_blockers"]);
}

#[test]
fn stage139_vless_vmess_utls_wire_gate_keeps_protocol_wide_closed() {
    let contract = stage139_vless_vmess_utls_wire_gate_contract();
    assert!(contract.stage_complete);
    assert!(!contract.blocked);
    assert!(contract.utls_wire_baseline_fixture_recorded);
    assert!(contract.utls_wire_profile_parser_admitted);
    assert_eq!(contract.fixture_sample_count, 6);
    assert_eq!(contract.parsed_profile_count, 6);
    assert_eq!(contract.profile_match_count, 6);

    assert!(!contract.vless_utls_fingerprint_wire_admitted);
    assert!(!contract.vmess_utls_fingerprint_wire_admitted);
    assert!(!contract.vless_reality_full_handshake_admitted);
    assert!(!contract.vless_vision_tls_reality_admitted);
    assert!(!contract.vless_protocol_true_dataplane_admitted);
    assert!(!contract.vmess_protocol_true_dataplane_admitted);
    assert!(!contract.shared_transport_true_dataplane_admitted);
    assert!(!contract.outbound_true_dataplane_admitted);
    assert!(!contract.matched_go_rust_default_daemon_benchmark_recorded);
    assert!(!contract.default_switch_allowed);
    assert!(!contract.product_chain_switch_allowed);
}
