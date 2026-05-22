use super::*;

#[test]
fn stage140_vless_vmess_utls_profile_builder_gate_matches_golden_fixture() {
    let fixture = load("product/daemon/stage140_vless_vmess_utls_profile_builder_gate.json");
    let contract = stage140_vless_vmess_utls_profile_builder_gate_contract();

    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.stage_complete,
        fixture["stage_complete"].as_bool().unwrap()
    );
    assert_eq!(
        contract.synthetic_record_count,
        fixture["synthetic_record_count"].as_u64().unwrap() as usize
    );
    assert_eq!(
        contract.roundtrip_profile_match_count,
        fixture["roundtrip_profile_match_count"].as_u64().unwrap() as usize
    );
    assert_eq!(
        contract.gate_decision,
        fixture["gate_decision"].as_str().unwrap()
    );
    assert_string_vec(&contract.benchmark_record, &fixture["benchmark_record"]);
    assert_string_vec(&contract.remaining_blockers, &fixture["remaining_blockers"]);
}

#[test]
fn stage140_vless_vmess_utls_profile_builder_keeps_full_handshake_closed() {
    let contract = stage140_vless_vmess_utls_profile_builder_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.utls_wire_profile_builder_admitted);
    assert!(!contract.utls_wire_full_handshake_builder_admitted);
    assert_eq!(contract.synthetic_record_count, 6);
    assert_eq!(contract.roundtrip_profile_match_count, 6);

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
