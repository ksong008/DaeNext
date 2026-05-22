use super::*;

#[test]
fn stage141_vless_reality_synthetic_utls_gate_matches_golden_fixture() {
    let fixture =
        load("product/daemon/stage141_vless_reality_synthetic_utls_raw_mutation_gate.json");
    let contract = stage141_vless_reality_synthetic_utls_gate_contract();

    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.mutation_report_count,
        fixture["mutation_report_count"].as_u64().unwrap() as usize
    );
    assert_eq!(
        contract.profile_preserved_count,
        fixture["profile_preserved_count"].as_u64().unwrap() as usize
    );
    assert_eq!(
        contract.gate_decision,
        fixture["gate_decision"].as_str().unwrap()
    );
    assert_string_vec(&contract.benchmark_record, &fixture["benchmark_record"]);
    assert_string_vec(&contract.remaining_blockers, &fixture["remaining_blockers"]);
}

#[test]
fn stage141_vless_reality_synthetic_utls_keeps_full_reality_closed() {
    let contract = stage141_vless_reality_synthetic_utls_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.vless_reality_synthetic_utls_raw_mutation_admitted);
    assert_eq!(contract.mutation_report_count, 12);
    assert_eq!(contract.profile_preserved_count, 12);
    assert_eq!(contract.session_id_hello_raw_offset, 39);
    assert_eq!(contract.session_id_record_offset, 44);

    assert!(!contract.vless_reality_full_handshake_admitted);
    assert!(!contract.vless_reality_verify_peer_certificate_admitted);
    assert!(!contract.vless_reality_spider_fallback_admitted);
    assert!(!contract.vless_utls_fingerprint_wire_admitted);
    assert!(!contract.vmess_utls_fingerprint_wire_admitted);
    assert!(!contract.vless_vision_tls_reality_admitted);
    assert!(!contract.vless_protocol_true_dataplane_admitted);
    assert!(!contract.vmess_protocol_true_dataplane_admitted);
    assert!(!contract.shared_transport_true_dataplane_admitted);
    assert!(!contract.outbound_true_dataplane_admitted);
    assert!(!contract.default_switch_allowed);
    assert!(!contract.product_chain_switch_allowed);
}
