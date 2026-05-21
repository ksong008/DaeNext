use super::*;

#[test]
fn stage135_vless_vmess_tls_gate_matches_golden_fixture() {
    let fixture = load("product/daemon/stage135_vless_vmess_tls_wss_httpupgrade_gate.json");
    let contract = stage135_vless_vmess_tls_gate_contract();

    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.stage_complete,
        fixture["stage_complete"].as_bool().unwrap()
    );
    assert_eq!(
        contract.gate_decision,
        fixture["gate_decision"].as_str().unwrap()
    );
    assert_string_vec(&contract.benchmark_record, &fixture["benchmark_record"]);
    assert_string_vec(&contract.remaining_blockers, &fixture["remaining_blockers"]);
}

#[test]
fn stage135_vless_vmess_tls_gate_admits_only_transport_subrows() {
    let contract = stage135_vless_vmess_tls_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.vless_grpc_http2_lifecycle_admitted);
    assert!(contract.vmess_grpc_http2_lifecycle_admitted);
    assert!(contract.vless_wss_tls_lifecycle_admitted);
    assert!(contract.vmess_wss_tls_lifecycle_admitted);
    assert!(contract.vless_https_httpupgrade_tls_lifecycle_admitted);
    assert!(contract.vmess_https_httpupgrade_tls_lifecycle_admitted);

    assert!(!contract.vless_utls_fingerprint_wire_admitted);
    assert!(!contract.vmess_utls_fingerprint_wire_admitted);
    assert!(!contract.vless_reality_full_handshake_admitted);
    assert!(!contract.vless_vision_tls_reality_admitted);
    assert!(!contract.vless_xhttp_h2_h3_lifecycle_admitted);
    assert!(!contract.vmess_xhttp_h2_lifecycle_admitted);
    assert!(!contract.vless_protocol_true_dataplane_admitted);
    assert!(!contract.vmess_protocol_true_dataplane_admitted);
    assert!(!contract.shared_transport_true_dataplane_admitted);
    assert!(!contract.outbound_true_dataplane_admitted);
    assert!(!contract.default_switch_allowed);
    assert!(!contract.product_chain_switch_allowed);
}
