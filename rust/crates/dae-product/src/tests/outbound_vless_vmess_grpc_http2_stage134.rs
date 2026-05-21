use super::*;

#[test]
fn stage134_vless_vmess_grpc_http2_gate_matches_golden_fixture() {
    let fixture = load("product/daemon/stage134_vless_vmess_grpc_http2_lifecycle_gate.json");
    let contract = stage134_vless_vmess_grpc_http2_gate_contract();

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
fn stage134_vless_vmess_grpc_http2_admits_only_subrows() {
    let contract = stage134_vless_vmess_grpc_http2_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.vless_protocol_partial_admitted);
    assert!(contract.vmess_protocol_partial_admitted);
    assert!(contract.vless_grpc_http2_lifecycle_admitted);
    assert!(contract.vmess_grpc_http2_lifecycle_admitted);
    assert!(contract.outbound_quic_go_dependency_preserved);
    assert!(contract.external_outbound_required);
    assert!(contract.external_quic_go_required);
    assert!(contract.go_default_path_preserved);
    assert!(contract.go_fallback_required);

    assert!(!contract.vless_tls_utls_reality_vision_admitted);
    assert!(!contract.vmess_tls_utls_wss_admitted);
    assert!(!contract.vless_xhttp_h2_h3_lifecycle_admitted);
    assert!(!contract.vmess_xhttp_h2_lifecycle_admitted);
    assert!(!contract.vless_protocol_true_dataplane_admitted);
    assert!(!contract.vmess_protocol_true_dataplane_admitted);
    assert!(!contract.trojan_go_shared_transport_admitted);
    assert!(!contract.shared_transport_true_dataplane_admitted);
    assert!(!contract.outbound_true_dataplane_admitted);
    assert!(!contract.matched_go_rust_default_daemon_benchmark_recorded);
    assert!(!contract.default_switch_allowed);
    assert!(!contract.default_path_mutation_allowed);
    assert!(!contract.product_chain_switch_allowed);
    assert!(!contract.true_rust_default_daemon_admitted);
}
