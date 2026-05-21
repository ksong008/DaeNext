use super::*;

#[test]
fn stage119_juicity_live_certchain_gate_matches_golden_fixture() {
    let fixture = load("product/daemon/stage119_juicity_live_certchain_gate.json");
    let contract = stage119_juicity_live_certchain_gate_contract();

    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.stage_complete,
        fixture["stage_complete"].as_bool().unwrap()
    );
    assert_eq!(
        contract.juicity_tls_certchain_verification_admitted,
        fixture["juicity_tls_certchain_verification_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.juicity_pinned_certchain_live_callback_matched,
        fixture["juicity_pinned_certchain_live_callback_matched"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.juicity_pinned_certchain_live_pin_format,
        fixture["juicity_pinned_certchain_live_pin_format"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        contract.juicity_true_quic_h3_dataplane_admitted,
        fixture["juicity_true_quic_h3_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.gate_decision,
        fixture["gate_decision"].as_str().unwrap()
    );
    assert_string_vec(&contract.benchmark, &fixture["benchmark"]);
    assert_string_vec(&contract.remaining_blockers, &fixture["remaining_blockers"]);
}

#[test]
fn stage119_juicity_live_certchain_keeps_dataplane_and_defaults_closed() {
    let contract = stage119_juicity_live_certchain_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.quinn_dependency_available);
    assert!(contract.h3_dependency_available);
    assert!(contract.h3_quinn_dependency_available);
    assert!(contract.tokio_quic_runtime_admitted);
    assert!(contract.juicity_h3_loopback_dependency_admitted);
    assert!(contract.juicity_h3_loopback_smoke_executed);
    assert!(contract.juicity_h3_loopback_benchmark_recorded);
    assert!(contract.juicity_tls13_h3_alpn_loopback_admitted);
    assert!(contract.juicity_tls_verify_peer_certificate_hook_admitted);
    assert!(contract.juicity_tls_certchain_verification_admitted);
    assert!(contract.juicity_pinned_certchain_live_callback_matched);
    assert_eq!(
        contract.juicity_pinned_certchain_live_pin_format,
        "url-base64"
    );
    assert!(contract.juicity_h3_handshake_admitted);
    assert!(contract.anytls_true_dataplane_admitted);
    assert!(contract.protocol_outbound_partial_admitted);
    assert!(contract.outbound_quic_go_dependency_preserved);
    assert!(contract.external_outbound_required);
    assert!(contract.external_quic_go_required);
    assert!(contract.go_default_path_preserved);
    assert!(contract.go_fallback_required);

    assert!(!contract.juicity_dialauth_over_h3_admitted);
    assert!(!contract.juicity_transport_packet_conn_dataplane_admitted);
    assert!(!contract.juicity_stream_packet_conn_dataplane_admitted);
    assert!(!contract.juicity_true_quic_h3_dataplane_admitted);
    assert!(!contract.hysteria2_true_quic_dataplane_admitted);
    assert!(!contract.tuic_true_quic_dataplane_admitted);
    assert!(!contract.quic_h3_family_true_dataplane_admitted);
    assert!(!contract.outbound_true_dataplane_admitted);
    assert!(!contract.matched_go_rust_default_daemon_benchmark_recorded);
    assert!(!contract.default_switch_allowed);
    assert!(!contract.default_path_mutation_allowed);
    assert!(!contract.product_chain_switch_allowed);
    assert!(!contract.true_rust_default_daemon_admitted);

    assert_contains_text(&contract.remaining_blockers, "DialAuth");
    assert_contains_text(&contract.validation_commands, "stage119");
}
