use super::*;

#[test]
fn stage128_juicity_client_integration_gate_matches_golden_fixture() {
    let fixture = load("product/daemon/stage128_juicity_client_integration_gate.json");
    let contract = stage128_juicity_client_integration_gate_contract();

    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.stage_complete,
        fixture["stage_complete"].as_bool().unwrap()
    );
    assert_eq!(
        contract.juicity_client_integration_candidate_admitted,
        fixture["juicity_client_integration_candidate_admitted"]
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
fn stage128_juicity_client_integration_keeps_true_h3_and_defaults_closed() {
    let contract = stage128_juicity_client_integration_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.juicity_transport_packet_conn_dataplane_admitted);
    assert!(contract.juicity_stream_packet_conn_dataplane_admitted);
    assert!(contract.juicity_packet_over_stream_admitted);
    assert!(contract.juicity_congestion_behavior_admitted);
    assert!(contract.juicity_client_integration_candidate_admitted);
    assert!(contract.juicity_full_local_client_smoke_admitted);
    assert!(contract.juicity_client_capability_matrix_admitted);
    assert_eq!(contract.alpn_protocol, "h3");
    assert!(contract.tls13_only_configured);
    assert!(contract.quic_datagram_disabled);
    assert_eq!(contract.keepalive_secs, 5);
    assert_eq!(contract.handshake_idle_timeout_secs, 8);
    assert_eq!(contract.default_auth_iterations, 1);
    assert_eq!(contract.default_transport_iterations, 8);
    assert_eq!(contract.default_stream_iterations, 2);
    assert_eq!(contract.default_congestion_iterations, 8);
    assert_eq!(contract.default_total_exchange_count, 19);
    assert_eq!(contract.default_max_in_flight_streams, 4);
    assert!(contract.anytls_true_dataplane_admitted);
    assert!(contract.protocol_outbound_partial_admitted);
    assert!(contract.outbound_quic_go_dependency_preserved);
    assert!(contract.external_outbound_required);
    assert!(contract.external_quic_go_required);
    assert!(contract.go_default_path_preserved);
    assert!(contract.go_fallback_required);

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

    assert_contains_text(&contract.remaining_blockers, "matched Go");
    assert_contains_text(&contract.validation_commands, "stage128");
}
