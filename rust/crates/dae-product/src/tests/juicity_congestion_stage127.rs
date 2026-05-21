use super::*;

#[test]
fn stage127_juicity_congestion_gate_matches_golden_fixture() {
    let fixture = load("product/daemon/stage127_juicity_congestion_gate.json");
    let contract = stage127_juicity_congestion_gate_contract();

    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.stage_complete,
        fixture["stage_complete"].as_bool().unwrap()
    );
    assert_eq!(
        contract.juicity_congestion_behavior_admitted,
        fixture["juicity_congestion_behavior_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.gate_decision,
        fixture["gate_decision"].as_str().unwrap()
    );
    assert_eq!(contract.congestion_control_effective, "bbr");
    assert_eq!(contract.rust_bbr_initial_window_bytes, 40960);
    assert_string_vec(&contract.benchmark, &fixture["benchmark"]);
    assert_string_vec(&contract.remaining_blockers, &fixture["remaining_blockers"]);
}

#[test]
fn stage127_juicity_congestion_keeps_true_h3_and_defaults_closed() {
    let contract = stage127_juicity_congestion_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.juicity_transport_packet_conn_dataplane_admitted);
    assert!(contract.juicity_stream_packet_conn_dataplane_admitted);
    assert!(contract.juicity_packet_over_stream_admitted);
    assert!(contract.juicity_congestion_bbr_controller_admitted);
    assert!(contract.juicity_congestion_sustained_relay_admitted);
    assert!(contract.juicity_congestion_behavior_admitted);
    assert_eq!(contract.congestion_control_effective, "bbr");
    assert_eq!(contract.go_cwnd_param, 10);
    assert_eq!(contract.go_bbr_initial_congestion_window_packets, 32);
    assert_eq!(contract.go_bbr_initial_packet_size_ipv4, 1280);
    assert_eq!(contract.rust_bbr_initial_window_bytes, 40960);
    assert_eq!(contract.default_iterations, 16);
    assert_eq!(contract.default_max_in_flight_streams, 4);
    assert_eq!(contract.request_payload_len, 4096);
    assert_eq!(contract.response_payload_len, 1024);
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

    assert_contains_text(&contract.remaining_blockers, "full Juicity");
    assert_contains_text(&contract.validation_commands, "stage127");
}
