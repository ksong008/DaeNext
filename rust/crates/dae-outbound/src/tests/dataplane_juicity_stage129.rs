use super::*;

#[test]
fn stage129_juicity_outbound_dataplane_selects_alive_group_and_runs_client_smoke() {
    let outcome =
        juicity::run_outbound_dataplane_smoke(&juicity::JuicityOutboundDataplaneOptions {
            client_integration: juicity::JuicityClientIntegrationOptions {
                auth_iterations: 1,
                transport_iterations: 3,
                stream_iterations: 2,
                congestion_iterations: 4,
                max_in_flight_streams: 2,
                timeout: Duration::from_secs(12),
                ..Default::default()
            },
            ..Default::default()
        })
        .unwrap();

    assert_eq!(
        outcome.group_name,
        juicity::DEFAULT_OUTBOUND_DATAPLANE_GROUP_NAME
    );
    assert_eq!(outcome.subscription_tag, "stage129-sub");
    assert_eq!(outcome.policy, "min");
    assert_eq!(outcome.network_type, "tcp4");
    assert_eq!(outcome.raw_link_count, 3);
    assert_eq!(outcome.valid_dialer_count, 2);
    assert_eq!(outcome.skipped_link_count, 1);
    assert_eq!(outcome.direct_index, 0);
    assert_eq!(outcome.block_index, 1);
    assert_eq!(outcome.first_user_group_index, 2);
    assert!(outcome.direct_block_indices_preserved);
    assert_eq!(outcome.property_protocols, vec!["juicity", "juicity"]);
    assert_eq!(
        outcome.property_addresses,
        vec!["slow.example:443", "fast.example:8443"]
    );
    assert_eq!(outcome.selected_index, 1);
    assert_eq!(outcome.selected_name, "stage129-fast");
    assert_eq!(outcome.selected_address, "fast.example:8443");
    assert_eq!(outcome.selected_protocol, "juicity");
    assert_eq!(outcome.selected_latency_ms, 52);
    assert_eq!(outcome.alive_count, 2);
    assert!(outcome.selected_pin_forces_insecure_verify);
    assert_eq!(outcome.selected_pin_decode_format, "hex");
    assert_eq!(outcome.selected_chain_adapter_mode, "native-opt-in");
    assert!(outcome.selected_chain_parent_dialer_non_nil);

    assert_eq!(outcome.client_integration.total_exchange_count, 10);
    assert_eq!(
        outcome.client_integration.transport_roundtrip_match_count,
        3
    );
    assert_eq!(outcome.client_integration.stream_response_match_count, 2);
    assert_eq!(
        outcome.client_integration.congestion_response_match_count,
        4
    );
    assert!(
        outcome
            .client_integration
            .juicity_client_integration_candidate_admitted
    );

    assert!(outcome.juicity_outbound_registry_admitted);
    assert!(outcome.juicity_group_selection_admitted);
    assert!(outcome.juicity_health_policy_admitted);
    assert!(outcome.juicity_true_quic_h3_dataplane_admitted);
    assert!(!outcome.quic_h3_family_true_dataplane_admitted);
    assert!(!outcome.outbound_true_dataplane_admitted);
    assert!(!outcome.default_switch_allowed);
    assert!(!outcome.product_chain_switch_allowed);
}
