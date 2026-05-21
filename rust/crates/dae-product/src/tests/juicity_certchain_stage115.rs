use super::*;

#[test]
fn stage115_juicity_certchain_verifier_gate_matches_golden_fixture() {
    let fixture = load("product/daemon/stage115_juicity_certchain_verifier_gate.json");
    let contract = stage115_juicity_certchain_verifier_gate_contract();

    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.stage_complete,
        fixture["stage_complete"].as_bool().unwrap()
    );
    assert_eq!(
        contract.juicity_certchain_hash_algorithm_admitted,
        fixture["juicity_certchain_hash_algorithm_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.juicity_tls_certchain_verification_admitted,
        fixture["juicity_tls_certchain_verification_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.go_chain_hash_hex,
        fixture["go_chain_hash_hex"].as_str().unwrap()
    );
    assert_eq!(
        contract.gate_decision,
        fixture["gate_decision"].as_str().unwrap()
    );
    assert_string_vec(
        &contract.benchmark_carry_forward,
        &fixture["benchmark_carry_forward"],
    );
    assert_string_vec(&contract.remaining_blockers, &fixture["remaining_blockers"]);
}

#[test]
fn stage115_juicity_certchain_verifier_keeps_live_h3_and_defaults_closed() {
    let contract = stage115_juicity_certchain_verifier_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.juicity_native_optin_contract_admitted);
    assert!(contract.juicity_pinned_certchain_decode_contract_admitted);
    assert!(contract.juicity_certchain_hash_algorithm_admitted);
    assert!(contract.juicity_pinned_certchain_url_base64_verify_vector_admitted);
    assert!(contract.juicity_pinned_certchain_std_base64_verify_vector_admitted);
    assert!(contract.juicity_pinned_certchain_hex_decode_caveat_recorded);
    assert!(contract.juicity_pinned_certchain_forces_insecure_verify_contract_admitted);
    assert!(contract.juicity_pinned_certchain_full_chain_hash_contract_admitted);
    assert!(contract.juicity_pinned_certchain_not_hysteria2_pin_sha256_recorded);
    assert_eq!(
        contract.go_chain_hash_hex,
        "584fb94485a58b9036f20086e915df79e51c4eb8b7dbb46fb75a113bb656bf4e"
    );
    assert!(contract.url_base64_pin_matched);
    assert!(contract.std_base64_pin_matched);
    assert_eq!(contract.hex_looking_sha256_pin_format, "url-base64");
    assert!(!contract.hex_looking_sha256_pin_matched);
    assert!(!contract.juicity_tls_verify_peer_certificate_hook_admitted);
    assert!(!contract.juicity_tls_certchain_verification_admitted);
    assert!(!contract.juicity_h3_handshake_admitted);
    assert!(!contract.juicity_dialauth_over_h3_admitted);
    assert!(!contract.juicity_transport_packet_conn_dataplane_admitted);
    assert!(!contract.juicity_stream_packet_conn_dataplane_admitted);
    assert!(!contract.juicity_true_quic_h3_dataplane_admitted);
    assert!(!contract.quic_h3_family_true_dataplane_admitted);
    assert!(!contract.outbound_true_dataplane_admitted);
    assert!(!contract.matched_go_rust_default_daemon_benchmark_recorded);
    assert!(!contract.default_switch_allowed);
    assert!(!contract.default_path_mutation_allowed);
    assert!(!contract.product_chain_switch_allowed);
    assert!(!contract.true_rust_default_daemon_admitted);
    assert!(contract.outbound_quic_go_dependency_preserved);
    assert!(contract.external_outbound_required);
    assert!(contract.external_quic_go_required);
    assert!(contract.go_default_path_preserved);
    assert!(contract.go_fallback_required);

    assert_contains_text(&contract.remaining_blockers, "VerifyPeerCertificate");
    assert_contains_text(&contract.validation_commands, "stage115");
}
