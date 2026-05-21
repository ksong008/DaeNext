use super::*;

#[test]
fn stage114_juicity_h3_blocker_queue_fixture_matches() {
    let fixture = load("engine/runtime_stage114/juicity_h3_client_blocker_queue.json");
    let output = run_with_args(["runtime", "stage114-juicity-h3-client-blocker-queue"]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();

    assert_eq!(json, fixture);
    assert!(json["read_only"].as_bool().unwrap());
    assert!(json["blocked"].as_bool().unwrap());
    assert!(
        json["juicity_native_optin_contract_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        json["juicity_pinned_certchain_decode_contract_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        json["juicity_udp_port_zero_dialauth_contract_recorded"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["juicity_h3_handshake_admitted"].as_bool().unwrap());
    assert!(
        !json["juicity_tls_certchain_verification_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["juicity_transport_packet_conn_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["juicity_true_quic_h3_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["quic_h3_family_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["outbound_true_dataplane_admitted"].as_bool().unwrap());
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
    assert!(!json["product_chain_switch_allowed"].as_bool().unwrap());
}

#[test]
fn stage114_juicity_h3_blocker_queue_rejects_extra_args() {
    let blocked = run_with_args([
        "runtime",
        "stage114-juicity-h3-client-blocker-queue",
        "--execute-smoke",
    ]);
    assert_eq!(blocked.exit_code, 2);
    assert!(
        blocked
            .stderr
            .contains("unsupported stage114 argument: --execute-smoke")
    );
}
