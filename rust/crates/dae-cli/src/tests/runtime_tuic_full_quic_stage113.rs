use super::*;

#[test]
fn stage113_tuic_full_quic_blocker_queue_fixture_matches() {
    let fixture = load("engine/runtime_stage113/tuic_full_quic_client_blocker_queue.json");
    let output = run_with_args(["runtime", "stage113-tuic-full-quic-client-blocker-queue"]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();

    assert_eq!(json, fixture);
    assert!(json["read_only"].as_bool().unwrap());
    assert!(json["blocked"].as_bool().unwrap());
    assert!(json["tuic_udp_underlay_socket_admitted"].as_bool().unwrap());
    assert!(json["tuic_so_mark_loopback_observed"].as_bool().unwrap());
    assert!(!json["tuic_full_quic_handshake_admitted"].as_bool().unwrap());
    assert!(!json["tuic_auth_stream_admitted"].as_bool().unwrap());
    assert!(
        !json["tuic_datagram_packet_relay_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["tuic_udp_relay_mode_quic_effective_relay_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["tuic_true_quic_dataplane_admitted"].as_bool().unwrap());
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
fn stage113_tuic_full_quic_blocker_queue_rejects_extra_args() {
    let blocked = run_with_args([
        "runtime",
        "stage113-tuic-full-quic-client-blocker-queue",
        "--execute-smoke",
    ]);
    assert_eq!(blocked.exit_code, 2);
    assert!(
        blocked
            .stderr
            .contains("unsupported stage113 argument: --execute-smoke")
    );
}
