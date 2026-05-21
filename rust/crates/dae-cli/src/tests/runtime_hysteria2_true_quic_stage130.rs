use super::*;

#[test]
fn stage130_hysteria2_true_quic_fixture_matches() {
    let fixture = load("engine/runtime_stage130/hysteria2_true_quic_dataplane_admission.json");
    let output = run_with_args([
        "runtime",
        "stage130-hysteria2-true-quic-dataplane-admission",
    ]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();

    assert_eq!(json, fixture);
    assert!(json["read_only"].as_bool().unwrap());
    assert!(json["blocked"].as_bool().unwrap());
    assert!(json["hysteria2_udp_underlay_admitted"].as_bool().unwrap());
    assert!(
        !json["hysteria2_true_quic_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        json["hysteria2_dataplane"]["property_protocol"]
            .as_str()
            .unwrap(),
        "hysteria2"
    );
    assert_eq!(
        json["hysteria2_dataplane"]["port_hopping"]["normalized_ports"],
        serde_json::json!([443, 8443, 8444])
    );
    assert_eq!(
        json["hysteria2_dataplane"]["quic"]["total_exchange_count"],
        6
    );
    assert!(
        !json["quic_h3_family_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["outbound_true_dataplane_admitted"].as_bool().unwrap());
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
}

#[test]
fn stage130_hysteria2_true_quic_rejects_bad_args() {
    for (flag, message) in [
        (
            "--stream-iters=0",
            "stage130 --stream-iters must be greater than zero",
        ),
        (
            "--datagram-iters=0",
            "stage130 --datagram-iters must be greater than zero",
        ),
        (
            "--udp-hop-interval-ms=0",
            "stage130 --udp-hop-interval-ms must be greater than zero",
        ),
        (
            "--port-hop-iters=0",
            "stage130 --port-hop-iters must be greater than zero",
        ),
    ] {
        let blocked = run_with_args([
            "runtime",
            "stage130-hysteria2-true-quic-dataplane-admission",
            flag,
        ]);
        assert_eq!(blocked.exit_code, 2);
        assert!(blocked.stderr.contains(message), "{}", blocked.stderr);
    }
}
