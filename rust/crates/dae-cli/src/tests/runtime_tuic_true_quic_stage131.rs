use super::*;

#[test]
fn stage131_tuic_true_quic_fixture_matches() {
    let fixture = load("engine/runtime_stage131/tuic_true_quic_dataplane_admission.json");
    let output = run_with_args(["runtime", "stage131-tuic-true-quic-dataplane-admission"]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();

    assert_eq!(json, fixture);
    assert!(json["read_only"].as_bool().unwrap());
    assert!(json["blocked"].as_bool().unwrap());
    assert!(json["tuic_underlay_contract_admitted"].as_bool().unwrap());
    assert!(!json["tuic_true_quic_dataplane_admitted"].as_bool().unwrap());
    assert!(
        !json["tuic_udp_relay_mode_quic_effective_relay_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        json["tuic_dataplane"]["property_protocol"]
            .as_str()
            .unwrap(),
        "tuic"
    );
    assert_eq!(json["tuic_dataplane"]["quic"]["total_exchange_count"], 5);
    assert!(
        json["hysteria2_true_quic_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        json["juicity_true_quic_h3_dataplane_admitted"]
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
}

#[test]
fn stage131_tuic_true_quic_rejects_bad_args() {
    let blocked = run_with_args([
        "runtime",
        "stage131-tuic-true-quic-dataplane-admission",
        "--datagram-iters=0",
    ]);
    assert_eq!(blocked.exit_code, 2);
    assert!(
        blocked
            .stderr
            .contains("stage131 --datagram-iters must be greater than zero"),
        "{}",
        blocked.stderr
    );
}
