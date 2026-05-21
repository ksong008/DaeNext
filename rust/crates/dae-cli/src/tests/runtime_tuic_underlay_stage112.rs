use super::*;

#[test]
fn stage112_tuic_underlay_fixture_matches() {
    let fixture = load("engine/runtime_stage112/tuic_udp_underlay_admission.json");
    let output = run_with_args(["runtime", "stage112-tuic-udp-underlay-admission"]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();

    assert_eq!(json, fixture);
    assert!(json["read_only"].as_bool().unwrap());
    assert!(!json["blocked"].as_bool().unwrap());
    assert!(json["tuic_underlay_contract_admitted"].as_bool().unwrap());
    assert!(
        !json["tuic_udp_underlay_socket_smoke_passed"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["tuic_udp_underlay_socket_admitted"].as_bool().unwrap());
    assert!(!json["tuic_so_mark_loopback_observed"].as_bool().unwrap());
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
fn stage112_tuic_underlay_requires_root_ack_for_smoke() {
    let blocked = run_with_args([
        "runtime",
        "stage112-tuic-udp-underlay-admission",
        "--execute-smoke",
    ]);
    assert_eq!(blocked.exit_code, 1);
    assert!(
        blocked
            .stdout
            .contains("stage112 root-gated smoke requires --ack-root-gate")
    );
}

#[test]
fn stage112_tuic_underlay_rejects_bad_args() {
    let blocked = run_with_args([
        "runtime",
        "stage112-tuic-udp-underlay-admission",
        "--benchmark-iters=0",
    ]);
    assert_eq!(blocked.exit_code, 2);
    assert!(
        blocked
            .stderr
            .contains("stage112 --benchmark-iters must be greater than zero")
    );
}
