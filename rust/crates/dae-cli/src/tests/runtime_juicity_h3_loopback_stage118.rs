use super::*;

#[test]
fn stage118_juicity_h3_loopback_fixture_matches() {
    let fixture = load("engine/runtime_stage118/juicity_h3_loopback_admission.json");
    let output = run_with_args(["runtime", "stage118-juicity-h3-loopback-admission"]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();

    assert_eq!(json, fixture);
    assert!(json["read_only"].as_bool().unwrap());
    assert!(json["blocked"].as_bool().unwrap());
    assert!(json["quinn_dependency_available"].as_bool().unwrap());
    assert!(json["h3_dependency_available"].as_bool().unwrap());
    assert!(json["h3_quinn_dependency_available"].as_bool().unwrap());
    assert!(json["tokio_quic_runtime_admitted"].as_bool().unwrap());
    assert!(
        json["juicity_h3_loopback_dependency_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["juicity_h3_loopback_smoke_executed"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["juicity_h3_handshake_admitted"].as_bool().unwrap());
    assert!(
        !json["juicity_tls_verify_peer_certificate_hook_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["juicity_tls_certchain_verification_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["juicity_true_quic_h3_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["outbound_true_dataplane_admitted"].as_bool().unwrap());
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
    assert!(!json["product_chain_switch_allowed"].as_bool().unwrap());
    assert_eq!(json["h3_loopback"]["alpn_protocol"].as_str().unwrap(), "h3");
    assert_eq!(
        json["h3_loopback"]["handshake_idle_timeout_secs"]
            .as_u64()
            .unwrap(),
        8
    );
}

#[test]
fn stage118_juicity_h3_loopback_rejects_bad_args() {
    let blocked = run_with_args([
        "runtime",
        "stage118-juicity-h3-loopback-admission",
        "--benchmark-iters=0",
    ]);
    assert_eq!(blocked.exit_code, 2);
    assert!(
        blocked
            .stderr
            .contains("stage118 --benchmark-iters must be greater than zero")
    );
}
