use super::*;

#[test]
fn stage119_juicity_live_certchain_fixture_matches() {
    let fixture = load("engine/runtime_stage119/juicity_live_certchain_admission.json");
    let output = run_with_args(["runtime", "stage119-juicity-live-certchain-admission"]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();

    assert_eq!(json, fixture);
    assert!(json["read_only"].as_bool().unwrap());
    assert!(json["blocked"].as_bool().unwrap());
    assert!(json["quinn_dependency_available"].as_bool().unwrap());
    assert!(json["h3_dependency_available"].as_bool().unwrap());
    assert!(json["h3_quinn_dependency_available"].as_bool().unwrap());
    assert!(
        json["juicity_h3_loopback_dependency_admitted"]
            .as_bool()
            .unwrap()
    );
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
        !json["juicity_pinned_certchain_live_callback_matched"]
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
    assert_eq!(
        json["live_certchain"]["generated_pin_format"]
            .as_str()
            .unwrap(),
        "url-base64"
    );
    assert!(
        json["live_certchain"]["requested_when_smoke_executes"]
            .as_bool()
            .unwrap()
    );
}

#[test]
fn stage119_juicity_live_certchain_rejects_bad_args() {
    let blocked = run_with_args([
        "runtime",
        "stage119-juicity-live-certchain-admission",
        "--benchmark-iters=0",
    ]);
    assert_eq!(blocked.exit_code, 2);
    assert!(
        blocked
            .stderr
            .contains("stage119 --benchmark-iters must be greater than zero")
    );
}
