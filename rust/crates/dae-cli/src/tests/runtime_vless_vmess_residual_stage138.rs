use super::*;

#[test]
fn stage138_runtime_blocker_fixture_matches() {
    let fixture = load("engine/runtime_stage138/vless_vmess_utls_reality_vision_blocker_gate.json");
    let output = run_with_args([
        "runtime",
        "stage138-vless-vmess-utls-reality-vision-blocker-gate",
    ]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();

    assert_eq!(json["name"], fixture["name"]);
    assert_eq!(json["stage"], fixture["stage"]);
    assert_eq!(json["evidence_class"], fixture["evidence_class"]);
    assert!(json["read_only"].as_bool().unwrap());
    assert!(json["blocked"].as_bool().unwrap());
    assert!(
        json["vless_xhttp_h2_h3_lifecycle_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        json["vmess_xhttp_h2_h3_lifecycle_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["vless_utls_fingerprint_wire_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["vmess_utls_fingerprint_wire_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["vless_reality_full_handshake_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["vless_vision_tls_reality_admitted"].as_bool().unwrap());
    assert!(
        !json["vless_protocol_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["vmess_protocol_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        json["residual_blocker_matrix"]["utls"]["rustls_is_not_utls"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["residual_blocker_matrix"]["vision"]["intrinsic_tls_reality_conn_hook_admitted"]
            .as_bool()
            .unwrap()
    );
}

#[test]
fn stage138_runtime_rejects_extra_args() {
    let output = run_with_args([
        "runtime",
        "stage138-vless-vmess-utls-reality-vision-blocker-gate",
        "--execute-smoke",
    ]);
    assert_ne!(output.exit_code, 0);
    assert!(output.stderr.contains("unsupported stage138 argument"));
}
