use super::*;

#[test]
fn stage142_runtime_vless_reality_fallback_fixture_matches() {
    let fixture = load("engine/runtime_stage142/vless_reality_full_handshake_fallback_gate.json");
    let output = run_with_args([
        "runtime",
        "stage142-vless-reality-full-handshake-fallback-gate",
    ]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();

    assert_eq!(json["name"], fixture["name"]);
    assert_eq!(json["stage"], fixture["stage"]);
    assert!(
        json["vless_reality_go_fallback_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        json["vless_reality_full_handshake_go_fallback_required"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["vless_reality_full_handshake_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["vless_reality_verify_peer_certificate_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["vless_reality_spider_fallback_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        json["fallback_decision"]["go_fallback_source"],
        "/root/project/outbound/transport/tls/reality.go"
    );
}

#[test]
fn stage142_runtime_rejects_extra_args() {
    let output = run_with_args([
        "runtime",
        "stage142-vless-reality-full-handshake-fallback-gate",
        "--execute-smoke",
    ]);
    assert_ne!(output.exit_code, 0);
    assert!(output.stderr.contains("unsupported stage142 argument"));
}
