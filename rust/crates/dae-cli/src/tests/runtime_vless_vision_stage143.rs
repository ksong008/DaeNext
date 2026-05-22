use super::*;

#[test]
fn stage143_runtime_vless_vision_fallback_fixture_matches() {
    let fixture = load("engine/runtime_stage143/vless_vision_intrinsic_conn_fallback_gate.json");
    let output = run_with_args([
        "runtime",
        "stage143-vless-vision-intrinsic-conn-fallback-gate",
    ]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();

    assert_eq!(json["name"], fixture["name"]);
    assert_eq!(json["stage"], fixture["stage"]);
    assert!(json["vless_vision_go_fallback_admitted"].as_bool().unwrap());
    assert!(
        json["vless_vision_intrinsic_conn_go_fallback_required"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["vless_vision_tls_reality_admitted"].as_bool().unwrap());
    assert!(
        !json["vless_vision_tcp_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["vless_vision_udp_packet_conn_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        json["fallback_decision"]["go_error_boundary"],
        "XTLS only supports TLS and REALITY directly for now"
    );
}

#[test]
fn stage143_runtime_rejects_extra_args() {
    let output = run_with_args([
        "runtime",
        "stage143-vless-vision-intrinsic-conn-fallback-gate",
        "--execute-smoke",
    ]);
    assert_ne!(output.exit_code, 0);
    assert!(output.stderr.contains("unsupported stage143 argument"));
}
