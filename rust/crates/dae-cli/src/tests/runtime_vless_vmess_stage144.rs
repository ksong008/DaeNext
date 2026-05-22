use super::*;

#[test]
fn stage144_runtime_vless_vmess_recertification_fixture_matches() {
    let fixture =
        load("engine/runtime_stage144/vless_vmess_fallback_aware_recertification_gate.json");
    let output = run_with_args([
        "runtime",
        "stage144-vless-vmess-fallback-aware-recertification-gate",
    ]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();

    assert_eq!(json["name"], fixture["name"]);
    assert_eq!(json["stage"], fixture["stage"]);
    assert!(
        json["vless_vmess_fallback_aware_recertified"]
            .as_bool()
            .unwrap()
    );
    assert!(
        json["vless_reality_go_fallback_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(json["vless_vision_go_fallback_admitted"].as_bool().unwrap());
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
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
}

#[test]
fn stage144_runtime_rejects_extra_args() {
    let output = run_with_args([
        "runtime",
        "stage144-vless-vmess-fallback-aware-recertification-gate",
        "--execute-smoke",
    ]);
    assert_ne!(output.exit_code, 0);
    assert!(output.stderr.contains("unsupported stage144 argument"));
}
