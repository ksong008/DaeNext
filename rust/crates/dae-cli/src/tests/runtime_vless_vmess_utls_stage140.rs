use super::*;

#[test]
fn stage140_runtime_utls_profile_builder_fixture_matches() {
    let fixture = load("engine/runtime_stage140/vless_vmess_utls_profile_builder_gate.json");
    let output = run_with_args(["runtime", "stage140-vless-vmess-utls-profile-builder-gate"]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();

    assert_eq!(json["name"], fixture["name"]);
    assert_eq!(json["stage"], fixture["stage"]);
    assert_eq!(json["evidence_class"], fixture["evidence_class"]);
    assert!(
        json["utls_wire_profile_builder_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        json["utls_profile_builder"]["sample_count"],
        fixture["utls_profile_builder"]["sample_count"]
    );
    assert_eq!(
        json["utls_profile_builder"]["roundtrip_profile_match_count"],
        fixture["utls_profile_builder"]["roundtrip_profile_match_count"]
    );
    assert!(
        json["utls_profile_builder"]["all_synthetic_profiles_match_source"]
            .as_bool()
            .unwrap()
    );
    assert!(
        json["utls_profile_builder"]["random_and_key_share_bytes_are_synthetic"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["utls_wire_full_handshake_builder_admitted"]
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
}

#[test]
fn stage140_runtime_rejects_extra_args() {
    let output = run_with_args([
        "runtime",
        "stage140-vless-vmess-utls-profile-builder-gate",
        "--execute-smoke",
    ]);
    assert_ne!(output.exit_code, 0);
    assert!(output.stderr.contains("unsupported stage140 argument"));
}
