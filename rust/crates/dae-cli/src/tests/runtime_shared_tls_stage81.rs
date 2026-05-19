use super::*;

#[test]
fn stage81_runtime_admission_fixture_matches() {
    let fixture = load("engine/runtime_stage81/shared_tls_underlay_dataplane_admission.json");
    let output = run_with_args(["runtime", "stage81-shared-tls-underlay-dataplane-admission"]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();

    assert_eq!(
        json["name"].as_str().unwrap(),
        fixture["name"].as_str().unwrap()
    );
    assert_eq!(
        json["stage"].as_str().unwrap(),
        fixture["stage"].as_str().unwrap()
    );
    assert_eq!(
        json["evidence_class"].as_str().unwrap(),
        fixture["evidence_class"].as_str().unwrap()
    );
    assert!(!json["execute_smoke"].as_bool().unwrap());
    assert!(json["read_only"].as_bool().unwrap());
    assert!(!json["blocked"].as_bool().unwrap());
    assert!(!json["shared_tls_underlay_smoke_passed"].as_bool().unwrap());
    assert!(!json["shared_tls_underlay_admitted"].as_bool().unwrap());
    assert!(!json["https_proxy_tls_underlay_admitted"].as_bool().unwrap());
    assert!(!json["trojan_tls_underlay_admitted"].as_bool().unwrap());
    assert!(!json["vless_tls_underlay_admitted"].as_bool().unwrap());
    assert!(!json["vmess_tls_underlay_admitted"].as_bool().unwrap());
    assert!(
        !json["shared_transport_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        json["shared_tls_contract"]["server_name"].as_str().unwrap(),
        "stage81-shared-tls.example"
    );
    assert_eq!(
        json["shared_tls_contract"]["alpn_protocol"]
            .as_str()
            .unwrap(),
        "http/1.1"
    );
    assert!(
        json["shared_tls_contract"]["protocol_specific_completion"]["https_proxy"]
            .as_bool()
            .is_some_and(|value| !value)
    );
    assert!(
        json["shared_tls_contract"]["full_utls_deferred"]
            .as_bool()
            .unwrap()
    );
    assert!(
        json["shared_tls_contract"]["reality_deferred"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["outbound_true_dataplane_admitted"].as_bool().unwrap());
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
    assert!(!json["product_chain_switch_allowed"].as_bool().unwrap());
    assert!(!json["true_rust_default_daemon_admitted"].as_bool().unwrap());
    assert!(json["go_default_path_preserved"].as_bool().unwrap());
    assert!(json["go_fallback_required"].as_bool().unwrap());
}

#[test]
fn stage81_runtime_admission_blocks_unsafe_execution() {
    let blocked = run_with_args([
        "runtime",
        "stage81-shared-tls-underlay-dataplane-admission",
        "--execute-smoke",
    ]);
    assert_eq!(blocked.exit_code, 1);
    assert!(
        blocked
            .stdout
            .contains("stage81 root-gated smoke requires --ack-root-gate")
    );
}
