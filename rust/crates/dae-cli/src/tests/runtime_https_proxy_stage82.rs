use super::*;

#[test]
fn stage82_runtime_admission_fixture_matches() {
    let fixture = load("engine/runtime_stage82/https_proxy_tls_dataplane_admission.json");
    let output = run_with_args(["runtime", "stage82-https-proxy-tls-dataplane-admission"]);
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
    assert!(!json["https_proxy_tls_smoke_passed"].as_bool().unwrap());
    assert!(!json["https_proxy_tls_underlay_admitted"].as_bool().unwrap());
    assert!(
        !json["https_proxy_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(json["shared_tls_underlay_admitted"].as_bool().unwrap());
    assert!(
        !json["shared_transport_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        json["https_proxy_contract"]["target"].as_str().unwrap(),
        "stage82-target.example:443"
    );
    assert_eq!(
        json["https_proxy_contract"]["host_override"]
            .as_str()
            .unwrap(),
        "front.stage82.example:443"
    );
    assert_eq!(
        json["https_proxy_contract"]["tls_server_name"]
            .as_str()
            .unwrap(),
        "stage82-https-proxy.example"
    );
    assert!(
        json["https_proxy_contract"]["utls_deferred"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["trojan_tls_underlay_admitted"].as_bool().unwrap());
    assert!(!json["vless_tls_underlay_admitted"].as_bool().unwrap());
    assert!(!json["vmess_tls_underlay_admitted"].as_bool().unwrap());
    assert!(!json["outbound_true_dataplane_admitted"].as_bool().unwrap());
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
    assert!(!json["product_chain_switch_allowed"].as_bool().unwrap());
    assert!(json["go_default_path_preserved"].as_bool().unwrap());
    assert!(json["go_fallback_required"].as_bool().unwrap());
}

#[test]
fn stage82_runtime_admission_blocks_unsafe_execution() {
    let blocked = run_with_args([
        "runtime",
        "stage82-https-proxy-tls-dataplane-admission",
        "--execute-smoke",
    ]);
    assert_eq!(blocked.exit_code, 1);
    assert!(
        blocked
            .stdout
            .contains("stage82 root-gated smoke requires --ack-root-gate")
    );
}
