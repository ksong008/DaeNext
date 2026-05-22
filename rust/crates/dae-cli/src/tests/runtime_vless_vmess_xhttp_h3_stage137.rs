use super::*;

#[test]
fn stage137_runtime_admission_fixture_matches() {
    let fixture = load("engine/runtime_stage137/vless_vmess_xhttp_h3_lifecycle_admission.json");
    let output = run_with_args([
        "runtime",
        "stage137-vless-vmess-xhttp-h3-lifecycle-admission",
    ]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();

    assert_eq!(json["name"], fixture["name"]);
    assert_eq!(json["stage"], fixture["stage"]);
    assert_eq!(json["evidence_class"], fixture["evidence_class"]);
    assert!(!json["execute_smoke"].as_bool().unwrap());
    assert!(json["read_only"].as_bool().unwrap());
    assert!(!json["blocked"].as_bool().unwrap());
    assert!(
        json["vless_xhttp_http2_lifecycle_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        json["vmess_xhttp_http2_lifecycle_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["vless_xhttp_h3_lifecycle_admitted"].as_bool().unwrap());
    assert!(!json["vmess_xhttp_h3_lifecycle_admitted"].as_bool().unwrap());
    assert!(
        !json["vless_xhttp_h2_h3_lifecycle_admitted"]
            .as_bool()
            .unwrap()
    );
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
        !json["shared_transport_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["outbound_true_dataplane_admitted"].as_bool().unwrap());
    assert_eq!(
        json["vless_vmess_xhttp_h3_contract"]["xhttp_alpn"]
            .as_str()
            .unwrap(),
        "h3"
    );
    assert!(
        json["vless_vmess_xhttp_h3_contract"]["reality_h3_rejected"]
            .as_bool()
            .unwrap()
    );
}

#[test]
fn stage137_runtime_execute_smoke_admits_only_xhttp_h3_subrows() {
    let output = run_with_args([
        "runtime",
        "stage137-vless-vmess-xhttp-h3-lifecycle-admission",
        "--execute-smoke",
        "--benchmark-iters",
        "1",
    ]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    let json: Value = serde_json::from_str(&output.stdout).unwrap();

    assert!(!json["read_only"].as_bool().unwrap());
    assert!(
        json["vless_vmess_xhttp_h3_lifecycle_smoke_passed"]
            .as_bool()
            .unwrap()
    );
    assert!(json["vless_xhttp_h3_lifecycle_admitted"].as_bool().unwrap());
    assert!(json["vmess_xhttp_h3_lifecycle_admitted"].as_bool().unwrap());
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
        !json["shared_transport_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["outbound_true_dataplane_admitted"].as_bool().unwrap());
    assert!(json["benchmark"]["benchmark_recorded"].as_bool().unwrap());
    assert_eq!(
        json["benchmark"]["total_exchange_count"].as_u64().unwrap(),
        2
    );
    assert_eq!(
        json["benchmark"]["vless_client_selected_alpn"]
            .as_str()
            .unwrap(),
        "h3"
    );
    assert_eq!(
        json["benchmark"]["vmess_server_selected_alpn"]
            .as_str()
            .unwrap(),
        "h3"
    );
    assert!(
        json["benchmark"]["vless_xhttp_request_path"]
            .as_str()
            .unwrap()
            .contains("session=")
    );
    assert_eq!(
        json["vless_vmess_xhttp_h3_contract"]["xhttp_mode"]
            .as_str()
            .unwrap(),
        "packet-up"
    );
}
