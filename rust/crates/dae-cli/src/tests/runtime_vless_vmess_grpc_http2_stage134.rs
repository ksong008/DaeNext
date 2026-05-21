use super::*;

#[test]
fn stage134_runtime_admission_fixture_matches() {
    let fixture = load("engine/runtime_stage134/vless_vmess_grpc_http2_lifecycle_admission.json");
    let output = run_with_args([
        "runtime",
        "stage134-vless-vmess-grpc-http2-lifecycle-admission",
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
        !json["vless_grpc_http2_lifecycle_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["vmess_grpc_http2_lifecycle_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(json["vless_protocol_partial_admitted"].as_bool().unwrap());
    assert!(json["vmess_protocol_partial_admitted"].as_bool().unwrap());
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
        json["vless_vmess_grpc_http2_contract"]["grpc_service_name"]
            .as_str()
            .unwrap(),
        "GunService"
    );
    assert!(
        json["vless_vmess_grpc_http2_contract"]["tls_utls_reality_deferred"]
            .as_bool()
            .unwrap()
    );
}

#[test]
fn stage134_runtime_execute_smoke_admits_only_grpc_http2_subrows() {
    let output = run_with_args([
        "runtime",
        "stage134-vless-vmess-grpc-http2-lifecycle-admission",
        "--execute-smoke",
        "--benchmark-iters",
        "2",
    ]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    let json: Value = serde_json::from_str(&output.stdout).unwrap();

    assert!(!json["read_only"].as_bool().unwrap());
    assert!(
        json["vless_vmess_grpc_http2_lifecycle_smoke_passed"]
            .as_bool()
            .unwrap()
    );
    assert!(
        json["vless_grpc_http2_lifecycle_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        json["vmess_grpc_http2_lifecycle_admitted"]
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
        4
    );
    assert!(
        json["vless_vmess_grpc_http2_contract"]["grpc_cache_key"]
            .as_str()
            .unwrap()
            .contains("magic:")
    );
    assert_eq!(
        json["vless_vmess_grpc_http2_contract"]["so_mark_carried"]
            .as_u64()
            .unwrap(),
        1340
    );
    assert!(
        json["vless_vmess_grpc_http2_contract"]["mptcp_carried"]
            .as_bool()
            .unwrap()
    );
}
