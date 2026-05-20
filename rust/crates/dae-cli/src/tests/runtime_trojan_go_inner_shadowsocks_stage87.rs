use super::*;

#[test]
fn stage87_runtime_admission_fixture_matches() {
    let fixture =
        load("engine/runtime_stage87/trojan_go_inner_shadowsocks_dataplane_admission.json");
    let output = run_with_args([
        "runtime",
        "stage87-trojan-go-inner-shadowsocks-dataplane-admission",
    ]);
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
    assert!(!json["execute_smoke"].as_bool().unwrap());
    assert!(json["read_only"].as_bool().unwrap());
    assert!(!json["blocked"].as_bool().unwrap());
    assert!(json["trojan_go_wss_admitted"].as_bool().unwrap());
    assert!(json["trojan_go_httpupgrade_admitted"].as_bool().unwrap());
    assert!(json["trojan_go_grpc_admitted"].as_bool().unwrap());
    assert!(
        !json["trojan_go_inner_shadowsocks_smoke_passed"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["trojan_go_inner_shadowsocks_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        json["trojan_go_shared_transport_partial_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["trojan_go_shared_transport_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        json["trojan_go_inner_shadowsocks_contract"]["cipher"]
            .as_str()
            .unwrap(),
        "aes-256-gcm"
    );
    assert!(
        !json["trojan_go_inner_shadowsocks_contract"]["inner_shadowsocks_is_client"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["trojan_go_inner_shadowsocks_contract"]["inner_shadowsocks_request_metadata_present"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["outbound_true_dataplane_admitted"].as_bool().unwrap());
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
    assert!(!json["product_chain_switch_allowed"].as_bool().unwrap());
}

#[test]
fn stage87_runtime_admission_blocks_unsafe_execution() {
    let blocked = run_with_args([
        "runtime",
        "stage87-trojan-go-inner-shadowsocks-dataplane-admission",
        "--execute-smoke",
    ]);
    assert_eq!(blocked.exit_code, 1);
    assert!(
        blocked
            .stdout
            .contains("stage87 root-gated smoke requires --ack-root-gate")
    );
}
