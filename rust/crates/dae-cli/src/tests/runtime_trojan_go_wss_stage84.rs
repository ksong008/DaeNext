use super::*;

#[test]
fn stage84_runtime_admission_fixture_matches() {
    let fixture = load("engine/runtime_stage84/trojan_go_wss_dataplane_admission.json");
    let output = run_with_args(["runtime", "stage84-trojan-go-wss-dataplane-admission"]);
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
    assert!(
        json["trojan_protocol_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["trojan_go_wss_smoke_passed"].as_bool().unwrap());
    assert!(!json["trojan_go_wss_admitted"].as_bool().unwrap());
    assert!(
        !json["trojan_go_shared_transport_partial_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["trojan_go_shared_transport_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["trojan_go_inner_shadowsocks_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        json["trojan_go_wss_contract"]["ws_host"].as_str().unwrap(),
        "stage84-ws-host.example"
    );
    assert_eq!(
        json["trojan_go_wss_contract"]["ws_path"].as_str().unwrap(),
        "/trojan-go-ws"
    );
    assert!(!json["outbound_true_dataplane_admitted"].as_bool().unwrap());
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
    assert!(!json["product_chain_switch_allowed"].as_bool().unwrap());
    assert!(json["go_default_path_preserved"].as_bool().unwrap());
    assert!(json["go_fallback_required"].as_bool().unwrap());
}

#[test]
fn stage84_runtime_admission_blocks_unsafe_execution() {
    let blocked = run_with_args([
        "runtime",
        "stage84-trojan-go-wss-dataplane-admission",
        "--execute-smoke",
    ]);
    assert_eq!(blocked.exit_code, 1);
    assert!(
        blocked
            .stdout
            .contains("stage84 root-gated smoke requires --ack-root-gate")
    );
}
