use super::*;

#[test]
fn stage96_protocol_matrix_recertification_fixture_matches() {
    let fixture = load("engine/runtime_stage96/protocol_matrix_recertification.json");
    let output = run_with_args(["runtime", "stage96-protocol-matrix-recertification"]);
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
    assert!(json["read_only"].as_bool().unwrap());
    assert!(!json["blocked"].as_bool().unwrap());
    assert!(
        json["shadowsocks_protocol_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(json["ss2022_true_dataplane_admitted"].as_bool().unwrap());
    assert!(json["sip003_plugin_transport_admitted"].as_bool().unwrap());
    assert!(
        json["shadowsocksr_true_dataplane_admitted"]
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
    assert!(!json["outbound_true_dataplane_admitted"].as_bool().unwrap());
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
    assert!(!json["product_chain_switch_allowed"].as_bool().unwrap());
}

#[test]
fn stage96_protocol_matrix_recertification_rejects_extra_args() {
    let blocked = run_with_args([
        "runtime",
        "stage96-protocol-matrix-recertification",
        "--execute-smoke",
    ]);
    assert_eq!(blocked.exit_code, 2);
    assert!(
        blocked
            .stderr
            .contains("unsupported stage96 argument: --execute-smoke")
    );
}
