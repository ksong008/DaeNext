use super::*;

#[test]
fn stage80_runtime_admission_fixture_matches() {
    let fixture = load("engine/runtime_stage80/vless_xhttp_xmux_dataplane_admission.json");
    let output = run_with_args(["runtime", "stage80-vless-xhttp-xmux-dataplane-admission"]);
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
    assert!(json["vless_xhttp_admitted"].as_bool().unwrap());
    assert!(!json["vless_xhttp_xmux_smoke_passed"].as_bool().unwrap());
    assert!(!json["vless_xhttp_xmux_admitted"].as_bool().unwrap());
    assert!(
        json["vless_shared_transport_partial_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["vless_shared_transport_admitted"].as_bool().unwrap());
    assert!(
        !json["vless_protocol_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        json["vless_xhttp_contract"]["target"].as_str().unwrap(),
        fixture["vless_xhttp_contract"]["target"].as_str().unwrap()
    );
    assert_eq!(
        json["vless_xhttp_contract"]["transport"].as_str().unwrap(),
        "xhttp-xmux-packet-up"
    );
    assert!(
        json["vless_xhttp_contract"]["xhttp_xmux_enabled"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["vless_xhttp_contract"]["xmux_session_reuse_validated"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        json["vless_xhttp_contract"]["xmux_max_connections"]
            .as_u64()
            .unwrap(),
        2
    );
    assert_eq!(
        json["vless_xhttp_contract"]["xmux_c_max_reuse_times"]
            .as_u64()
            .unwrap(),
        4
    );
    assert_eq!(
        json["vless_xhttp_contract"]["xhttp_request_path"]
            .as_str()
            .unwrap(),
        "/dae-stage80-xhttp-xmux/?session=dae-stage80-xhttp-xmux&seq=80"
    );
    assert!(
        !json["vless_xhttp_contract"]["full_h2_h3_stack"]
            .as_bool()
            .unwrap()
    );
    assert!(
        json["vless_xhttp_contract"]["full_xhttp_lifecycle_deferred"]
            .as_str()
            .unwrap()
            .contains("downloadSettings")
    );
    assert!(!json["outbound_true_dataplane_admitted"].as_bool().unwrap());
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
    assert!(!json["product_chain_switch_allowed"].as_bool().unwrap());
    assert!(!json["true_rust_default_daemon_admitted"].as_bool().unwrap());
    assert!(json["go_default_path_preserved"].as_bool().unwrap());
    assert!(json["go_fallback_required"].as_bool().unwrap());
}

#[test]
fn stage80_runtime_admission_blocks_unsafe_execution() {
    let blocked = run_with_args([
        "runtime",
        "stage80-vless-xhttp-xmux-dataplane-admission",
        "--execute-smoke",
    ]);
    assert_eq!(blocked.exit_code, 1);
    assert!(
        blocked
            .stdout
            .contains("stage80 root-gated smoke requires --ack-root-gate")
    );
}
