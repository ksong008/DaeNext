use super::*;

#[test]
fn stage62_runtime_admission_fixture_matches() {
    let fixture = load("engine/runtime_stage62/vless_tcp_dataplane_admission.json");
    let output = run_with_args(["runtime", "stage62-vless-tcp-dataplane-admission"]);
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
    assert!(!json["vless_tcp_raw_smoke_passed"].as_bool().unwrap());
    assert!(
        !json["vless_tcp_raw_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["vless_protocol_partial_admitted"].as_bool().unwrap());
    assert!(
        !json["vless_protocol_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["vless_tls_underlay_admitted"].as_bool().unwrap());
    assert!(!json["vless_reality_admitted"].as_bool().unwrap());
    assert!(!json["vless_xtls_vision_admitted"].as_bool().unwrap());
    assert!(!json["vless_shared_transport_admitted"].as_bool().unwrap());
    assert_eq!(
        json["vless_tcp_contract"]["target"].as_str().unwrap(),
        fixture["vless_tcp_contract"]["target"].as_str().unwrap()
    );
    assert_eq!(
        json["vless_tcp_contract"]["payload_ascii"]
            .as_str()
            .unwrap(),
        fixture["vless_tcp_contract"]["payload_ascii"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        json["underlay_socket"]["requested_mark"].as_u64().unwrap(),
        fixture["underlay_socket"]["requested_mark"]
            .as_u64()
            .unwrap()
    );
    assert!(
        json["underlay_socket"]["requested_mptcp"]
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
fn stage62_runtime_admission_blocks_unsafe_execution() {
    let blocked = run_with_args([
        "runtime",
        "stage62-vless-tcp-dataplane-admission",
        "--execute-smoke",
    ]);
    assert_eq!(blocked.exit_code, 1);
    assert!(
        blocked
            .stdout
            .contains("stage62 root-gated smoke requires --ack-root-gate")
    );
}

#[test]
fn stage63_runtime_admission_fixture_matches() {
    let fixture = load("engine/runtime_stage63/vless_udp_over_tcp_dataplane_admission.json");
    let output = run_with_args(["runtime", "stage63-vless-udp-over-tcp-dataplane-admission"]);
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
        json["vless_tcp_raw_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["vless_udp_over_tcp_smoke_passed"].as_bool().unwrap());
    assert!(!json["vless_udp_over_tcp_admitted"].as_bool().unwrap());
    assert!(!json["vless_protocol_partial_admitted"].as_bool().unwrap());
    assert!(
        !json["vless_protocol_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["vless_tls_underlay_admitted"].as_bool().unwrap());
    assert!(!json["vless_reality_admitted"].as_bool().unwrap());
    assert!(!json["vless_xtls_vision_admitted"].as_bool().unwrap());
    assert!(!json["vless_shared_transport_admitted"].as_bool().unwrap());
    assert!(!json["vless_mux_admitted"].as_bool().unwrap());
    assert_eq!(
        json["vless_udp_over_tcp_contract"]["target"]
            .as_str()
            .unwrap(),
        fixture["vless_udp_over_tcp_contract"]["target"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        json["vless_udp_over_tcp_contract"]["payload_ascii"]
            .as_str()
            .unwrap(),
        fixture["vless_udp_over_tcp_contract"]["payload_ascii"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        json["underlay_socket"]["requested_mark"].as_u64().unwrap(),
        fixture["underlay_socket"]["requested_mark"]
            .as_u64()
            .unwrap()
    );
    assert!(
        json["underlay_socket"]["requested_mptcp"]
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
fn stage63_runtime_admission_blocks_unsafe_execution() {
    let blocked = run_with_args([
        "runtime",
        "stage63-vless-udp-over-tcp-dataplane-admission",
        "--execute-smoke",
    ]);
    assert_eq!(blocked.exit_code, 1);
    assert!(
        blocked
            .stdout
            .contains("stage63 root-gated smoke requires --ack-root-gate")
    );
}

#[test]
fn stage64_runtime_admission_fixture_matches() {
    let fixture = load("engine/runtime_stage64/vless_mux_dataplane_admission.json");
    let output = run_with_args(["runtime", "stage64-vless-mux-dataplane-admission"]);
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
        json["vless_tcp_raw_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(json["vless_udp_over_tcp_admitted"].as_bool().unwrap());
    assert!(!json["vless_mux_smoke_passed"].as_bool().unwrap());
    assert!(!json["vless_mux_admitted"].as_bool().unwrap());
    assert!(!json["vless_protocol_partial_admitted"].as_bool().unwrap());
    assert!(
        !json["vless_protocol_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["vless_tls_underlay_admitted"].as_bool().unwrap());
    assert!(!json["vless_reality_admitted"].as_bool().unwrap());
    assert!(!json["vless_xtls_vision_admitted"].as_bool().unwrap());
    assert!(!json["vless_shared_transport_admitted"].as_bool().unwrap());
    assert_eq!(
        json["vless_mux_contract"]["target"].as_str().unwrap(),
        fixture["vless_mux_contract"]["target"].as_str().unwrap()
    );
    assert_eq!(
        json["vless_mux_contract"]["payload_ascii"]
            .as_str()
            .unwrap(),
        fixture["vless_mux_contract"]["payload_ascii"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        json["vless_mux_contract"]["mux_id_hex"].as_str().unwrap(),
        fixture["vless_mux_contract"]["mux_id_hex"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        json["underlay_socket"]["requested_mark"].as_u64().unwrap(),
        fixture["underlay_socket"]["requested_mark"]
            .as_u64()
            .unwrap()
    );
    assert!(
        json["underlay_socket"]["requested_mptcp"]
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
fn stage64_runtime_admission_blocks_unsafe_execution() {
    let blocked = run_with_args([
        "runtime",
        "stage64-vless-mux-dataplane-admission",
        "--execute-smoke",
    ]);
    assert_eq!(blocked.exit_code, 1);
    assert!(
        blocked
            .stdout
            .contains("stage64 root-gated smoke requires --ack-root-gate")
    );
}
