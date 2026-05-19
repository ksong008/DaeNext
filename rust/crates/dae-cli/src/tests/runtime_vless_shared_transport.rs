use super::*;

#[test]
fn stage74_runtime_admission_fixture_matches() {
    let fixture = load("engine/runtime_stage74/vless_websocket_dataplane_admission.json");
    let output = run_with_args(["runtime", "stage74-vless-websocket-dataplane-admission"]);
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
    assert!(json["vless_mux_admitted"].as_bool().unwrap());
    assert!(!json["vless_websocket_smoke_passed"].as_bool().unwrap());
    assert!(!json["vless_websocket_admitted"].as_bool().unwrap());
    assert!(!json["vless_tls_underlay_admitted"].as_bool().unwrap());
    assert!(!json["vless_reality_underlay_admitted"].as_bool().unwrap());
    assert!(!json["vless_vision_admitted"].as_bool().unwrap());
    assert!(!json["vless_xhttp_admitted"].as_bool().unwrap());
    assert!(!json["vless_xhttp_xmux_admitted"].as_bool().unwrap());
    assert!(
        !json["vless_protocol_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["vless_shared_transport_admitted"].as_bool().unwrap());
    assert!(json["vmess_http_transport_put_admitted"].as_bool().unwrap());
    assert_eq!(
        json["vless_websocket_contract"]["target"].as_str().unwrap(),
        fixture["vless_websocket_contract"]["target"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        json["vless_websocket_contract"]["ws_host"]
            .as_str()
            .unwrap(),
        fixture["vless_websocket_contract"]["ws_host"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        json["vless_websocket_contract"]["ws_path"]
            .as_str()
            .unwrap(),
        fixture["vless_websocket_contract"]["ws_path"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        json["vless_websocket_contract"]["payload_ascii"]
            .as_str()
            .unwrap(),
        fixture["vless_websocket_contract"]["payload_ascii"]
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
fn stage74_runtime_admission_blocks_unsafe_execution() {
    let blocked = run_with_args([
        "runtime",
        "stage74-vless-websocket-dataplane-admission",
        "--execute-smoke",
    ]);
    assert_eq!(blocked.exit_code, 1);
    assert!(
        blocked
            .stdout
            .contains("stage74 root-gated smoke requires --ack-root-gate")
    );
}

#[test]
fn stage75_runtime_admission_fixture_matches() {
    let fixture = load("engine/runtime_stage75/vless_httpupgrade_dataplane_admission.json");
    let output = run_with_args(["runtime", "stage75-vless-httpupgrade-dataplane-admission"]);
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
    assert!(json["vless_mux_admitted"].as_bool().unwrap());
    assert!(json["vless_websocket_admitted"].as_bool().unwrap());
    assert!(!json["vless_httpupgrade_smoke_passed"].as_bool().unwrap());
    assert!(!json["vless_httpupgrade_admitted"].as_bool().unwrap());
    assert!(!json["vless_tls_underlay_admitted"].as_bool().unwrap());
    assert!(!json["vless_reality_underlay_admitted"].as_bool().unwrap());
    assert!(!json["vless_vision_admitted"].as_bool().unwrap());
    assert!(!json["vless_xhttp_admitted"].as_bool().unwrap());
    assert!(!json["vless_xhttp_xmux_admitted"].as_bool().unwrap());
    assert!(
        !json["vless_protocol_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["vless_shared_transport_admitted"].as_bool().unwrap());
    assert!(json["vmess_websocket_admitted"].as_bool().unwrap());
    assert!(json["vmess_http_transport_put_admitted"].as_bool().unwrap());
    assert_eq!(
        json["vless_httpupgrade_contract"]["target"]
            .as_str()
            .unwrap(),
        fixture["vless_httpupgrade_contract"]["target"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        json["vless_httpupgrade_contract"]["httpupgrade_host"]
            .as_str()
            .unwrap(),
        fixture["vless_httpupgrade_contract"]["httpupgrade_host"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        json["vless_httpupgrade_contract"]["httpupgrade_path"]
            .as_str()
            .unwrap(),
        fixture["vless_httpupgrade_contract"]["httpupgrade_path"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        json["vless_httpupgrade_contract"]["payload_ascii"]
            .as_str()
            .unwrap(),
        fixture["vless_httpupgrade_contract"]["payload_ascii"]
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
fn stage75_runtime_admission_blocks_unsafe_execution() {
    let blocked = run_with_args([
        "runtime",
        "stage75-vless-httpupgrade-dataplane-admission",
        "--execute-smoke",
    ]);
    assert_eq!(blocked.exit_code, 1);
    assert!(
        blocked
            .stdout
            .contains("stage75 root-gated smoke requires --ack-root-gate")
    );
}

#[test]
fn stage76_runtime_admission_fixture_matches() {
    let fixture = load("engine/runtime_stage76/vless_grpc_hunk_dataplane_admission.json");
    let output = run_with_args(["runtime", "stage76-vless-grpc-hunk-dataplane-admission"]);
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
    assert!(json["vless_mux_admitted"].as_bool().unwrap());
    assert!(json["vless_websocket_admitted"].as_bool().unwrap());
    assert!(json["vless_httpupgrade_admitted"].as_bool().unwrap());
    assert!(!json["vless_grpc_hunk_smoke_passed"].as_bool().unwrap());
    assert!(!json["vless_grpc_hunk_admitted"].as_bool().unwrap());
    assert!(
        json["vless_shared_transport_partial_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["vless_tls_underlay_admitted"].as_bool().unwrap());
    assert!(!json["vless_reality_underlay_admitted"].as_bool().unwrap());
    assert!(!json["vless_vision_admitted"].as_bool().unwrap());
    assert!(!json["vless_xhttp_admitted"].as_bool().unwrap());
    assert!(!json["vless_xhttp_xmux_admitted"].as_bool().unwrap());
    assert!(
        !json["vless_protocol_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["vless_shared_transport_admitted"].as_bool().unwrap());
    assert!(json["vmess_grpc_hunk_admitted"].as_bool().unwrap());
    assert!(json["vmess_http_transport_put_admitted"].as_bool().unwrap());
    assert_eq!(
        json["vless_grpc_hunk_contract"]["target"].as_str().unwrap(),
        fixture["vless_grpc_hunk_contract"]["target"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        json["vless_grpc_hunk_contract"]["grpc_service_name"]
            .as_str()
            .unwrap(),
        fixture["vless_grpc_hunk_contract"]["grpc_service_name"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        json["vless_grpc_hunk_contract"]["payload_ascii"]
            .as_str()
            .unwrap(),
        fixture["vless_grpc_hunk_contract"]["payload_ascii"]
            .as_str()
            .unwrap()
    );
    assert!(
        !json["vless_grpc_hunk_contract"]["full_grpc_http2_stack"]
            .as_bool()
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
fn stage76_runtime_admission_blocks_unsafe_execution() {
    let blocked = run_with_args([
        "runtime",
        "stage76-vless-grpc-hunk-dataplane-admission",
        "--execute-smoke",
    ]);
    assert_eq!(blocked.exit_code, 1);
    assert!(
        blocked
            .stdout
            .contains("stage76 root-gated smoke requires --ack-root-gate")
    );
}

#[test]
fn stage77_runtime_admission_fixture_matches() {
    let fixture = load("engine/runtime_stage77/vless_meek_polling_dataplane_admission.json");
    let output = run_with_args(["runtime", "stage77-vless-meek-polling-dataplane-admission"]);
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
    assert!(json["vless_websocket_admitted"].as_bool().unwrap());
    assert!(json["vless_httpupgrade_admitted"].as_bool().unwrap());
    assert!(json["vless_grpc_hunk_admitted"].as_bool().unwrap());
    assert!(!json["vless_meek_polling_smoke_passed"].as_bool().unwrap());
    assert!(!json["vless_meek_polling_admitted"].as_bool().unwrap());
    assert!(
        !json["vless_meek_full_https_roundtripper_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        json["vless_shared_transport_partial_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["vless_tls_underlay_admitted"].as_bool().unwrap());
    assert!(!json["vless_reality_underlay_admitted"].as_bool().unwrap());
    assert!(!json["vless_vision_admitted"].as_bool().unwrap());
    assert!(!json["vless_xhttp_admitted"].as_bool().unwrap());
    assert!(!json["vless_xhttp_xmux_admitted"].as_bool().unwrap());
    assert!(
        !json["vless_protocol_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["vless_shared_transport_admitted"].as_bool().unwrap());
    assert!(json["vmess_meek_polling_admitted"].as_bool().unwrap());
    assert!(json["vmess_http_transport_put_admitted"].as_bool().unwrap());
    assert_eq!(
        json["vless_meek_polling_contract"]["target"]
            .as_str()
            .unwrap(),
        fixture["vless_meek_polling_contract"]["target"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        json["vless_meek_polling_contract"]["meek_url"]
            .as_str()
            .unwrap(),
        fixture["vless_meek_polling_contract"]["meek_url"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        json["vless_meek_polling_contract"]["meek_session_id"]
            .as_str()
            .unwrap(),
        fixture["vless_meek_polling_contract"]["meek_session_id"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        json["vless_meek_polling_contract"]["payload_ascii"]
            .as_str()
            .unwrap(),
        fixture["vless_meek_polling_contract"]["payload_ascii"]
            .as_str()
            .unwrap()
    );
    assert!(
        !json["vless_meek_polling_contract"]["full_https_round_tripper"]
            .as_bool()
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
fn stage77_runtime_admission_blocks_unsafe_execution() {
    let blocked = run_with_args([
        "runtime",
        "stage77-vless-meek-polling-dataplane-admission",
        "--execute-smoke",
    ]);
    assert_eq!(blocked.exit_code, 1);
    assert!(
        blocked
            .stdout
            .contains("stage77 root-gated smoke requires --ack-root-gate")
    );
}

#[test]
fn stage78_runtime_admission_fixture_matches() {
    let fixture = load("engine/runtime_stage78/vless_http_transport_dataplane_admission.json");
    let output = run_with_args([
        "runtime",
        "stage78-vless-http-transport-dataplane-admission",
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
    assert_eq!(
        json["evidence_class"].as_str().unwrap(),
        fixture["evidence_class"].as_str().unwrap()
    );
    assert!(!json["execute_smoke"].as_bool().unwrap());
    assert!(json["read_only"].as_bool().unwrap());
    assert!(!json["blocked"].as_bool().unwrap());
    assert!(json["vless_websocket_admitted"].as_bool().unwrap());
    assert!(json["vless_httpupgrade_admitted"].as_bool().unwrap());
    assert!(json["vless_grpc_hunk_admitted"].as_bool().unwrap());
    assert!(json["vless_meek_polling_admitted"].as_bool().unwrap());
    assert!(
        !json["vless_http_transport_put_smoke_passed"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["vless_http_transport_put_admitted"].as_bool().unwrap());
    assert!(!json["vless_http_h2_full_admitted"].as_bool().unwrap());
    assert!(
        json["vless_shared_transport_partial_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["vless_tls_underlay_admitted"].as_bool().unwrap());
    assert!(!json["vless_reality_underlay_admitted"].as_bool().unwrap());
    assert!(!json["vless_vision_admitted"].as_bool().unwrap());
    assert!(!json["vless_xhttp_admitted"].as_bool().unwrap());
    assert!(!json["vless_xhttp_xmux_admitted"].as_bool().unwrap());
    assert!(
        !json["vless_protocol_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["vless_shared_transport_admitted"].as_bool().unwrap());
    assert!(json["vmess_http_transport_put_admitted"].as_bool().unwrap());
    assert_eq!(
        json["vless_http_transport_contract"]["target"]
            .as_str()
            .unwrap(),
        fixture["vless_http_transport_contract"]["target"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        json["vless_http_transport_contract"]["http_proxy_target"]
            .as_str()
            .unwrap(),
        fixture["vless_http_transport_contract"]["http_proxy_target"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        json["vless_http_transport_contract"]["http_host"]
            .as_str()
            .unwrap(),
        fixture["vless_http_transport_contract"]["http_host"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        json["vless_http_transport_contract"]["http_path"]
            .as_str()
            .unwrap(),
        fixture["vless_http_transport_contract"]["http_path"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        json["vless_http_transport_contract"]["payload_ascii"]
            .as_str()
            .unwrap(),
        fixture["vless_http_transport_contract"]["payload_ascii"]
            .as_str()
            .unwrap()
    );
    assert!(
        !json["vless_http_transport_contract"]["full_http2_stack"]
            .as_bool()
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
fn stage78_runtime_admission_blocks_unsafe_execution() {
    let blocked = run_with_args([
        "runtime",
        "stage78-vless-http-transport-dataplane-admission",
        "--execute-smoke",
    ]);
    assert_eq!(blocked.exit_code, 1);
    assert!(
        blocked
            .stdout
            .contains("stage78 root-gated smoke requires --ack-root-gate")
    );
}

#[test]
fn stage79_runtime_admission_fixture_matches() {
    let fixture = load("engine/runtime_stage79/vless_xhttp_packet_dataplane_admission.json");
    let output = run_with_args(["runtime", "stage79-vless-xhttp-packet-dataplane-admission"]);
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
    assert!(json["vless_websocket_admitted"].as_bool().unwrap());
    assert!(json["vless_httpupgrade_admitted"].as_bool().unwrap());
    assert!(json["vless_grpc_hunk_admitted"].as_bool().unwrap());
    assert!(json["vless_meek_polling_admitted"].as_bool().unwrap());
    assert!(json["vless_http_transport_put_admitted"].as_bool().unwrap());
    assert!(!json["vless_http_h2_full_admitted"].as_bool().unwrap());
    assert!(!json["vless_xhttp_packet_smoke_passed"].as_bool().unwrap());
    assert!(!json["vless_xhttp_admitted"].as_bool().unwrap());
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
        json["vless_xhttp_contract"]["xhttp_host"].as_str().unwrap(),
        fixture["vless_xhttp_contract"]["xhttp_host"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        json["vless_xhttp_contract"]["xhttp_path"].as_str().unwrap(),
        fixture["vless_xhttp_contract"]["xhttp_path"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        json["vless_xhttp_contract"]["xhttp_request_path"]
            .as_str()
            .unwrap(),
        fixture["vless_xhttp_contract"]["xhttp_request_path"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        json["vless_xhttp_contract"]["xhttp_mode"].as_str().unwrap(),
        "packet-up"
    );
    assert_eq!(
        json["vless_xhttp_contract"]["payload_ascii"]
            .as_str()
            .unwrap(),
        fixture["vless_xhttp_contract"]["payload_ascii"]
            .as_str()
            .unwrap()
    );
    assert!(
        !json["vless_xhttp_contract"]["xhttp_xmux_enabled"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["vless_xhttp_contract"]["full_h2_h3_stack"]
            .as_bool()
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
fn stage79_runtime_admission_blocks_unsafe_execution() {
    let blocked = run_with_args([
        "runtime",
        "stage79-vless-xhttp-packet-dataplane-admission",
        "--execute-smoke",
    ]);
    assert_eq!(blocked.exit_code, 1);
    assert!(
        blocked
            .stdout
            .contains("stage79 root-gated smoke requires --ack-root-gate")
    );
}
