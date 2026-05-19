use super::*;

#[test]
fn stage69_runtime_admission_fixture_matches() {
    let fixture = load("engine/runtime_stage69/vmess_websocket_dataplane_admission.json");
    let output = run_with_args(["runtime", "stage69-vmess-websocket-dataplane-admission"]);
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
        json["vmess_aead_tcp_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(json["vmess_aead_udp_over_tcp_admitted"].as_bool().unwrap());
    assert!(json["vmess_udp_packet_addr_admitted"].as_bool().unwrap());
    assert!(json["vmess_mux_admitted"].as_bool().unwrap());
    assert!(!json["vmess_websocket_smoke_passed"].as_bool().unwrap());
    assert!(!json["vmess_websocket_admitted"].as_bool().unwrap());
    assert!(
        !json["vmess_shared_transport_partial_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(json["vmess_protocol_partial_admitted"].as_bool().unwrap());
    assert!(
        !json["vmess_protocol_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["vmess_tls_underlay_admitted"].as_bool().unwrap());
    assert!(!json["vmess_shared_transport_admitted"].as_bool().unwrap());
    assert_eq!(
        json["vmess_websocket_contract"]["target"].as_str().unwrap(),
        fixture["vmess_websocket_contract"]["target"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        json["vmess_websocket_contract"]["ws_host"]
            .as_str()
            .unwrap(),
        fixture["vmess_websocket_contract"]["ws_host"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        json["vmess_websocket_contract"]["ws_path"]
            .as_str()
            .unwrap(),
        fixture["vmess_websocket_contract"]["ws_path"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        json["vmess_websocket_contract"]["payload_ascii"]
            .as_str()
            .unwrap(),
        fixture["vmess_websocket_contract"]["payload_ascii"]
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
fn stage69_runtime_admission_blocks_unsafe_execution() {
    let blocked = run_with_args([
        "runtime",
        "stage69-vmess-websocket-dataplane-admission",
        "--execute-smoke",
    ]);
    assert_eq!(blocked.exit_code, 1);
    assert!(
        blocked
            .stdout
            .contains("stage69 root-gated smoke requires --ack-root-gate")
    );
}

#[test]
fn stage70_runtime_admission_fixture_matches() {
    let fixture = load("engine/runtime_stage70/vmess_httpupgrade_dataplane_admission.json");
    let output = run_with_args(["runtime", "stage70-vmess-httpupgrade-dataplane-admission"]);
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
        json["vmess_aead_tcp_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(json["vmess_aead_udp_over_tcp_admitted"].as_bool().unwrap());
    assert!(json["vmess_udp_packet_addr_admitted"].as_bool().unwrap());
    assert!(json["vmess_mux_admitted"].as_bool().unwrap());
    assert!(json["vmess_websocket_admitted"].as_bool().unwrap());
    assert!(!json["vmess_httpupgrade_smoke_passed"].as_bool().unwrap());
    assert!(!json["vmess_httpupgrade_admitted"].as_bool().unwrap());
    assert!(
        json["vmess_shared_transport_partial_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(json["vmess_protocol_partial_admitted"].as_bool().unwrap());
    assert!(
        !json["vmess_protocol_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["vmess_tls_underlay_admitted"].as_bool().unwrap());
    assert!(!json["vmess_shared_transport_admitted"].as_bool().unwrap());
    assert_eq!(
        json["vmess_httpupgrade_contract"]["target"]
            .as_str()
            .unwrap(),
        fixture["vmess_httpupgrade_contract"]["target"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        json["vmess_httpupgrade_contract"]["httpupgrade_host"]
            .as_str()
            .unwrap(),
        fixture["vmess_httpupgrade_contract"]["httpupgrade_host"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        json["vmess_httpupgrade_contract"]["httpupgrade_path"]
            .as_str()
            .unwrap(),
        fixture["vmess_httpupgrade_contract"]["httpupgrade_path"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        json["vmess_httpupgrade_contract"]["payload_ascii"]
            .as_str()
            .unwrap(),
        fixture["vmess_httpupgrade_contract"]["payload_ascii"]
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
fn stage70_runtime_admission_blocks_unsafe_execution() {
    let blocked = run_with_args([
        "runtime",
        "stage70-vmess-httpupgrade-dataplane-admission",
        "--execute-smoke",
    ]);
    assert_eq!(blocked.exit_code, 1);
    assert!(
        blocked
            .stdout
            .contains("stage70 root-gated smoke requires --ack-root-gate")
    );
}

#[test]
fn stage71_runtime_admission_fixture_matches() {
    let fixture = load("engine/runtime_stage71/vmess_grpc_hunk_dataplane_admission.json");
    let output = run_with_args(["runtime", "stage71-vmess-grpc-hunk-dataplane-admission"]);
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
        json["vmess_aead_tcp_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(json["vmess_aead_udp_over_tcp_admitted"].as_bool().unwrap());
    assert!(json["vmess_udp_packet_addr_admitted"].as_bool().unwrap());
    assert!(json["vmess_mux_admitted"].as_bool().unwrap());
    assert!(json["vmess_websocket_admitted"].as_bool().unwrap());
    assert!(json["vmess_httpupgrade_admitted"].as_bool().unwrap());
    assert!(!json["vmess_grpc_hunk_smoke_passed"].as_bool().unwrap());
    assert!(!json["vmess_grpc_hunk_admitted"].as_bool().unwrap());
    assert!(
        json["vmess_shared_transport_partial_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(json["vmess_protocol_partial_admitted"].as_bool().unwrap());
    assert!(
        !json["vmess_protocol_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["vmess_tls_underlay_admitted"].as_bool().unwrap());
    assert!(!json["vmess_shared_transport_admitted"].as_bool().unwrap());
    assert_eq!(
        json["vmess_grpc_hunk_contract"]["target"].as_str().unwrap(),
        fixture["vmess_grpc_hunk_contract"]["target"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        json["vmess_grpc_hunk_contract"]["grpc_service_name"]
            .as_str()
            .unwrap(),
        fixture["vmess_grpc_hunk_contract"]["grpc_service_name"]
            .as_str()
            .unwrap()
    );
    assert!(
        !json["vmess_grpc_hunk_contract"]["full_grpc_http2_stack"]
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
fn stage71_runtime_admission_blocks_unsafe_execution() {
    let blocked = run_with_args([
        "runtime",
        "stage71-vmess-grpc-hunk-dataplane-admission",
        "--execute-smoke",
    ]);
    assert_eq!(blocked.exit_code, 1);
    assert!(
        blocked
            .stdout
            .contains("stage71 root-gated smoke requires --ack-root-gate")
    );
}

#[test]
fn stage72_runtime_admission_fixture_matches() {
    let fixture = load("engine/runtime_stage72/vmess_meek_polling_dataplane_admission.json");
    let output = run_with_args(["runtime", "stage72-vmess-meek-polling-dataplane-admission"]);
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
        json["vmess_aead_tcp_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(json["vmess_aead_udp_over_tcp_admitted"].as_bool().unwrap());
    assert!(json["vmess_udp_packet_addr_admitted"].as_bool().unwrap());
    assert!(json["vmess_mux_admitted"].as_bool().unwrap());
    assert!(json["vmess_websocket_admitted"].as_bool().unwrap());
    assert!(json["vmess_httpupgrade_admitted"].as_bool().unwrap());
    assert!(json["vmess_grpc_hunk_admitted"].as_bool().unwrap());
    assert!(!json["vmess_grpc_full_http2_admitted"].as_bool().unwrap());
    assert!(!json["vmess_meek_polling_smoke_passed"].as_bool().unwrap());
    assert!(!json["vmess_meek_polling_admitted"].as_bool().unwrap());
    assert!(
        !json["vmess_meek_full_https_roundtripper_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        json["vmess_shared_transport_partial_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(json["vmess_protocol_partial_admitted"].as_bool().unwrap());
    assert!(
        !json["vmess_protocol_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["vmess_tls_underlay_admitted"].as_bool().unwrap());
    assert!(!json["vmess_shared_transport_admitted"].as_bool().unwrap());
    assert_eq!(
        json["vmess_meek_polling_contract"]["target"]
            .as_str()
            .unwrap(),
        fixture["vmess_meek_polling_contract"]["target"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        json["vmess_meek_polling_contract"]["meek_url"]
            .as_str()
            .unwrap(),
        fixture["vmess_meek_polling_contract"]["meek_url"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        json["vmess_meek_polling_contract"]["meek_session_id"]
            .as_str()
            .unwrap(),
        fixture["vmess_meek_polling_contract"]["meek_session_id"]
            .as_str()
            .unwrap()
    );
    assert!(
        !json["vmess_meek_polling_contract"]["full_https_round_tripper"]
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
fn stage72_runtime_admission_blocks_unsafe_execution() {
    let blocked = run_with_args([
        "runtime",
        "stage72-vmess-meek-polling-dataplane-admission",
        "--execute-smoke",
    ]);
    assert_eq!(blocked.exit_code, 1);
    assert!(
        blocked
            .stdout
            .contains("stage72 root-gated smoke requires --ack-root-gate")
    );
}

#[test]
fn stage73_runtime_admission_fixture_matches() {
    let fixture = load("engine/runtime_stage73/vmess_http_transport_dataplane_admission.json");
    let output = run_with_args([
        "runtime",
        "stage73-vmess-http-transport-dataplane-admission",
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
    assert!(
        json["vmess_aead_tcp_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(json["vmess_aead_udp_over_tcp_admitted"].as_bool().unwrap());
    assert!(json["vmess_udp_packet_addr_admitted"].as_bool().unwrap());
    assert!(json["vmess_mux_admitted"].as_bool().unwrap());
    assert!(json["vmess_websocket_admitted"].as_bool().unwrap());
    assert!(json["vmess_httpupgrade_admitted"].as_bool().unwrap());
    assert!(json["vmess_grpc_hunk_admitted"].as_bool().unwrap());
    assert!(json["vmess_meek_polling_admitted"].as_bool().unwrap());
    assert!(
        !json["vmess_http_transport_put_smoke_passed"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["vmess_http_transport_put_admitted"].as_bool().unwrap());
    assert!(!json["vmess_http_h2_full_admitted"].as_bool().unwrap());
    assert!(
        json["vmess_shared_transport_partial_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(json["vmess_protocol_partial_admitted"].as_bool().unwrap());
    assert!(
        !json["vmess_protocol_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["vmess_tls_underlay_admitted"].as_bool().unwrap());
    assert!(!json["vmess_shared_transport_admitted"].as_bool().unwrap());
    assert_eq!(
        json["vmess_http_transport_contract"]["target"]
            .as_str()
            .unwrap(),
        fixture["vmess_http_transport_contract"]["target"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        json["vmess_http_transport_contract"]["http_proxy_target"]
            .as_str()
            .unwrap(),
        fixture["vmess_http_transport_contract"]["http_proxy_target"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        json["vmess_http_transport_contract"]["http_host"]
            .as_str()
            .unwrap(),
        fixture["vmess_http_transport_contract"]["http_host"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        json["vmess_http_transport_contract"]["http_path"]
            .as_str()
            .unwrap(),
        fixture["vmess_http_transport_contract"]["http_path"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        json["vmess_http_transport_contract"]["http_method"]
            .as_str()
            .unwrap(),
        "PUT"
    );
    assert!(
        !json["vmess_http_transport_contract"]["full_http2_stack"]
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
fn stage73_runtime_admission_blocks_unsafe_execution() {
    let blocked = run_with_args([
        "runtime",
        "stage73-vmess-http-transport-dataplane-admission",
        "--execute-smoke",
    ]);
    assert_eq!(blocked.exit_code, 1);
    assert!(
        blocked
            .stdout
            .contains("stage73 root-gated smoke requires --ack-root-gate")
    );
}
