use super::*;

#[test]
fn stage41_to_stage48_runtime_admission_fixtures_match() {
    for (fixture_path, command) in [
        (
            "engine/runtime_stage41/param_object_image_admission.json",
            "stage41-param-object-image-admission",
        ),
        (
            "engine/runtime_stage42/param_object_load_admission.json",
            "stage42-param-object-load-admission",
        ),
        (
            "engine/runtime_stage43/production_param_listener_admission.json",
            "stage43-production-param-listener-admission",
        ),
        (
            "engine/runtime_stage44/active_tcp_tproxy_admission.json",
            "stage44-active-tcp-tproxy-admission",
        ),
        (
            "engine/runtime_stage45/active_udp_tproxy_admission.json",
            "stage45-active-udp-tproxy-admission",
        ),
        (
            "engine/runtime_stage46/active_dns_tproxy_admission.json",
            "stage46-active-dns-tproxy-admission",
        ),
        (
            "engine/runtime_stage47/outbound_true_dataplane_admission.json",
            "stage47-outbound-true-dataplane-admission",
        ),
        (
            "engine/runtime_stage48/true_daemon_benchmark_admission.json",
            "stage48-true-daemon-benchmark-admission",
        ),
    ] {
        let fixture = load(fixture_path);
        let output = run_with_args(["runtime", command]);
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
        assert!(!json["default_switch_allowed"].as_bool().unwrap());
        assert!(!json["product_chain_switch_allowed"].as_bool().unwrap());
        assert!(!json["true_rust_default_daemon_admitted"].as_bool().unwrap());
        assert!(json["go_default_path_preserved"].as_bool().unwrap());
        assert!(json["go_fallback_required"].as_bool().unwrap());
        assert_eq!(
            json["remaining_blockers"].as_array().unwrap().len(),
            fixture["remaining_blockers"].as_array().unwrap().len()
        );
    }
}

#[test]
fn stage41_runtime_admission_writes_param_object_when_requested() {
    let source = dae_golden::repo_root_from_manifest()
        .unwrap()
        .join("control/bpf_bpfel.o");
    let output_path = temp_path("stage41-param-object.o");
    let output = run_with_args([
        "runtime",
        "stage41-param-object-image-admission",
        "--write-image",
        "--require-admission",
        "--object",
        source.to_str().unwrap(),
        "--output",
        output_path.to_str().unwrap(),
    ]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();
    assert!(json["param_object_image_written"].as_bool().unwrap());
    assert!(json["param_object_image_admitted"].as_bool().unwrap());
    assert_eq!(
        json["rewritten_param"]["tproxy_port"].as_u64().unwrap(),
        14640
    );
    let _ = fs::remove_file(output_path);
}

#[test]
fn stage42_runtime_admission_blocks_unsafe_execution() {
    let blocked = run_with_args([
        "runtime",
        "stage42-param-object-load-admission",
        "--execute-smoke",
    ]);
    assert_eq!(blocked.exit_code, 1);
    assert!(
        blocked
            .stdout
            .contains("stage42 root-gated smoke requires --ack-root-gate")
    );
}

#[test]
fn stage49_runtime_admission_fixture_matches() {
    let fixture = load("engine/runtime_stage49/production_param_listener_admission.json");
    let output = run_with_args(["runtime", "stage49-production-param-listener-admission"]);
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
    assert!(
        !json["combined_production_param_listener_smoke_passed"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["combined_production_param_listener_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["active_tproxy_traffic_executed"].as_bool().unwrap());
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
    assert!(!json["product_chain_switch_allowed"].as_bool().unwrap());
    assert!(!json["true_rust_default_daemon_admitted"].as_bool().unwrap());
    assert!(json["go_default_path_preserved"].as_bool().unwrap());
    assert!(json["go_fallback_required"].as_bool().unwrap());
    assert_eq!(
        json["remaining_blockers"].as_array().unwrap().len(),
        fixture["remaining_blockers"].as_array().unwrap().len()
    );
}

#[test]
fn stage49_runtime_admission_blocks_unsafe_execution() {
    let blocked = run_with_args([
        "runtime",
        "stage49-production-param-listener-admission",
        "--execute-smoke",
    ]);
    assert_eq!(blocked.exit_code, 1);
    assert!(
        blocked
            .stdout
            .contains("stage49 root-gated smoke requires --ack-root-gate")
    );
}

#[test]
fn stage50_runtime_admission_fixture_matches() {
    let fixture = load("engine/runtime_stage50/active_tcp_tproxy_ingress_admission.json");
    let output = run_with_args(["runtime", "stage50-active-tcp-tproxy-ingress-admission"]);
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
    assert!(
        !json["active_tcp_tproxy_ingress_smoke_passed"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["active_tcp_tproxy_ingress_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["active_tcp_tproxy_admitted"].as_bool().unwrap());
    assert!(
        !json["route_dial_tcp_rust_control_plane_executed"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
    assert!(!json["product_chain_switch_allowed"].as_bool().unwrap());
    assert!(!json["true_rust_default_daemon_admitted"].as_bool().unwrap());
    assert!(json["go_default_path_preserved"].as_bool().unwrap());
    assert!(json["go_fallback_required"].as_bool().unwrap());
    assert_eq!(
        json["remaining_blockers"].as_array().unwrap().len(),
        fixture["remaining_blockers"].as_array().unwrap().len()
    );
}

#[test]
fn stage50_runtime_admission_blocks_unsafe_execution() {
    let blocked = run_with_args([
        "runtime",
        "stage50-active-tcp-tproxy-ingress-admission",
        "--execute-smoke",
    ]);
    assert_eq!(blocked.exit_code, 1);
    assert!(
        blocked
            .stdout
            .contains("stage50 root-gated smoke requires --ack-root-gate")
    );
}

#[test]
fn stage51_runtime_admission_fixture_matches() {
    let fixture = load("engine/runtime_stage51/active_tcp_route_dial_relay_admission.json");
    let output = run_with_args(["runtime", "stage51-active-tcp-route-dial-relay-admission"]);
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
    assert!(!json["active_tcp_relay_smoke_passed"].as_bool().unwrap());
    assert!(
        !json["active_tcp_relay_benchmark_recorded"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["route_dial_tcp_direct_path_executed"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["so_mark_mptcp_real_outbound_socket_recorded"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
    assert!(!json["product_chain_switch_allowed"].as_bool().unwrap());
    assert!(!json["true_rust_default_daemon_admitted"].as_bool().unwrap());
    assert!(json["go_default_path_preserved"].as_bool().unwrap());
    assert!(json["go_fallback_required"].as_bool().unwrap());
    assert_eq!(
        json["remaining_blockers"].as_array().unwrap().len(),
        fixture["remaining_blockers"].as_array().unwrap().len()
    );
}

#[test]
fn stage51_runtime_admission_blocks_unsafe_execution() {
    let blocked = run_with_args([
        "runtime",
        "stage51-active-tcp-route-dial-relay-admission",
        "--execute-smoke",
    ]);
    assert_eq!(blocked.exit_code, 1);
    assert!(
        blocked
            .stdout
            .contains("stage51 root-gated smoke requires --ack-root-gate")
    );
}

#[test]
fn stage52_runtime_admission_fixture_matches() {
    let fixture = load("engine/runtime_stage52/active_tcp_route_table_group_admission.json");
    let output = run_with_args([
        "runtime",
        "stage52-active-tcp-route-table-group-relay-admission",
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
    assert!(
        json["route_dial_tcp_route_table_recorded"]
            .as_bool()
            .unwrap()
    );
    assert!(json["choose_dial_target_recorded"].as_bool().unwrap());
    assert!(json["outbound_group_selection_recorded"].as_bool().unwrap());
    assert!(
        json["route_dial_tcp_rust_control_plane_executed"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["active_tcp_route_table_group_relay_smoke_passed"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["active_tcp_route_table_group_benchmark_recorded"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        json["route_dial_plan"]["final_dial_target"]
            .as_str()
            .unwrap(),
        fixture["route_dial_plan"]["final_dial_target"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        json["group_selection"]["selected_dialer"].as_str().unwrap(),
        fixture["group_selection"]["selected_dialer"]
            .as_str()
            .unwrap()
    );
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
    assert!(!json["product_chain_switch_allowed"].as_bool().unwrap());
    assert!(!json["true_rust_default_daemon_admitted"].as_bool().unwrap());
    assert!(json["go_default_path_preserved"].as_bool().unwrap());
    assert!(json["go_fallback_required"].as_bool().unwrap());
    assert_eq!(
        json["remaining_blockers"].as_array().unwrap().len(),
        fixture["remaining_blockers"].as_array().unwrap().len()
    );
}

#[test]
fn stage52_runtime_admission_blocks_unsafe_execution() {
    let blocked = run_with_args([
        "runtime",
        "stage52-active-tcp-route-table-group-relay-admission",
        "--execute-smoke",
    ]);
    assert_eq!(blocked.exit_code, 1);
    assert!(
        blocked
            .stdout
            .contains("stage52 root-gated smoke requires --ack-root-gate")
    );
}

#[test]
fn stage53_runtime_admission_fixture_matches() {
    let fixture = load("engine/runtime_stage53/active_udp_tproxy_endpoint_admission.json");
    let output = run_with_args(["runtime", "stage53-active-udp-tproxy-endpoint-admission"]);
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
    assert!(!json["active_udp_tproxy_smoke_passed"].as_bool().unwrap());
    assert!(!json["active_udp_tproxy_admitted"].as_bool().unwrap());
    assert!(
        !json["active_udp_original_destination_observed"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["udp_endpoint_pool_live_recorded"].as_bool().unwrap());
    assert!(
        !json["udp_packetconn_write_read_recorded"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["udp_sendpkt_reply_recorded"].as_bool().unwrap());
    assert!(
        !json["udp_so_mark_real_outbound_socket_observed"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        json["active_udp_contract"]["target"].as_str().unwrap(),
        fixture["active_udp_contract"]["target"].as_str().unwrap()
    );
    assert_eq!(
        json["udp_endpoint_pool"]["key_model"].as_str().unwrap(),
        fixture["udp_endpoint_pool"]["key_model"].as_str().unwrap()
    );
    assert!(
        json["udp_endpoint_pool"]["dns_udp53_excluded"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["active_dns_tproxy_admitted"].as_bool().unwrap());
    assert!(!json["outbound_true_dataplane_admitted"].as_bool().unwrap());
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
    assert!(!json["product_chain_switch_allowed"].as_bool().unwrap());
    assert!(!json["true_rust_default_daemon_admitted"].as_bool().unwrap());
    assert!(json["go_default_path_preserved"].as_bool().unwrap());
    assert!(json["go_fallback_required"].as_bool().unwrap());
    assert_eq!(
        json["remaining_blockers"].as_array().unwrap().len(),
        fixture["remaining_blockers"].as_array().unwrap().len()
    );
}

#[test]
fn stage53_runtime_admission_blocks_unsafe_execution() {
    let blocked = run_with_args([
        "runtime",
        "stage53-active-udp-tproxy-endpoint-admission",
        "--execute-smoke",
    ]);
    assert_eq!(blocked.exit_code, 1);
    assert!(
        blocked
            .stdout
            .contains("stage53 root-gated smoke requires --ack-root-gate")
    );
}

#[test]
fn stage54_runtime_admission_fixture_matches() {
    let fixture = load("engine/runtime_stage54/active_dns_tproxy_cache_admission.json");
    let output = run_with_args(["runtime", "stage54-active-dns-tproxy-cache-admission"]);
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
    assert!(!json["active_dns_tproxy_smoke_passed"].as_bool().unwrap());
    assert!(!json["active_dns_tproxy_admitted"].as_bool().unwrap());
    assert!(
        !json["active_dns_original_destination_observed"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["dns_controller_path_recorded"].as_bool().unwrap());
    assert!(!json["dns_upstream_query_recorded"].as_bool().unwrap());
    assert!(!json["dns_cache_restore_recorded"].as_bool().unwrap());
    assert!(
        !json["domain_routing_owner_migration_recorded"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        json["active_dns_contract"]["dns_target"].as_str().unwrap(),
        fixture["active_dns_contract"]["dns_target"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        json["active_dns_contract"]["dns_upstream"]
            .as_str()
            .unwrap(),
        fixture["active_dns_contract"]["dns_upstream"]
            .as_str()
            .unwrap()
    );
    assert!(
        json["dns_cache"]["cache_key_includes_qclass"]
            .as_bool()
            .unwrap()
    );
    assert!(
        json["dns_cache"]["packed_response_id_rewrite_required"]
            .as_bool()
            .unwrap()
    );
    assert!(json["active_udp_tproxy_admitted"].as_bool().unwrap());
    assert!(!json["outbound_true_dataplane_admitted"].as_bool().unwrap());
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
    assert!(!json["product_chain_switch_allowed"].as_bool().unwrap());
    assert!(!json["true_rust_default_daemon_admitted"].as_bool().unwrap());
    assert!(json["go_default_path_preserved"].as_bool().unwrap());
    assert!(json["go_fallback_required"].as_bool().unwrap());
    assert_eq!(
        json["remaining_blockers"].as_array().unwrap().len(),
        fixture["remaining_blockers"].as_array().unwrap().len()
    );
}

#[test]
fn stage54_runtime_admission_blocks_unsafe_execution() {
    let blocked = run_with_args([
        "runtime",
        "stage54-active-dns-tproxy-cache-admission",
        "--execute-smoke",
    ]);
    assert_eq!(blocked.exit_code, 1);
    assert!(
        blocked
            .stdout
            .contains("stage54 root-gated smoke requires --ack-root-gate")
    );
}
