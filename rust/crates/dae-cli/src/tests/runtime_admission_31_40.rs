use super::*;

#[test]
fn stage31_to_stage34_runtime_admission_fixtures_match() {
    for (fixture_path, command) in [
        (
            "engine/runtime_stage31/ebpf_attach_admission.json",
            "stage31-ebpf-attach-admission",
        ),
        (
            "engine/runtime_stage32/active_traffic_admission.json",
            "stage32-active-traffic-admission",
        ),
        (
            "engine/runtime_stage33/reload_rollback_admission.json",
            "stage33-reload-rollback-admission",
        ),
        (
            "engine/runtime_stage34/benchmark_admission.json",
            "stage34-benchmark-admission",
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
        assert!(!json["default_path_mutated"].as_bool().unwrap());
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
fn stage31_to_stage34_runtime_admission_gates_block_defaults() {
    let stage31_blocked = run_with_args([
        "runtime",
        "stage31-ebpf-attach-admission",
        "--execute-smoke",
    ]);
    assert_eq!(stage31_blocked.exit_code, 1);
    assert!(
        stage31_blocked
            .stdout
            .contains("stage31 root-gated smoke requires --ack-root-gate")
    );

    let stage32_blocked = run_with_args([
        "runtime",
        "stage32-active-traffic-admission",
        "--execute-smoke",
    ]);
    assert_eq!(stage32_blocked.exit_code, 1);
    assert!(
        stage32_blocked
            .stdout
            .contains("stage32 local traffic smoke requires --ack-traffic-gate")
    );

    let report_path = std::env::temp_dir().join(format!(
        "dae-stage31-report-{}-{}.json",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::write(
        &report_path,
        r#"{"filter_cleanup_smoke_passed":true,"blockers":[]}"#,
    )
    .unwrap();
    let stage32 = run_with_args([
        "runtime",
        "stage32-active-traffic-admission",
        "--stage31-report",
        report_path.to_str().unwrap(),
        "--execute-smoke",
        "--ack-traffic-gate",
    ]);
    assert_eq!(stage32.exit_code, 0, "{}", stage32.stdout);
    let stage32_json: Value = serde_json::from_str(&stage32.stdout).unwrap();
    assert!(
        stage32_json["local_traffic_harness_passed"]
            .as_bool()
            .unwrap()
    );
    assert!(
        stage32_json["local_tcp_udp_harness_executed"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !stage32_json["active_tproxy_traffic_executed"]
            .as_bool()
            .unwrap()
    );
    assert!(!stage32_json["default_switch_allowed"].as_bool().unwrap());
    let _ = fs::remove_file(report_path);
}

#[test]
fn stage35_to_stage36_runtime_admission_fixtures_match() {
    for (fixture_path, command) in [
        (
            "engine/runtime_stage35/real_ebpf_attach_admission.json",
            "stage35-real-ebpf-attach-admission",
        ),
        (
            "engine/runtime_stage36/listen_socket_map_admission.json",
            "stage36-listen-socket-map-admission",
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
        assert!(!json["default_path_mutated"].as_bool().unwrap());
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
fn stage35_to_stage36_runtime_admission_gates_block_defaults() {
    let stage35_blocked = run_with_args([
        "runtime",
        "stage35-real-ebpf-attach-admission",
        "--execute-smoke",
    ]);
    assert_eq!(stage35_blocked.exit_code, 1);
    assert!(
        stage35_blocked
            .stdout
            .contains("stage35 root-gated smoke requires --ack-root-gate")
    );

    let stage36_blocked = run_with_args([
        "runtime",
        "stage36-listen-socket-map-admission",
        "--execute-smoke",
    ]);
    assert_eq!(stage36_blocked.exit_code, 1);
    assert!(
        stage36_blocked
            .stdout
            .contains("stage36 root-gated smoke requires --ack-root-gate")
    );
}

#[test]
fn stage37_runtime_admission_fixture_matches() {
    let fixture = load("engine/runtime_stage37/loaded_listen_socket_map_admission.json");
    let output = run_with_args(["runtime", "stage37-loaded-listen-socket-map-admission"]);
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
    assert_eq!(
        json["real_loaded_object_contract"]["section"],
        fixture["real_loaded_object_contract"]["section"]
    );
    assert!(
        !json["real_loaded_object_listen_socket_map_fd_update_executed"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
    assert!(!json["default_path_mutated"].as_bool().unwrap());
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
fn stage37_runtime_admission_blocks_unsafe_execution() {
    let blocked = run_with_args([
        "runtime",
        "stage37-loaded-listen-socket-map-admission",
        "--execute-smoke",
    ]);
    assert_eq!(blocked.exit_code, 1);
    assert!(
        blocked
            .stdout
            .contains("stage37 root-gated smoke requires --ack-root-gate")
    );
}

#[test]
fn stage38_runtime_admission_fixture_matches() {
    let fixture = load("engine/runtime_stage38/production_dae_attach_admission.json");
    let output = run_with_args(["runtime", "stage38-production-dae-attach-admission"]);
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
    assert_eq!(
        json["production_name_contract"]["peer_section"],
        fixture["production_name_contract"]["peer_section"]
    );
    assert!(
        !json["production_name_dae0_dae0peer_attach_executed"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["production_name_listen_socket_map_fd_update_executed"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["production_default_daemon_attach_executed"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
    assert!(!json["default_path_mutated"].as_bool().unwrap());
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
fn stage38_runtime_admission_blocks_unsafe_execution() {
    let blocked = run_with_args([
        "runtime",
        "stage38-production-dae-attach-admission",
        "--execute-smoke",
    ]);
    assert_eq!(blocked.exit_code, 1);
    assert!(
        blocked
            .stdout
            .contains("stage38 root-gated smoke requires --ack-root-gate")
    );
}

#[test]
fn stage39_runtime_admission_fixture_matches() {
    let fixture = load("engine/runtime_stage39/transparent_listener_admission.json");
    let output = run_with_args(["runtime", "stage39-transparent-listener-admission"]);
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
    assert_eq!(
        json["transparent_listener_contract"]["required_socket_options"],
        fixture["transparent_listener_contract"]["required_socket_options"]
    );
    assert!(
        !json["real_loaded_object_transparent_listener_fd_update_executed"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["transparent_listener_socket_options_verified"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["active_tproxy_traffic_executed"].as_bool().unwrap());
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
    assert!(!json["default_path_mutated"].as_bool().unwrap());
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
fn stage39_runtime_admission_blocks_unsafe_execution() {
    let blocked = run_with_args([
        "runtime",
        "stage39-transparent-listener-admission",
        "--execute-smoke",
    ]);
    assert_eq!(blocked.exit_code, 1);
    assert!(
        blocked
            .stdout
            .contains("stage39 root-gated smoke requires --ack-root-gate")
    );
}

#[test]
fn stage40_runtime_admission_fixture_matches() {
    let fixture = load("engine/runtime_stage40/param_aware_object_admission.json");
    let output = run_with_args(["runtime", "stage40-param-aware-object-admission"]);
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
    assert_eq!(
        json["object_contract"]["required_symbol"],
        fixture["object_contract"]["required_symbol"]
    );
    assert_eq!(
        json["object_contract"]["expected_symbol_size"],
        fixture["object_contract"]["expected_symbol_size"]
    );
    assert_eq!(
        json["param_payload"]["tproxy_port_big_endian"],
        fixture["param_payload"]["tproxy_port_big_endian"]
    );
    assert!(json["blocked"].as_bool().unwrap());
    assert!(
        json["direct_tc_object_loader_rejected_for_active_traffic"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["rust_param_aware_loader_proven"].as_bool().unwrap());
    assert!(!json["param_aware_object_load_admitted"].as_bool().unwrap());
    assert!(!json["active_tproxy_traffic_allowed"].as_bool().unwrap());
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
    assert!(!json["default_path_mutated"].as_bool().unwrap());
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
fn stage40_runtime_admission_blocks_required_admission() {
    let blocked = run_with_args([
        "runtime",
        "stage40-param-aware-object-admission",
        "--require-admission",
    ]);
    assert_eq!(blocked.exit_code, 1);
    assert!(
        blocked
            .stdout
            .contains("stage40 PARAM-aware Rust object loader is not implemented/proven")
    );
}
