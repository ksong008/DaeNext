use super::*;
#[test]
pub(super) fn listener_ebpf_preflight_uses_temporary_loopback_scope() {
    let root = std::env::temp_dir().join(format!(
        "dae-listener-ebpf-preflight-daemon-test-{}",
        std::process::id()
    ));
    let report = listener_ebpf_preflight_report(&root).unwrap();
    assert!(
        report["isolated_listener_preflight_harness_available"]
            .as_bool()
            .unwrap()
    );
    assert!(report["temporary_port_scope_validated"].as_bool().unwrap());
    assert!(
        report["tcp_udp_loopback_listener_smoke_passed"]
            .as_bool()
            .unwrap()
    );
    assert!(report["listener"]["tcp_udp_same_port"].as_bool().unwrap());
    assert!(
        report["listener"]["tcp_roundtrip_passed"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["listener"]["udp_roundtrip_passed"]
            .as_bool()
            .unwrap()
    );
    assert!(report["capability_preflight_executed"].as_bool().unwrap());
    assert!(
        report["temporary_bpf_pin_scope_validated"]
            .as_bool()
            .unwrap()
    );
    assert!(report["rollback_cleanup_smoke_passed"].as_bool().unwrap());
    assert!(!report["production_listener_bound"].as_bool().unwrap());
    assert!(!report["ebpf_attached"].as_bool().unwrap());
    assert!(
        !report["temporary_ebpf_attach_smoke_passed"]
            .as_bool()
            .unwrap()
    );
    assert!(!report["benchmark_executable_now"].as_bool().unwrap());
    let _ = std::fs::remove_dir_all(root);
}

#[test]
pub(super) fn daemon_runner_listener_ebpf_preflight_command_outputs_json() {
    let root = std::env::temp_dir().join(format!(
        "dae-listener-ebpf-preflight-runner-test-{}",
        std::process::id()
    ));
    let output = run_with_args_and_version(
        [
            "listener-ebpf-preflight".to_owned(),
            "--root".to_owned(),
            root.display().to_string(),
        ],
        "test-version",
    );
    assert_eq!(output.exit_code, 0, "{}", output.stderr);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();
    assert!(
        json["tcp_udp_loopback_listener_smoke_passed"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["temporary_ebpf_attach_smoke_passed"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["true_rust_default_daemon_admitted"].as_bool().unwrap());
    let _ = std::fs::remove_dir_all(root);
}
