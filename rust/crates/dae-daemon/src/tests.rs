use serde_json::Value;

use crate::{
    RunOptions, Stage156DefaultRunIdentityOptions, daemon_identity, run_default_optin_report,
    run_with_args_and_version, stage149_identity_preflight_report, stage150_lifecycle_smoke_report,
    stage151_control_plane_owner_preflight_report, stage152_signal_control_plane_smoke_report,
    stage153_run_entrypoint_preflight_report, stage156_default_run_identity_admission_report,
    stage157_control_plane_entrypoint_admission_report,
    stage160_listener_ebpf_preflight_harness_report,
};

#[test]
fn daemon_identity_is_opt_in_and_not_default() {
    let report = daemon_identity("test-version");
    assert_eq!(report["name"].as_str().unwrap(), "dae-daemon-optin");
    assert_eq!(report["crate"].as_str().unwrap(), "dae-daemon");
    assert_eq!(report["version"].as_str().unwrap(), "test-version");
    assert!(report["rust_daemon_identity_scaffolded"].as_bool().unwrap());
    assert!(
        report["rust_daemon_crate_manifest_exists"]
            .as_bool()
            .unwrap()
    );
    assert!(report["rust_daemon_optin_binary_exists"].as_bool().unwrap());
    assert!(
        report["rust_daemon_optin_run_command_available"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !report["rust_default_run_entrypoint_exists"]
            .as_bool()
            .unwrap()
    );
    assert!(!report["default_switch_allowed"].as_bool().unwrap());
}

#[test]
fn stage149_preflight_keeps_benchmark_closed() {
    let report = stage149_identity_preflight_report("test-version");
    assert!(report["rust_daemon_identity_scaffolded"].as_bool().unwrap());
    assert!(
        !report["rust_daemon_lifecycle_smoke_passed"]
            .as_bool()
            .unwrap()
    );
    assert!(!report["benchmark_executable_now"].as_bool().unwrap());
    assert!(
        !report["matched_go_rust_default_daemon_benchmark_recorded"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !report["true_rust_default_daemon_admitted"]
            .as_bool()
            .unwrap()
    );
}

#[test]
fn daemon_runner_identity_command_outputs_json() {
    let output = run_with_args_and_version(["identity"], "test-version");
    assert_eq!(output.exit_code, 0, "{}", output.stderr);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();
    assert_eq!(json["name"].as_str().unwrap(), "dae-daemon-optin");
    assert_eq!(json["version"].as_str().unwrap(), "test-version");
}

#[test]
fn daemon_runner_run_command_requires_config() {
    let output = run_with_args_and_version(["run"], "test-version");
    assert_eq!(output.exit_code, 2);
    assert!(output.stderr.contains("run requires -c/--config"));
}

#[test]
fn daemon_runner_run_command_rejects_missing_config_file() {
    let root = std::env::temp_dir().join(format!("dae-daemon-run-missing-{}", std::process::id()));
    let output = run_with_args_and_version(
        [
            "run".to_owned(),
            "--config".to_owned(),
            root.join("missing.dae").display().to_string(),
            "--root".to_owned(),
            root.display().to_string(),
        ],
        "test-version",
    );
    assert_eq!(output.exit_code, 1);
    assert!(output.stderr.contains("run config does not exist"));
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn daemon_runner_run_command_requires_ack_for_production_dataplane_smoke() {
    let root = std::env::temp_dir().join(format!(
        "dae-daemon-run-dataplane-noack-{}",
        std::process::id()
    ));
    let config = root.join("config").join("run.dae");
    std::fs::create_dir_all(config.parent().unwrap()).unwrap();
    std::fs::write(&config, "global {\n  log_level: info\n}\n").unwrap();
    let output = run_with_args_and_version(
        [
            "run".to_owned(),
            "--config".to_owned(),
            config.display().to_string(),
            "--root".to_owned(),
            root.display().to_string(),
            "--execute-production-dataplane-smoke".to_owned(),
            "--exit-after-ready".to_owned(),
        ],
        "test-version",
    );
    assert_eq!(output.exit_code, 1);
    assert!(output.stderr.contains("--ack-root-gate"));
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn daemon_runner_run_command_requires_ack_for_production_runtime_owner() {
    let root = std::env::temp_dir().join(format!(
        "dae-daemon-run-production-runtime-noack-{}",
        std::process::id()
    ));
    let config = root.join("config").join("run.dae");
    std::fs::create_dir_all(config.parent().unwrap()).unwrap();
    std::fs::write(&config, "global {\n  log_level: info\n}\n").unwrap();
    let output = run_with_args_and_version(
        [
            "run".to_owned(),
            "--config".to_owned(),
            config.display().to_string(),
            "--root".to_owned(),
            root.display().to_string(),
            "--execute-production-runtime-owner".to_owned(),
            "--exit-after-ready".to_owned(),
        ],
        "test-version",
    );
    assert_eq!(output.exit_code, 1);
    assert!(output.stderr.contains("--ack-root-gate"));
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn daemon_runner_run_command_rejects_active_tcp_without_owner() {
    let root = std::env::temp_dir().join(format!(
        "dae-daemon-run-active-tcp-without-owner-{}",
        std::process::id()
    ));
    let config = root.join("config").join("run.dae");
    std::fs::create_dir_all(config.parent().unwrap()).unwrap();
    std::fs::write(&config, "global {\n  log_level: info\n}\n").unwrap();
    let output = run_with_args_and_version(
        [
            "run".to_owned(),
            "--config".to_owned(),
            config.display().to_string(),
            "--root".to_owned(),
            root.display().to_string(),
            "--execute-production-runtime-active-tcp".to_owned(),
            "--ack-root-gate".to_owned(),
            "--exit-after-ready".to_owned(),
        ],
        "test-version",
    );
    assert_eq!(output.exit_code, 1);
    assert!(output.stderr.contains("--execute-production-runtime-owner"));
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn daemon_runner_run_command_rejects_reload_parity_without_active_tcp() {
    let root = std::env::temp_dir().join(format!(
        "dae-daemon-run-reload-parity-without-tcp-{}",
        std::process::id()
    ));
    let config = root.join("config").join("run.dae");
    std::fs::create_dir_all(config.parent().unwrap()).unwrap();
    std::fs::write(&config, "global {\n  log_level: info\n}\n").unwrap();
    let output = run_with_args_and_version(
        [
            "run".to_owned(),
            "--config".to_owned(),
            config.display().to_string(),
            "--root".to_owned(),
            root.display().to_string(),
            "--execute-production-runtime-owner".to_owned(),
            "--execute-production-runtime-reload-parity".to_owned(),
            "--ack-root-gate".to_owned(),
            "--exit-after-ready".to_owned(),
        ],
        "test-version",
    );
    assert_eq!(output.exit_code, 1);
    assert!(
        output
            .stderr
            .contains("--execute-production-runtime-active-tcp")
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn daemon_runner_run_command_rejects_active_udp_without_active_tcp() {
    let root = std::env::temp_dir().join(format!(
        "dae-daemon-run-active-udp-without-tcp-{}",
        std::process::id()
    ));
    let config = root.join("config").join("run.dae");
    std::fs::create_dir_all(config.parent().unwrap()).unwrap();
    std::fs::write(&config, "global {\n  log_level: info\n}\n").unwrap();
    let output = run_with_args_and_version(
        [
            "run".to_owned(),
            "--config".to_owned(),
            config.display().to_string(),
            "--root".to_owned(),
            root.display().to_string(),
            "--execute-production-runtime-owner".to_owned(),
            "--execute-production-runtime-active-udp".to_owned(),
            "--ack-root-gate".to_owned(),
            "--exit-after-ready".to_owned(),
        ],
        "test-version",
    );
    assert_eq!(output.exit_code, 1);
    assert!(
        output
            .stderr
            .contains("--execute-production-runtime-active-tcp")
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn daemon_runner_run_command_rejects_active_dns_without_active_udp() {
    let root = std::env::temp_dir().join(format!(
        "dae-daemon-run-active-dns-without-udp-{}",
        std::process::id()
    ));
    let config = root.join("config").join("run.dae");
    std::fs::create_dir_all(config.parent().unwrap()).unwrap();
    std::fs::write(&config, "global {\n  log_level: info\n}\n").unwrap();
    let output = run_with_args_and_version(
        [
            "run".to_owned(),
            "--config".to_owned(),
            config.display().to_string(),
            "--root".to_owned(),
            root.display().to_string(),
            "--execute-production-runtime-owner".to_owned(),
            "--execute-production-runtime-active-tcp".to_owned(),
            "--execute-production-runtime-active-dns".to_owned(),
            "--ack-root-gate".to_owned(),
            "--exit-after-ready".to_owned(),
        ],
        "test-version",
    );
    assert_eq!(output.exit_code, 1);
    assert!(
        output
            .stderr
            .contains("--execute-production-runtime-active-udp")
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn daemon_runner_run_command_requires_ack_for_matched_default_benchmark() {
    let root = std::env::temp_dir().join(format!(
        "dae-daemon-run-matched-benchmark-noack-{}",
        std::process::id()
    ));
    let config = root.join("config").join("run.dae");
    std::fs::create_dir_all(config.parent().unwrap()).unwrap();
    std::fs::write(&config, "global {\n  log_level: info\n}\n").unwrap();
    let output = run_with_args_and_version(
        [
            "run".to_owned(),
            "--config".to_owned(),
            config.display().to_string(),
            "--root".to_owned(),
            root.display().to_string(),
            "--execute-matched-default-benchmark".to_owned(),
            "--exit-after-ready".to_owned(),
        ],
        "test-version",
    );
    assert_eq!(output.exit_code, 1);
    assert!(output.stderr.contains("--ack-root-gate"));
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn run_default_optin_report_executes_bounded_lifecycle_and_smokes() {
    let root =
        std::env::temp_dir().join(format!("dae-daemon-run-report-test-{}", std::process::id()));
    let config = root.join("config").join("run.dae");
    std::fs::create_dir_all(config.parent().unwrap()).unwrap();
    std::fs::write(
        &config,
        "global {\n  log_level: info\n}\n\nrouting {\n  pname(NetworkManager) -> direct\n}\n",
    )
    .unwrap();
    let mut options = RunOptions::under_root(&root, &config);
    options.disable_timestamp = true;
    options.disable_sudo = true;

    let report = run_default_optin_report(&options, "test-version").unwrap();
    assert_eq!(report["name"].as_str().unwrap(), "dae-daemon-optin-run");
    assert!(report["run_command_supported"].as_bool().unwrap());
    assert!(report["run_entrypoint_executed"].as_bool().unwrap());
    assert!(
        report["rust_default_run_entrypoint_exists"]
            .as_bool()
            .unwrap()
    );
    assert!(report["config_loaded"].as_bool().unwrap());
    assert!(report["pid_file_written"].as_bool().unwrap());
    assert!(
        report["progress_file_reload_done_written"]
            .as_bool()
            .unwrap()
    );
    assert!(report["sdnotify_ready_recorded"].as_bool().unwrap());
    assert!(report["listener_smoke_passed"].as_bool().unwrap());
    assert!(
        report["listener"]["tcp_udp_loopback_listener_smoke_passed"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["reload_owner_handoff_smoke_passed"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["reload_owner_handoff"]["listener_reuse_sequence_smoke_passed"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !report["production_dataplane_harness_executed"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !report["production_runtime_owner_executed"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !report["production_reload_runtime_parity_executed"]
            .as_bool()
            .unwrap()
    );
    assert!(!report["reload_runtime_parity_admitted"].as_bool().unwrap());
    assert!(!report["production_runtime_owner_passed"].as_bool().unwrap());
    assert!(
        !report["production_dataplane_harness_passed"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !report["matched_default_benchmark"]["execute_benchmark"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !report["matched_go_rust_default_daemon_benchmark_recorded"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        report["production_dataplane_admission_scope"]
            .as_str()
            .unwrap(),
        "not-executed"
    );
    assert!(!report["production_listener_bound"].as_bool().unwrap());
    assert!(
        !report["production_listener_bound_during_owner_smoke"]
            .as_bool()
            .unwrap()
    );
    assert!(!report["ebpf_attached"].as_bool().unwrap());
    assert!(
        !report["ebpf_attached_during_owner_smoke"]
            .as_bool()
            .unwrap()
    );
    assert!(!report["benchmark_executable_now"].as_bool().unwrap());
    assert!(!report["default_switch_allowed"].as_bool().unwrap());
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn daemon_runner_run_command_outputs_json() {
    let root =
        std::env::temp_dir().join(format!("dae-daemon-run-runner-test-{}", std::process::id()));
    let config = root.join("config").join("run.dae");
    std::fs::create_dir_all(config.parent().unwrap()).unwrap();
    std::fs::write(
        &config,
        "global {\n  log_level: info\n}\n\nrouting {\n  pname(NetworkManager) -> direct\n}\n",
    )
    .unwrap();
    let output = run_with_args_and_version(
        [
            "run".to_owned(),
            "--config".to_owned(),
            config.display().to_string(),
            "--root".to_owned(),
            root.display().to_string(),
            "--disable-timestamp".to_owned(),
            "--disable-sudo".to_owned(),
            "--production-runtime-tproxy-port=23456".to_owned(),
            "--production-runtime-dae-netns-id=123".to_owned(),
            "--production-runtime-active-tcp-target-ip=198.18.60.1".to_owned(),
            "--production-runtime-active-tcp-client-ip=10.220.60.2".to_owned(),
            "--production-runtime-active-tcp-target-port=19090".to_owned(),
            "--production-runtime-active-tcp-so-mark=4321".to_owned(),
            "--production-runtime-active-tcp-no-mptcp".to_owned(),
            "--production-runtime-active-udp-target-ip=198.18.63.1".to_owned(),
            "--production-runtime-active-udp-target-port=19093".to_owned(),
            "--production-runtime-active-udp-benchmark-iters=11".to_owned(),
            "--production-runtime-active-dns-target-ip=9.9.9.9".to_owned(),
            "--production-runtime-active-dns-target-port=53".to_owned(),
            "--production-runtime-active-dns-upstream-ip=127.0.0.1".to_owned(),
            "--production-runtime-active-dns-upstream-port=11530".to_owned(),
            "--production-runtime-active-dns-qname=runner.example.".to_owned(),
            "--production-runtime-active-dns-benchmark-iters=13".to_owned(),
            "--dataplane-benchmark-iters=7".to_owned(),
            "--matched-benchmark-iterations=9".to_owned(),
            "--exit-after-ready".to_owned(),
        ],
        "test-version",
    );
    assert_eq!(output.exit_code, 0, "{}", output.stderr);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();
    assert!(json["run_command_supported"].as_bool().unwrap());
    assert!(json["listener_smoke_passed"].as_bool().unwrap());
    assert!(json["reload_owner_handoff_smoke_passed"].as_bool().unwrap());
    assert!(
        !json["matched_go_rust_default_daemon_benchmark_recorded"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        json["production_runtime_owner"]["contract"]["tproxy_port"]
            .as_u64()
            .unwrap(),
        23456
    );
    assert_eq!(
        json["production_runtime_owner"]["contract"]["dae_netns_id"]
            .as_u64()
            .unwrap(),
        123
    );
    assert_eq!(
        json["production_runtime_owner"]["contract"]["active_tcp"]["target_ip"]
            .as_str()
            .unwrap(),
        "198.18.60.1"
    );
    assert_eq!(
        json["production_runtime_owner"]["contract"]["active_tcp"]["client_ip"]
            .as_str()
            .unwrap(),
        "10.220.60.2"
    );
    assert_eq!(
        json["production_runtime_owner"]["contract"]["active_tcp"]["target_port"]
            .as_u64()
            .unwrap(),
        19090
    );
    assert_eq!(
        json["production_runtime_owner"]["contract"]["active_tcp"]["so_mark"]
            .as_u64()
            .unwrap(),
        4321
    );
    assert!(
        !json["production_runtime_owner"]["contract"]["active_tcp"]["mptcp"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["production_runtime_active_tcp_executed"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        json["production_runtime_owner"]["contract"]["active_udp"]["target_ip"]
            .as_str()
            .unwrap(),
        "198.18.63.1"
    );
    assert_eq!(
        json["production_runtime_owner"]["contract"]["active_udp"]["target_port"]
            .as_u64()
            .unwrap(),
        19093
    );
    assert_eq!(
        json["production_runtime_owner"]["contract"]["active_udp"]["benchmark_iters"]
            .as_u64()
            .unwrap(),
        11
    );
    assert_eq!(
        json["production_runtime_owner"]["contract"]["active_dns"]["target_ip"]
            .as_str()
            .unwrap(),
        "9.9.9.9"
    );
    assert_eq!(
        json["production_runtime_owner"]["contract"]["active_dns"]["upstream_port"]
            .as_u64()
            .unwrap(),
        11530
    );
    assert_eq!(
        json["production_runtime_owner"]["contract"]["active_dns"]["qname"]
            .as_str()
            .unwrap(),
        "runner.example."
    );
    assert_eq!(
        json["production_runtime_owner"]["contract"]["active_dns"]["benchmark_iters"]
            .as_u64()
            .unwrap(),
        13
    );
    assert!(
        !json["production_runtime_active_udp_executed"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["production_runtime_active_dns_executed"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        json["production_dataplane_harness"]["benchmark_iters"]
            .as_u64()
            .unwrap(),
        7
    );
    assert!(
        !json["production_dataplane_harness_executed"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        json["matched_default_benchmark"]["iterations_requested"]
            .as_u64()
            .unwrap(),
        9
    );
    assert!(
        !json["matched_default_benchmark"]["execute_benchmark"]
            .as_bool()
            .unwrap()
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn daemon_runner_run_command_records_product_chain_recertification() {
    let root = std::env::temp_dir().join(format!(
        "dae-daemon-run-product-chain-test-{}",
        std::process::id()
    ));
    let fixture = std::env::temp_dir().join(format!(
        "dae-daemon-product-chain-runner-fixture-{}",
        std::process::id()
    ));
    let config = root.join("config").join("run.dae");
    std::fs::create_dir_all(config.parent().unwrap()).unwrap();
    std::fs::create_dir_all(&fixture).unwrap();
    std::fs::write(
        &config,
        "global {\n  log_level: info\n}\n\nrouting {\n  pname(NetworkManager) -> direct\n}\n",
    )
    .unwrap();
    let service = fixture.join("dae.service");
    let go_mod = fixture.join("go.mod");
    let fresh_install_binary = fixture.join("dae-daemon-optin");
    std::fs::write(
        &service,
        "ExecStartPre=/usr/bin/dae validate -c /etc/dae/config.dae\nExecStart=/usr/bin/dae run --disable-timestamp -c /etc/dae/config.dae\nExecReload=/usr/bin/dae reload $MAINPID\n",
    )
    .unwrap();
    std::fs::write(
        &go_mod,
        "replace github.com/daeuniverse/outbound => github.com/ksong008/outbound v0.0.0\nreplace github.com/daeuniverse/quic-go => github.com/ksong008/quic-go v0.0.0\n",
    )
    .unwrap();
    std::fs::write(&fresh_install_binary, "local-validation-rust-binary").unwrap();
    for repo in ["dae", "dae-wing", "daed", "outbound", "quic-go"] {
        let repo_dir = fixture.join(repo);
        std::fs::create_dir_all(&repo_dir).unwrap();
        assert!(
            std::process::Command::new("git")
                .args(["init", "--quiet"])
                .current_dir(&repo_dir)
                .status()
                .unwrap()
                .success()
        );
    }

    let output = run_with_args_and_version(
        [
            "run".to_owned(),
            "--config".to_owned(),
            config.display().to_string(),
            "--root".to_owned(),
            root.display().to_string(),
            "--disable-timestamp".to_owned(),
            "--disable-sudo".to_owned(),
            "--execute-product-chain-recertification".to_owned(),
            "--request-default-path-mutation".to_owned(),
            "--plan-production-run-command-replacement".to_owned(),
            "--execute-production-run-command-replacement".to_owned(),
            "--plan-production-run-command-apply".to_owned(),
            "--allow-host-default-path-mutation".to_owned(),
            "--plan-local-validation-fresh-install".to_owned(),
            "--product-chain-fresh-install-binary-source".to_owned(),
            fresh_install_binary.display().to_string(),
            "--product-chain-dae-repo".to_owned(),
            fixture.join("dae").display().to_string(),
            "--product-chain-dae-wing-repo".to_owned(),
            fixture.join("dae-wing").display().to_string(),
            "--product-chain-daed-repo".to_owned(),
            fixture.join("daed").display().to_string(),
            "--product-chain-outbound-repo".to_owned(),
            fixture.join("outbound").display().to_string(),
            "--product-chain-quic-go-repo".to_owned(),
            fixture.join("quic-go").display().to_string(),
            "--product-chain-service-file".to_owned(),
            service.display().to_string(),
            "--product-chain-go-mod-file".to_owned(),
            go_mod.display().to_string(),
            "--exit-after-ready".to_owned(),
        ],
        "test-version",
    );
    assert_eq!(output.exit_code, 0, "{}", output.stderr);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();
    assert!(
        json["product_chain_recertification_executed"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["product_chain_recertification_clean"]
            .as_bool()
            .unwrap()
    );
    assert!(
        json["product_chain_recertification"]["service_contract_preserved"]
            .as_bool()
            .unwrap()
    );
    assert!(
        json["product_chain_recertification"]["outbound_quic_go_dependency_boundary_preserved"]
            .as_bool()
            .unwrap()
    );
    assert!(
        json["product_chain_recertification"]["sibling_repo_status_available"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["product_chain_recertification"]["daed_wing_runtime_control_api_regression_recorded"]
            .as_bool()
            .unwrap()
    );
    assert!(
        json["product_chain_recertification"]["default_path_mutation_requested"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["product_chain_recertification"]["default_path_mutation_allowed"]
            .as_bool()
            .unwrap()
    );
    assert!(
        json["product_chain_recertification"]["production_run_command_replacement_plan"]
            ["requested"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["product_chain_recertification"]["production_run_command_replacement_plan"]
            ["admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        json["product_chain_recertification"]["production_run_command_replacement_plan"]
            ["execute_requested"]
            .as_bool()
            .unwrap()
    );
    assert!(
        json["product_chain_recertification"]["production_run_command_replacement_plan"]
            ["apply_plan_requested"]
            .as_bool()
            .unwrap()
    );
    assert!(
        json["product_chain_recertification"]["production_run_command_replacement_plan"]
            ["apply_plan"]["requested"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["product_chain_recertification"]["production_run_command_replacement_plan"]
            ["apply_plan"]["admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["product_chain_recertification"]["production_run_command_replacement_plan"]
            ["apply_plan"]["host_write_allowed"]
            .as_bool()
            .unwrap()
    );
    assert!(
        json["product_chain_recertification"]["production_run_command_replacement_plan"]
            ["host_mutation_allow_requested"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["product_chain_recertification"]["production_run_command_replacement_plan"]
            ["host_mutation_allowed"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["product_chain_recertification"]["production_run_command_replacement_plan"]
            ["execute_allowed"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["product_chain_recertification"]["production_run_command_replacement_plan"]
            ["actual_mutation_executed"]
            .as_bool()
            .unwrap()
    );
    assert!(
        json["product_chain_recertification"]["local_validation_fresh_install_plan"]["requested"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        json["product_chain_recertification"]["local_validation_fresh_install_plan"]["inputs"]
            ["config_source"]
            .as_str()
            .unwrap(),
        config.display().to_string()
    );
    assert_eq!(
        json["product_chain_recertification"]["local_validation_fresh_install_plan"]["inputs"]
            ["binary_source"]
            .as_str()
            .unwrap(),
        fresh_install_binary.display().to_string()
    );
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
    assert!(!json["product_chain_switch_allowed"].as_bool().unwrap());
    let _ = std::fs::remove_dir_all(root);
    let _ = std::fs::remove_dir_all(fixture);
}

#[test]
fn stage150_lifecycle_smoke_uses_isolated_paths() {
    let root =
        std::env::temp_dir().join(format!("dae-stage150-daemon-test-{}", std::process::id()));
    let report = stage150_lifecycle_smoke_report(&root).unwrap();
    assert!(
        report["rust_daemon_lifecycle_smoke_passed"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["isolated_pid_progress_paths_validated"]
            .as_bool()
            .unwrap()
    );
    assert!(!report["production_paths_mutated"].as_bool().unwrap());
    assert!(!report["benchmark_executable_now"].as_bool().unwrap());
    assert!(!report["default_switch_allowed"].as_bool().unwrap());
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn daemon_runner_stage150_lifecycle_command_outputs_json() {
    let root =
        std::env::temp_dir().join(format!("dae-stage150-runner-test-{}", std::process::id()));
    let output = run_with_args_and_version(
        [
            "stage150-lifecycle-smoke".to_owned(),
            "--root".to_owned(),
            root.display().to_string(),
        ],
        "test-version",
    );
    assert_eq!(output.exit_code, 0, "{}", output.stderr);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();
    assert!(
        json["rust_daemon_lifecycle_smoke_passed"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["production_paths_mutated"].as_bool().unwrap());
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn stage151_control_plane_owner_preflight_uses_isolated_paths() {
    let root =
        std::env::temp_dir().join(format!("dae-stage151-daemon-test-{}", std::process::id()));
    let report = stage151_control_plane_owner_preflight_report(&root).unwrap();
    assert!(
        report["rust_control_plane_owner_preflight_recorded"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["control_plane_startup_sequence_recorded"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["control_plane_reload_owner_sequence_recorded"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["control_plane_rollback_sequence_recorded"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["listener_reuse_contract_recorded"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["dns_cache_migration_guard_recorded"]
            .as_bool()
            .unwrap()
    );
    assert!(!report["production_listener_bound"].as_bool().unwrap());
    assert!(!report["ebpf_attached"].as_bool().unwrap());
    assert!(!report["default_switch_allowed"].as_bool().unwrap());
    assert_eq!(report["reload_core"]["flip"].as_u64().unwrap(), 1);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn daemon_runner_stage151_control_plane_owner_command_outputs_json() {
    let root =
        std::env::temp_dir().join(format!("dae-stage151-runner-test-{}", std::process::id()));
    let output = run_with_args_and_version(
        [
            "stage151-control-plane-owner-preflight".to_owned(),
            "--root".to_owned(),
            root.display().to_string(),
        ],
        "test-version",
    );
    assert_eq!(output.exit_code, 0, "{}", output.stderr);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();
    assert!(
        json["rust_control_plane_owner_smoke_passed"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["rust_default_control_plane_entrypoint_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["production_listener_bound"].as_bool().unwrap());
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn stage152_signal_control_plane_smoke_uses_isolated_paths() {
    let root =
        std::env::temp_dir().join(format!("dae-stage152-daemon-test-{}", std::process::id()));
    let report = stage152_signal_control_plane_smoke_report(&root).unwrap();
    assert!(
        report["rust_signal_control_plane_smoke_passed"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["reload_signal_progress_owner_sequence_validated"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["suspend_signal_progress_sequence_validated"]
            .as_bool()
            .unwrap()
    );
    assert!(report["abort_file_one_shot_consumed"].as_bool().unwrap());
    assert!(report["isolated_pid_removed_on_stop"].as_bool().unwrap());
    assert!(
        !report["production_signal_handler_installed"]
            .as_bool()
            .unwrap()
    );
    assert!(!report["production_listener_bound"].as_bool().unwrap());
    assert!(!report["ebpf_attached"].as_bool().unwrap());
    assert!(!report["default_switch_allowed"].as_bool().unwrap());
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn daemon_runner_stage152_signal_control_plane_command_outputs_json() {
    let root =
        std::env::temp_dir().join(format!("dae-stage152-runner-test-{}", std::process::id()));
    let output = run_with_args_and_version(
        [
            "stage152-signal-control-plane-smoke".to_owned(),
            "--root".to_owned(),
            root.display().to_string(),
        ],
        "test-version",
    );
    assert_eq!(output.exit_code, 0, "{}", output.stderr);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();
    assert!(
        json["rust_signal_control_plane_smoke_passed"]
            .as_bool()
            .unwrap()
    );
    assert!(
        json["owner"]["rust_control_plane_owner_smoke_passed"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["rust_default_control_plane_entrypoint_admitted"]
            .as_bool()
            .unwrap()
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn stage153_run_entrypoint_preflight_composes_prior_smokes() {
    let root =
        std::env::temp_dir().join(format!("dae-stage153-daemon-test-{}", std::process::id()));
    let report = stage153_run_entrypoint_preflight_report(&root).unwrap();
    assert!(
        report["non_default_run_entrypoint_wrapper_available"]
            .as_bool()
            .unwrap()
    );
    assert!(report["run_entrypoint_wrapper_composed"].as_bool().unwrap());
    assert!(
        report["run_entrypoint_lifecycle_smoke_reused"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["run_entrypoint_signal_control_plane_smoke_reused"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["go_default_run_command_preserved"]
            .as_bool()
            .unwrap()
    );
    assert!(!report["production_run_command_replaced"].as_bool().unwrap());
    assert!(
        !report["rust_default_run_entrypoint_exists"]
            .as_bool()
            .unwrap()
    );
    assert!(!report["default_switch_allowed"].as_bool().unwrap());
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn daemon_runner_stage153_run_entrypoint_command_outputs_json() {
    let root =
        std::env::temp_dir().join(format!("dae-stage153-runner-test-{}", std::process::id()));
    let output = run_with_args_and_version(
        [
            "stage153-run-entrypoint-preflight".to_owned(),
            "--root".to_owned(),
            root.display().to_string(),
        ],
        "test-version",
    );
    assert_eq!(output.exit_code, 0, "{}", output.stderr);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();
    assert!(json["run_entrypoint_wrapper_composed"].as_bool().unwrap());
    assert!(
        json["composed_smokes"]["lifecycle"]["rust_daemon_lifecycle_smoke_passed"]
            .as_bool()
            .unwrap()
    );
    assert!(
        json["composed_smokes"]["signal_control_plane"]["rust_signal_control_plane_smoke_passed"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["production_run_command_replaced"].as_bool().unwrap());
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn stage156_default_run_identity_admits_optin_identity_only() {
    let root =
        std::env::temp_dir().join(format!("dae-stage156-daemon-test-{}", std::process::id()));
    let opts = Stage156DefaultRunIdentityOptions::under_root(&root);
    let report = stage156_default_run_identity_admission_report(&opts).unwrap();
    assert!(
        report["rust_default_run_identity_optin_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["rust_default_run_entrypoint_exists"]
            .as_bool()
            .unwrap()
    );
    assert!(report["config_corpus_loaded"].as_bool().unwrap());
    assert!(
        report["isolated_pid_progress_paths_validated"]
            .as_bool()
            .unwrap()
    );
    assert!(!report["production_run_command_replaced"].as_bool().unwrap());
    assert!(
        !report["rust_default_control_plane_entrypoint_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!report["benchmark_executable_now"].as_bool().unwrap());
    assert!(!report["default_switch_allowed"].as_bool().unwrap());
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn daemon_runner_stage156_default_run_identity_command_outputs_json() {
    let root =
        std::env::temp_dir().join(format!("dae-stage156-runner-test-{}", std::process::id()));
    let output = run_with_args_and_version(
        [
            "stage156-default-run-identity-admission".to_owned(),
            "--root".to_owned(),
            root.display().to_string(),
            "--disable-timestamp".to_owned(),
            "--disable-sudo".to_owned(),
        ],
        "test-version",
    );
    assert_eq!(output.exit_code, 0, "{}", output.stderr);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();
    assert!(
        json["rust_default_run_identity_optin_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(json["run_shaped_flags_validated"].as_bool().unwrap());
    assert!(json["stage153_wrapper_reused"].as_bool().unwrap());
    assert!(
        json["stage153_wrapper"]["run_entrypoint_wrapper_composed"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["production_listener_bound"].as_bool().unwrap());
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn stage157_control_plane_entrypoint_admits_optin_contract_only() {
    let root =
        std::env::temp_dir().join(format!("dae-stage157-daemon-test-{}", std::process::id()));
    let report = stage157_control_plane_entrypoint_admission_report(&root).unwrap();
    assert!(
        report["control_plane_entrypoint_optin_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["rust_default_run_entrypoint_exists"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["rust_default_control_plane_entrypoint_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(report["stage156_run_identity_reused"].as_bool().unwrap());
    assert!(report["stage151_owner_preflight_reused"].as_bool().unwrap());
    assert!(!report["production_listener_bound"].as_bool().unwrap());
    assert!(!report["ebpf_attached"].as_bool().unwrap());
    assert!(!report["benchmark_executable_now"].as_bool().unwrap());
    assert!(!report["default_switch_allowed"].as_bool().unwrap());
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn daemon_runner_stage157_control_plane_entrypoint_command_outputs_json() {
    let root =
        std::env::temp_dir().join(format!("dae-stage157-runner-test-{}", std::process::id()));
    let output = run_with_args_and_version(
        [
            "stage157-control-plane-entrypoint-admission".to_owned(),
            "--root".to_owned(),
            root.display().to_string(),
        ],
        "test-version",
    );
    assert_eq!(output.exit_code, 0, "{}", output.stderr);
    let json: Value = serde_json::from_str(&output.stdout).unwrap();
    assert!(
        json["control_plane_entrypoint_optin_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        json["control_plane_owner"]["rust_control_plane_owner_smoke_passed"]
            .as_bool()
            .unwrap()
    );
    assert!(
        json["run_identity"]["rust_default_run_identity_optin_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["true_rust_default_daemon_admitted"].as_bool().unwrap());
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn stage160_listener_ebpf_preflight_uses_temporary_loopback_scope() {
    let root =
        std::env::temp_dir().join(format!("dae-stage160-daemon-test-{}", std::process::id()));
    let report = stage160_listener_ebpf_preflight_harness_report(&root).unwrap();
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
fn daemon_runner_stage160_listener_ebpf_preflight_command_outputs_json() {
    let root =
        std::env::temp_dir().join(format!("dae-stage160-runner-test-{}", std::process::id()));
    let output = run_with_args_and_version(
        [
            "stage160-listener-ebpf-preflight-harness".to_owned(),
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
