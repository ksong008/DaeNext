use super::*;
#[test]
pub(super) fn daemon_runner_validate_command_accepts_a_valid_restricted_config() {
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    let root =
        std::env::temp_dir().join(format!("dae-daemon-validate-valid-{}", std::process::id()));
    let config = root.join("example.dae");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(
        &config,
        "global {\n  log_level: info\n}\n\nrouting {\n  pname(NetworkManager) -> direct\n}\n",
    )
    .unwrap();
    #[cfg(unix)]
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600)).unwrap();

    let output = run_with_args_and_version(
        [
            "validate".to_owned(),
            "-c".to_owned(),
            config.display().to_string(),
        ],
        "test-version",
    );

    assert_eq!(output.exit_code, 0, "{}", output.stderr);
    assert_eq!(output.stdout, "");
    assert_eq!(output.stderr, "");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
pub(super) fn daemon_runner_validate_command_rejects_missing_config_argument() {
    let output = run_with_args_and_version(["validate"], "test-version");
    assert_eq!(output.exit_code, 2);
    assert!(output.stderr.contains("validate requires -c/--config"));
}

#[test]
pub(super) fn daemon_runner_run_command_requires_config() {
    let output = run_with_args_and_version(["run"], "test-version");
    assert_eq!(output.exit_code, 2);
    assert!(output.stderr.contains("run requires -c/--config"));
}

#[test]
pub(super) fn daemon_runner_run_command_rejects_missing_config_file() {
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
pub(super) fn daemon_runner_run_command_requires_ack_for_production_dataplane_smoke() {
    let root = std::env::temp_dir().join(format!(
        "dae-daemon-run-dataplane-noack-{}",
        std::process::id()
    ));
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
pub(super) fn daemon_runner_run_command_requires_ack_for_production_runtime_owner() {
    let root = std::env::temp_dir().join(format!(
        "dae-daemon-run-production-runtime-noack-{}",
        std::process::id()
    ));
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
pub(super) fn daemon_runner_run_command_rejects_active_tcp_without_owner() {
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
pub(super) fn daemon_runner_run_command_rejects_reload_parity_without_active_tcp() {
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
pub(super) fn daemon_runner_run_command_rejects_active_udp_without_active_tcp() {
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
pub(super) fn daemon_runner_run_command_rejects_active_dns_without_active_udp() {
    let root = std::env::temp_dir().join(format!(
        "dae-daemon-run-active-dns-without-udp-{}",
        std::process::id()
    ));
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
pub(super) fn daemon_runner_run_command_rejects_active_dns_without_configured_target() {
    let root = std::env::temp_dir().join(format!(
        "dae-daemon-run-active-dns-no-target-{}",
        std::process::id()
    ));
    let config = root.join("config").join("run.dae");
    std::fs::create_dir_all(config.parent().unwrap()).unwrap();
    std::fs::write(
        &config,
        "global {\n  log_level: info\n  udp_check_dns: ''\n}\n\nrouting {\n  pname(NetworkManager) -> direct\n}\n",
    )
    .unwrap();
    let output = run_with_args_and_version(
        [
            "run".to_owned(),
            "--config".to_owned(),
            config.display().to_string(),
            "--root".to_owned(),
            root.display().to_string(),
            "--execute-production-runtime-owner".to_owned(),
            "--execute-production-runtime-active-tcp".to_owned(),
            "--execute-production-runtime-active-udp".to_owned(),
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
            .contains("global.udp_check_dns or --production-runtime-active-dns-target-ip"),
        "{}",
        output.stderr
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
pub(super) fn daemon_runner_run_command_requires_ack_for_matched_default_benchmark() {
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
