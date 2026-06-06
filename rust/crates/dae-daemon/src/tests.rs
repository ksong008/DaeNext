use serde_json::{Value, json};

use crate::{
    DefaultRunIdentityAdmissionOptions, RunOptions, control_plane_entrypoint_admission_report,
    control_plane_owner_preflight_report, daemon_identity, default_run_identity_admission_report,
    identity_preflight_report, lifecycle_smoke_report, listener_ebpf_preflight_report,
    run_default_optin_report, run_entrypoint_preflight_report, run_with_args_and_version,
    rust_native_control_plane_admission_report, signal_control_plane_smoke_report,
};

#[test]
fn contract_names_do_not_use_retired_version_suffix_or_stage_ids() {
    let repo_root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .unwrap();
    let mut files = Vec::new();
    for relative in ["rust/crates", "scripts", "testdata/rebuild-golden"] {
        collect_contract_name_scan_files(&repo_root.join(relative), &mut files);
    }

    let retired_suffix = String::from_utf8(vec![b'-', b'v', b'1']).unwrap();
    let retired_stage_ids = [
        retired_stage_id("23", "product-chain-admission"),
        retired_stage_id("22", "daemon-live-evidence-queue"),
        retired_stage_id("19", "complex-dataplane-gate"),
        retired_stage_id("17", "protocol-dataplane-admission"),
        retired_stage_id("16", "daemon-default-readiness"),
        retired_stage_id("22", "daemon-gray-switch-gate"),
        retired_stage_id("23", "true-default-daemon-admission"),
        retired_stage_id("7", "release-product-chain-live-gate"),
        retired_stage_id("6", "datapath-outbound-ebpf-deep-area"),
        retired_stage_id("7", "default-daemon-live-matrix"),
    ];

    let mut offenders = Vec::new();
    for file in files {
        let text = std::fs::read_to_string(&file).unwrap();
        let relative = file.strip_prefix(&repo_root).unwrap_or(&file);
        if text.contains(&retired_suffix) {
            offenders.push(format!(
                "{} contains retired hyphen-version suffix",
                relative.display()
            ));
        }
        for retired_id in &retired_stage_ids {
            if text.contains(retired_id) {
                offenders.push(format!(
                    "{} contains retired active stage contract id {retired_id}",
                    relative.display()
                ));
            }
        }
    }

    assert!(offenders.is_empty(), "{}", offenders.join("\n"));
}

#[test]
fn userland_ffi_c_abi_is_not_in_default_control_crate_path() {
    let repo_root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .unwrap();
    let cargo_toml =
        std::fs::read_to_string(repo_root.join("rust/crates/dae-control/Cargo.toml")).unwrap();
    let control_lib =
        std::fs::read_to_string(repo_root.join("rust/crates/dae-control/src/lib.rs")).unwrap();

    assert!(
        !cargo_toml.contains("staticlib"),
        "dae-control must not expose a default userland C ABI staticlib"
    );
    assert!(
        control_lib.contains("#[cfg(feature = \"ffi-compat\")]\npub mod ffi;"),
        "dae-control ffi module must be behind explicit ffi-compat"
    );
}

fn collect_contract_name_scan_files(root: &std::path::Path, files: &mut Vec<std::path::PathBuf>) {
    if !root.exists() {
        return;
    }
    let entries = std::fs::read_dir(root).unwrap();
    for entry in entries {
        let path = entry.unwrap().path();
        if path.is_dir() {
            collect_contract_name_scan_files(&path, files);
        } else if matches!(
            path.extension().and_then(|extension| extension.to_str()),
            Some("rs" | "sh" | "json")
        ) {
            files.push(path);
        }
    }
}

fn retired_stage_id(stage: &str, name: &str) -> String {
    format!("{}{}-{}", "stage", stage, name)
}

#[test]
fn resident_dataplane_events_do_not_emit_legacy_execution_fields() {
    let repo_root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .unwrap();
    let mut files = Vec::new();
    collect_contract_name_scan_files(
        &repo_root.join("rust/crates/dae-daemon/src/production_runtime_owner/resident_dataplane"),
        &mut files,
    );

    let forbidden = [
        format!("\"{}\":", "execution"),
        format!("\"{}\":", "proxy_execution"),
        format!("[\"{}\"] =", "execution"),
        format!("[\"{}\"] =", "proxy_execution"),
    ];
    let mut offenders = Vec::new();
    for file in files {
        let text = std::fs::read_to_string(&file).unwrap();
        let relative = file.strip_prefix(&repo_root).unwrap_or(&file);
        for pattern in &forbidden {
            if text.contains(pattern) {
                offenders.push(format!(
                    "{} emits retired runtime execution field pattern {pattern}",
                    relative.display()
                ));
            }
        }
    }

    assert!(offenders.is_empty(), "{}", offenders.join("\n"));
}

#[test]
fn resident_dataplane_latency_snapshots_do_not_emit_raw_link_fields() {
    let repo_root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .unwrap();
    let mut files = Vec::new();
    collect_contract_name_scan_files(
        &repo_root.join("rust/crates/dae-daemon/src/production_runtime_owner/resident_dataplane"),
        &mut files,
    );

    let mut offenders = Vec::new();
    for file in files {
        let text = std::fs::read_to_string(&file).unwrap();
        let relative = file.strip_prefix(&repo_root).unwrap_or(&file);
        if text.contains("\"link\":") {
            offenders.push(format!(
                "{} emits raw runtime link field",
                relative.display()
            ));
        }
    }

    assert!(offenders.is_empty(), "{}", offenders.join("\n"));
}

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
fn identity_preflight_keeps_benchmark_closed() {
    let report = identity_preflight_report("test-version");
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
fn daemon_runner_identity_preflight_command_outputs_json() {
    let output = run_with_args_and_version(["identity-preflight"], "test-version");
    assert_eq!(output.exit_code, 0, "{}", output.stderr);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();
    assert!(json["rust_daemon_identity_scaffolded"].as_bool().unwrap());
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
}

#[test]
fn daemon_runner_bpf_loader_contract_outputs_json() {
    let output = run_with_args_and_version(["bpf-loader", "contract"], "test-version");
    assert_eq!(output.exit_code, 0, "{}", output.stderr);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();
    assert_eq!(
        json["name"].as_str().unwrap(),
        "rust-aya-bpf-loader-go-adoption-contract"
    );
    assert!(
        json["go_bpf_loader_removed_when_opted_in"]
            .as_bool()
            .unwrap()
    );
    assert!(
        json["go_userspace_outbound_remains_authoritative"]
            .as_bool()
            .unwrap()
    );
    assert!(json["kernel_ebpf_program_rewrite"].as_bool().unwrap());
}

#[test]
fn daemon_runner_rejects_retired_migration_command_aliases() {
    let output = run_with_args_and_version(["runtime-identity-preflight"], "test-version");
    assert_eq!(output.exit_code, 2);
    assert!(
        output
            .stderr
            .contains("unsupported dae-daemon-optin command: runtime-identity-preflight")
    );
}

#[test]
fn daemon_runner_validate_command_accepts_a_valid_restricted_config() {
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
fn daemon_runner_validate_command_rejects_missing_config_argument() {
    let output = run_with_args_and_version(["validate"], "test-version");
    assert_eq!(output.exit_code, 2);
    assert!(output.stderr.contains("validate requires -c/--config"));
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
    assert_eq!(
        report["default_daemon_live_matrix"]["schema"]
            .as_str()
            .unwrap(),
        "default-daemon-live-matrix"
    );
    assert!(
        !report["default_daemon_live_matrix"]["matrix_complete"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !report["default_daemon_live_matrix"]["default_switch_allowed_by_this_matrix"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["default_daemon_live_matrix"]["remaining_rows"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row.as_str().unwrap() == "production-runtime-owner")
    );
    assert_eq!(
        report["release_product_chain_live_gate"]["schema"]
            .as_str()
            .unwrap(),
        "release-product-chain-live-gate"
    );
    assert!(
        report["release_product_chain_live_gate"]["fixed_queue_completed"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !report["release_product_chain_live_gate"]["release_gate_open"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["release_product_chain_live_gate"]["go_runtime_outbound_fallback_required"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !report["release_product_chain_live_gate"]["default_daemon_live_matrix_complete"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !report["release_product_chain_live_gate"]["go_bpf_loader_restored"]
            .as_bool()
            .unwrap()
    );
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
            "--production-runtime-fallback-retirement-product-chain-recertified".to_owned(),
            "--production-runtime-fallback-retirement-explicit-approval".to_owned(),
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
    assert!(
        json["production_runtime_owner"]["contract"]["native_ebpf"]
            ["fallback_retirement_product_chain_recertified"]
            .as_bool()
            .unwrap()
    );
    assert!(
        json["production_runtime_owner"]["contract"]["native_ebpf"]
            ["fallback_retirement_explicit_user_approval"]
            .as_bool()
            .unwrap()
    );
    let fallback_gate = &json["production_runtime_owner"]["ebpf_backend_capabilities"]["kernel_program_fallback_retirement_gate"];
    assert!(
        fallback_gate["product_chain_recertified"]
            .as_bool()
            .unwrap()
    );
    assert!(
        fallback_gate["explicit_user_approval_recorded"]
            .as_bool()
            .unwrap()
    );
    assert!(fallback_gate["admitted"].as_bool().unwrap());
    let fallback_blockers = fallback_gate["blockers"].as_array().unwrap();
    assert!(fallback_blockers.is_empty());
    assert!(
        json["production_runtime_owner"]["go_bpf_fallback_retired"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["production_runtime_owner"]["default_switch_allowed"]
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
    std::fs::write(
        &fresh_install_binary,
        "#!/bin/sh\n[ \"$1\" = \"validate\" ] && exit 0\nexit 2\n",
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            &fresh_install_binary,
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
    }
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
    assert!(
        !json["product_chain_recertification"]["local_validation_fresh_install_plan"]
            ["candidate_validate"]["executed"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["product_chain_recertification"]["local_validation_fresh_install_plan"]["pass"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["product_chain_recertification"]["local_validation_fresh_install_plan"]["checks"]
            ["resident_run_service_contract_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
    assert!(!json["product_chain_switch_allowed"].as_bool().unwrap());
    let _ = std::fs::remove_dir_all(root);
    let _ = std::fs::remove_dir_all(fixture);
}

#[test]
fn daemon_runner_product_chain_accepts_external_admission_evidence() {
    let root = std::env::temp_dir().join(format!(
        "dae-daemon-run-product-chain-external-admission-{}",
        std::process::id()
    ));
    let fixture = std::env::temp_dir().join(format!(
        "dae-daemon-product-chain-external-admission-fixture-{}",
        std::process::id()
    ));
    let config = fixture.join("config.dae");
    let service = fixture.join("install/dae.service");
    let go_mod = fixture.join("go.mod");
    let admission = fixture.join("admission.json");
    std::fs::create_dir_all(config.parent().unwrap()).unwrap();
    std::fs::write(
        &config,
        "global {\n  log_level: info\n}\n\nrouting {\n  pname(NetworkManager) -> direct\n}\n",
    )
    .unwrap();
    std::fs::create_dir_all(service.parent().unwrap()).unwrap();
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
    std::fs::write(
        &admission,
        serde_json::to_vec_pretty(&json!({
            "production_dataplane_admitted": true,
            "reload_runtime_parity_admitted": true,
            "matched_go_rust_default_daemon_benchmark_recorded": true,
            "bpf_go_fallback_retired": true,
            "true_rust_default_daemon_admitted": true,
        }))
        .unwrap(),
    )
    .unwrap();
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
            "--product-chain-admission-evidence".to_owned(),
            admission.display().to_string(),
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
    let json: Value = serde_json::from_str(&output.stdout).unwrap();
    assert!(
        json["product_chain_admission_evidence_override"]["used"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        json["product_chain_admission_evidence_override"]["source"]
            .as_str()
            .unwrap(),
        admission.display().to_string()
    );
    assert!(
        json["product_chain_recertification"]["admission_input"]
            ["true_rust_default_daemon_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        json["product_chain_recertification"]["runtime_control_api_clean_baseline"]
            ["true_rust_default_daemon_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["true_rust_default_daemon_admitted"].as_bool().unwrap());
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
    assert!(
        !json["default_daemon_live_matrix"]["matrix_complete"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["release_product_chain_live_gate"]["release_gate_open"]
            .as_bool()
            .unwrap()
    );
    assert!(
        json["release_product_chain_live_gate"]["go_runtime_outbound_fallback_required"]
            .as_bool()
            .unwrap()
    );
    let _ = std::fs::remove_dir_all(root);
    let _ = std::fs::remove_dir_all(fixture);
}

#[test]
fn daemon_runner_product_chain_accepts_fallback_retirement_without_release_switch() {
    let root = std::env::temp_dir().join(format!(
        "dae-daemon-run-product-chain-fallback-retirement-{}",
        std::process::id()
    ));
    let fixture = std::env::temp_dir().join(format!(
        "dae-daemon-product-chain-fallback-retirement-fixture-{}",
        std::process::id()
    ));
    let config = fixture.join("config.dae");
    let service = fixture.join("install/dae.service");
    let go_mod = fixture.join("go.mod");
    std::fs::create_dir_all(config.parent().unwrap()).unwrap();
    std::fs::write(
        &config,
        "global {\n  log_level: info\n}\n\nrouting {\n  pname(NetworkManager) -> direct\n}\n",
    )
    .unwrap();
    std::fs::create_dir_all(service.parent().unwrap()).unwrap();
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
            "--production-runtime-fallback-retirement-product-chain-recertified".to_owned(),
            "--production-runtime-fallback-retirement-explicit-approval".to_owned(),
            "--execute-product-chain-recertification".to_owned(),
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
    let json: Value = serde_json::from_str(&output.stdout).unwrap();
    let fallback_gate = &json["production_runtime_owner"]["ebpf_backend_capabilities"]["kernel_program_fallback_retirement_gate"];
    assert!(fallback_gate["admitted"].as_bool().unwrap());
    assert!(
        json["production_runtime_owner"]["go_bpf_fallback_retired"]
            .as_bool()
            .unwrap()
    );
    assert!(
        json["product_chain_recertification"]["admission_input"]["bpf_go_fallback_retired"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["product_chain_recertification_clean"]
            .as_bool()
            .unwrap()
    );
    let dae_branch_mismatch =
        json["product_chain_recertification"]["branch_mismatched_sibling_repos"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| entry.as_str().unwrap())
            .find(|entry| entry.starts_with("dae:"))
            .unwrap();
    assert!(dae_branch_mismatch.ends_with("!=dae-daex-align"));
    assert!(
        !json["product_chain_default_switch_admission_clean"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["release_gate_open"].as_bool().unwrap());
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
    assert!(!json["product_chain_switch_allowed"].as_bool().unwrap());
    assert!(
        !json["default_daemon_live_matrix"]["matrix_complete"]
            .as_bool()
            .unwrap()
    );
    let release_blockers = json["release_product_chain_live_gate"]["remaining_blockers"]
        .as_array()
        .unwrap();
    assert!(release_blockers.iter().any(|blocker| {
        blocker
            .as_str()
            .unwrap()
            .contains("full default daemon live matrix")
    }));
    assert!(release_blockers.iter().any(|blocker| {
        blocker
            .as_str()
            .unwrap()
            .contains("resident userspace dataplane")
    }));
    assert!(fallback_gate["default_switch_allowed"].as_bool().unwrap());
    assert!(
        fallback_gate["c_tproxy_object_retirement_allowed"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !fallback_gate["tc_command_fallback_retirement_allowed"]
            .as_bool()
            .unwrap()
    );
    let _ = std::fs::remove_dir_all(root);
    let _ = std::fs::remove_dir_all(fixture);
}

#[test]
fn daemon_runner_product_chain_accepts_explicit_resident_default_candidate_source() {
    let root = std::env::temp_dir().join(format!(
        "dae-daemon-run-product-chain-resident-source-{}",
        std::process::id()
    ));
    let fixture = std::env::temp_dir().join(format!(
        "dae-daemon-product-chain-resident-source-fixture-{}",
        std::process::id()
    ));
    let config = fixture.join("config.dae");
    let service = fixture.join("install/dae.service");
    let go_mod = fixture.join("go.mod");
    let resident_binary = fixture.join("resident-candidate");
    std::fs::create_dir_all(config.parent().unwrap()).unwrap();
    std::fs::write(
        &config,
        "global {\n  log_level: info\n}\n\nrouting {\n  pname(NetworkManager) -> direct\n}\n",
    )
    .unwrap();
    std::fs::create_dir_all(service.parent().unwrap()).unwrap();
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
    std::fs::write(
        &resident_binary,
        "#!/bin/sh\nif [ \"$1\" = \"service-contract\" ]; then printf '%s\\n' '{\"resident_run_service_contract_ready\":true,\"reload_command_service_contract_ready\":true,\"resident_production_dataplane_ready\":false}'; exit 0; fi\nexit 2\n",
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&resident_binary, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
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
            "--product-chain-resident-default-daemon-binary-source".to_owned(),
            resident_binary.display().to_string(),
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
    let json: Value = serde_json::from_str(&output.stdout).unwrap();
    let gate = &json["product_chain_recertification"]["resident_default_daemon_switch_gate"];
    assert_eq!(
        gate["binary_source"].as_str().unwrap(),
        resident_binary.display().to_string()
    );
    assert_eq!(gate["status"].as_str().unwrap(), "blocked");
    assert!(
        !json["product_chain_recertification"]["resident_default_daemon_switch_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["product_chain_recertification"]["default_path_mutation_allowed"]
            .as_bool()
            .unwrap()
    );
    assert!(gate["blockers"].as_array().unwrap().iter().any(|blocker| {
        blocker
            .as_str()
            .unwrap()
            .contains("resident default service path does not admit production dataplane")
    }));
    assert!(
        !json["product_chain_recertification"]["local_validation_fresh_install_plan"]["requested"]
            .as_bool()
            .unwrap()
    );
    let _ = std::fs::remove_dir_all(root);
    let _ = std::fs::remove_dir_all(fixture);
}

#[test]
fn lifecycle_smoke_uses_isolated_paths() {
    let root = std::env::temp_dir().join(format!(
        "dae-lifecycle-smoke-daemon-test-{}",
        std::process::id()
    ));
    let report = lifecycle_smoke_report(&root).unwrap();
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
fn daemon_runner_lifecycle_smoke_command_outputs_json() {
    let root = std::env::temp_dir().join(format!(
        "dae-lifecycle-smoke-runner-test-{}",
        std::process::id()
    ));
    let output = run_with_args_and_version(
        [
            "lifecycle-smoke".to_owned(),
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
fn control_plane_owner_preflight_uses_isolated_paths() {
    let root = std::env::temp_dir().join(format!(
        "dae-control-plane-owner-daemon-test-{}",
        std::process::id()
    ));
    let report = control_plane_owner_preflight_report(&root).unwrap();
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
fn daemon_runner_control_plane_owner_command_outputs_json() {
    let root = std::env::temp_dir().join(format!(
        "dae-control-plane-owner-runner-test-{}",
        std::process::id()
    ));
    let output = run_with_args_and_version(
        [
            "control-plane-owner-preflight".to_owned(),
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
fn signal_control_plane_smoke_uses_isolated_paths() {
    let root = std::env::temp_dir().join(format!(
        "dae-signal-control-plane-daemon-test-{}",
        std::process::id()
    ));
    let report = signal_control_plane_smoke_report(&root).unwrap();
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
fn daemon_runner_signal_control_plane_command_outputs_json() {
    let root = std::env::temp_dir().join(format!(
        "dae-signal-control-plane-runner-test-{}",
        std::process::id()
    ));
    let output = run_with_args_and_version(
        [
            "signal-control-plane-smoke".to_owned(),
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
fn run_entrypoint_preflight_composes_prior_smokes() {
    let root = std::env::temp_dir().join(format!(
        "dae-run-entrypoint-daemon-test-{}",
        std::process::id()
    ));
    let report = run_entrypoint_preflight_report(&root).unwrap();
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
fn daemon_runner_run_entrypoint_command_outputs_json() {
    let root = std::env::temp_dir().join(format!(
        "dae-run-entrypoint-runner-test-{}",
        std::process::id()
    ));
    let output = run_with_args_and_version(
        [
            "run-entrypoint-preflight".to_owned(),
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
fn default_run_identity_admits_optin_identity_only() {
    let root = std::env::temp_dir().join(format!(
        "dae-default-run-identity-daemon-test-{}",
        std::process::id()
    ));
    let opts = DefaultRunIdentityAdmissionOptions::under_root(&root);
    let report = default_run_identity_admission_report(&opts).unwrap();
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
fn daemon_runner_default_run_identity_command_outputs_json() {
    let root = std::env::temp_dir().join(format!(
        "dae-default-run-identity-runner-test-{}",
        std::process::id()
    ));
    let output = run_with_args_and_version(
        [
            "default-run-identity-admission".to_owned(),
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
    assert!(json["run_entrypoint_wrapper_reused"].as_bool().unwrap());
    assert!(
        json["run_entrypoint_wrapper"]["run_entrypoint_wrapper_composed"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["production_listener_bound"].as_bool().unwrap());
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn control_plane_entrypoint_admits_optin_contract_only() {
    let root = std::env::temp_dir().join(format!(
        "dae-control-plane-entrypoint-daemon-test-{}",
        std::process::id()
    ));
    let report = control_plane_entrypoint_admission_report(&root).unwrap();
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
    assert!(report["run_identity_admission_reused"].as_bool().unwrap());
    assert!(
        report["control_plane_owner_preflight_reused"]
            .as_bool()
            .unwrap()
    );
    assert!(!report["production_listener_bound"].as_bool().unwrap());
    assert!(!report["ebpf_attached"].as_bool().unwrap());
    assert!(!report["benchmark_executable_now"].as_bool().unwrap());
    assert!(!report["default_switch_allowed"].as_bool().unwrap());
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn daemon_runner_control_plane_entrypoint_command_outputs_json() {
    let root = std::env::temp_dir().join(format!(
        "dae-control-plane-entrypoint-runner-test-{}",
        std::process::id()
    ));
    let output = run_with_args_and_version(
        [
            "control-plane-entrypoint-admission".to_owned(),
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
fn rust_native_control_plane_admission_records_no_cgo_hot_path() {
    let root = std::env::temp_dir().join(format!(
        "dae-rust-native-control-plane-daemon-test-{}",
        std::process::id()
    ));
    let report = rust_native_control_plane_admission_report(&root, 50).unwrap();
    assert!(
        report["rust_native_control_plane_no_cgo_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!report["hot_path_cgo_required"].as_bool().unwrap());
    assert!(!report["helper_required"].as_bool().unwrap());
    assert!(!report["go_bpf_loader_required"].as_bool().unwrap());
    assert!(report["dns_domain_routing_event_native"].as_bool().unwrap());
    assert!(report["reload_transaction_native"].as_bool().unwrap());
    assert!(report["routing_lpm_owner_native"].as_bool().unwrap());
    assert!(report["connectivity_owner_native"].as_bool().unwrap());
    assert!(
        report["rust_aya_datapath_contract_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["rust_owned_1_to_5"]["all_1_to_5_admission_completed"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["rust_owned_1_to_5"]["phase_4_routing_sniff_active_handoff_state_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["rust_owned_1_to_5"]["phase_5_rust_aya_datapath_parity_candidate_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !report["rust_owned_1_to_5"]["helper_expansion_allowed"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["benchmark"]["dns_packet_to_domain_event_ns_per_op"]
            .as_u64()
            .unwrap()
            > 0
    );
    assert!(!report["default_switch_allowed"].as_bool().unwrap());
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn daemon_runner_rust_native_control_plane_command_outputs_json() {
    let root = std::env::temp_dir().join(format!(
        "dae-rust-native-control-plane-runner-test-{}",
        std::process::id()
    ));
    let output = run_with_args_and_version(
        [
            "rust-native-control-plane-admission".to_owned(),
            "--root".to_owned(),
            root.display().to_string(),
            "--iterations".to_owned(),
            "50".to_owned(),
        ],
        "test-version",
    );
    assert_eq!(output.exit_code, 0, "{}", output.stderr);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();
    assert!(
        json["rust_native_control_plane_no_cgo_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["ffi_symbols_called"].as_bool().unwrap());
    assert_eq!(json["benchmark"]["iterations"].as_u64().unwrap(), 50);
    assert!(
        json["rust_owned_1_to_5"]["all_1_to_5_admission_completed"]
            .as_bool()
            .unwrap()
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn listener_ebpf_preflight_uses_temporary_loopback_scope() {
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
fn daemon_runner_listener_ebpf_preflight_command_outputs_json() {
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
