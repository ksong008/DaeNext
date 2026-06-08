use super::*;
#[test]
pub(super) fn daemon_identity_is_opt_in_and_not_default() {
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
pub(super) fn identity_preflight_keeps_benchmark_closed() {
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
pub(super) fn daemon_runner_identity_command_outputs_json() {
    let output = run_with_args_and_version(["identity"], "test-version");
    assert_eq!(output.exit_code, 0, "{}", output.stderr);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();
    assert_eq!(json["name"].as_str().unwrap(), "dae-daemon-optin");
    assert_eq!(json["version"].as_str().unwrap(), "test-version");
}

#[test]
pub(super) fn daemon_runner_identity_preflight_command_outputs_json() {
    let output = run_with_args_and_version(["identity-preflight"], "test-version");
    assert_eq!(output.exit_code, 0, "{}", output.stderr);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();
    assert!(json["rust_daemon_identity_scaffolded"].as_bool().unwrap());
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
}

#[test]
pub(super) fn daemon_runner_bpf_loader_contract_outputs_json() {
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
pub(super) fn daemon_runner_rejects_retired_migration_command_aliases() {
    let output = run_with_args_and_version(["runtime-identity-preflight"], "test-version");
    assert_eq!(output.exit_code, 2);
    assert!(
        output
            .stderr
            .contains("unsupported dae-daemon-optin command: runtime-identity-preflight")
    );
}
