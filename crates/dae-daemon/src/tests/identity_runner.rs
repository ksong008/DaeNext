use super::*;
#[test]
pub(super) fn daemon_identity_is_production_product() {
    let report = daemon_identity("test-version");
    assert_eq!(report["name"].as_str().unwrap(), "daed");
    assert_eq!(report["crate"].as_str().unwrap(), "dae-daemon");
    assert_eq!(
        report["productCrate"].as_str().unwrap(),
        "dae-product-identity"
    );
    assert_eq!(
        report["productIdentityCrate"].as_str().unwrap(),
        "dae-product-identity"
    );
    assert_eq!(report["version"].as_str().unwrap(), "test-version");
    assert!(report["rust_daemon_identity_scaffolded"].as_bool().unwrap());
    assert!(
        report["rust_daemon_crate_manifest_exists"]
            .as_bool()
            .unwrap()
    );
    assert!(report["rust_daemon_binary_exists"].as_bool().unwrap());
    assert!(
        report["rust_daemon_run_command_available"]
            .as_bool()
            .unwrap()
    );
    assert!(report["rust_run_entrypoint_exists"].as_bool().unwrap());
    assert!(report["production_admission_allowed"].as_bool().unwrap());
}

#[test]
pub(super) fn identity_preflight_reports_production_identity_ready() {
    let report = identity_preflight_report("test-version");
    assert!(report["rust_daemon_identity_scaffolded"].as_bool().unwrap());
    assert!(
        report["rust_daemon_lifecycle_smoke_passed"]
            .as_bool()
            .unwrap()
    );
    assert!(report["benchmark_executable_now"].as_bool().unwrap());
    assert!(
        report["true_rust_native_daemon_admitted"]
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
    assert_eq!(json["name"].as_str().unwrap(), "daed");
    assert_eq!(json["version"].as_str().unwrap(), "test-version");
}

#[test]
pub(super) fn daemon_runner_identity_preflight_command_outputs_json() {
    let output = run_with_args_and_version(["identity-preflight"], "test-version");
    assert_eq!(output.exit_code, 0, "{}", output.stderr);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();
    assert!(json["rust_daemon_identity_scaffolded"].as_bool().unwrap());
    assert!(json["production_admission_allowed"].as_bool().unwrap());
}

#[test]
pub(super) fn daemon_runner_bpf_loader_contract_outputs_json() {
    let output = run_with_args_and_version(["bpf-loader", "contract"], "test-version");
    assert_eq!(output.exit_code, 0, "{}", output.stderr);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();
    assert_eq!(
        json["name"].as_str().unwrap(),
        "rust-aya-bpf-loader-native-runtime-contract"
    );
    assert!(
        json["native_bpf_loader_enabled_for_product"]
            .as_bool()
            .unwrap()
    );
    assert!(json["native_userspace_outbound_ready"].as_bool().unwrap());
    assert!(json["kernel_ebpf_program_rewrite"].as_bool().unwrap());
}

#[test]
pub(super) fn daemon_runner_rejects_retired_migration_command_aliases() {
    let output = run_with_args_and_version(["runtime-identity-preflight"], "test-version");
    assert_eq!(output.exit_code, 2);
    assert!(
        output
            .stderr
            .contains("unsupported daed command: runtime-identity-preflight")
    );
}
