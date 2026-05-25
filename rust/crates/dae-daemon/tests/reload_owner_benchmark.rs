use serde_json::Value;

#[test]
fn reload_owner_benchmark_records_bounded_metrics() {
    let root = std::env::temp_dir().join(format!(
        "dae-reload-owner-benchmark-daemon-test-{}",
        std::process::id()
    ));
    let report = dae_daemon::reload_owner_benchmark_report(&root, 2).unwrap();
    assert!(
        report["bounded_production_equivalent_benchmark_harness_executed"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(report["iterations"].as_u64().unwrap(), 2);
    assert!(report["total_elapsed_ns"].as_u64().unwrap() > 0);
    assert!(
        report["bounded_benchmark_executable_now"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !report["matched_go_rust_default_daemon_benchmark_recorded"]
            .as_bool()
            .unwrap()
    );
    assert!(!report["default_switch_allowed"].as_bool().unwrap());
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn daemon_runner_reload_owner_benchmark_command_outputs_json() {
    let root = std::env::temp_dir().join(format!(
        "dae-reload-owner-benchmark-runner-test-{}",
        std::process::id()
    ));
    let output = dae_daemon::run_with_args_and_version(
        [
            "reload-owner-benchmark".to_owned(),
            "--root".to_owned(),
            root.display().to_string(),
            "--iterations".to_owned(),
            "2".to_owned(),
        ],
        "test-version",
    );
    assert_eq!(output.exit_code, 0, "{}", output.stderr);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();
    assert_eq!(json["iterations"].as_u64().unwrap(), 2);
    assert!(
        json["benchmark_artifact_summary_recorded"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["true_rust_default_daemon_admitted"].as_bool().unwrap());
    let _ = std::fs::remove_dir_all(root);
}
