use crate::{MatchedDefaultBenchmarkOptions, matched_default_benchmark_report};

#[test]
fn matched_benchmark_report_is_read_only_by_default() {
    let root = std::env::temp_dir().join(format!(
        "dae-daemon-matched-benchmark-default-{}",
        std::process::id()
    ));
    let config = root.join("config.dae");
    let report = matched_default_benchmark_report(
        &root,
        &config,
        &MatchedDefaultBenchmarkOptions::default(),
    )
    .unwrap();
    assert!(!report["execute_benchmark"].as_bool().unwrap());
    assert!(!report["benchmark_executable_now"].as_bool().unwrap());
    assert!(
        !report["matched_go_rust_default_daemon_benchmark_recorded"]
            .as_bool()
            .unwrap()
    );
    assert!(report["aggregate"].is_null());
}

#[test]
fn matched_benchmark_execute_requires_root_gate_ack() {
    let root = std::env::temp_dir().join(format!(
        "dae-daemon-matched-benchmark-noack-{}",
        std::process::id()
    ));
    let config = root.join("config.dae");
    let options = MatchedDefaultBenchmarkOptions {
        execute: true,
        ..MatchedDefaultBenchmarkOptions::default()
    };
    let err = matched_default_benchmark_report(&root, &config, &options).unwrap_err();
    assert!(err.contains("--ack-root-gate"));
}

#[test]
fn matched_benchmark_rejects_zero_iterations() {
    let root = std::env::temp_dir().join(format!(
        "dae-daemon-matched-benchmark-zero-{}",
        std::process::id()
    ));
    let config = root.join("config.dae");
    let options = MatchedDefaultBenchmarkOptions {
        iterations: 0,
        ..MatchedDefaultBenchmarkOptions::default()
    };
    let err = matched_default_benchmark_report(&root, &config, &options).unwrap_err();
    assert!(err.contains("matched-benchmark-iterations"));
}
