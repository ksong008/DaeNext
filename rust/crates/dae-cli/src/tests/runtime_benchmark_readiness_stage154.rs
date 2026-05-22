use super::*;

#[test]
fn stage154_benchmark_readiness_refresh_fixture_matches() {
    let fixture = load(
        "engine/runtime_stage154/matched_default_daemon_benchmark_readiness_refresh_gate.json",
    );
    let output = run_with_args([
        "runtime",
        "stage154-matched-default-daemon-benchmark-readiness-refresh-gate",
    ]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();

    assert_eq!(json, fixture);
    assert!(json["blocked"].as_bool().unwrap());
    assert!(
        json["stage153_non_default_wrapper_recorded"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["benchmark_executable_now"].as_bool().unwrap());
    assert!(
        !json["matched_go_rust_default_daemon_benchmark_recorded"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
}

#[test]
fn stage154_runtime_rejects_bad_args() {
    let output = run_with_args([
        "runtime",
        "stage154-matched-default-daemon-benchmark-readiness-refresh-gate",
        "--bad",
    ]);
    assert_ne!(output.exit_code, 0);
    assert!(output.stderr.contains("unsupported stage154 argument"));
}
