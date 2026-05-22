use super::*;

#[test]
fn stage182_production_rust_daemon_admission_preflight_fixture_matches() {
    let fixture = load("engine/runtime_stage182/production_rust_daemon_admission_preflight.json");
    let output = run_with_args([
        "runtime",
        "stage182-production-rust-daemon-admission-preflight",
    ]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();

    assert_eq!(json, fixture);
    assert!(
        json["production_rust_daemon_admission_preflight_recorded"]
            .as_bool()
            .unwrap()
    );
    assert!(json["stage181_runtime_blocker_carried"].as_bool().unwrap());
    assert_eq!(json["preflight_rows"].as_array().unwrap().len(), 6);
    assert!(
        !json["rust_production_run_command_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["benchmark_executable_now"].as_bool().unwrap());
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
}

#[test]
fn stage182_production_rust_daemon_admission_preflight_rejects_extra_args() {
    let output = run_with_args([
        "runtime",
        "stage182-production-rust-daemon-admission-preflight",
        "--bad",
    ]);
    assert_ne!(output.exit_code, 0);
    assert!(output.stderr.contains("unsupported stage182 argument"));
}
