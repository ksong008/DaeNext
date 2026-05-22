use super::*;

#[test]
fn stage165_daemon_reload_owner_handoff_fixture_matches() {
    let fixture =
        load("engine/runtime_stage165/non_production_daemon_reload_owner_handoff_smoke_gate.json");
    let output = run_with_args([
        "runtime",
        "stage165-non-production-daemon-reload-owner-handoff-smoke-gate",
    ]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();

    assert_eq!(json, fixture);
    assert!(json["blocked"].as_bool().unwrap());
    assert!(
        json["reload_owner_handoff_harness_available"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["production_listener_bound"].as_bool().unwrap());
}

#[test]
fn stage165_daemon_reload_owner_handoff_execute_smoke_is_environment_aware() {
    let root = std::env::temp_dir().join(format!(
        "dae-stage165-cli-test-{}-reload-owner-handoff",
        std::process::id()
    ));
    let output = run_with_args([
        "runtime",
        "stage165-non-production-daemon-reload-owner-handoff-smoke-gate",
        "--execute-smoke",
        "--root",
        &root.display().to_string(),
    ]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();
    if json["non_production_daemon_reload_owner_transfer_smoke_passed"]
        .as_bool()
        .unwrap()
    {
        assert!(json["reload_current_swap_smoke_passed"].as_bool().unwrap());
        assert!(json["old_owner_close_smoke_passed"].as_bool().unwrap());
        assert!(
            json["smoke"]["stage164_handoff"]["keys_updated"]
                .as_array()
                .unwrap()
                .len()
                == 2
        );
    } else {
        assert!(json["smoke"]["smoke_error"].as_str().is_some());
    }
    assert!(json["rollback_blocker_recorded"].as_bool().unwrap());
    assert!(
        json["reload_scoped_cleanup_smoke_passed"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["production_tc_attach_smoke_passed"].as_bool().unwrap());
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn stage165_runtime_rejects_bad_args() {
    let output = run_with_args([
        "runtime",
        "stage165-non-production-daemon-reload-owner-handoff-smoke-gate",
        "--bad",
    ]);
    assert_ne!(output.exit_code, 0);
    assert!(output.stderr.contains("unsupported stage165 argument"));
}
