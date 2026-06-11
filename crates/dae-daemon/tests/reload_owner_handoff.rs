use serde_json::Value;

#[test]
fn reload_owner_handoff_smoke_is_environment_aware() {
    let root = std::env::temp_dir().join(format!(
        "dae-reload-owner-handoff-daemon-test-{}",
        std::process::id()
    ));
    let report = dae_daemon::reload_owner_handoff_smoke_report(&root).unwrap();
    assert!(
        report["reload_owner_handoff_harness_available"]
            .as_bool()
            .unwrap()
    );
    assert!(report["restore_blocker_recorded"].as_bool().unwrap());
    assert!(
        report["reload_scoped_cleanup_smoke_passed"]
            .as_bool()
            .unwrap()
    );
    if report["non_production_daemon_reload_owner_transfer_smoke_passed"]
        .as_bool()
        .unwrap()
    {
        assert!(
            report["reload_current_swap_smoke_passed"]
                .as_bool()
                .unwrap()
        );
        assert!(report["old_owner_close_smoke_passed"].as_bool().unwrap());
        assert_eq!(
            report["reload_owner_handoff"]["keys_updated"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
    } else {
        assert!(report["smoke_error"].as_str().is_some());
    }
    assert!(!report["production_listener_bound"].as_bool().unwrap());
    assert!(
        !report["production_tc_attach_smoke_passed"]
            .as_bool()
            .unwrap()
    );
    assert!(!report["final_native_admission_allowed"].as_bool().unwrap());
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn daemon_runner_reload_owner_handoff_command_outputs_json() {
    let root = std::env::temp_dir().join(format!(
        "dae-reload-owner-handoff-runner-test-{}",
        std::process::id()
    ));
    let output = dae_daemon::run_with_args_and_version(
        [
            "reload-owner-handoff-smoke".to_owned(),
            "--root".to_owned(),
            root.display().to_string(),
        ],
        "test-version",
    );
    assert_eq!(output.exit_code, 0, "{}", output.stderr);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();
    assert!(
        json["reload_owner_handoff_harness_available"]
            .as_bool()
            .unwrap()
    );
    assert!(json["restore_blocker_recorded"].as_bool().unwrap());
    assert!(!json["true_rust_native_daemon_admitted"].as_bool().unwrap());
    let _ = std::fs::remove_dir_all(root);
}
