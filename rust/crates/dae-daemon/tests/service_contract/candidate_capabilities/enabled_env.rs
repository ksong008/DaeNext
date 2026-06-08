use super::*;
pub(crate) fn assert_resident_dataplane_enabled_contract() {
    let enabled_output = Command::new(binary())
        .arg("service-contract")
        .env("DAE_RUST_RESIDENT_DATAPLANE", "1")
        .output()
        .unwrap();
    assert!(enabled_output.status.success());
    let enabled_report: Value = serde_json::from_slice(&enabled_output.stdout).unwrap();
    assert!(
        enabled_report["resident_dataplane_env_enabled"]
            .as_bool()
            .unwrap()
    );
    assert!(
        enabled_report["resident_production_dataplane_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(
        enabled_report["resident_default_daemon_switch_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(enabled_report["default_path_switch_blocker"].is_null());
    assert!(
        enabled_report["reload_failure_rollback_supported"]
            .as_bool()
            .unwrap()
    );
    assert!(
        enabled_report["invalid_runtime_config_rejected_before_current_swap"]
            .as_bool()
            .unwrap()
    );
    assert!(
        enabled_report["reload_start_failure_attempts_previous_runtime_restore"]
            .as_bool()
            .unwrap()
    );
}
