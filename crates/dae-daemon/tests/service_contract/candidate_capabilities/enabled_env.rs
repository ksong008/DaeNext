use super::*;
pub(crate) fn assert_resident_dataplane_enabled_contract() {
    let default_output = Command::new(binary())
        .arg("service-contract")
        .output()
        .unwrap();
    assert!(default_output.status.success());
    let default_report: Value = serde_json::from_slice(&default_output.stdout).unwrap();
    assert!(
        default_report["resident_dataplane_admission_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !default_report["resident_dataplane_env_required"]
            .as_bool()
            .unwrap()
    );
    assert!(default_report["resident_dataplane_admission_blocker"].is_null());

    let enabled_output = Command::new(binary())
        .arg("service-contract")
        .env("RESIDENT_DATAPLANE", "1")
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
        enabled_report["resident_daemon_runtime_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(enabled_report["resident_dataplane_admission_blocker"].is_null());
    assert!(
        enabled_report["reload_failure_restore_supported"]
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

    let disabled_output = Command::new(binary())
        .arg("service-contract")
        .env("RESIDENT_DATAPLANE", "0")
        .output()
        .unwrap();
    assert!(disabled_output.status.success());
    let disabled_report: Value = serde_json::from_slice(&disabled_output.stdout).unwrap();
    assert!(
        !disabled_report["resident_dataplane_admission_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(
        disabled_report["resident_dataplane_admission_blocker"]
            .as_str()
            .unwrap()
            .contains("explicitly disables")
    );
}
