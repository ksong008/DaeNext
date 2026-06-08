use super::*;
pub(crate) fn insert_resident_runtime_contract(
    report: &mut serde_json::Map<String, Value>,
    resident_dataplane_ready: bool,
) {
    report.insert(
        "resident_run_service_contract_ready".to_owned(),
        json!(true),
    );
    report.insert(
        "reload_command_service_contract_ready".to_owned(),
        json!(true),
    );
    report.insert("systemd_notify_ready_supported".to_owned(), json!(true));
    report.insert("reload_failure_rollback_supported".to_owned(), json!(true));
    report.insert(
        "invalid_runtime_config_rejected_before_current_swap".to_owned(),
        json!(true),
    );
    report.insert(
        "reload_start_failure_attempts_previous_runtime_restore".to_owned(),
        json!(true),
    );
    report.insert(
        "resident_production_dataplane_ready".to_owned(),
        json!(resident_dataplane_ready),
    );
    report.insert(
        "resident_default_daemon_switch_ready".to_owned(),
        json!(resident_dataplane_ready),
    );
    report.insert(
        "resident_runtime_platform_contract_ready".to_owned(),
        json!(true),
    );
    report.insert(
        "resident_runtime_typed_report_ready".to_owned(),
        json!(true),
    );
    report.insert(
        "resident_runtime_resource_gate_ready".to_owned(),
        json!(true),
    );
    report.insert(
        "resident_runtime_report_schema".to_owned(),
        json!("resident-runtime-platform-report"),
    );
    report.insert(
        "resident_runtime_lifecycle_contract".to_owned(),
        json!({
            "pid_file": "/var/run/dae.pid",
            "progress_file": "/var/run/dae.progress",
            "abort_file": "/var/run/dae.abort",
            "ready_record_file_supported": true,
            "cleanup_report": "resident-production-runtime-cleanup.json",
            "start_report": "resident-production-runtime-start.json",
        }),
    );
    report.insert(
        "resident_runtime_resource_limits".to_owned(),
        json!({
            "max_rss_bytes": 536870912_u64,
            "max_thread_count": 256,
            "max_fd_count": 1024,
            "max_report_size_bytes": 524288,
        }),
    );
    report.insert(
        "resident_runtime_resource_observation_fields".to_owned(),
        json!([
            "resident_memory_rss_bytes",
            "resident_thread_count",
            "resident_fd_count",
            "resident_report_size_bytes",
        ]),
    );
}
