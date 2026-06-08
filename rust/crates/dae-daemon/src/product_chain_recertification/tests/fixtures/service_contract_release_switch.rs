use super::*;
pub(crate) fn insert_release_default_switch_contract(report: &mut serde_json::Map<String, Value>) {
    for key in [
        "release_default_switch_contract_ready",
        "release_default_artifact_path_ready",
        "default_runtime_selector_no_env_rust_owned_ready",
        "install_service_package_scripts_ready",
        "release_default_switch_live_evidence_contract_ready",
        "backup_manifest_contract_ready",
        "rollback_rehearsal_contract_ready",
        "host_write_freeze_contract_required",
        "go_product_shell_allowed_until_go_free",
        "release_default_switch_typed_report_ready",
    ] {
        report.insert(key.to_owned(), json!(true));
    }
    report.insert(
        "release_default_switch_final_go_free_claim".to_owned(),
        json!(false),
    );
    report.insert(
        "release_default_switch_report_schema".to_owned(),
        json!("release-default-switch"),
    );
    report.insert(
        "release_default_switch_required_live_hosts".to_owned(),
        json!(["38", "10.10.10.2"]),
    );
    report.insert(
        "release_default_switch_surface".to_owned(),
        json!([
            "release/action/docker/package default candidate path",
            "default runtime selector with no environment override",
            "install service and package script default command contract",
            "candidate service-contract and live evidence record contract",
            "backup manifest and rollback script contract",
            "read-only host-write freeze before any production mutation"
        ]),
    );
    report.insert(
        "release_default_switch_typed_report".to_owned(),
        json!({
            "schema": "release-default-switch-typed-report",
            "status": "pass",
            "stage_report_schema": false,
        }),
    );
}
