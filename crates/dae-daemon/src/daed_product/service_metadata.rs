use super::*;
pub(super) fn daed_service_contract(version: &str) -> Value {
    let mut report = crate::service_contract::service_contract_capabilities(version);
    let final_native_evidence =
        crate::final_native_evidence::final_native_state_evidence_from_env();
    if let Value::Object(report) = &mut report {
        report.insert("product_binary".to_owned(), json!("daed"));
        report.insert("product_entry".to_owned(), json!("/usr/bin/daed"));
        report.insert("product_surface".to_owned(), json!("final-native"));
        report.insert(
            "final_native_runtime_state".to_owned(),
            json!("final-native-state"),
        );
        report.insert("primary_state_store".to_owned(), json!(PRIMARY_STATE_STORE));
        report.insert(
            "legacy_import_state_store".to_owned(),
            json!(LEGACY_IMPORT_STATE_STORE),
        );
        report.insert(
            "rust_daed_writes_wing_db_by_default".to_owned(),
            json!(false),
        );
        report.insert("wing_db_import_supported".to_owned(), json!(true));
        report.insert(
            "wing_db_import_destructive_by_default".to_owned(),
            json!(false),
        );
        report.insert("daed_db_primary_required".to_owned(), json!(true));
        report.insert("var_lib_daed_required_by_default".to_owned(), json!(false));
        report.insert(
            "rust_product_runtime_defaults".to_owned(),
            product_runtime_defaults(),
        );
        report.insert("rust_product_binary_contract_ready".to_owned(), json!(true));
        report.insert(
            "rust_product_lifecycle_contract_ready".to_owned(),
            json!(true),
        );
        report.insert(
            "rust_product_web_api_package_release_contract_ready".to_owned(),
            json!(true),
        );
        report.insert("rust_daed_state_layer_ready".to_owned(), json!(true));
        report.insert(
            "rust_daed_non_destructive_wing_db_import_ready".to_owned(),
            json!(true),
        );
        report.insert("rust_daed_validate_command_ready".to_owned(), json!(true));
        report.insert(
            "rust_daed_setup_auth_user_storage_api_ready".to_owned(),
            json!(true),
        );
        report.insert(
            "rust_daed_static_webui_serving_ready".to_owned(),
            json!(true),
        );
        report.insert(
            "rust_daed_current_react_webui_served_by_rust_ready".to_owned(),
            json!(true),
        );
        report.insert("rust_daed_resource_crud_api_ready".to_owned(), json!(true));
        report.insert("rust_daed_materializer_ready".to_owned(), json!(true));
        report.insert("rust_daed_runtime_owner_ready".to_owned(), json!(true));
        report.insert(
            "rust_daed_real_runtime_bridge_ready".to_owned(),
            json!(true),
        );
        report.insert(
            "rust_daed_runtime_state_metadata_only".to_owned(),
            json!(false),
        );
        report.insert(
            "rust_daed_logs_sse_latency_subscription_ready".to_owned(),
            json!(true),
        );
        report.insert(
            "rust_daed_import_export_package_surface_ready".to_owned(),
            json!(true),
        );
        report.insert("rust_daed_subscription_fetch_ready".to_owned(), json!(true));
        report.insert("rust_daed_latency_probe_tcp_ready".to_owned(), json!(true));
        report.insert("rust_daed_resetpass_parity_ready".to_owned(), json!(true));
        report.insert("rust_daed_package_manifest_ready".to_owned(), json!(true));
        report.insert("rust_daed_webui_route_audit_ready".to_owned(), json!(true));
        report.insert(
            "rust_daed_local_package_admission_ready".to_owned(),
            json!(true),
        );
        report.insert(
            "final_native_product_package_ready".to_owned(),
            json!(final_native_evidence.final_native_product_package_ready),
        );
        report.insert(
            "native_product_shell_ready".to_owned(),
            json!(final_native_evidence.native_product_shell_ready),
        );
        report.insert(
            "native_orchestration_ready".to_owned(),
            json!(final_native_evidence.native_orchestration_ready),
        );
        report.insert(
            "native_control_runtime_api_service_release_ready".to_owned(),
            json!(final_native_evidence.native_control_runtime_api_service_release_ready),
        );
        report.insert(
            "native_outbound_dependency_ready".to_owned(),
            json!(final_native_evidence.native_outbound_dependency_ready),
        );
        report.insert("leptos_webui_rewrite_considered".to_owned(), json!(false));
        report.insert(
            "final_native_live_host_contract_ready".to_owned(),
            json!(final_native_evidence.live_host_contract_ready),
        );
        report.insert(
            "final_native_final_state_artifact_ready".to_owned(),
            json!(final_native_evidence.final_state_artifact_ready),
        );
        report.insert(
            "final_native_state_typed_report_ready".to_owned(),
            json!(final_native_evidence.typed_report_ready),
        );
        report.insert(
            "final_native_state_ready".to_owned(),
            json!(final_native_evidence.ready),
        );
        report.insert(
            "final_native_state_final_evidence".to_owned(),
            final_native_evidence.report.clone(),
        );
        report.insert(
            "final_native_state_current_status".to_owned(),
            json!(if final_native_evidence.ready {
                "final native state evidence admitted"
            } else {
                "final native state blocked pending live matrix and artifact evidence"
            }),
        );
        report.insert(
            "final_native_state_remaining_work".to_owned(),
            json!(final_native_evidence.blockers.clone()),
        );
        let typed_report_value = report
            .entry("final_native_state_typed_report".to_owned())
            .or_insert_with(|| json!({ "schema": "final-native-state-typed-report" }));
        if let Value::Object(typed_report) = typed_report_value {
            typed_report.insert(
                "final_native_product_package_ready".to_owned(),
                json!(final_native_evidence.final_native_product_package_ready),
            );
            typed_report.insert(
                "native_product_shell_ready".to_owned(),
                json!(final_native_evidence.native_product_shell_ready),
            );
            typed_report.insert(
                "native_orchestration_ready".to_owned(),
                json!(final_native_evidence.native_orchestration_ready),
            );
            typed_report.insert(
                "native_control_runtime_api_service_release_ready".to_owned(),
                json!(final_native_evidence.native_control_runtime_api_service_release_ready),
            );
            typed_report.insert(
                "native_outbound_dependency_ready".to_owned(),
                json!(final_native_evidence.native_outbound_dependency_ready),
            );
            typed_report.insert(
                "userland_native_abi_ready".to_owned(),
                json!(final_native_evidence.userland_native_abi_ready),
            );
            typed_report.insert(
                "final_native_live_host_contract_ready".to_owned(),
                json!(final_native_evidence.live_host_contract_ready),
            );
            typed_report.insert(
                "final_native_final_state_artifact_ready".to_owned(),
                json!(final_native_evidence.final_state_artifact_ready),
            );
            typed_report.insert(
                "final_native_state_ready".to_owned(),
                json!(final_native_evidence.ready),
            );
            typed_report.insert(
                "live_host_replacement_applied".to_owned(),
                final_native_evidence.report["liveHostReplacementApplied"].clone(),
            );
            typed_report.insert(
                "final_state_validation_applied_on_live_host".to_owned(),
                final_native_evidence.report["finalStateValidationAppliedOnLiveHost"].clone(),
            );
            typed_report.insert("rust_product_binary_contract_ready".to_owned(), json!(true));
            typed_report.insert(
                "rust_product_lifecycle_contract_ready".to_owned(),
                json!(true),
            );
            typed_report.insert(
                "rust_product_web_api_package_release_contract_ready".to_owned(),
                json!(true),
            );
            typed_report.insert("rust_daed_validate_command_ready".to_owned(), json!(true));
            typed_report.insert(
                "current_status".to_owned(),
                json!(if final_native_evidence.ready {
                    "final native state evidence admitted"
                } else {
                    "final native state blocked pending live matrix and artifact evidence"
                }),
            );
            typed_report.insert(
                "status".to_owned(),
                json!(if final_native_evidence.ready {
                    "pass"
                } else {
                    "blocked"
                }),
            );
            typed_report.insert(
                "blockers".to_owned(),
                json!(final_native_evidence.blockers.clone()),
            );
            typed_report.insert(
                "final_evidence".to_owned(),
                final_native_evidence.report.clone(),
            );
        }
    }
    report
}

pub(super) fn daed_package_info(version: &str) -> Value {
    let final_native_evidence =
        crate::final_native_evidence::final_native_state_evidence_from_env();
    json!({
        "name": "daed",
        "version": version,
        "binary": "/usr/bin/daed",
        "product_surface": "final-native",
        "runtime_state": "final-native-state",
        "primary_state_store": PRIMARY_STATE_STORE,
        "legacy_import_state_store": LEGACY_IMPORT_STATE_STORE,
        "rust_daed_writes_wing_db_by_default": false,
        "wing_db_import_supported": true,
        "wing_db_import_destructive_by_default": false,
        "daed_db_primary_required": true,
        "var_lib_daed_required_by_default": false,
        "runtime_defaults": product_runtime_defaults(),
        "webui": {
            "framework": "current React/Vite dist",
            "served_by": "Rust daed static file server",
            "default_root": DEFAULT_WEB_ROOT,
            "leptos_considered": false
        },
        "default_layout": {
            "config_dir": DEFAULT_CONFIG_DIR,
            "runtime_dir": "/etc/daed/runtime",
            "backup_dir": "/etc/daed/backups",
            "web_root": DEFAULT_WEB_ROOT,
            "geoip": "/usr/share/daed/geoip.dat",
            "geosite": "/usr/share/daed/geosite.dat"
        },
        "current_runtime_ready": {
            "product_binary_skeleton": true,
            "validate_command": true,
            "state_check": true,
            "wing_db_non_destructive_import": true,
            "setup_auth_user_storage_api": true,
            "static_webui_serving": true,
            "resource_crud_api": true,
            "materializer": true,
            "runtime_owner": true,
            "real_runtime_bridge": true,
            "metadata_only_runtime_state": false,
            "logs_sse_latency_subscription": true,
            "import_export_package_surface": true,
            "subscription_fetch": true,
            "tcp_latency_probe": true,
            "resetpass_parity": true,
            "package_manifest": true,
            "webui_route_audit": true,
            "local_package_admission": true
        },
        "package_surface": {
            "validate": "daed validate -c /etc/daed/",
            "systemd_unit": "daed.service validates then uses /usr/bin/daed run -c /etc/daed/",
            "docker_entrypoint": "/usr/bin/daed run -c /etc/daed --listen 0.0.0.0:2023",
            "package_manifest": "daed export package-manifest",
            "admission_report": "daed export admission-report",
            "live_host_replacement_applied": final_native_evidence
                .report["liveHostReplacementApplied"]
                .as_bool()
                .unwrap_or(false),
            "final_state_validation_applied_on_live_host": final_native_evidence
                .report["finalStateValidationAppliedOnLiveHost"]
                .as_bool()
                .unwrap_or(false),
            "final_native_product_package_ready": final_native_evidence.final_native_product_package_ready,
            "native_product_shell_ready": final_native_evidence.native_product_shell_ready,
            "native_outbound_dependency_ready": final_native_evidence.native_outbound_dependency_ready
        },
        "final_gate_evidence": final_native_evidence.report,
        "full_final_native_state_ready": final_native_evidence.ready,
        "remaining_admission": final_native_evidence.blockers
    })
}
