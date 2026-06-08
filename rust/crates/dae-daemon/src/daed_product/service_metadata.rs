fn daed_service_contract(version: &str) -> Value {
    let mut report = crate::service_contract::service_contract_capabilities(version);
    let c10_evidence = crate::c10_go_free_evidence::c10_go_free_product_chain_evidence_from_env();
    if let Value::Object(report) = &mut report {
        report.insert("product_binary".to_owned(), json!("daed"));
        report.insert("product_entry".to_owned(), json!("/usr/bin/daed"));
        report.insert("c_phase".to_owned(), json!("C10"));
        report.insert(
            "c10_work_package".to_owned(),
            json!("go-free-product-chain"),
        );
        report.insert("primary_state_store".to_owned(), json!(PRIMARY_STATE_STORE));
        report.insert(
            "protected_rollback_state_store".to_owned(),
            json!(PROTECTED_ROLLBACK_STATE_STORE),
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
            "default_product_package_go_free".to_owned(),
            json!(c10_evidence.default_product_package_go_free),
        );
        report.insert(
            "go_product_shell_retired_from_default_package".to_owned(),
            json!(c10_evidence.go_product_shell_retired),
        );
        report.insert(
            "go_orchestration_retired_from_default_package".to_owned(),
            json!(c10_evidence.go_orchestration_retired),
        );
        report.insert(
            "go_control_runtime_api_service_release_retired_from_default_package".to_owned(),
            json!(c10_evidence.go_control_runtime_api_service_release_retired),
        );
        report.insert(
            "go_outbound_dependency_retired_from_default_package".to_owned(),
            json!(c10_evidence.go_outbound_dependency_retired),
        );
        report.insert("leptos_webui_rewrite_considered".to_owned(), json!(false));
        report.insert(
            "go_compat_oracle_boundary_ready".to_owned(),
            json!(c10_evidence.go_compat_oracle_boundary_ready),
        );
        report.insert(
            "go_free_live_host_contract_ready".to_owned(),
            json!(c10_evidence.live_host_contract_ready),
        );
        report.insert(
            "go_free_rollback_model_ready".to_owned(),
            json!(c10_evidence.rollback_model_ready),
        );
        report.insert(
            "go_free_product_chain_typed_report_ready".to_owned(),
            json!(c10_evidence.typed_report_ready),
        );
        report.insert(
            "go_free_product_chain_ready".to_owned(),
            json!(c10_evidence.ready),
        );
        report.insert(
            "go_free_product_chain_final_evidence".to_owned(),
            c10_evidence.report.clone(),
        );
        report.insert(
            "go_free_product_chain_current_batch".to_owned(),
            json!(if c10_evidence.ready {
                "C10 final go-free product-chain evidence admitted"
            } else {
                "C10 final go-free product-chain blocked pending live matrix and artifact evidence"
            }),
        );
        report.insert(
            "go_free_product_chain_remaining_work".to_owned(),
            json!(c10_evidence.blockers.clone()),
        );
        if let Some(Value::Object(typed_report)) =
            report.get_mut("go_free_product_chain_typed_report")
        {
            typed_report.insert(
                "default_product_package_go_free".to_owned(),
                json!(c10_evidence.default_product_package_go_free),
            );
            typed_report.insert(
                "go_product_shell_retired_from_default_package".to_owned(),
                json!(c10_evidence.go_product_shell_retired),
            );
            typed_report.insert(
                "go_orchestration_retired_from_default_package".to_owned(),
                json!(c10_evidence.go_orchestration_retired),
            );
            typed_report.insert(
                "go_control_runtime_api_service_release_retired_from_default_package".to_owned(),
                json!(c10_evidence.go_control_runtime_api_service_release_retired),
            );
            typed_report.insert(
                "go_outbound_dependency_retired_from_default_package".to_owned(),
                json!(c10_evidence.go_outbound_dependency_retired),
            );
            typed_report.insert(
                "go_compat_oracle_boundary_ready".to_owned(),
                json!(c10_evidence.go_compat_oracle_boundary_ready),
            );
            typed_report.insert(
                "userland_ffi_c_abi_retired_from_default_path".to_owned(),
                json!(c10_evidence.userland_ffi_c_abi_retired),
            );
            typed_report.insert(
                "go_oracle_default_dependency_retired_from_default_path".to_owned(),
                json!(c10_evidence.go_oracle_default_dependency_retired),
            );
            typed_report.insert(
                "rust_internal_fallback_normalized_for_default_path".to_owned(),
                json!(c10_evidence.rust_internal_fallback_normalized),
            );
            typed_report.insert(
                "go_free_live_host_contract_ready".to_owned(),
                json!(c10_evidence.live_host_contract_ready),
            );
            typed_report.insert(
                "go_free_rollback_model_ready".to_owned(),
                json!(c10_evidence.rollback_model_ready),
            );
            typed_report.insert(
                "go_free_product_chain_ready".to_owned(),
                json!(c10_evidence.ready),
            );
            typed_report.insert(
                "live_default_switch_applied".to_owned(),
                c10_evidence.report["liveDefaultSwitchApplied"].clone(),
            );
            typed_report.insert(
                "rollback_validation_applied_on_live_host".to_owned(),
                c10_evidence.report["rollbackValidationAppliedOnLiveHost"].clone(),
            );
            typed_report.insert(
                "release_default_switch_admission_ready".to_owned(),
                c10_evidence.report["releaseDefaultSwitchAdmission"].clone(),
            );
            typed_report.insert(
                "production_package_admission_ready".to_owned(),
                c10_evidence.report["productionPackageAdmission"].clone(),
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
                "current_batch".to_owned(),
                json!(if c10_evidence.ready {
                    "C10 final go-free product-chain evidence admitted"
                } else {
                    "C10 final go-free product-chain blocked pending live matrix and artifact evidence"
                }),
            );
            typed_report.insert(
                "status".to_owned(),
                json!(if c10_evidence.ready {
                    "pass"
                } else {
                    "blocked"
                }),
            );
            typed_report.insert("blockers".to_owned(), json!(c10_evidence.blockers.clone()));
            typed_report.insert("final_evidence".to_owned(), c10_evidence.report.clone());
        }
    }
    report
}

fn daed_package_info(version: &str) -> Value {
    json!({
        "name": "daed",
        "version": version,
        "binary": "/usr/bin/daed",
        "c_phase": "C10",
        "work_package": "go-free-product-chain",
        "primary_state_store": PRIMARY_STATE_STORE,
        "protected_rollback_state_store": PROTECTED_ROLLBACK_STATE_STORE,
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
        "current_batch_ready": {
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
            "default_package_switch_live_applied": false,
            "rollback_validation_applied_on_live_host": false,
            "release_default_switch_admission": false,
            "production_package_admission": false,
            "go_daewing_default_path_removed": false
        },
        "final_gate_evidence": c10_final_gate_evidence(),
        "full_go_free_product_chain_ready": false,
        "remaining_admission": c10_final_blockers()
    })
}
