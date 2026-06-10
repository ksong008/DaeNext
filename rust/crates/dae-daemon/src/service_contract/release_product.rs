use super::*;
pub(crate) fn insert_release_default_switch_service_contract_capabilities(report: &mut Value) {
    let contract = dae_product::release_default_switch_contract();
    if let Value::Object(report) = report {
        report.insert(
            "release_default_switch_contract_ready".to_owned(),
            json!(contract.contract_ready),
        );
        report.insert(
            "release_default_artifact_path_ready".to_owned(),
            json!(contract.default_artifact_path_ready),
        );
        report.insert(
            "default_runtime_selector_no_env_rust_owned_ready".to_owned(),
            json!(contract.default_runtime_selector_ready),
        );
        report.insert(
            "install_service_package_scripts_ready".to_owned(),
            json!(contract.service_package_scripts_ready),
        );
        report.insert(
            "release_default_switch_live_evidence_contract_ready".to_owned(),
            json!(contract.live_evidence_contract_ready),
        );
        report.insert(
            "backup_manifest_contract_ready".to_owned(),
            json!(contract.backup_manifest_contract_ready),
        );
        report.insert(
            "rollback_rehearsal_contract_ready".to_owned(),
            json!(contract.rollback_rehearsal_contract_ready),
        );
        report.insert(
            "host_write_freeze_contract_required".to_owned(),
            json!(contract.host_write_freeze_required),
        );
        report.insert(
            "go_product_shell_allowed_until_go_free".to_owned(),
            json!(contract.go_product_shell_allowed_until_go_free),
        );
        report.insert(
            "release_default_switch_final_go_free_claim".to_owned(),
            json!(contract.final_go_free_claim),
        );
        report.insert(
            "release_default_switch_typed_report_ready".to_owned(),
            json!(contract.contract_ready),
        );
        report.insert(
            "release_default_switch_report_schema".to_owned(),
            json!(contract.name),
        );
        report.insert(
            "release_default_switch_required_live_hosts".to_owned(),
            json!(contract.required_live_hosts),
        );
        report.insert(
            "release_default_switch_surface".to_owned(),
            json!(contract.surface),
        );
        report.insert(
            "release_default_switch_typed_report".to_owned(),
            json!({
                "schema": "release-default-switch-typed-report",
                "status": "pass",
                "c_phase": contract.c_phase,
                "prior_gate": contract.prior_gate,
                "release_default_artifact_path_ready": contract.default_artifact_path_ready,
                "default_runtime_selector_no_env_rust_owned_ready": contract.default_runtime_selector_ready,
                "install_service_package_scripts_ready": contract.service_package_scripts_ready,
                "host_write_freeze_required": contract.host_write_freeze_required,
                "final_go_free_claim": contract.final_go_free_claim,
                "stage_report_schema": false,
            }),
        );
    }
}

pub(crate) fn insert_go_free_product_chain_service_contract_capabilities(report: &mut Value) {
    let contract = dae_product::go_free_product_chain_contract();
    let evidence = crate::c10_go_free_evidence::c10_go_free_product_chain_evidence_from_env();
    if let Value::Object(report) = report {
        report.insert(
            "go_free_product_chain_contract_ready".to_owned(),
            json!(contract.contract_ready),
        );
        report.insert(
            "default_product_package_go_free".to_owned(),
            json!(evidence.default_product_package_go_free),
        );
        report.insert(
            "go_product_shell_retired_from_default_package".to_owned(),
            json!(evidence.go_product_shell_retired),
        );
        report.insert(
            "go_orchestration_retired_from_default_package".to_owned(),
            json!(evidence.go_orchestration_retired),
        );
        report.insert(
            "go_control_runtime_api_service_release_retired_from_default_package".to_owned(),
            json!(evidence.go_control_runtime_api_service_release_retired),
        );
        report.insert(
            "go_outbound_dependency_retired_from_default_package".to_owned(),
            json!(evidence.go_outbound_dependency_retired),
        );
        report.insert(
            "go_compat_oracle_boundary_ready".to_owned(),
            json!(evidence.go_compat_oracle_boundary_ready),
        );
        report.insert(
            "rust_product_binary_contract_ready".to_owned(),
            json!(evidence.rust_product_binary_contract_ready),
        );
        report.insert(
            "rust_product_lifecycle_contract_ready".to_owned(),
            json!(evidence.rust_product_lifecycle_contract_ready),
        );
        report.insert(
            "rust_product_web_api_package_release_contract_ready".to_owned(),
            json!(evidence.rust_product_web_api_package_release_contract_ready),
        );
        report.insert(
            "go_free_live_host_contract_ready".to_owned(),
            json!(evidence.live_host_contract_ready),
        );
        report.insert(
            "go_free_rollback_model_ready".to_owned(),
            json!(evidence.rollback_model_ready),
        );
        report.insert(
            "go_free_product_chain_typed_report_ready".to_owned(),
            json!(evidence.typed_report_ready),
        );
        report.insert(
            "go_free_product_chain_ready".to_owned(),
            json!(evidence.ready),
        );
        report.insert(
            "go_free_product_chain_report_schema".to_owned(),
            json!(contract.name),
        );
        report.insert(
            "go_free_product_chain_default_dependency_policy".to_owned(),
            json!(contract.default_dependency_policy),
        );
        report.insert(
            "go_free_product_chain_retained_go_scope".to_owned(),
            json!(contract.retained_go_scope),
        );
        report.insert(
            "go_free_product_chain_surface".to_owned(),
            json!(contract.surface),
        );
        report.insert(
            "go_free_product_chain_typed_report".to_owned(),
            json!({
                "schema": "go-free-product-chain-typed-report",
                "status": if evidence.ready { "pass" } else { "blocked" },
                "c_phase": contract.c_phase,
                "prior_gate": contract.prior_gate,
                "default_product_package_go_free": evidence.default_product_package_go_free,
                "go_product_shell_retired_from_default_package": evidence.go_product_shell_retired,
                "go_orchestration_retired_from_default_package": evidence.go_orchestration_retired,
                "go_control_runtime_api_service_release_retired_from_default_package": evidence.go_control_runtime_api_service_release_retired,
                "go_outbound_dependency_retired_from_default_package": evidence.go_outbound_dependency_retired,
                "go_compat_oracle_boundary_ready": evidence.go_compat_oracle_boundary_ready,
                "userland_ffi_c_abi_retired_from_default_path": evidence.userland_ffi_c_abi_retired,
                "go_oracle_default_dependency_retired_from_default_path": evidence.go_oracle_default_dependency_retired,
                "rust_internal_fallback_normalized_for_default_path": evidence.rust_internal_fallback_normalized,
                "rust_product_binary_contract_ready": evidence.rust_product_binary_contract_ready,
                "rust_product_lifecycle_contract_ready": evidence.rust_product_lifecycle_contract_ready,
                "rust_product_web_api_package_release_contract_ready": evidence.rust_product_web_api_package_release_contract_ready,
                "live_host_contract_ready": evidence.live_host_contract_ready,
                "rollback_model_ready": evidence.rollback_model_ready,
                "go_free_product_chain_ready": evidence.ready,
                "blockers": evidence.blockers.clone(),
                "final_evidence": evidence.report.clone(),
                "stage_report_schema": false,
            }),
        );
    }
}

pub(crate) fn resident_dataplane_default_switch_ready_from_env() -> bool {
    let value = env::var(RESIDENT_DATAPLANE_ENV)
        .or_else(|_| env::var(RESIDENT_DATAPLANE_LEGACY_ENV))
        .ok();
    resident_dataplane_default_switch_value_enabled(value.as_deref())
}

pub(crate) fn resident_dataplane_default_switch_value_enabled(value: Option<&str>) -> bool {
    !matches!(
        value,
        Some("0" | "false" | "FALSE" | "off" | "OFF" | "no" | "NO")
    )
}
