use super::*;
pub(crate) fn go_free_product_chain_gate_json(
    executed: bool,
    release_default_switch_gate: &Value,
    resident_default_daemon_switch_gate: &Value,
    dependency_boundary_preserved: bool,
    product_chain_branch_contract_preserved: bool,
    default_product_package_scan: &Value,
) -> GoFreeProductChainGateReport {
    if !executed {
        return GoFreeProductChainGateReport {
            report: json!({
                "name": "go-free-product-chain",
                "status": "not-executed",
                "requested": false,
                "go_free_product_chain_ready": false,
                "go_free_product_chain_admission_ready": false,
                "blockers": [],
            }),
        };
    }

    let requested = true;
    let release_default_switch_ready = release_default_switch_gate["release_default_switch_ready"]
        .as_bool()
        .unwrap_or(false);
    let resident_live_adapter_matrix_ready =
        release_default_switch_gate["resident_live_adapter_matrix_ready"]
            .as_bool()
            .unwrap_or(false);
    let candidate_service_contract =
        resident_default_daemon_switch_gate["candidate_service_contract"].clone();
    let candidate_executed = candidate_service_contract["executed"]
        .as_bool()
        .unwrap_or(false);
    let candidate_passed = candidate_service_contract["passed"]
        .as_bool()
        .unwrap_or(false);
    let contract_ready = candidate_service_contract["go_free_product_chain_contract_ready"]
        .as_bool()
        .unwrap_or(false);
    let default_package_go_free = candidate_service_contract["default_product_package_go_free"]
        .as_bool()
        .unwrap_or(false);
    let product_shell_retired =
        candidate_service_contract["go_product_shell_retired_from_default_package"]
            .as_bool()
            .unwrap_or(false);
    let orchestration_retired =
        candidate_service_contract["go_orchestration_retired_from_default_package"]
            .as_bool()
            .unwrap_or(false);
    let control_runtime_api_service_release_retired = candidate_service_contract
        ["go_control_runtime_api_service_release_retired_from_default_package"]
        .as_bool()
        .unwrap_or(false);
    let outbound_dependency_retired =
        candidate_service_contract["go_outbound_dependency_retired_from_default_package"]
            .as_bool()
            .unwrap_or(false);
    let compat_oracle_boundary_ready =
        candidate_service_contract["go_compat_oracle_boundary_ready"]
            .as_bool()
            .unwrap_or(false);
    let rust_product_binary_ready =
        candidate_service_contract["rust_product_binary_contract_ready"]
            .as_bool()
            .unwrap_or(false);
    let rust_product_lifecycle_ready =
        candidate_service_contract["rust_product_lifecycle_contract_ready"]
            .as_bool()
            .unwrap_or(false);
    let rust_product_web_api_package_release_ready =
        candidate_service_contract["rust_product_web_api_package_release_contract_ready"]
            .as_bool()
            .unwrap_or(false);
    let live_host_contract_ready = candidate_service_contract["go_free_live_host_contract_ready"]
        .as_bool()
        .unwrap_or(false);
    let rollback_model_ready = candidate_service_contract["go_free_rollback_model_ready"]
        .as_bool()
        .unwrap_or(false);
    let typed_report_ready = candidate_service_contract["go_free_product_chain_typed_report_ready"]
        .as_bool()
        .unwrap_or(false);
    let candidate_go_free_ready = candidate_service_contract["go_free_product_chain_ready"]
        .as_bool()
        .unwrap_or(false);
    let expanded_source_matrix_c10_ready =
        candidate_service_contract["expanded_source_matrix_c10_ready"]
            .as_bool()
            .unwrap_or(false);
    let default_product_package_scan_ready =
        default_product_package_scan["default_product_package_go_free"]
            .as_bool()
            .unwrap_or(false);
    let scanned_product_shell_retired =
        default_product_package_scan["go_product_shell_retired_from_default_package"]
            .as_bool()
            .unwrap_or(false);

    let go_free_product_chain_admission_ready = requested
        && release_default_switch_ready
        && resident_live_adapter_matrix_ready
        && candidate_executed
        && candidate_passed
        && contract_ready
        && dependency_boundary_preserved
        && product_chain_branch_contract_preserved
        && default_package_go_free
        && product_shell_retired
        && orchestration_retired
        && control_runtime_api_service_release_retired
        && outbound_dependency_retired
        && compat_oracle_boundary_ready
        && rust_product_binary_ready
        && rust_product_lifecycle_ready
        && rust_product_web_api_package_release_ready
        && live_host_contract_ready
        && rollback_model_ready
        && typed_report_ready
        && expanded_source_matrix_c10_ready
        && default_product_package_scan_ready;
    let go_free_product_chain_ready =
        go_free_product_chain_admission_ready && candidate_go_free_ready;

    let mut blockers = Vec::new();
    if !release_default_switch_ready {
        blockers.push("C10 requires C9 release default switch readiness".to_owned());
    }
    if !resident_live_adapter_matrix_ready {
        blockers.push("C10 requires resident live adapter matrix readiness".to_owned());
    }
    if !candidate_executed {
        blockers.push("C10 candidate service-contract was not executed".to_owned());
    }
    if candidate_executed && !candidate_passed {
        blockers.push("C10 candidate service-contract command did not pass".to_owned());
    }
    if !contract_ready {
        blockers.push("C10 go-free product-chain contract is not declared".to_owned());
    }
    if !dependency_boundary_preserved {
        blockers.push("C10 dependency boundary is not preserved".to_owned());
    }
    if !product_chain_branch_contract_preserved {
        blockers.push("C10 product-chain branch contract is not preserved".to_owned());
    }
    if !default_package_go_free {
        blockers.push("C10 default product package is not declared go-free".to_owned());
    }
    if !default_product_package_scan_ready {
        blockers.push("C10 default product package source scan is not go-free".to_owned());
    }
    if !product_shell_retired {
        blockers.push("C10 Go product shell is not retired from default package".to_owned());
    }
    if !scanned_product_shell_retired {
        blockers.push("C10 source scan still finds Go product shell on a default path".to_owned());
    }
    if !orchestration_retired {
        blockers.push("C10 Go orchestration is not retired from default package".to_owned());
    }
    if !control_runtime_api_service_release_retired {
        blockers.push(
            "C10 Go control/runtime/API/service/release default path is not retired".to_owned(),
        );
    }
    if !outbound_dependency_retired {
        blockers.push("C10 Go outbound dependency is not retired from default package".to_owned());
    }
    if !compat_oracle_boundary_ready {
        blockers.push("C10 Go compat/oracle boundary is not ready".to_owned());
    }
    if !rust_product_binary_ready {
        blockers.push("C10 Rust product binary contract is not ready".to_owned());
    }
    if !rust_product_lifecycle_ready {
        blockers.push("C10 Rust product run/reload/stop contract is not ready".to_owned());
    }
    if !rust_product_web_api_package_release_ready {
        blockers.push("C10 Rust product Web/API/package/release contract is not ready".to_owned());
    }
    if !live_host_contract_ready {
        blockers.push("C10 final go-free live host contract is not ready".to_owned());
    }
    if !rollback_model_ready {
        blockers.push("C10 final go-free rollback model is not ready".to_owned());
    }
    if !typed_report_ready {
        blockers.push("C10 typed report is not ready".to_owned());
    }
    if !candidate_go_free_ready {
        blockers.push("C10 candidate does not declare go-free product-chain readiness".to_owned());
    }
    if !expanded_source_matrix_c10_ready {
        blockers
            .push("C10 expanded source matrix is not ready for final go-free release".to_owned());
    }
    blockers.extend(
        default_product_package_scan["blockers"]
            .as_array()
            .into_iter()
            .flat_map(|items| items.iter())
            .filter_map(Value::as_str)
            .map(str::to_owned),
    );

    let mut report = Map::new();
    report.insert("name".to_owned(), json!("go-free-product-chain"));
    report.insert(
        "status".to_owned(),
        json!(if go_free_product_chain_ready {
            "pass"
        } else {
            "blocked"
        }),
    );
    report.insert("requested".to_owned(), json!(requested));
    report.insert(
        "go_free_product_chain_admission_ready".to_owned(),
        json!(go_free_product_chain_admission_ready),
    );
    report.insert(
        "go_free_product_chain_ready".to_owned(),
        json!(go_free_product_chain_ready),
    );
    report.insert(
        "release_default_switch_ready".to_owned(),
        json!(release_default_switch_ready),
    );
    report.insert(
        "resident_live_adapter_matrix_ready".to_owned(),
        json!(resident_live_adapter_matrix_ready),
    );
    report.insert(
        "candidate_service_contract".to_owned(),
        candidate_service_contract.clone(),
    );
    report.insert(
        "go_free_product_chain_contract_ready".to_owned(),
        json!(contract_ready),
    );
    report.insert(
        "default_product_package_go_free".to_owned(),
        json!(default_package_go_free),
    );
    report.insert(
        "default_product_package_scan_ready".to_owned(),
        json!(default_product_package_scan_ready),
    );
    report.insert(
        "default_product_package_scan".to_owned(),
        default_product_package_scan.clone(),
    );
    report.insert(
        "go_product_shell_retired_from_default_package".to_owned(),
        json!(product_shell_retired),
    );
    report.insert(
        "go_orchestration_retired_from_default_package".to_owned(),
        json!(orchestration_retired),
    );
    report.insert(
        "go_control_runtime_api_service_release_retired_from_default_package".to_owned(),
        json!(control_runtime_api_service_release_retired),
    );
    report.insert(
        "go_outbound_dependency_retired_from_default_package".to_owned(),
        json!(outbound_dependency_retired),
    );
    report.insert(
        "go_compat_oracle_boundary_ready".to_owned(),
        json!(compat_oracle_boundary_ready),
    );
    report.insert(
        "rust_product_binary_contract_ready".to_owned(),
        json!(rust_product_binary_ready),
    );
    report.insert(
        "rust_product_lifecycle_contract_ready".to_owned(),
        json!(rust_product_lifecycle_ready),
    );
    report.insert(
        "rust_product_web_api_package_release_contract_ready".to_owned(),
        json!(rust_product_web_api_package_release_ready),
    );
    report.insert(
        "go_free_live_host_contract_ready".to_owned(),
        json!(live_host_contract_ready),
    );
    report.insert(
        "go_free_rollback_model_ready".to_owned(),
        json!(rollback_model_ready),
    );
    report.insert(
        "go_free_product_chain_typed_report_ready".to_owned(),
        json!(typed_report_ready),
    );
    report.insert(
        "candidate_go_free_product_chain_ready".to_owned(),
        json!(candidate_go_free_ready),
    );
    report.insert(
        "expanded_source_matrix_c10_ready".to_owned(),
        json!(expanded_source_matrix_c10_ready),
    );
    report.insert(
        "expanded_source_matrix_typed_report".to_owned(),
        candidate_service_contract["expanded_source_matrix_typed_report"].clone(),
    );
    report.insert(
        "dependency_boundary_preserved".to_owned(),
        json!(dependency_boundary_preserved),
    );
    report.insert(
        "product_chain_branch_contract_preserved".to_owned(),
        json!(product_chain_branch_contract_preserved),
    );
    report.insert(
        "report_schema".to_owned(),
        candidate_service_contract["go_free_product_chain_report_schema"].clone(),
    );
    report.insert(
        "default_dependency_policy".to_owned(),
        candidate_service_contract["go_free_product_chain_default_dependency_policy"].clone(),
    );
    report.insert(
        "retained_go_scope".to_owned(),
        candidate_service_contract["go_free_product_chain_retained_go_scope"].clone(),
    );
    report.insert(
        "surface".to_owned(),
        candidate_service_contract["go_free_product_chain_surface"].clone(),
    );
    report.insert(
        "typed_report".to_owned(),
        candidate_service_contract["go_free_product_chain_typed_report"].clone(),
    );
    report.insert("blockers".to_owned(), json!(blockers.clone()));

    GoFreeProductChainGateReport {
        report: Value::Object(report),
    }
}
