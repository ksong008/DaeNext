use serde_json::{Map, Value, json};

use super::{ProductChainRecertificationOptions, path_string};

#[derive(Debug, Clone)]
pub(super) struct ReleaseDefaultSwitchGateReport {
    pub(super) report: Value,
}

#[allow(clippy::too_many_arguments)]
pub(super) fn release_default_switch_gate_json(
    executed: bool,
    options: &ProductChainRecertificationOptions,
    default_switch_admission_clean: bool,
    product_chain_switch_allowed: bool,
    outbound_production_matrix_gate: &Value,
    resident_default_daemon_switch_gate: &Value,
    production_run_command_replacement_plan: &Value,
    production_replacement_readiness: Option<&Value>,
    product_chain_switch_rehearsal: Option<&Value>,
    production_host_write_plan_freeze: Option<&Value>,
) -> ReleaseDefaultSwitchGateReport {
    if !executed {
        return ReleaseDefaultSwitchGateReport {
            report: json!({
                "name": "release-default-switch-v1",
                "status": "not-executed",
                "requested": false,
                "release_default_switch_admission_ready": false,
                "release_default_switch_ready": false,
                "product_chain_switch_allowed": false,
                "blockers": [],
            }),
        };
    }

    let requested = options.default_path_mutation_requested
        || options.production_run_command_replacement_dry_run_requested
        || options.production_run_command_replacement_execute_requested
        || options.production_run_command_replacement_apply_plan_requested
        || options.host_default_path_mutation_allow_requested;
    let outbound_production_matrix_ready =
        outbound_production_matrix_gate["outbound_production_matrix_ready"]
            .as_bool()
            .unwrap_or(false);
    let resident_live_adapter_matrix_ready =
        outbound_production_matrix_gate["resident_live_adapter_matrix_ready"]
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

    let contract_ready = candidate_service_contract["release_default_switch_contract_ready"]
        .as_bool()
        .unwrap_or(false);
    let default_artifact_path_ready =
        candidate_service_contract["release_default_artifact_path_ready"]
            .as_bool()
            .unwrap_or(false);
    let default_runtime_selector_ready =
        candidate_service_contract["default_runtime_selector_no_env_rust_owned_ready"]
            .as_bool()
            .unwrap_or(false);
    let service_package_scripts_ready =
        candidate_service_contract["install_service_package_scripts_ready"]
            .as_bool()
            .unwrap_or(false);
    let live_evidence_contract_ready =
        candidate_service_contract["release_default_switch_live_evidence_contract_ready"]
            .as_bool()
            .unwrap_or(false);
    let backup_manifest_contract_ready =
        candidate_service_contract["backup_manifest_contract_ready"]
            .as_bool()
            .unwrap_or(false);
    let rollback_rehearsal_contract_ready =
        candidate_service_contract["rollback_rehearsal_contract_ready"]
            .as_bool()
            .unwrap_or(false);
    let host_write_freeze_contract_required =
        candidate_service_contract["host_write_freeze_contract_required"]
            .as_bool()
            .unwrap_or(false);
    let go_product_shell_allowed_until_go_free =
        candidate_service_contract["go_product_shell_allowed_until_go_free"]
            .as_bool()
            .unwrap_or(false);
    let final_go_free_claim =
        candidate_service_contract["release_default_switch_final_go_free_claim"]
            .as_bool()
            .unwrap_or(false);
    let typed_report_ready =
        candidate_service_contract["release_default_switch_typed_report_ready"]
            .as_bool()
            .unwrap_or(false);

    let plan_requested = production_run_command_replacement_plan["requested"]
        .as_bool()
        .unwrap_or(false);
    let plan_admitted = production_run_command_replacement_plan["admitted"]
        .as_bool()
        .unwrap_or(false);
    let backup_manifest_materialized =
        production_run_command_replacement_plan["backup_manifest_materialized"]
            .as_bool()
            .unwrap_or(false);
    let rollback_script_materialized =
        production_run_command_replacement_plan["rollback_script_materialized"]
            .as_bool()
            .unwrap_or(false);
    let apply_manifest_materialized =
        production_run_command_replacement_plan["apply_manifest_materialized"]
            .as_bool()
            .unwrap_or(false);
    let service_diff_materialized =
        production_run_command_replacement_plan["service_diff_materialized"]
            .as_bool()
            .unwrap_or(false);
    let no_host_write_executed =
        !production_run_command_replacement_plan["actual_mutation_executed"]
            .as_bool()
            .unwrap_or(true)
            && !production_run_command_replacement_plan["production_run_command_replaced"]
                .as_bool()
                .unwrap_or(true);

    let readiness_passed = production_replacement_readiness
        .and_then(|value| value["ready_for_manual_authorization"].as_bool())
        .unwrap_or(false);
    let rollback_rehearsal_passed = product_chain_switch_rehearsal
        .and_then(|value| value["pass"].as_bool())
        .unwrap_or(false);
    let host_write_freeze_passed = production_host_write_plan_freeze
        .and_then(|value| value["pass"].as_bool())
        .unwrap_or(false);

    let release_default_switch_admission_ready = requested
        && default_switch_admission_clean
        && product_chain_switch_allowed
        && outbound_production_matrix_ready
        && resident_live_adapter_matrix_ready
        && candidate_executed
        && candidate_passed
        && contract_ready
        && default_artifact_path_ready
        && default_runtime_selector_ready
        && service_package_scripts_ready
        && live_evidence_contract_ready
        && backup_manifest_contract_ready
        && rollback_rehearsal_contract_ready
        && host_write_freeze_contract_required
        && go_product_shell_allowed_until_go_free
        && !final_go_free_claim
        && typed_report_ready
        && plan_requested
        && plan_admitted;
    let release_default_switch_ready = release_default_switch_admission_ready
        && readiness_passed
        && rollback_rehearsal_passed
        && host_write_freeze_passed
        && backup_manifest_materialized
        && rollback_script_materialized
        && apply_manifest_materialized
        && service_diff_materialized
        && no_host_write_executed;

    let mut blockers = Vec::new();
    if !requested {
        blockers.push("C9 release default switch was not requested".to_owned());
    }
    if !default_switch_admission_clean {
        blockers.push("C9 requires clean default-switch admission".to_owned());
    }
    if !product_chain_switch_allowed {
        blockers.push("C9 product-chain switch is not allowed".to_owned());
    }
    if !outbound_production_matrix_ready {
        blockers.push("C9 requires C8 outbound production matrix readiness".to_owned());
    }
    if !resident_live_adapter_matrix_ready {
        blockers.push("C9 requires C8 resident live adapter matrix readiness".to_owned());
    }
    if !candidate_executed {
        blockers.push("C9 candidate service-contract was not executed".to_owned());
    }
    if candidate_executed && !candidate_passed {
        blockers.push("C9 candidate service-contract command did not pass".to_owned());
    }
    if !contract_ready {
        blockers.push("C9 release default switch contract is not declared".to_owned());
    }
    if !default_artifact_path_ready {
        blockers
            .push("C9 release/action/docker/package default artifact path is not ready".to_owned());
    }
    if !default_runtime_selector_ready {
        blockers.push(
            "C9 default runtime selector without environment override is not Rust-owned".to_owned(),
        );
    }
    if !service_package_scripts_ready {
        blockers.push("C9 install service and package scripts are not aligned".to_owned());
    }
    if !live_evidence_contract_ready {
        blockers.push("C9 live evidence contract is not ready".to_owned());
    }
    if !backup_manifest_contract_ready {
        blockers.push("C9 backup manifest contract is not ready".to_owned());
    }
    if !rollback_rehearsal_contract_ready {
        blockers.push("C9 rollback rehearsal contract is not ready".to_owned());
    }
    if !host_write_freeze_contract_required {
        blockers.push("C9 host-write freeze requirement is not declared".to_owned());
    }
    if !go_product_shell_allowed_until_go_free {
        blockers.push("C9 must explicitly allow Go product shell only until C10".to_owned());
    }
    if final_go_free_claim {
        blockers.push("C9 must not claim final go-free product-chain completion".to_owned());
    }
    if !typed_report_ready {
        blockers.push("C9 typed report is not ready".to_owned());
    }
    if !plan_requested {
        blockers.push(
            "C9 production run-command replacement artifact plan is not requested".to_owned(),
        );
    }
    if plan_requested && !plan_admitted {
        blockers
            .push("C9 production run-command replacement artifact plan is not admitted".to_owned());
    }
    if !readiness_passed {
        blockers.push("C9 production replacement readiness is not pass".to_owned());
    }
    if !rollback_rehearsal_passed {
        blockers.push("C9 rollback rehearsal is not pass".to_owned());
    }
    if !host_write_freeze_passed {
        blockers.push("C9 host-write freeze is not pass".to_owned());
    }
    if !backup_manifest_materialized {
        blockers.push("C9 backup manifest is not materialized".to_owned());
    }
    if !rollback_script_materialized {
        blockers.push("C9 rollback script is not materialized".to_owned());
    }
    if !apply_manifest_materialized {
        blockers.push("C9 apply manifest is not materialized".to_owned());
    }
    if !service_diff_materialized {
        blockers.push("C9 service diff is not materialized".to_owned());
    }
    if !no_host_write_executed {
        blockers.push("C9 must remain read-only before explicit production host write".to_owned());
    }

    let status = if release_default_switch_ready {
        "pass"
    } else if release_default_switch_admission_ready {
        "admission-pass-pending-host-freeze"
    } else {
        "blocked"
    };
    let mut report = Map::new();
    report.insert("name".to_owned(), json!("release-default-switch-v1"));
    report.insert("status".to_owned(), json!(status));
    report.insert("requested".to_owned(), json!(requested));
    report.insert("read_only".to_owned(), json!(true));
    report.insert("host_write_allowed".to_owned(), json!(false));
    report.insert("actual_host_write_executed".to_owned(), json!(false));
    report.insert(
        "release_default_switch_admission_ready".to_owned(),
        json!(release_default_switch_admission_ready),
    );
    report.insert(
        "release_default_switch_ready".to_owned(),
        json!(release_default_switch_ready),
    );
    report.insert(
        "product_chain_switch_allowed".to_owned(),
        json!(product_chain_switch_allowed),
    );
    report.insert(
        "default_switch_admission_clean".to_owned(),
        json!(default_switch_admission_clean),
    );
    report.insert(
        "outbound_production_matrix_ready".to_owned(),
        json!(outbound_production_matrix_ready),
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
        "release_default_switch_contract_ready".to_owned(),
        json!(contract_ready),
    );
    report.insert(
        "release_default_artifact_path_ready".to_owned(),
        json!(default_artifact_path_ready),
    );
    report.insert(
        "default_runtime_selector_no_env_rust_owned_ready".to_owned(),
        json!(default_runtime_selector_ready),
    );
    report.insert(
        "install_service_package_scripts_ready".to_owned(),
        json!(service_package_scripts_ready),
    );
    report.insert(
        "release_default_switch_live_evidence_contract_ready".to_owned(),
        json!(live_evidence_contract_ready),
    );
    report.insert(
        "backup_manifest_contract_ready".to_owned(),
        json!(backup_manifest_contract_ready),
    );
    report.insert(
        "rollback_rehearsal_contract_ready".to_owned(),
        json!(rollback_rehearsal_contract_ready),
    );
    report.insert(
        "host_write_freeze_contract_required".to_owned(),
        json!(host_write_freeze_contract_required),
    );
    report.insert(
        "go_product_shell_allowed_until_go_free".to_owned(),
        json!(go_product_shell_allowed_until_go_free),
    );
    report.insert(
        "release_default_switch_final_go_free_claim".to_owned(),
        json!(final_go_free_claim),
    );
    report.insert(
        "release_default_switch_typed_report_ready".to_owned(),
        json!(typed_report_ready),
    );
    report.insert("plan_requested".to_owned(), json!(plan_requested));
    report.insert("plan_admitted".to_owned(), json!(plan_admitted));
    report.insert(
        "production_replacement_readiness_passed".to_owned(),
        json!(readiness_passed),
    );
    report.insert(
        "rollback_rehearsal_passed".to_owned(),
        json!(rollback_rehearsal_passed),
    );
    report.insert(
        "host_write_freeze_passed".to_owned(),
        json!(host_write_freeze_passed),
    );
    report.insert(
        "backup_manifest_materialized".to_owned(),
        json!(backup_manifest_materialized),
    );
    report.insert(
        "rollback_script_materialized".to_owned(),
        json!(rollback_script_materialized),
    );
    report.insert(
        "apply_manifest_materialized".to_owned(),
        json!(apply_manifest_materialized),
    );
    report.insert(
        "service_diff_materialized".to_owned(),
        json!(service_diff_materialized),
    );
    report.insert(
        "no_host_write_executed".to_owned(),
        json!(no_host_write_executed),
    );
    report.insert(
        "production_run_command_replacement_plan".to_owned(),
        production_run_command_replacement_plan.clone(),
    );
    report.insert(
        "production_replacement_readiness".to_owned(),
        production_replacement_readiness
            .cloned()
            .unwrap_or(Value::Null),
    );
    report.insert(
        "product_chain_switch_rehearsal".to_owned(),
        product_chain_switch_rehearsal
            .cloned()
            .unwrap_or(Value::Null),
    );
    report.insert(
        "production_host_write_plan_freeze".to_owned(),
        production_host_write_plan_freeze
            .cloned()
            .unwrap_or(Value::Null),
    );
    report.insert(
        "candidate_binary_source_hint".to_owned(),
        json!(
            options
                .resident_default_daemon_binary_source
                .as_ref()
                .map(|path| path_string(path))
        ),
    );
    report.insert(
        "service_file".to_owned(),
        json!(path_string(&options.service_file)),
    );
    report.insert(
        "report_schema".to_owned(),
        candidate_service_contract["release_default_switch_report_schema"].clone(),
    );
    report.insert(
        "required_live_hosts".to_owned(),
        candidate_service_contract["release_default_switch_required_live_hosts"].clone(),
    );
    report.insert(
        "surface".to_owned(),
        candidate_service_contract["release_default_switch_surface"].clone(),
    );
    report.insert(
        "typed_report".to_owned(),
        candidate_service_contract["release_default_switch_typed_report"].clone(),
    );
    report.insert("blockers".to_owned(), json!(blockers.clone()));

    ReleaseDefaultSwitchGateReport {
        report: Value::Object(report),
    }
}

pub(super) fn attach_release_default_switch_gate_from_report(report: &mut Value) {
    let gate = release_default_switch_gate_json(
        report["execute"].as_bool().unwrap_or(false),
        &ProductChainRecertificationOptions {
            execute: report["execute"].as_bool().unwrap_or(false),
            default_path_mutation_requested: report["default_path_mutation_requested"]
                .as_bool()
                .unwrap_or(false),
            production_run_command_replacement_dry_run_requested:
                report["production_run_command_replacement_plan"]["requested"]
                    .as_bool()
                    .unwrap_or(false),
            production_run_command_replacement_execute_requested:
                report["production_run_command_replacement_plan"]["execute_requested"]
                    .as_bool()
                    .unwrap_or(false),
            production_run_command_replacement_apply_plan_requested:
                report["production_run_command_replacement_plan"]["apply_plan_requested"]
                    .as_bool()
                    .unwrap_or(false),
            host_default_path_mutation_allow_requested:
                report["production_run_command_replacement_plan"]["host_mutation_allow_requested"]
                    .as_bool()
                    .unwrap_or(false),
            service_file: report["paths"]["service_file"]
                .as_str()
                .map(Into::into)
                .unwrap_or_default(),
            resident_default_daemon_binary_source:
                report["resident_default_daemon_switch_gate"]["binary_source"]
                    .as_str()
                    .map(Into::into),
            ..ProductChainRecertificationOptions::default()
        },
        report["product_chain_default_switch_admission_clean"]
            .as_bool()
            .unwrap_or(false),
        report["product_chain_switch_allowed"]
            .as_bool()
            .unwrap_or(false),
        &report["outbound_production_matrix_gate"],
        &report["resident_default_daemon_switch_gate"],
        &report["production_run_command_replacement_plan"],
        report.get("production_replacement_readiness"),
        report.get("daed2_product_chain_switch_rehearsal"),
        report.get("production_host_write_plan_freeze"),
    )
    .report;
    upsert_release_default_switch_gate(report, gate);
}

pub(super) fn upsert_release_default_switch_gate(report: &mut Value, gate: Value) {
    let Some(report_object) = report.as_object_mut() else {
        return;
    };
    let ready = gate["release_default_switch_ready"]
        .as_bool()
        .unwrap_or(false);
    let admission_ready = gate["release_default_switch_admission_ready"]
        .as_bool()
        .unwrap_or(false);
    report_object.insert("release_default_switch_ready".to_owned(), json!(ready));
    report_object.insert(
        "release_default_switch_admission_ready".to_owned(),
        json!(admission_ready),
    );
    report_object.insert("release_default_switch_gate".to_owned(), gate.clone());
    report_object.insert("c9_release_default_switch".to_owned(), gate);
    if let Some(typed_report) = report_object
        .get_mut("typed_report")
        .and_then(Value::as_object_mut)
    {
        typed_report.insert("release_default_switch_ready".to_owned(), json!(ready));
        typed_report.insert(
            "release_default_switch_admission_ready".to_owned(),
            json!(admission_ready),
        );
    }
}
