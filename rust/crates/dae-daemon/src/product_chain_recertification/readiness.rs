use std::fs;
use std::path::Path;

use serde_json::{Value, json};

use super::path_string;

pub(super) fn materialize_production_replacement_readiness_report(
    report: &Value,
    artifact_dir: &Path,
) -> Result<Value, String> {
    let readiness_file = artifact_dir.join("production-replacement-readiness.json");
    let plan = &report["production_run_command_replacement_plan"];
    let apply_plan = &plan["apply_plan"];
    let artifact_materialization = &plan["artifact_materialization"];
    let requested = apply_plan["requested"].as_bool().unwrap_or(false);
    let product_chain_clean = report["product_chain_recertification_clean"]
        .as_bool()
        .unwrap_or(false);
    let replacement_plan_admitted = plan["admitted"].as_bool().unwrap_or(false);
    let execute_allowed = plan["execute_allowed"].as_bool().unwrap_or(false);
    let host_mutation_allowed = plan["host_mutation_allowed"].as_bool().unwrap_or(false);
    let apply_plan_admitted = apply_plan["admitted"].as_bool().unwrap_or(false);
    let apply_manifest_materialized = apply_plan["apply_manifest_materialized"]
        .as_bool()
        .unwrap_or(false);
    let service_diff_materialized = apply_plan["service_diff_materialized"]
        .as_bool()
        .unwrap_or(false);
    let backup_manifest_materialized = artifact_materialization["backup_manifest_materialized"]
        .as_bool()
        .unwrap_or(false);
    let rollback_script_materialized = artifact_materialization["rollback_script_materialized"]
        .as_bool()
        .unwrap_or(false);
    let go_fallback_required = plan["go_fallback_required"].as_bool().unwrap_or(false);
    let resident_default_daemon_switch_ready = report["resident_default_daemon_switch_ready"]
        .as_bool()
        .unwrap_or(false);
    let resident_default_daemon_switch_gate = &report["resident_default_daemon_switch_gate"];
    let no_host_write_executed = !plan["actual_mutation_executed"].as_bool().unwrap_or(true)
        && !apply_plan["actual_host_write_executed"]
            .as_bool()
            .unwrap_or(true)
        && !apply_plan["actual_mutation_executed"]
            .as_bool()
            .unwrap_or(true)
        && !report["production_run_command_replaced"]
            .as_bool()
            .unwrap_or(true);

    let mut blockers = Vec::new();
    if requested && !product_chain_clean {
        blockers.push("product-chain recertification is not clean");
    }
    if requested && !resident_default_daemon_switch_ready {
        blockers.push("resident default service path does not admit production dataplane");
    }
    if requested && !replacement_plan_admitted {
        blockers.push("production run command replacement plan is not admitted");
    }
    if requested && !execute_allowed {
        blockers.push("production run command replacement execute gate is not allowed");
    }
    if requested && !host_mutation_allowed {
        blockers.push("host mutation allow admission is not present");
    }
    if requested && !apply_plan_admitted {
        blockers.push("production run command apply plan is not admitted");
    }
    if requested && !apply_manifest_materialized {
        blockers.push("production run command apply manifest is not materialized");
    }
    if requested && !service_diff_materialized {
        blockers.push("production run command service diff is not materialized");
    }
    if requested && !backup_manifest_materialized {
        blockers.push("production run command backup manifest is not materialized");
    }
    if requested && !rollback_script_materialized {
        blockers.push("production run command rollback script is not materialized");
    }
    if requested && !go_fallback_required {
        blockers.push("Go fallback requirement is not recorded");
    }
    if requested && !no_host_write_executed {
        blockers.push("host write or production run command replacement was already executed");
    }

    let installed_system_service_files: Vec<String> = [
        Path::new("/etc/systemd/system/dae.service"),
        Path::new("/usr/lib/systemd/system/dae.service"),
        Path::new("/lib/systemd/system/dae.service"),
    ]
    .into_iter()
    .filter(|path| path.exists())
    .map(path_string)
    .collect();
    let installed_system_service_exists = !installed_system_service_files.is_empty();
    let installed_runtime_config_file = Path::new("/etc/dae/config.dae");
    let installed_runtime_config_exists = installed_runtime_config_file.exists();
    let ready_for_manual_authorization = requested && blockers.is_empty();
    let readiness = json!({
        "status": if ready_for_manual_authorization { "pass" } else if requested { "blocked" } else { "not-requested" },
        "requested": requested,
        "ready_for_manual_authorization": ready_for_manual_authorization,
        "manual_authorization_required": true,
        "host_write_allowed": false,
        "host_write_executed": false,
        "actual_mutation_executed": false,
        "production_run_command_replaced": false,
        "readiness_blockers": blockers,
        "readiness_file": path_string(&readiness_file),
        "required_artifacts": {
            "apply_manifest_file": apply_plan["apply_manifest_file"].clone(),
            "apply_manifest_materialized": apply_manifest_materialized,
            "service_diff_file": apply_plan["service_diff_file"].clone(),
            "service_diff_materialized": service_diff_materialized,
            "backup_manifest_file": artifact_materialization["backup_manifest_file"].clone(),
            "backup_manifest_materialized": backup_manifest_materialized,
            "rollback_script": artifact_materialization["rollback_script"].clone(),
            "rollback_script_materialized": rollback_script_materialized,
        },
        "checks": {
            "product_chain_recertification_clean": product_chain_clean,
            "replacement_plan_admitted": replacement_plan_admitted,
            "execute_allowed": execute_allowed,
            "host_mutation_allowed": host_mutation_allowed,
            "apply_plan_admitted": apply_plan_admitted,
            "go_fallback_required": go_fallback_required,
            "no_host_write_executed": no_host_write_executed,
            "resident_default_daemon_switch_ready": resident_default_daemon_switch_ready,
            "resident_default_daemon_switch_gate": resident_default_daemon_switch_gate.clone(),
            "daed2_product_chain_used": report["product_chain_topology"]["daed2_wing_repo_used"].clone(),
            "product_chain_switch_allowed": report["product_chain_switch_allowed"].clone(),
        },
        "host_inventory": {
            "usr_bin_dae_exists": Path::new("/usr/bin/dae").exists(),
            "usr_local_bin_dae_exists": Path::new("/usr/local/bin/dae").exists(),
            "service_file": report["paths"]["service_file"].clone(),
            "repository_service_template_file": report["paths"]["service_file"].clone(),
            "installed_system_service_exists": installed_system_service_exists,
            "installed_system_service_files": installed_system_service_files,
            "runtime_config_file": path_string(installed_runtime_config_file),
            "runtime_config_exists": installed_runtime_config_exists,
        },
        "manual_authorization_conditions": [
            "review production-replacement-readiness.json",
            "review production-run-command-replacement-apply.json",
            "review production-run-command-replacement-service.diff",
            "review backup-manifest.json",
            "review rollback-production-run-command-replacement.sh",
            "confirm Go fallback and daed2.0 product-chain paths",
            "explicitly authorize controlled production host write"
        ],
        "source": [
            "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:后续阶段 1",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:install/dae.service",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:pid-progress-reload-contract"
        ],
    });
    let encoded = serde_json::to_vec_pretty(&readiness).map_err(|err| {
        format!("failed to encode production replacement readiness report: {err}")
    })?;
    fs::write(&readiness_file, encoded).map_err(|err| {
        format!(
            "failed to write production replacement readiness report {}: {err}",
            path_string(&readiness_file)
        )
    })?;
    Ok(readiness)
}

pub(super) fn attach_production_replacement_readiness(report: &mut Value, readiness: Value) {
    let Some(report_object) = report.as_object_mut() else {
        return;
    };
    report_object.insert(
        "production_replacement_readiness_file".to_owned(),
        readiness["readiness_file"].clone(),
    );
    report_object.insert(
        "production_replacement_ready_for_manual_authorization".to_owned(),
        readiness["ready_for_manual_authorization"].clone(),
    );
    report_object.insert(
        "production_replacement_readiness".to_owned(),
        readiness.clone(),
    );
    if let Some(plan) = report_object
        .get_mut("production_run_command_replacement_plan")
        .and_then(Value::as_object_mut)
    {
        plan.insert(
            "production_replacement_readiness_file".to_owned(),
            readiness["readiness_file"].clone(),
        );
        plan.insert(
            "production_replacement_ready_for_manual_authorization".to_owned(),
            readiness["ready_for_manual_authorization"].clone(),
        );
    }
}
