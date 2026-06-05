use std::fs;
use std::path::Path;

use serde_json::{Map, Value, json};

use super::host_write_safety::{
    production_run_command_apply_plan_blockers_json, production_run_command_execution_blockers_json,
};
use super::product_layout::ProductPathLayout;
use super::rollback_model::{make_user_executable, rollback_script_content};
use super::{ProductChainRecertificationOptions, path_string};

pub(super) fn production_run_command_replacement_plan_json(
    options: &ProductChainRecertificationOptions,
    artifact_dir: &Path,
    default_path_mutation_allowed: bool,
    resident_default_daemon_switch_ready: bool,
    service_contract_preserved: bool,
    go_fallback_required: bool,
    go_fallback_retired: bool,
) -> Value {
    let execute_requested = options.production_run_command_replacement_execute_requested;
    let apply_plan_requested = options.production_run_command_replacement_apply_plan_requested;
    let requested = options.production_run_command_replacement_dry_run_requested
        || execute_requested
        || apply_plan_requested;
    let go_default_path_preserved = true;
    let admitted = requested
        && default_path_mutation_allowed
        && resident_default_daemon_switch_ready
        && service_contract_preserved
        && go_default_path_preserved;
    let host_mutation_allow_requested = options.host_default_path_mutation_allow_requested;
    let host_mutation_allowed = host_mutation_allow_requested && admitted;
    let execute_allowed = execute_requested && admitted && host_mutation_allowed;
    let layout = ProductPathLayout::from_service_file(&options.service_file);
    let apply_plan = production_run_command_replacement_apply_plan_json(
        apply_plan_requested,
        admitted,
        execute_requested,
        host_mutation_allowed,
        artifact_dir,
        layout,
    );
    let execution_blockers = production_run_command_execution_blockers_json(
        execute_requested,
        admitted,
        host_mutation_allow_requested,
        host_mutation_allowed,
    );
    let backup_artifact_dir = artifact_dir.join("production-run-command-replacement-backup");
    let mut pre_execution_checks = Map::new();
    pre_execution_checks.insert(
        "default_path_mutation_allowed".to_owned(),
        json!(default_path_mutation_allowed),
    );
    pre_execution_checks.insert(
        "resident_default_daemon_switch_ready".to_owned(),
        json!(resident_default_daemon_switch_ready),
    );
    pre_execution_checks.insert(
        "service_contract_preserved".to_owned(),
        json!(service_contract_preserved),
    );
    pre_execution_checks.insert(
        "go_default_path_preserved".to_owned(),
        json!(go_default_path_preserved),
    );
    pre_execution_checks.insert(
        "go_fallback_required".to_owned(),
        json!(go_fallback_required),
    );
    pre_execution_checks.insert("go_fallback_retired".to_owned(), json!(go_fallback_retired));
    pre_execution_checks.insert("backup_required".to_owned(), json!(true));
    pre_execution_checks.insert("rollback_required".to_owned(), json!(true));
    pre_execution_checks.insert("post_replacement_smoke_required".to_owned(), json!(true));
    pre_execution_checks.insert("explicit_execute_flag_required".to_owned(), json!(true));
    pre_execution_checks.insert(
        "explicit_host_mutation_allow_flag_required".to_owned(),
        json!(true),
    );
    pre_execution_checks.insert(
        "host_mutation_allow_requested".to_owned(),
        json!(host_mutation_allow_requested),
    );
    pre_execution_checks.insert(
        "host_mutation_allowed".to_owned(),
        json!(host_mutation_allowed),
    );

    let mut plan = Map::new();
    plan.insert(
        "status".to_owned(),
        json!(if admitted {
            "pass"
        } else if requested {
            "blocked"
        } else {
            "not-requested"
        }),
    );
    plan.insert("requested".to_owned(), json!(requested));
    plan.insert("dry_run".to_owned(), json!(true));
    plan.insert("admitted".to_owned(), json!(admitted));
    plan.insert("execute_requested".to_owned(), json!(execute_requested));
    plan.insert("execute_allowed".to_owned(), json!(execute_allowed));
    plan.insert(
        "apply_plan_requested".to_owned(),
        json!(apply_plan_requested),
    );
    plan.insert("execution_blockers".to_owned(), execution_blockers);
    plan.insert(
        "default_path_mutation_allowed".to_owned(),
        json!(default_path_mutation_allowed),
    );
    plan.insert(
        "resident_default_daemon_switch_ready".to_owned(),
        json!(resident_default_daemon_switch_ready),
    );
    plan.insert(
        "service_contract_preserved".to_owned(),
        json!(service_contract_preserved),
    );
    plan.insert(
        "go_default_path_preserved".to_owned(),
        json!(go_default_path_preserved),
    );
    plan.insert(
        "go_fallback_required".to_owned(),
        json!(go_fallback_required),
    );
    plan.insert("go_fallback_retired".to_owned(), json!(go_fallback_retired));
    plan.insert(
        "go_fallback_retirement_scope".to_owned(),
        json!(if go_fallback_retired {
            "product-chain-run-command-replacement-admission"
        } else {
            "blocked-before-product-chain-run-command-replacement-admission"
        }),
    );
    plan.insert(
        "service_file".to_owned(),
        json!(path_string(&options.service_file)),
    );
    plan.insert(
        "current_exec_start_pre".to_owned(),
        json!(layout.current_exec_start_pre),
    );
    plan.insert(
        "current_exec_start".to_owned(),
        json!(layout.current_exec_start),
    );
    plan.insert(
        "current_exec_reload".to_owned(),
        json!(layout.current_exec_reload),
    );
    plan.insert("product_layout_kind".to_owned(), json!(layout.kind));
    plan.insert(
        "target_run_binary".to_owned(),
        json!(layout.target_run_binary),
    );
    plan.insert(
        "target_exec_start_pre".to_owned(),
        json!(layout.target_exec_start_pre),
    );
    plan.insert(
        "target_exec_start".to_owned(),
        json!(layout.target_exec_start),
    );
    plan.insert(
        "target_exec_reload".to_owned(),
        json!(layout.target_exec_reload),
    );
    plan.insert("backup_required".to_owned(), json!(true));
    plan.insert("rollback_required".to_owned(), json!(true));
    plan.insert("post_replacement_smoke_required".to_owned(), json!(true));
    plan.insert(
        "pid_progress_compatibility_required".to_owned(),
        json!(true),
    );
    plan.insert(
        "host_mutation_allow_requested".to_owned(),
        json!(host_mutation_allow_requested),
    );
    plan.insert(
        "host_mutation_allowed".to_owned(),
        json!(host_mutation_allowed),
    );
    plan.insert(
        "requires_explicit_execute_flag".to_owned(),
        json!("--execute-production-run-command-replacement"),
    );
    plan.insert(
        "requires_explicit_host_mutation_allow_flag".to_owned(),
        json!("--allow-host-default-path-mutation"),
    );
    plan.insert(
        "backup_artifact_dir".to_owned(),
        json!(path_string(&backup_artifact_dir)),
    );
    plan.insert(
        "backup_service_file".to_owned(),
        json!(path_string(
            &backup_artifact_dir.join(layout.backup_service_file_name)
        )),
    );
    plan.insert(
        "backup_binary".to_owned(),
        json!(path_string(
            &backup_artifact_dir.join(layout.backup_binary_file_name)
        )),
    );
    plan.insert(
        "rollback_script".to_owned(),
        json!(path_string(
            &artifact_dir.join("rollback-production-run-command-replacement.sh"),
        )),
    );
    plan.insert(
        "rollback_commands".to_owned(),
        json!([
            "restore backup service file if service was changed",
            format!(
                "restore backup {} if binary was changed",
                layout.binary_target
            ),
            "systemctl daemon-reload",
            format!(
                "systemctl restart {} only after rollback validation is explicit",
                layout.service_name
            ),
        ]),
    );
    let post_smoke_commands = layout.post_smoke_commands();
    plan.insert(
        "post_replacement_smoke_commands".to_owned(),
        json!([
            post_smoke_commands[0],
            post_smoke_commands[1],
            post_smoke_commands[2],
        ]),
    );
    let service_manager_commands = layout.service_manager_commands();
    plan.insert(
        "service_manager_commands".to_owned(),
        json!([
            service_manager_commands[0],
            service_manager_commands[1],
            service_manager_commands[2],
        ]),
    );
    plan.insert(
        "pre_execution_checks".to_owned(),
        Value::Object(pre_execution_checks),
    );
    plan.insert("apply_plan".to_owned(), apply_plan);
    plan.insert(
        "host_mutation_execution_mode".to_owned(),
        json!("read-only-admission-only"),
    );
    plan.insert("actual_mutation_executed".to_owned(), json!(false));
    plan.insert("production_run_command_replaced".to_owned(), json!(false));
    plan.insert("read_only".to_owned(), json!(true));
    plan.insert(
        "installed_binary_target_exists".to_owned(),
        json!(Path::new(layout.binary_target).exists()),
    );
    plan.insert(
        "installed_local_binary_target_exists".to_owned(),
        json!(Path::new(layout.local_binary_target).exists()),
    );
    plan.insert(
        "evidence_class".to_owned(),
        json!("read-only-production-run-command-replacement-dry-run-plan"),
    );
    Value::Object(plan)
}

fn production_run_command_replacement_apply_plan_json(
    requested: bool,
    replacement_plan_admitted: bool,
    execute_requested: bool,
    host_mutation_allowed: bool,
    artifact_dir: &Path,
    layout: ProductPathLayout,
) -> Value {
    let admitted =
        requested && replacement_plan_admitted && execute_requested && host_mutation_allowed;
    let blockers = production_run_command_apply_plan_blockers_json(
        requested,
        replacement_plan_admitted,
        execute_requested,
        host_mutation_allowed,
    );
    let apply_manifest_file = artifact_dir.join("production-run-command-replacement-apply.json");
    let service_diff_file = artifact_dir.join("production-run-command-replacement-service.diff");
    json!({
        "status": if admitted { "pass" } else if requested { "blocked" } else { "not-requested" },
        "requested": requested,
        "admitted": admitted,
        "execution_blockers": blockers,
        "execution_mode": "read-only-apply-plan",
        "replacement_plan_admitted": replacement_plan_admitted,
        "execute_requested": execute_requested,
        "host_mutation_allowed": host_mutation_allowed,
        "host_write_allowed": false,
        "actual_host_write_executed": false,
        "actual_mutation_executed": false,
        "production_run_command_replaced": false,
        "requires_unimplemented_host_write_flag": "--execute-production-run-command-host-write",
        "apply_manifest_file": path_string(&apply_manifest_file),
        "apply_manifest_materialized": false,
        "service_diff_file": path_string(&service_diff_file),
        "service_diff_materialized": false,
        "product_layout_kind": layout.kind,
        "current_exec_start_pre": layout.current_exec_start_pre,
        "current_exec_start": layout.current_exec_start,
        "current_exec_reload": layout.current_exec_reload,
        "target_exec_start_pre": layout.target_exec_start_pre,
        "target_exec_start": layout.target_exec_start,
        "target_exec_reload": layout.target_exec_reload,
        "read_only": true,
    })
}

pub(super) fn materialize_production_run_command_replacement_artifacts(
    options: &ProductChainRecertificationOptions,
    report: &Value,
    artifact_dir: &Path,
) -> Result<Value, String> {
    let plan = &report["production_run_command_replacement_plan"];
    let requested = plan["requested"].as_bool().unwrap_or(false);
    if !requested {
        return Ok(json!({
            "status": "not-requested",
            "executed": false,
            "requested": false,
        }));
    }

    let backup_artifact_dir = artifact_dir.join("production-run-command-replacement-backup");
    let backup_manifest_file = backup_artifact_dir.join("backup-manifest.json");
    let apply_manifest_file = artifact_dir.join("production-run-command-replacement-apply.json");
    let service_diff_file = artifact_dir.join("production-run-command-replacement-service.diff");
    let layout = ProductPathLayout::from_service_file(&options.service_file);
    let backup_service_file = backup_artifact_dir.join(layout.backup_service_file_name);
    let backup_binary = backup_artifact_dir.join(layout.backup_binary_file_name);
    let rollback_script = artifact_dir.join("rollback-production-run-command-replacement.sh");
    fs::create_dir_all(&backup_artifact_dir).map_err(|err| {
        format!(
            "failed to create production run command replacement backup dir {}: {err}",
            path_string(&backup_artifact_dir)
        )
    })?;

    let backup_manifest = json!({
        "status": "pass",
        "requested": true,
        "executed": true,
        "backup_artifact_dir": path_string(&backup_artifact_dir),
        "backup_manifest_file": path_string(&backup_manifest_file),
        "product_layout_kind": layout.kind,
        "service_file": path_string(&options.service_file),
        "backup_service_file": path_string(&backup_service_file),
        "binary_target": {
            "path": layout.binary_target,
            "exists": Path::new(layout.binary_target).exists(),
            "backup_file": path_string(&backup_binary),
            "backup_copy_executed": false,
        },
        "local_binary_target": {
            "path": layout.local_binary_target,
            "exists": Path::new(layout.local_binary_target).exists(),
            "backup_file": path_string(&backup_artifact_dir.join(layout.backup_local_binary_file_name)),
            "backup_copy_executed": false,
        },
        "backup_copy_executed": false,
        "actual_host_mutation_executed": false,
        "production_run_command_replaced": false,
        "go_fallback_required": true,
        "read_only": true,
        "source": [
            "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:production-run-command-replacement-artifact-materialization",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:cmd-run-reload-validate-service-contract"
        ],
    });
    let encoded = serde_json::to_vec_pretty(&backup_manifest)
        .map_err(|err| format!("failed to encode production run command backup manifest: {err}"))?;
    fs::write(&backup_manifest_file, encoded).map_err(|err| {
        format!(
            "failed to write production run command backup manifest {}: {err}",
            path_string(&backup_manifest_file)
        )
    })?;

    let rollback_script_content = rollback_script_content(
        &options.service_file,
        &backup_service_file,
        layout.binary_target,
        &backup_binary,
        &backup_manifest_file,
    );
    fs::write(&rollback_script, rollback_script_content).map_err(|err| {
        format!(
            "failed to write production run command rollback script {}: {err}",
            path_string(&rollback_script)
        )
    })?;
    make_user_executable(&rollback_script)?;

    let apply_artifacts = materialize_production_run_command_apply_plan_artifacts(
        options,
        plan,
        &apply_manifest_file,
        &service_diff_file,
    )?;

    let mut artifacts = Map::new();
    artifacts.insert("status".to_owned(), json!("pass"));
    artifacts.insert("requested".to_owned(), json!(true));
    artifacts.insert("executed".to_owned(), json!(true));
    artifacts.insert(
        "backup_artifact_dir".to_owned(),
        json!(path_string(&backup_artifact_dir)),
    );
    artifacts.insert(
        "backup_manifest_file".to_owned(),
        json!(path_string(&backup_manifest_file)),
    );
    artifacts.insert(
        "backup_manifest_materialized".to_owned(),
        json!(backup_manifest_file.exists()),
    );
    artifacts.insert(
        "rollback_script".to_owned(),
        json!(path_string(&rollback_script)),
    );
    artifacts.insert(
        "rollback_script_materialized".to_owned(),
        json!(rollback_script.exists()),
    );
    artifacts.insert(
        "rollback_requires_env".to_owned(),
        json!("DAE_PRODUCTION_ROLLBACK_EXECUTE=1"),
    );
    artifacts.insert("backup_copy_executed".to_owned(), json!(false));
    artifacts.insert("actual_host_mutation_executed".to_owned(), json!(false));
    artifacts.insert("production_run_command_replaced".to_owned(), json!(false));
    artifacts.insert("read_only".to_owned(), json!(true));
    artifacts.insert("apply_plan_artifacts".to_owned(), apply_artifacts.clone());
    for key in [
        "apply_manifest_file",
        "apply_manifest_materialized",
        "service_diff_file",
        "service_diff_materialized",
    ] {
        if let Some(value) = apply_artifacts.get(key) {
            artifacts.insert(key.to_owned(), value.clone());
        }
    }
    Ok(Value::Object(artifacts))
}

fn materialize_production_run_command_apply_plan_artifacts(
    options: &ProductChainRecertificationOptions,
    plan: &Value,
    apply_manifest_file: &Path,
    service_diff_file: &Path,
) -> Result<Value, String> {
    let apply_plan = &plan["apply_plan"];
    let requested = apply_plan["requested"].as_bool().unwrap_or(false);
    if !requested {
        return Ok(json!({
            "status": "not-requested",
            "requested": false,
            "executed": false,
            "apply_manifest_materialized": false,
            "service_diff_materialized": false,
        }));
    }

    let layout = ProductPathLayout::from_service_file(&options.service_file);
    let diff = production_run_command_service_diff(&options.service_file);
    fs::write(service_diff_file, diff).map_err(|err| {
        format!(
            "failed to write production run command service diff {}: {err}",
            path_string(service_diff_file)
        )
    })?;
    let apply_manifest = json!({
        "status": "pass",
        "requested": true,
        "executed": true,
        "admitted": apply_plan["admitted"].as_bool().unwrap_or(false),
        "execution_blockers": apply_plan["execution_blockers"].clone(),
        "execution_mode": "read-only-apply-plan",
        "product_layout_kind": layout.kind,
        "service_file": path_string(&options.service_file),
        "service_diff_file": path_string(service_diff_file),
        "apply_manifest_file": path_string(apply_manifest_file),
        "current_exec_start_pre": layout.current_exec_start_pre,
        "current_exec_start": layout.current_exec_start,
        "current_exec_reload": layout.current_exec_reload,
        "target_exec_start_pre": layout.target_exec_start_pre,
        "target_exec_start": layout.target_exec_start,
        "target_exec_reload": layout.target_exec_reload,
        "host_write_allowed": false,
        "actual_host_write_executed": false,
        "actual_mutation_executed": false,
        "production_run_command_replaced": false,
        "requires_unimplemented_host_write_flag": "--execute-production-run-command-host-write",
        "post_apply_required_checks": [
            layout.post_smoke_commands()[0],
            layout.post_smoke_commands()[1],
            layout.post_smoke_commands()[2],
            layout.service_manager_commands()[0],
            layout.service_manager_commands()[1],
            layout.service_manager_commands()[2]
        ],
        "read_only": true,
    });
    let encoded = serde_json::to_vec_pretty(&apply_manifest)
        .map_err(|err| format!("failed to encode production run command apply manifest: {err}"))?;
    fs::write(apply_manifest_file, encoded).map_err(|err| {
        format!(
            "failed to write production run command apply manifest {}: {err}",
            path_string(apply_manifest_file)
        )
    })?;

    Ok(json!({
        "status": "pass",
        "requested": true,
        "executed": true,
        "product_layout_kind": layout.kind,
        "apply_manifest_file": path_string(apply_manifest_file),
        "apply_manifest_materialized": apply_manifest_file.exists(),
        "service_diff_file": path_string(service_diff_file),
        "service_diff_materialized": service_diff_file.exists(),
        "host_write_allowed": false,
        "actual_host_write_executed": false,
        "actual_mutation_executed": false,
        "production_run_command_replaced": false,
        "read_only": true,
    }))
}

fn production_run_command_service_diff(service_file: &Path) -> String {
    let layout = ProductPathLayout::from_service_file(service_file);
    format!("{}", layout.service_diff(&path_string(service_file)),)
}

pub(super) fn attach_production_run_command_replacement_artifacts(
    report: &mut Value,
    artifacts: Value,
) {
    let Some(plan) = report
        .get_mut("production_run_command_replacement_plan")
        .and_then(Value::as_object_mut)
    else {
        return;
    };
    plan.insert("artifact_materialization".to_owned(), artifacts.clone());
    for key in [
        "backup_manifest_file",
        "backup_manifest_materialized",
        "rollback_script",
        "rollback_script_materialized",
        "backup_copy_executed",
        "apply_manifest_file",
        "apply_manifest_materialized",
        "service_diff_file",
        "service_diff_materialized",
    ] {
        if let Some(value) = artifacts.get(key) {
            plan.insert(key.to_owned(), value.clone());
        }
    }
    if let Some(apply_artifacts) = artifacts.get("apply_plan_artifacts") {
        if let Some(apply_plan) = plan.get_mut("apply_plan").and_then(Value::as_object_mut) {
            apply_plan.insert(
                "artifact_materialization".to_owned(),
                apply_artifacts.clone(),
            );
            for key in [
                "apply_manifest_file",
                "apply_manifest_materialized",
                "service_diff_file",
                "service_diff_materialized",
            ] {
                if let Some(value) = apply_artifacts.get(key) {
                    apply_plan.insert(key.to_owned(), value.clone());
                }
            }
        }
    }
}
