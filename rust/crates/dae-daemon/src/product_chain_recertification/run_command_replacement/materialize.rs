use super::*;
pub(crate) fn materialize_production_run_command_replacement_artifacts(
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

pub(crate) fn materialize_production_run_command_apply_plan_artifacts(
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

pub(crate) fn production_run_command_service_diff(service_file: &Path) -> String {
    let layout = ProductPathLayout::from_service_file(service_file);
    format!("{}", layout.service_diff(&path_string(service_file)),)
}
