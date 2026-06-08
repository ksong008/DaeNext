use super::*;
pub(crate) fn production_run_command_replacement_plan_json(
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

pub(crate) fn production_run_command_replacement_apply_plan_json(
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
