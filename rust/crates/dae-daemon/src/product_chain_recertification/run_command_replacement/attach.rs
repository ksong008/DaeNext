use super::*;
pub(crate) fn attach_production_run_command_replacement_artifacts(
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
