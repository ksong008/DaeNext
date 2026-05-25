use serde_json::{Value, json};

pub(super) fn production_run_command_execution_blockers(plan: &Value) -> Vec<String> {
    plan["execution_blockers"]
        .as_array()
        .map(|blockers| {
            blockers
                .iter()
                .filter_map(|blocker| blocker.as_str().map(ToOwned::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

pub(super) fn production_run_command_execution_blockers_json(
    execute_requested: bool,
    plan_admitted: bool,
    host_mutation_allow_requested: bool,
    host_mutation_allowed: bool,
) -> Value {
    let mut blockers = Vec::new();
    if execute_requested && !plan_admitted {
        blockers.push(
            "production run command replacement execute requested but dry-run plan is not admitted",
        );
    }
    if execute_requested && !host_mutation_allow_requested {
        blockers.push(
            "production run command replacement execute requested but host default path mutation is not allowed",
        );
    } else if execute_requested && !host_mutation_allowed {
        blockers.push(
            "production run command replacement execute requested but host default path mutation is not admitted",
        );
    }
    json!(blockers)
}

pub(super) fn production_run_command_apply_plan_blockers(plan: &Value) -> Vec<String> {
    plan["apply_plan"]["execution_blockers"]
        .as_array()
        .map(|blockers| {
            blockers
                .iter()
                .filter_map(|blocker| blocker.as_str().map(ToOwned::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

pub(super) fn production_run_command_apply_plan_blockers_json(
    requested: bool,
    replacement_plan_admitted: bool,
    execute_requested: bool,
    host_mutation_allowed: bool,
) -> Value {
    let mut blockers = Vec::new();
    if requested && !replacement_plan_admitted {
        blockers.push(
            "production run command apply plan requested but replacement dry-run plan is not admitted",
        );
    }
    if requested && !execute_requested {
        blockers.push(
            "production run command apply plan requested but replacement execute was not requested",
        );
    }
    if requested && !host_mutation_allowed {
        blockers.push(
            "production run command apply plan requested but host default path mutation is not admitted",
        );
    }
    json!(blockers)
}
