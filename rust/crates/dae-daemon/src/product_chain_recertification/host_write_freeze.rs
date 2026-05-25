use std::fs;
use std::path::Path;

use serde_json::{Value, json};

use super::path_string;

pub(super) fn materialize_production_host_write_plan_freeze_report(
    report: &Value,
    artifact_dir: &Path,
) -> Result<Value, String> {
    let freeze_file = artifact_dir.join("production-host-write-plan-freeze.json");
    let readiness = &report["production_replacement_readiness"];
    let rehearsal = &report["daed2_product_chain_switch_rehearsal"];
    let readiness_passed = readiness["ready_for_manual_authorization"]
        .as_bool()
        .unwrap_or(false);
    let resident_default_daemon_switch_ready =
        readiness["checks"]["resident_default_daemon_switch_ready"]
            .as_bool()
            .unwrap_or(false);
    let rehearsal_passed = rehearsal["pass"].as_bool().unwrap_or(false);
    let no_host_write_executed = readiness["checks"]["no_host_write_executed"]
        .as_bool()
        .unwrap_or(false)
        && !rehearsal["actual_host_write_executed"]
            .as_bool()
            .unwrap_or(true);
    let host_inventory = &readiness["host_inventory"];
    let usr_bin_dae_exists = host_inventory["usr_bin_dae_exists"]
        .as_bool()
        .unwrap_or(false);
    let installed_system_service_exists = host_inventory["installed_system_service_exists"]
        .as_bool()
        .unwrap_or(false);
    let runtime_config_exists = host_inventory["runtime_config_exists"]
        .as_bool()
        .unwrap_or(false);
    let local_validation_fresh_install_plan = &report["local_validation_fresh_install_plan"];
    let local_validation_fresh_install_plan_passed = local_validation_fresh_install_plan["pass"]
        .as_bool()
        .unwrap_or(false);
    let fresh_install_required = !usr_bin_dae_exists && !installed_system_service_exists;
    let operation_mode = if fresh_install_required {
        "fresh-install"
    } else {
        "replacement"
    };
    let mut blockers = Vec::new();
    if !readiness_passed {
        blockers.push("production replacement readiness is not pass");
    }
    if !resident_default_daemon_switch_ready {
        blockers.push("resident default service path does not admit production dataplane");
    }
    if !rehearsal_passed {
        blockers.push("daed2.0 product-chain switch rehearsal is not pass");
    }
    if !no_host_write_executed {
        blockers.push("host write was already executed");
    }
    if fresh_install_required {
        if local_validation_fresh_install_plan_passed {
            blockers.push(
                "fresh install is frozen for local validation only; production host write requires production configuration and explicit authorization",
            );
        } else {
            blockers.push(
                "fresh install requires a separately frozen binary, service, config, and removal rollback plan",
            );
            if local_validation_fresh_install_plan["requested"]
                .as_bool()
                .unwrap_or(false)
            {
                blockers.push(
                    "local validation fresh-install plan is blocked by candidate service command contract",
                );
            }
        }
    } else if !usr_bin_dae_exists {
        blockers.push("installed /usr/bin/dae target is absent for the replacement plan");
    }
    if !installed_system_service_exists {
        blockers.push("installed dae.service target is absent for the frozen service change");
    }
    if !runtime_config_exists {
        blockers.push("required runtime config /etc/dae/config.dae is absent");
    }
    let pass = blockers.is_empty();
    let frozen_execution_checklist = if fresh_install_required {
        json!([
            "confirm user explicitly authorized controlled production fresh installation",
            "confirm production-host-write-plan-freeze.json is regenerated as pass before any write",
            "freeze the production Rust binary source and absolute installed binary target",
            "freeze the installed dae.service target and materialized /etc/dae/config.dae source",
            "create a removal rollback manifest that preserves the pre-install absence state",
            "apply only the frozen binary, service, and config installation targets",
            "run post-write validation immediately"
        ])
    } else {
        json!([
            "confirm user explicitly authorized controlled production host write",
            "confirm production-host-write-plan-freeze.json status is pass",
            "confirm production-replacement-readiness.json status is pass",
            "confirm daed2-product-chain-switch-rehearsal.json status is pass",
            "confirm service diff is the intended default-path command change",
            "create real backup before any write",
            "apply only the frozen service/run-command change",
            "run post-write validation immediately"
        ])
    };
    let frozen_rollback_checklist = if fresh_install_required {
        json!([
            "use the real installation manifest produced during controlled host write",
            "remove only newly installed dae.service files if installation fails",
            "remove only the newly installed default daemon binary if installation fails",
            "remove only the newly installed runtime config if it was created by this execution",
            "run systemctl daemon-reload only after rollback is explicitly authorized",
            "verify that the pre-install absence state and daed2.0 chain are restored"
        ])
    } else {
        json!([
            "use the real backup artifact produced during controlled host write",
            "restore service file if changed",
            "restore /usr/bin/dae or target binary if changed",
            "run systemctl daemon-reload only after rollback is explicitly authorized",
            "restart dae.service only after rollback validation is explicit",
            "rerun daed2.0 product-chain validation after rollback"
        ])
    };
    let frozen_validation_checklist = if fresh_install_required {
        json!([
            "validate using the frozen installed daemon target and materialized /etc/dae/config.dae",
            "run ready using the frozen installed daemon target and materialized /etc/dae/config.dae",
            "validate reload against the newly installed service process",
            "active TCP relay smoke and benchmark",
            "active UDP smoke and benchmark",
            "active DNS smoke and benchmark",
            "daed2.0 runtime/control API compatibility check",
            "matched Go/Rust default daemon benchmark",
            "resource cleanup check"
        ])
    } else {
        json!([
            "dae-daemon-optin validate -c /etc/dae/config.dae",
            "dae-daemon-optin run --disable-timestamp -c /etc/dae/config.dae --exit-after-ready",
            "dae-daemon-optin reload $MAINPID",
            "active TCP relay smoke and benchmark",
            "active UDP smoke and benchmark",
            "active DNS smoke and benchmark",
            "daed2.0 runtime/control API compatibility check",
            "matched Go/Rust default daemon benchmark",
            "resource cleanup check"
        ])
    };
    let freeze = json!({
        "status": if pass { "pass" } else { "blocked" },
        "pass": pass,
        "frozen": pass,
        "blockers": blockers,
        "freeze_file": path_string(&freeze_file),
        "operation_mode": operation_mode,
        "fresh_install_requires_replan": fresh_install_required,
        "manual_authorization_required_for_phase4": true,
        "phase4_must_not_start_without_user_authorization": true,
        "phase4_must_not_start_while_freeze_blocked": true,
        "host_write_allowed": false,
        "actual_host_write_executed": false,
        "production_run_command_replaced": false,
        "checks": {
            "production_replacement_readiness_passed": readiness_passed,
            "resident_default_daemon_switch_ready": resident_default_daemon_switch_ready,
            "daed2_product_chain_switch_rehearsal_passed": rehearsal_passed,
            "no_host_write_executed": no_host_write_executed,
            "installed_usr_bin_dae_exists": usr_bin_dae_exists,
            "installed_system_service_exists": installed_system_service_exists,
            "runtime_config_exists": runtime_config_exists,
            "local_validation_fresh_install_plan_passed": local_validation_fresh_install_plan_passed,
        },
        "host_inventory": host_inventory.clone(),
        "local_validation_fresh_install_plan": local_validation_fresh_install_plan.clone(),
        "inputs": {
            "readiness_file": readiness["readiness_file"].clone(),
            "rehearsal_file": rehearsal["rehearsal_file"].clone(),
            "apply_manifest_file": readiness["required_artifacts"]["apply_manifest_file"].clone(),
            "service_diff_file": readiness["required_artifacts"]["service_diff_file"].clone(),
            "backup_manifest_file": readiness["required_artifacts"]["backup_manifest_file"].clone(),
            "rollback_script": readiness["required_artifacts"]["rollback_script"].clone(),
            "local_validation_fresh_install_plan_file": local_validation_fresh_install_plan["plan_file"].clone(),
        },
        "frozen_execution_checklist": frozen_execution_checklist,
        "frozen_rollback_checklist": frozen_rollback_checklist,
        "frozen_validation_checklist": frozen_validation_checklist,
        "read_only": true,
        "source": [
            "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:后续阶段 3",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:default-path-service-runtime-contract"
        ],
    });
    let encoded = serde_json::to_vec_pretty(&freeze)
        .map_err(|err| format!("failed to encode production host-write plan freeze: {err}"))?;
    fs::write(&freeze_file, encoded).map_err(|err| {
        format!(
            "failed to write production host-write plan freeze {}: {err}",
            path_string(&freeze_file)
        )
    })?;
    Ok(freeze)
}

pub(super) fn attach_production_host_write_plan_freeze(report: &mut Value, freeze: Value) {
    let Some(report_object) = report.as_object_mut() else {
        return;
    };
    report_object.insert(
        "production_host_write_plan_freeze_file".to_owned(),
        freeze["freeze_file"].clone(),
    );
    report_object.insert(
        "production_host_write_plan_freeze_passed".to_owned(),
        freeze["pass"].clone(),
    );
    report_object.insert("production_host_write_plan_freeze".to_owned(), freeze);
}
