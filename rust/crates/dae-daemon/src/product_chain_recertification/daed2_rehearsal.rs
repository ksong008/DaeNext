use std::fs;
use std::path::Path;

use serde_json::{Value, json};

use super::path_string;

pub(super) fn materialize_daed2_product_chain_switch_rehearsal_report(
    report: &Value,
    artifact_dir: &Path,
) -> Result<Value, String> {
    let rehearsal_file = artifact_dir.join("daed2-product-chain-switch-rehearsal.json");
    let readiness = &report["production_replacement_readiness"];
    let plan = &report["production_run_command_replacement_plan"];
    let apply_plan = &plan["apply_plan"];
    let topology = &report["product_chain_topology"];
    let daed2_product_chain_used = topology["daed2_wing_repo_used"].as_bool().unwrap_or(false);
    let product_chain_clean = report["product_chain_recertification_clean"]
        .as_bool()
        .unwrap_or(false);
    let runtime_control_api_preserved = report["runtime_control_api_source_contract_preserved"]
        .as_bool()
        .unwrap_or(false);
    let dependency_boundary_preserved = report["outbound_quic_go_dependency_boundary_preserved"]
        .as_bool()
        .unwrap_or(false);
    let branch_contract_preserved = report["product_chain_branch_contract_preserved"]
        .as_bool()
        .unwrap_or(false);
    let readiness_passed = readiness["ready_for_manual_authorization"]
        .as_bool()
        .unwrap_or(false);
    let resident_default_daemon_switch_ready = report["resident_default_daemon_switch_ready"]
        .as_bool()
        .unwrap_or(false);
    let apply_manifest_materialized = apply_plan["apply_manifest_materialized"]
        .as_bool()
        .unwrap_or(false);
    let service_diff_materialized = apply_plan["service_diff_materialized"]
        .as_bool()
        .unwrap_or(false);
    let no_host_write_executed = readiness["checks"]["no_host_write_executed"]
        .as_bool()
        .unwrap_or(false);
    let mut blockers = Vec::new();
    if !daed2_product_chain_used {
        blockers.push("daed2.0 product-chain topology is not selected");
    }
    if !product_chain_clean {
        blockers.push("product-chain recertification is not clean");
    }
    if !runtime_control_api_preserved {
        blockers.push("daed2.0 runtime/control API source contract is not preserved");
    }
    if !dependency_boundary_preserved {
        blockers.push("outbound / quic-go dependency boundary is not preserved");
    }
    if !branch_contract_preserved {
        blockers.push("product-chain sibling repo branches do not match daed2.0 switch contract");
    }
    if !resident_default_daemon_switch_ready {
        blockers.push("resident default service path does not admit production dataplane");
    }
    if !readiness_passed {
        blockers.push("production replacement readiness report is not pass");
    }
    if !apply_manifest_materialized {
        blockers.push("apply manifest is not materialized");
    }
    if !service_diff_materialized {
        blockers.push("service diff is not materialized");
    }
    if !no_host_write_executed {
        blockers.push("host write was already executed");
    }
    let pass = blockers.is_empty();
    let rehearsal = json!({
        "status": if pass { "pass" } else { "blocked" },
        "dry_run": true,
        "pass": pass,
        "blockers": blockers,
        "rehearsal_file": path_string(&rehearsal_file),
        "daed2_product_chain_used": daed2_product_chain_used,
        "product_chain_topology": topology.clone(),
        "paths": {
            "dae_repo": report["paths"]["dae_repo"].clone(),
            "daed_repo": report["paths"]["daed_repo"].clone(),
            "dae_wing_repo": report["paths"]["dae_wing_repo"].clone(),
            "outbound_repo": report["paths"]["outbound_repo"].clone(),
            "quic_go_repo": report["paths"]["quic_go_repo"].clone(),
        },
        "checks": {
            "product_chain_recertification_clean": product_chain_clean,
            "runtime_control_api_source_contract_preserved": runtime_control_api_preserved,
            "outbound_quic_go_dependency_boundary_preserved": dependency_boundary_preserved,
            "product_chain_branch_contract_preserved": branch_contract_preserved,
            "resident_default_daemon_switch_ready": resident_default_daemon_switch_ready,
            "production_replacement_readiness_passed": readiness_passed,
            "apply_manifest_materialized": apply_manifest_materialized,
            "service_diff_materialized": service_diff_materialized,
            "no_host_write_executed": no_host_write_executed,
        },
        "artifacts": {
            "readiness_file": readiness["readiness_file"].clone(),
            "apply_manifest_file": apply_plan["apply_manifest_file"].clone(),
            "service_diff_file": apply_plan["service_diff_file"].clone(),
            "backup_manifest_file": plan["artifact_materialization"]["backup_manifest_file"].clone(),
            "rollback_script": plan["artifact_materialization"]["rollback_script"].clone(),
        },
        "expected_product_chain": [
            "daed2.0 apps/web",
            "/api",
            "daed/wing/transport/httpapi",
            "daed/wing/orchestrator",
            "daed/wing/engine",
            "daed/wing/dae-core",
            "outbound",
            "quic-go"
        ],
        "host_write_allowed": false,
        "actual_host_write_executed": false,
        "production_run_command_replaced": false,
        "read_only": true,
        "source": [
            "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:后续阶段 2",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:daed2-runtime-control-api"
        ],
    });
    let encoded = serde_json::to_vec_pretty(&rehearsal)
        .map_err(|err| format!("failed to encode daed2 switch rehearsal report: {err}"))?;
    fs::write(&rehearsal_file, encoded).map_err(|err| {
        format!(
            "failed to write daed2 switch rehearsal report {}: {err}",
            path_string(&rehearsal_file)
        )
    })?;
    Ok(rehearsal)
}

pub(super) fn attach_daed2_product_chain_switch_rehearsal(report: &mut Value, rehearsal: Value) {
    let Some(report_object) = report.as_object_mut() else {
        return;
    };
    report_object.insert(
        "daed2_product_chain_switch_rehearsal_file".to_owned(),
        rehearsal["rehearsal_file"].clone(),
    );
    report_object.insert(
        "daed2_product_chain_switch_rehearsal_passed".to_owned(),
        rehearsal["pass"].clone(),
    );
    report_object.insert("daed2_product_chain_switch_rehearsal".to_owned(), rehearsal);
}
