use std::fs;
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde_json::{Value, json};

use super::service_contract::{candidate_service_contract_report, candidate_validate_report};
use super::{ProductChainRecertificationOptions, path_string};

pub(super) fn materialize_local_validation_fresh_install_plan(
    options: &ProductChainRecertificationOptions,
    report: &Value,
    artifact_dir: &Path,
) -> Result<Value, String> {
    let plan_file = artifact_dir.join("local-validation-fresh-install-plan.json");
    let requested = options.local_validation_fresh_install_plan_requested;
    let config_source = options.local_validation_config_source.as_deref();
    let binary_source = options.local_validation_binary_source.as_deref();
    let service_source = options.service_file.as_path();
    let host_inventory = &report["production_replacement_readiness"]["host_inventory"];
    let usr_bin_dae_exists = host_inventory["usr_bin_dae_exists"]
        .as_bool()
        .unwrap_or(false);
    let installed_system_service_exists = host_inventory["installed_system_service_exists"]
        .as_bool()
        .unwrap_or(false);
    let runtime_config_exists = host_inventory["runtime_config_exists"]
        .as_bool()
        .unwrap_or(false);
    let fresh_install_host_state_confirmed =
        !usr_bin_dae_exists && !installed_system_service_exists && !runtime_config_exists;
    let config_source_exists = config_source.is_some_and(Path::is_file);
    let binary_source_exists = binary_source.is_some_and(Path::is_file);
    let service_source_exists = service_source.is_file();
    let service_contract_preserved = report["service_contract_preserved"]
        .as_bool()
        .unwrap_or(false);
    let product_chain_clean = report["product_chain_recertification_clean"]
        .as_bool()
        .unwrap_or(false);
    let rehearsal_passed = report["daed2_product_chain_switch_rehearsal_passed"]
        .as_bool()
        .unwrap_or(false);
    let no_host_write_executed = !report["production_run_command_replaced"]
        .as_bool()
        .unwrap_or(true);
    let staged_config_source = if requested && config_source_exists {
        Some(materialize_local_validation_validate_input(
            config_source.unwrap(),
            artifact_dir,
        )?)
    } else {
        None
    };
    let candidate_validate =
        candidate_validate_report(requested, binary_source, staged_config_source.as_deref());
    let candidate_validate_passed = candidate_validate["passed"].as_bool().unwrap_or(false);
    let candidate_service_contract = candidate_service_contract_report(requested, binary_source);
    let resident_run_service_contract_ready =
        candidate_service_contract["resident_run_service_contract_ready"]
            .as_bool()
            .unwrap_or(false);
    let reload_command_service_contract_ready =
        candidate_service_contract["reload_command_service_contract_ready"]
            .as_bool()
            .unwrap_or(false);
    let resident_production_dataplane_ready =
        candidate_service_contract["resident_production_dataplane_ready"]
            .as_bool()
            .unwrap_or(false);

    let mut blockers = Vec::new();
    if requested && !fresh_install_host_state_confirmed {
        blockers.push("local validation fresh install requires an initially uninstalled host");
    }
    if requested && !config_source_exists {
        blockers.push("local validation config source is absent");
    }
    if requested && !binary_source_exists {
        blockers.push("local validation Rust binary source is absent");
    }
    if requested && !service_source_exists {
        blockers.push("local validation service template source is absent");
    }
    if requested && !service_contract_preserved {
        blockers.push("local validation service template does not preserve /usr/bin/dae contract");
    }
    if requested && !product_chain_clean {
        blockers.push("product-chain recertification is not clean");
    }
    if requested && !rehearsal_passed {
        blockers.push("daed2.0 product-chain switch rehearsal is not pass");
    }
    if requested && !no_host_write_executed {
        blockers.push("host write was already executed");
    }
    if requested && !candidate_validate_passed {
        blockers.push("local validation Rust binary cannot validate the staged 0600 config input");
    }
    if requested && !resident_run_service_contract_ready {
        blockers.push("resident run service contract is not implemented by dae-daemon-optin");
    }
    if requested && !reload_command_service_contract_ready {
        blockers.push("reload command service contract is not implemented by dae-daemon-optin");
    }
    if requested && !resident_production_dataplane_ready {
        blockers.push("resident default service path does not admit production dataplane");
    }
    let pass = requested && blockers.is_empty();
    let plan = json!({
        "status": if pass { "pass" } else if requested { "blocked" } else { "not-requested" },
        "pass": pass,
        "requested": requested,
        "scope": "local-validation-only",
        "configuration_class": "example-config-not-production-input",
        "production_host_write_authorized": false,
        "actual_host_write_executed": false,
        "plan_file": path_string(&plan_file),
        "blockers": blockers,
        "checks": {
            "fresh_install_host_state_confirmed": fresh_install_host_state_confirmed,
            "config_source_exists": config_source_exists,
            "binary_source_exists": binary_source_exists,
            "service_source_exists": service_source_exists,
            "service_contract_preserved": service_contract_preserved,
            "product_chain_recertification_clean": product_chain_clean,
            "daed2_product_chain_switch_rehearsal_passed": rehearsal_passed,
            "no_host_write_executed": no_host_write_executed,
            "candidate_validate_passed": candidate_validate_passed,
            "resident_run_service_contract_ready": resident_run_service_contract_ready,
            "reload_command_service_contract_ready": reload_command_service_contract_ready,
            "resident_production_dataplane_ready": resident_production_dataplane_ready,
        },
        "candidate_validate": candidate_validate,
        "candidate_service_contract": candidate_service_contract,
        "inputs": {
            "binary_source": binary_source.map(path_string),
            "binary_source_exists": binary_source_exists,
            "service_template_source": path_string(service_source),
            "service_template_source_exists": service_source_exists,
            "config_source": config_source.map(path_string),
            "config_source_exists": config_source_exists,
            "config_source_usage": "local-validation-only",
            "staged_validate_config_source": staged_config_source.as_deref().map(path_string),
            "staged_validate_config_mode": "0600",
        },
        "installation_targets": {
            "binary_target": "/usr/bin/dae",
            "service_target": "/etc/systemd/system/dae.service",
            "config_target": "/etc/dae/config.dae",
            "config_target_mode": "0600",
            "preserved_external_command_contract": "/usr/bin/dae validate/run/reload",
        },
        "execution_checklist": [
            "require explicit authorization before local validation host write",
            "copy the frozen Rust binary source only to /usr/bin/dae",
            "copy install/dae.service only to /etc/systemd/system/dae.service",
            "install example.dae only to /etc/dae/config.dae with mode 0600 and label it local validation only",
            "run systemctl actions only within explicit authorization",
            "run validation and resource cleanup checks immediately"
        ],
        "rollback_checklist": [
            "remove /usr/bin/dae only if created by this local validation installation",
            "remove /etc/systemd/system/dae.service only if created by this local validation installation",
            "remove /etc/dae/config.dae only if copied from example.dae by this execution",
            "run systemctl daemon-reload only if service target was installed and rollback is authorized",
            "confirm the pre-install absent state is restored",
            "rerun daed2.0 product-chain validation after rollback"
        ],
        "read_only": true,
        "boundary": "local-validation service install may exercise resident run and reload; resident production forwarding remains separately gated",
        "source": [
            "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:后续阶段 3 local-validation fresh-install 输入冻结",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:default-path-service-runtime-contract"
        ],
    });
    if requested {
        let encoded = serde_json::to_vec_pretty(&plan).map_err(|err| {
            format!("failed to encode local validation fresh-install plan: {err}")
        })?;
        fs::write(&plan_file, encoded).map_err(|err| {
            format!(
                "failed to write local validation fresh-install plan {}: {err}",
                path_string(&plan_file)
            )
        })?;
    }
    Ok(plan)
}

fn materialize_local_validation_validate_input(
    config_source: &Path,
    artifact_dir: &Path,
) -> Result<PathBuf, String> {
    let staged_config = artifact_dir.join("local-validation-validate-input.dae");
    let content = fs::read(config_source).map_err(|err| {
        format!(
            "failed to read local validation config source {}: {err}",
            path_string(config_source)
        )
    })?;
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut output = options.open(&staged_config).map_err(|err| {
        format!(
            "failed to create staged local validation config {}: {err}",
            path_string(&staged_config)
        )
    })?;
    output.write_all(&content).map_err(|err| {
        format!(
            "failed to write staged local validation config {}: {err}",
            path_string(&staged_config)
        )
    })?;
    #[cfg(unix)]
    fs::set_permissions(&staged_config, std::fs::Permissions::from_mode(0o600)).map_err(|err| {
        format!(
            "failed to restrict staged local validation config {}: {err}",
            path_string(&staged_config)
        )
    })?;
    Ok(staged_config)
}

pub(super) fn attach_local_validation_fresh_install_plan(report: &mut Value, plan: Value) {
    let Some(report_object) = report.as_object_mut() else {
        return;
    };
    report_object.insert(
        "local_validation_fresh_install_plan_file".to_owned(),
        plan["plan_file"].clone(),
    );
    report_object.insert(
        "local_validation_fresh_install_plan_passed".to_owned(),
        plan["pass"].clone(),
    );
    report_object.insert("local_validation_fresh_install_plan".to_owned(), plan);
}
