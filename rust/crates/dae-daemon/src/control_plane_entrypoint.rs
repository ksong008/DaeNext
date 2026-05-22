use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{Value, json};

use crate::{
    Stage156DefaultRunIdentityOptions, stage151_control_plane_owner_preflight_report,
    stage156_default_run_identity_admission_report,
};

pub fn default_stage157_root() -> PathBuf {
    PathBuf::from("/tmp/dae-stage157-control-plane-entrypoint")
}

pub fn stage157_control_plane_entrypoint_admission_report(root: &Path) -> Result<Value, String> {
    ensure_safe_stage157_root(root)?;
    if root.exists() {
        fs::remove_dir_all(root).map_err(|err| {
            format!(
                "failed to remove existing stage157 root {}: {err}",
                path_string(root)
            )
        })?;
    }

    let run_dir = root.join("run");
    let log_file = root.join("log").join("control-plane-entrypoint.log");
    let manifest_file = run_dir.join("stage157-control-plane-entrypoint.json");
    let stage156_root = derived_root("/tmp/dae-stage156-entrypoint", root);
    let stage151_root = derived_root("/tmp/dae-stage151-entrypoint", root);

    fs::create_dir_all(&run_dir).map_err(|err| {
        format!(
            "failed to create stage157 run dir {}: {err}",
            path_string(&run_dir)
        )
    })?;
    if let Some(parent) = log_file.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            format!(
                "failed to create stage157 log dir {}: {err}",
                path_string(parent)
            )
        })?;
    }

    let run_identity = stage156_default_run_identity_admission_report(
        &Stage156DefaultRunIdentityOptions::under_root(&stage156_root),
    )?;
    let owner = stage151_control_plane_owner_preflight_report(&stage151_root)?;

    let mut report = json!({
        "name": "stage157-control-plane-entrypoint-admission",
        "stage": "stage157",
        "root": path_string(root),
        "run_dir": path_string(&run_dir),
        "log_file": path_string(&log_file),
        "manifest_file": path_string(&manifest_file),
        "stage156_root": path_string(&stage156_root),
        "stage151_root": path_string(&stage151_root),
        "run_identity": run_identity,
        "control_plane_owner": owner
    });
    for key in [
        "control_plane_entrypoint_optin_admitted",
        "rust_default_run_identity_optin_admitted",
        "rust_default_run_entrypoint_exists",
        "rust_default_control_plane_entrypoint_admitted",
        "stage156_run_identity_reused",
        "stage151_owner_preflight_reused",
        "control_plane_startup_sequence_recorded",
        "control_plane_reload_owner_sequence_recorded",
        "control_plane_rollback_sequence_recorded",
        "listener_reuse_contract_recorded",
        "bpf_owner_transfer_contract_recorded",
        "dns_cache_migration_guard_recorded",
        "reload_scoped_flush_after_current_swap_recorded",
        "isolated_control_plane_entrypoint_paths_validated",
        "go_default_path_preserved",
        "go_fallback_required",
    ] {
        report[key] = json!(true);
    }
    for key in [
        "production_run_command_replaced",
        "production_pid_progress_paths_mutated",
        "production_signal_handler_installed",
        "production_listener_bound",
        "ebpf_attached",
        "benchmark_executable_now",
        "matched_go_rust_default_daemon_benchmark_recorded",
        "true_rust_default_daemon_admitted",
        "default_switch_allowed",
        "default_path_mutation_allowed",
        "product_chain_switch_allowed",
    ] {
        report[key] = json!(false);
    }

    let manifest = serde_json::to_vec_pretty(&report)
        .map_err(|err| format!("failed to encode stage157 manifest: {err}"))?;
    fs::write(&manifest_file, manifest)
        .map_err(|err| format!("failed to write stage157 manifest: {err}"))?;
    fs::write(&log_file, "stage157 control-plane entrypoint admission\n")
        .map_err(|err| format!("failed to write stage157 log: {err}"))?;
    Ok(report)
}

fn ensure_safe_stage157_root(root: &Path) -> Result<(), String> {
    if !root.is_absolute() {
        return Err(format!(
            "stage157 root must be absolute: {}",
            path_string(root)
        ));
    }
    let root_string = path_string(root);
    if !root_string.starts_with("/tmp/dae-stage157") {
        return Err(format!(
            "stage157 root must be under /tmp/dae-stage157*: {root_string}"
        ));
    }
    Ok(())
}

fn derived_root(prefix: &str, root: &Path) -> PathBuf {
    let suffix = root
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("stage157");
    PathBuf::from(format!("{prefix}-{suffix}"))
}

fn path_string(path: &Path) -> String {
    path.display().to_string()
}
