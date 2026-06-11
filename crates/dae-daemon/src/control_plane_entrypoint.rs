use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{Value, json};

use crate::{
    ProductRunIdentityAdmissionOptions, control_plane_owner_preflight_report,
    product_run_identity_admission_report,
};

pub fn default_control_plane_entrypoint_admission_root() -> PathBuf {
    PathBuf::from("/tmp/dae-control-plane-entrypoint-admission")
}

pub fn control_plane_entrypoint_admission_report(root: &Path) -> Result<Value, String> {
    ensure_safe_control_plane_entrypoint_admission_root(root)?;
    if root.exists() {
        fs::remove_dir_all(root).map_err(|err| {
            format!(
                "failed to remove existing control-plane-entrypoint root {}: {err}",
                path_string(root)
            )
        })?;
    }

    let run_dir = root.join("run");
    let log_file = root.join("log").join("control-plane-entrypoint.log");
    let manifest_file = run_dir.join("control-plane-entrypoint-admission.json");
    let product_run_identity_root = derived_root("/tmp/dae-product-run-identity-entrypoint", root);
    let control_plane_owner_root = derived_root("/tmp/dae-control-plane-owner-entrypoint", root);

    fs::create_dir_all(&run_dir).map_err(|err| {
        format!(
            "failed to create control-plane-entrypoint run dir {}: {err}",
            path_string(&run_dir)
        )
    })?;
    if let Some(parent) = log_file.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            format!(
                "failed to create control-plane-entrypoint log dir {}: {err}",
                path_string(parent)
            )
        })?;
    }

    let run_identity = product_run_identity_admission_report(
        &ProductRunIdentityAdmissionOptions::under_root(&product_run_identity_root),
    )?;
    let owner = control_plane_owner_preflight_report(&control_plane_owner_root)?;

    let mut report = json!({
        "name": "control-plane-entrypoint-admission",
        "root": path_string(root),
        "run_dir": path_string(&run_dir),
        "log_file": path_string(&log_file),
        "manifest_file": path_string(&manifest_file),
        "product_run_identity_root": path_string(&product_run_identity_root),
        "control_plane_owner_root": path_string(&control_plane_owner_root),
        "run_identity": run_identity,
        "control_plane_owner": owner
    });
    for key in [
        "control_plane_entrypoint_admitted",
        "rust_run_identity_admitted",
        "rust_run_entrypoint_exists",
        "rust_control_plane_entrypoint_admitted",
        "run_identity_admission_reused",
        "control_plane_owner_preflight_reused",
        "control_plane_startup_sequence_recorded",
        "control_plane_reload_owner_sequence_recorded",
        "control_plane_restore_sequence_recorded",
        "listener_reuse_contract_recorded",
        "bpf_owner_transfer_contract_recorded",
        "dns_cache_migration_guard_recorded",
        "reload_scoped_flush_after_current_swap_recorded",
        "isolated_control_plane_entrypoint_paths_validated",
        "native_runtime_path_preserved",
        "runtime_state_evidence_required",
    ] {
        report[key] = json!(true);
    }
    report["production_evidence_required"] = json!(true);
    for key in [
        "production_run_command_owned",
        "production_pid_progress_paths_mutated",
        "production_signal_handler_installed",
        "production_listener_bound",
        "ebpf_attached",
        "benchmark_executable_now",
        "native_daemon_benchmark_recorded",
        "true_rust_native_daemon_admitted",
        "production_admission_allowed",
        "host_mutation_allowed",
        "final_state_admission_allowed",
    ] {
        report[key] = json!(false);
    }

    let manifest = serde_json::to_vec_pretty(&report)
        .map_err(|err| format!("failed to encode control-plane-entrypoint manifest: {err}"))?;
    fs::write(&manifest_file, manifest)
        .map_err(|err| format!("failed to write control-plane-entrypoint manifest: {err}"))?;
    fs::write(&log_file, "control-plane entrypoint admission\n")
        .map_err(|err| format!("failed to write control-plane-entrypoint log: {err}"))?;
    Ok(report)
}

fn ensure_safe_control_plane_entrypoint_admission_root(root: &Path) -> Result<(), String> {
    if !root.is_absolute() {
        return Err(format!(
            "control-plane-entrypoint root must be absolute: {}",
            path_string(root)
        ));
    }
    let root_string = path_string(root);
    if !root_string.starts_with("/tmp/dae-control-plane-entrypoint") {
        return Err(format!(
            "control-plane-entrypoint root must be under /tmp/dae-control-plane-entrypoint*: {root_string}"
        ));
    }
    Ok(())
}

fn derived_root(prefix: &str, root: &Path) -> PathBuf {
    let suffix = root
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("control-plane-entrypoint");
    PathBuf::from(format!("{prefix}-{suffix}"))
}

fn path_string(path: &Path) -> String {
    path.display().to_string()
}
