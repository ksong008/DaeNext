use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{Value, json};

use crate::{stage150_lifecycle_smoke_report, stage152_signal_control_plane_smoke_report};

pub fn default_stage153_root() -> PathBuf {
    PathBuf::from("/tmp/dae-stage153-run-entrypoint-preflight")
}

pub fn stage153_run_entrypoint_preflight_report(root: &Path) -> Result<Value, String> {
    ensure_safe_stage153_root(root)?;
    if root.exists() {
        fs::remove_dir_all(root).map_err(|err| {
            format!(
                "failed to remove existing stage153 root {}: {err}",
                path_string(root)
            )
        })?;
    }

    let run_dir = root.join("run");
    let log_dir = root.join("log");
    fs::create_dir_all(&run_dir).map_err(|err| {
        format!(
            "failed to create stage153 run dir {}: {err}",
            path_string(&run_dir)
        )
    })?;
    fs::create_dir_all(&log_dir).map_err(|err| {
        format!(
            "failed to create stage153 log dir {}: {err}",
            path_string(&log_dir)
        )
    })?;

    let lifecycle_root = derived_root("/tmp/dae-stage150-entrypoint", root);
    let signal_root = derived_root("/tmp/dae-stage152-entrypoint", root);
    let wrapper_manifest = run_dir.join("run-entrypoint-wrapper.json");
    let log_file = log_dir.join("run-entrypoint-wrapper.log");

    let lifecycle = stage150_lifecycle_smoke_report(&lifecycle_root)?;
    let signal = stage152_signal_control_plane_smoke_report(&signal_root)?;

    let report = json!({
        "name": "stage153-rust-run-entrypoint-preflight",
        "stage": "stage153",
        "root": path_string(root),
        "run_dir": path_string(&run_dir),
        "log_file": path_string(&log_file),
        "wrapper_manifest": path_string(&wrapper_manifest),
        "lifecycle_root": path_string(&lifecycle_root),
        "signal_root": path_string(&signal_root),
        "non_default_command": "stage153-run-entrypoint-preflight",
        "default_command": "run",
        "go_default_path_preserved": true,
        "run_flag_contract": {
            "config_flag": "-c/--config required for production run",
            "logfile_flag": "--logfile supported by Go default path",
            "disable_timestamp_flag": "--disable-timestamp supported by Go default path",
            "disable_pidfile_flag": "--disable-pidfile supported by Go default path",
            "disable_sudo_flag": "--disable-sudo supported by Go default path"
        },
        "on_ready_contract": [
            "systemd ready notification",
            "pid file write unless disable-pidfile",
            "progress file ReloadDone write"
        ],
        "composed_smokes": {
            "lifecycle": lifecycle,
            "signal_control_plane": signal
        },
        "non_default_run_entrypoint_wrapper_available": true,
        "run_entrypoint_wrapper_composed": true,
        "run_entrypoint_lifecycle_smoke_reused": true,
        "run_entrypoint_signal_control_plane_smoke_reused": true,
        "run_entrypoint_on_ready_contract_recorded": true,
        "run_entrypoint_flag_contract_recorded": true,
        "isolated_run_entrypoint_paths_validated": true,
        "go_default_run_command_preserved": true,
        "production_run_command_replaced": false,
        "production_pid_progress_paths_mutated": false,
        "production_signal_handler_installed": false,
        "production_listener_bound": false,
        "ebpf_attached": false,
        "rust_default_run_entrypoint_exists": false,
        "rust_default_control_plane_entrypoint_admitted": false,
        "benchmark_executable_now": false,
        "matched_go_rust_default_daemon_benchmark_recorded": false,
        "true_rust_default_daemon_admitted": false,
        "default_switch_allowed": false,
        "product_chain_switch_allowed": false
    });
    let manifest = serde_json::to_vec_pretty(&report)
        .map_err(|err| format!("failed to encode stage153 wrapper manifest: {err}"))?;
    fs::write(&wrapper_manifest, manifest)
        .map_err(|err| format!("failed to write stage153 wrapper manifest: {err}"))?;
    fs::write(&log_file, "stage153 run entrypoint wrapper preflight\n")
        .map_err(|err| format!("failed to write stage153 wrapper log: {err}"))?;
    Ok(report)
}

fn ensure_safe_stage153_root(root: &Path) -> Result<(), String> {
    if !root.is_absolute() {
        return Err(format!(
            "stage153 root must be absolute: {}",
            path_string(root)
        ));
    }
    let root_string = path_string(root);
    if !root_string.starts_with("/tmp/dae-stage153") {
        return Err(format!(
            "stage153 root must be under /tmp/dae-stage153*: {root_string}"
        ));
    }
    Ok(())
}

fn derived_root(prefix: &str, root: &Path) -> PathBuf {
    let suffix = root
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("stage153");
    PathBuf::from(format!("{prefix}-{suffix}"))
}

fn path_string(path: &Path) -> String {
    path.display().to_string()
}
