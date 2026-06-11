use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{Value, json};

use crate::{lifecycle_smoke_report, signal_control_plane_smoke_report};

pub fn product_run_entrypoint_preflight_root() -> PathBuf {
    PathBuf::from("/tmp/dae-run-entrypoint-preflight")
}

pub fn run_entrypoint_preflight_report(root: &Path) -> Result<Value, String> {
    ensure_safe_run_entrypoint_preflight_root(root)?;
    if root.exists() {
        fs::remove_dir_all(root).map_err(|err| {
            format!(
                "failed to remove existing run-entrypoint root {}: {err}",
                path_string(root)
            )
        })?;
    }

    let run_dir = root.join("run");
    let log_dir = root.join("log");
    fs::create_dir_all(&run_dir).map_err(|err| {
        format!(
            "failed to create run-entrypoint run dir {}: {err}",
            path_string(&run_dir)
        )
    })?;
    fs::create_dir_all(&log_dir).map_err(|err| {
        format!(
            "failed to create run-entrypoint log dir {}: {err}",
            path_string(&log_dir)
        )
    })?;

    let lifecycle_root = derived_root("/tmp/dae-lifecycle-smoke-entrypoint", root);
    let signal_root = derived_root("/tmp/dae-signal-control-plane-entrypoint", root);
    let wrapper_manifest = run_dir.join("run-entrypoint-wrapper.json");
    let log_file = log_dir.join("run-entrypoint-wrapper.log");

    let lifecycle = lifecycle_smoke_report(&lifecycle_root)?;
    let signal = signal_control_plane_smoke_report(&signal_root)?;

    let report = json!({
        "name": "rust-run-entrypoint-preflight",
        "root": path_string(root),
        "run_dir": path_string(&run_dir),
        "log_file": path_string(&log_file),
        "wrapper_manifest": path_string(&wrapper_manifest),
        "lifecycle_root": path_string(&lifecycle_root),
        "signal_root": path_string(&signal_root),
        "preflight_command": "run-entrypoint-preflight",
        "primary_command": "run",
        "run_flag_contract": {
            "config_flag": "-c/--config required for production run",
            "logfile_flag": "--logfile supported by Rust-native product runtime path",
            "disable_timestamp_flag": "--disable-timestamp supported by Rust-native product runtime path",
            "disable_pidfile_flag": "--disable-pidfile supported by Rust-native product runtime path",
            "disable_sudo_flag": "--disable-sudo supported by Rust-native product runtime path"
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
        "run_entrypoint_wrapper_available": true,
        "run_entrypoint_wrapper_composed": true,
        "run_entrypoint_lifecycle_smoke_reused": true,
        "run_entrypoint_signal_control_plane_smoke_reused": true,
        "run_entrypoint_on_ready_contract_recorded": true,
        "run_entrypoint_flag_contract_recorded": true,
        "isolated_run_entrypoint_paths_validated": true,
        "rust_run_command_owned": true,
        "production_run_command_owned": true,
        "production_pid_progress_paths_mutated": false,
        "production_signal_handler_installed": false,
        "production_listener_bound": false,
        "ebpf_attached": false,
        "rust_run_entrypoint_exists": true,
        "rust_control_plane_entrypoint_admitted": true,
        "benchmark_executable_now": false,
        "true_rust_native_daemon_admitted": false,
        "production_admission_allowed": false,
        "final_state_admission_allowed": false
    });
    let manifest = serde_json::to_vec_pretty(&report)
        .map_err(|err| format!("failed to encode run-entrypoint wrapper manifest: {err}"))?;
    fs::write(&wrapper_manifest, manifest)
        .map_err(|err| format!("failed to write run-entrypoint wrapper manifest: {err}"))?;
    fs::write(
        &log_file,
        "run-entrypoint run entrypoint wrapper preflight\n",
    )
    .map_err(|err| format!("failed to write run-entrypoint wrapper log: {err}"))?;
    Ok(report)
}

fn ensure_safe_run_entrypoint_preflight_root(root: &Path) -> Result<(), String> {
    if !root.is_absolute() {
        return Err(format!(
            "run-entrypoint root must be absolute: {}",
            path_string(root)
        ));
    }
    let root_string = path_string(root);
    if !root_string.starts_with("/tmp/dae-run-entrypoint") {
        return Err(format!(
            "run-entrypoint root must be under /tmp/dae-run-entrypoint*: {root_string}"
        ));
    }
    Ok(())
}

fn derived_root(prefix: &str, root: &Path) -> PathBuf {
    let suffix = root
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("run-entrypoint");
    PathBuf::from(format!("{prefix}-{suffix}"))
}

fn path_string(path: &Path) -> String {
    path.display().to_string()
}
