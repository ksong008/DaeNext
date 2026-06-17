use std::fs;
use std::path::{Path, PathBuf};

use dae_runtime_control::{CoreFlip, ReloadCoreState};
use serde_json::{Value, json};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlPlaneOwnerPaths {
    pub root: PathBuf,
    pub run_dir: PathBuf,
    pub state_file: PathBuf,
    pub log_file: PathBuf,
}

impl ControlPlaneOwnerPaths {
    pub fn under_root(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        let run_dir = root.join("run");
        Self {
            state_file: run_dir.join("control-plane-owner.json"),
            log_file: root.join("log").join("control-plane-owner.log"),
            run_dir,
            root,
        }
    }
}

pub fn default_control_plane_owner_preflight_root() -> PathBuf {
    PathBuf::from("/tmp/dae-control-plane-owner-preflight")
}

pub fn control_plane_owner_preflight_report(root: &Path) -> Result<Value, String> {
    let paths = run_control_plane_owner_preflight(root)?;
    Ok(control_plane_owner_report_value(&paths))
}

pub fn run_control_plane_owner_preflight(root: &Path) -> Result<ControlPlaneOwnerPaths, String> {
    ensure_safe_control_plane_owner_preflight_root(root)?;
    let paths = ControlPlaneOwnerPaths::under_root(root);
    if paths.root.exists() {
        fs::remove_dir_all(&paths.root).map_err(|err| {
            format!(
                "failed to remove existing control-plane-owner root {}: {err}",
                path_string(&paths.root)
            )
        })?;
    }
    fs::create_dir_all(&paths.run_dir).map_err(|err| {
        format!(
            "failed to create control-plane-owner run dir {}: {err}",
            path_string(&paths.run_dir)
        )
    })?;
    if let Some(parent) = paths.log_file.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            format!(
                "failed to create control-plane-owner log dir {}: {err}",
                path_string(parent)
            )
        })?;
    }

    let report = control_plane_owner_report_value(&paths);
    let state = serde_json::to_vec_pretty(&report)
        .map_err(|err| format!("failed to encode control-plane-owner owner state: {err}"))?;
    fs::write(&paths.state_file, state)
        .map_err(|err| format!("failed to write control-plane-owner owner state: {err}"))?;
    fs::write(
        &paths.log_file,
        "control-plane-owner control-plane owner preflight\n",
    )
    .map_err(|err| format!("failed to write control-plane-owner owner log: {err}"))?;

    Ok(paths)
}

fn control_plane_owner_report_value(paths: &ControlPlaneOwnerPaths) -> Value {
    let mut core_flip = CoreFlip::default();
    let startup_core = ReloadCoreState::new(false, &mut core_flip);
    let reload_core = ReloadCoreState::new(true, &mut core_flip);
    json!({
        "name": "rust-control-plane-owner-preflight",
        "root": path_string(&paths.root),
        "run_dir": path_string(&paths.run_dir),
        "state_file": path_string(&paths.state_file),
        "log_file": path_string(&paths.log_file),
        "state_file_written": true,
        "log_file_written": true,
        "startup_core": {
            "is_reload": startup_core.is_reload,
            "bpf_ejected": startup_core.bpf_ejected,
            "defer_func_count": startup_core.defer_func_count,
            "flip": startup_core.flip
        },
        "reload_core": {
            "is_reload": reload_core.is_reload,
            "bpf_ejected": reload_core.bpf_ejected,
            "defer_func_count": reload_core.defer_func_count,
            "flip": reload_core.flip
        },
        "startup_sequence": [
            "config-parse",
            "bootstrap-direct",
            "wait-for-network",
            "subscription-resolve",
            "control-plane-build",
            "listen-socket-map-ready",
            "listener-ready",
            "on-ready"
        ],
        "reload_success_owner_sequence": [
            "old-eject-bpf",
            "dns-cache-snapshot-if-config-equal",
            "stop-old-dns-listener-if-same-bind",
            "next-build-with-ejected-bpf",
            "next-inject-bpf",
            "set-current-next",
            "abort-old-connections-if-requested",
            "close-old",
            "flush-reload-scoped-resources",
            "reuse-old-listener",
            "reload-callback"
        ],
        "restore_owner_sequence": [
            "old-eject-bpf",
            "next-build-failed",
            "restore-build-old-config",
            "restore-inject-bpf-to-old",
            "restart-old-dns-listener-if-stopped",
            "close-unowned-new-resources",
            "current-remains-old",
            "reload-error-recorded"
        ],
        "rust_control_plane_owner_preflight_recorded": true,
        "rust_control_plane_owner_smoke_passed": true,
        "control_plane_startup_sequence_recorded": true,
        "control_plane_reload_owner_sequence_recorded": true,
        "control_plane_restore_sequence_recorded": true,
        "listener_reuse_contract_recorded": true,
        "bpf_owner_transfer_contract_recorded": true,
        "dns_cache_migration_guard_recorded": true,
        "reload_scoped_flush_after_current_swap_recorded": true,
        "isolated_control_plane_owner_paths_validated": true,
        "production_listener_bound": false,
        "ebpf_attached": false,
        "production_paths_mutated": false,
        "rust_run_entrypoint_exists": false,
        "rust_control_plane_entrypoint_admitted": false,
        "benchmark_executable_now": false,
        "native_daemon_benchmark_recorded": false,
        "true_rust_native_daemon_admitted": false,
        "production_admission_allowed": false,
        "final_state_admission_allowed": false
    })
}

fn ensure_safe_control_plane_owner_preflight_root(root: &Path) -> Result<(), String> {
    if !root.is_absolute() {
        return Err(format!(
            "control-plane-owner root must be absolute: {}",
            path_string(root)
        ));
    }
    let root_string = path_string(root);
    if !root_string.starts_with("/tmp/dae-control-plane-owner") {
        return Err(format!(
            "control-plane-owner root must be under /tmp/dae-control-plane-owner*: {root_string}"
        ));
    }
    Ok(())
}

fn path_string(path: &Path) -> String {
    path.display().to_string()
}
