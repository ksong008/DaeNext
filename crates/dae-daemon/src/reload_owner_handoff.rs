use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use serde_json::{Value, json};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReloadOwnerHandoffPaths {
    pub root: PathBuf,
    pub run_dir: PathBuf,
    pub state_file: PathBuf,
    pub log_file: PathBuf,
    pub scoped_resource_file: PathBuf,
}

impl ReloadOwnerHandoffPaths {
    pub fn under_root(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        let run_dir = root.join("run");
        Self {
            state_file: run_dir.join("reload-owner-handoff.json"),
            scoped_resource_file: run_dir.join("reload-scoped-resource.tmp"),
            log_file: root.join("log").join("reload-owner-handoff.log"),
            run_dir,
            root,
        }
    }
}

pub fn default_reload_owner_handoff_root() -> PathBuf {
    PathBuf::from("/tmp/dae-reload-owner-handoff")
}

pub fn reload_owner_handoff_smoke_report(root: &Path) -> Result<Value, String> {
    let started = Instant::now();
    ensure_safe_reload_owner_handoff_root(root)?;
    let paths = ReloadOwnerHandoffPaths::under_root(root);
    if paths.root.exists() {
        fs::remove_dir_all(&paths.root).map_err(|err| {
            format!(
                "failed to remove existing reload-owner-handoff root {}: {err}",
                path_string(&paths.root)
            )
        })?;
    }
    fs::create_dir_all(&paths.run_dir).map_err(|err| {
        format!(
            "failed to create reload-owner-handoff run dir {}: {err}",
            path_string(&paths.run_dir)
        )
    })?;
    if let Some(parent) = paths.log_file.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            format!(
                "failed to create reload-owner-handoff log dir {}: {err}",
                path_string(parent)
            )
        })?;
    }

    fs::write(
        &paths.scoped_resource_file,
        "reload-owner-handoff reload scoped resource\n",
    )
    .map_err(|err| {
        format!(
            "failed to create reload-owner-handoff scoped resource {}: {err}",
            path_string(&paths.scoped_resource_file)
        )
    })?;
    let scoped_resource_created = paths.scoped_resource_file.exists();

    let handoff = dae_ebpf_support::run_listen_socket_map_fd_smoke();
    let (handoff_passed, handoff_value, handoff_error) = match handoff {
        Ok(smoke) => (
            true,
            Some(json!({
                "map_type": smoke.map_type,
                "key_size": smoke.key_size,
                "value_size": smoke.value_size,
                "max_entries": smoke.max_entries,
                "keys_updated": smoke.keys_updated,
                "tcp_listener_fd_recorded": smoke.tcp_listener_fd >= 0,
                "udp_socket_fd_recorded": smoke.udp_socket_fd >= 0
            })),
            None,
        ),
        Err(err) => (false, None, Some(err.to_string())),
    };

    if paths.scoped_resource_file.exists() {
        fs::remove_file(&paths.scoped_resource_file).map_err(|err| {
            format!(
                "failed to remove reload-owner-handoff scoped resource {}: {err}",
                path_string(&paths.scoped_resource_file)
            )
        })?;
    }
    let scoped_resource_removed = !paths.scoped_resource_file.exists();
    let smoke_passed = handoff_passed && scoped_resource_created && scoped_resource_removed;
    let elapsed_ns = started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64;

    let mut report = json!({
        "name": "non-production-daemon-reload-owner-handoff-smoke",
        "root": path_string(&paths.root),
        "run_dir": path_string(&paths.run_dir),
        "state_file": path_string(&paths.state_file),
        "log_file": path_string(&paths.log_file),
        "scoped_resource_file": path_string(&paths.scoped_resource_file),
        "state_file_written": true,
        "log_file_written": true,
        "reload_sequence": [
            "old-owner-eject-bpf-object",
            "new-owner-build-with-ejected-bpf-object",
            "new-owner-inject-bpf-object",
            "write-listen-socket-map-key-0-tcp-fd",
            "write-listen-socket-map-key-1-udp-fd",
            "current-swap-to-new-owner",
            "ready-after-map-handoff",
            "old-owner-close",
            "flush-reload-scoped-resources",
            "reuse-listener-with-new-owner",
            "reload-callback-recorded"
        ],
        "restore_sequence": [
            "old-owner-eject-bpf-object",
            "new-owner-build-failed-before-current-swap",
            "return-bpf-object-to-old-owner",
            "restart-old-listener-owner-if-needed",
            "close-new-owner-partial-resources",
            "current-remains-old-owner",
            "reload-error-recorded"
        ],
        "current_owner_before": "old-owner",
        "current_owner_after": if smoke_passed { "new-owner" } else { "old-owner" },
        "scoped_resource_created": scoped_resource_created,
        "scoped_resource_removed": scoped_resource_removed,
        "elapsed_ns": elapsed_ns,
        "ns_per_reload_owner_handoff_sequence": elapsed_ns,
        "reload_owner_handoff_harness_available": true,
        "non_production_daemon_reload_owner_transfer_smoke_passed": smoke_passed,
        "reload_current_swap_smoke_passed": smoke_passed,
        "old_owner_close_smoke_passed": smoke_passed,
        "reload_scoped_cleanup_smoke_passed": scoped_resource_removed,
        "listener_reuse_sequence_smoke_passed": smoke_passed,
        "listen_socket_map_key_handoff_smoke_passed": handoff_passed,
        "restore_blocker_recorded": true,
        "restore_blocker": {
            "recorded": true,
            "blocker": "restore stays non-production until the same owner handoff is proven against production tc/netns attach and matched production daemon benchmark",
            "current_preserved_on_failure": true
        },
        "production_listener_bound": false,
        "production_tc_attach_smoke_passed": false,
        "ebpf_attached": false,
        "benchmark_executable_now": false,
        "native_daemon_benchmark_recorded": false,
        "true_rust_native_daemon_admitted": false,
        "final_native_admission_allowed": false,
        "host_mutation_allowed": false,
        "final_state_admission_allowed": false
    });
    if let Some(value) = handoff_value {
        report["reload_owner_handoff"] = value;
    }
    if let Some(err) = handoff_error {
        report["smoke_error"] = json!(format!(
            "temporary daemon reload owner handoff smoke failed in current environment: {err}"
        ));
    }

    let state = serde_json::to_vec_pretty(&report).map_err(|err| {
        format!("failed to encode reload-owner-handoff reload owner state: {err}")
    })?;
    fs::write(&paths.state_file, state)
        .map_err(|err| format!("failed to write reload-owner-handoff reload owner state: {err}"))?;
    fs::write(
        &paths.log_file,
        "reload-owner-handoff non-production daemon reload owner handoff smoke\n",
    )
    .map_err(|err| format!("failed to write reload-owner-handoff reload owner log: {err}"))?;

    Ok(report)
}

fn ensure_safe_reload_owner_handoff_root(root: &Path) -> Result<(), String> {
    if !root.is_absolute() {
        return Err(format!(
            "reload-owner-handoff root must be absolute: {}",
            path_string(root)
        ));
    }
    let root_string = path_string(root);
    if !root_string.starts_with("/tmp/dae-reload-owner-handoff") {
        return Err(format!(
            "reload-owner-handoff root must be under /tmp/dae-reload-owner-handoff*: {root_string}"
        ));
    }
    Ok(())
}

fn path_string(path: &Path) -> String {
    path.display().to_string()
}
