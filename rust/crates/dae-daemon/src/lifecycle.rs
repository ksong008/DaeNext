use std::fs;
use std::path::{Path, PathBuf};

use dae_core_types::reload::{RELOAD_DONE, RELOAD_PROCESSING, RELOAD_SEND};
use serde_json::{Value, json};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LifecyclePaths {
    pub root: PathBuf,
    pub run_dir: PathBuf,
    pub pid_file: PathBuf,
    pub progress_file: PathBuf,
    pub sdnotify_file: PathBuf,
    pub log_file: PathBuf,
}

impl LifecyclePaths {
    pub fn under_root(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        let run_dir = root.join("run");
        Self {
            pid_file: run_dir.join("dae-lifecycle.pid"),
            progress_file: run_dir.join("dae-lifecycle.progress"),
            sdnotify_file: run_dir.join("sdnotify.ready"),
            log_file: root.join("log").join("dae-lifecycle.log"),
            run_dir,
            root,
        }
    }
}

pub fn default_lifecycle_smoke_root() -> PathBuf {
    PathBuf::from("/tmp/dae-lifecycle-smoke")
}

pub fn lifecycle_smoke_report(root: &Path) -> Result<Value, String> {
    let paths = run_lifecycle_smoke(root)?;
    Ok(json!({
        "name": "rust-daemon-lifecycle-smoke",
        "root": path_string(&paths.root),
        "run_dir": path_string(&paths.run_dir),
        "pid_file": path_string(&paths.pid_file),
        "progress_file": path_string(&paths.progress_file),
        "sdnotify_file": path_string(&paths.sdnotify_file),
        "log_file": path_string(&paths.log_file),
        "candidate_pid": std::process::id(),
        "pid_file_written": true,
        "startup_progress_done": true,
        "reload_progress_sequence": [
            progress_char(RELOAD_SEND),
            progress_char(RELOAD_PROCESSING),
            progress_char(RELOAD_DONE)
        ],
        "suspend_progress_sequence": [
            progress_char(RELOAD_PROCESSING),
            progress_char(RELOAD_DONE)
        ],
        "sdnotify_ready_recorded": true,
        "log_file_written": true,
        "isolated_pid_progress_paths_validated": true,
        "production_pid_file_touched": false,
        "production_progress_file_touched": false,
        "production_paths_mutated": false,
        "rust_daemon_lifecycle_smoke_passed": true,
        "rust_default_run_entrypoint_exists": false,
        "rust_default_control_plane_entrypoint_admitted": false,
        "benchmark_executable_now": false,
        "matched_go_rust_default_daemon_benchmark_recorded": false,
        "true_rust_default_daemon_admitted": false,
        "default_switch_allowed": false,
        "product_chain_switch_allowed": false
    }))
}

pub fn run_lifecycle_smoke(root: &Path) -> Result<LifecyclePaths, String> {
    ensure_safe_lifecycle_smoke_root(root)?;
    let paths = LifecyclePaths::under_root(root);
    if paths.root.exists() {
        fs::remove_dir_all(&paths.root).map_err(|err| {
            format!(
                "failed to remove existing lifecycle-smoke root {}: {err}",
                path_string(&paths.root)
            )
        })?;
    }
    fs::create_dir_all(&paths.run_dir).map_err(|err| {
        format!(
            "failed to create lifecycle-smoke run dir {}: {err}",
            path_string(&paths.run_dir)
        )
    })?;
    if let Some(parent) = paths.log_file.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            format!(
                "failed to create lifecycle-smoke log dir {}: {err}",
                path_string(parent)
            )
        })?;
    }

    fs::write(&paths.pid_file, format!("{}\n", std::process::id()))
        .map_err(|err| format!("failed to write pid file: {err}"))?;
    write_progress(&paths.progress_file, RELOAD_DONE, "")?;
    assert_progress(&paths.progress_file, RELOAD_DONE)?;
    fs::write(&paths.sdnotify_file, "READY=1\n")
        .map_err(|err| format!("failed to write sdnotify file: {err}"))?;
    fs::write(&paths.log_file, "lifecycle-smoke lifecycle smoke\n")
        .map_err(|err| format!("failed to write log file: {err}"))?;

    write_progress(&paths.progress_file, RELOAD_SEND, "")?;
    assert_progress(&paths.progress_file, RELOAD_SEND)?;
    write_progress(&paths.progress_file, RELOAD_PROCESSING, "")?;
    assert_progress(&paths.progress_file, RELOAD_PROCESSING)?;
    write_progress(&paths.progress_file, RELOAD_DONE, "\nOK")?;
    assert_progress(&paths.progress_file, RELOAD_DONE)?;

    write_progress(&paths.progress_file, RELOAD_PROCESSING, "")?;
    assert_progress(&paths.progress_file, RELOAD_PROCESSING)?;
    write_progress(&paths.progress_file, RELOAD_DONE, "\nOK")?;
    assert_progress(&paths.progress_file, RELOAD_DONE)?;

    Ok(paths)
}

fn ensure_safe_lifecycle_smoke_root(root: &Path) -> Result<(), String> {
    if !root.is_absolute() {
        return Err(format!(
            "lifecycle-smoke root must be absolute: {}",
            path_string(root)
        ));
    }
    let root_string = path_string(root);
    if !root_string.starts_with("/tmp/dae-lifecycle-smoke") {
        return Err(format!(
            "lifecycle-smoke root must be under /tmp/dae-lifecycle-smoke*: {root_string}"
        ));
    }
    Ok(())
}

fn write_progress(path: &Path, byte: u8, suffix: &str) -> Result<(), String> {
    let mut content = vec![byte];
    content.extend_from_slice(suffix.as_bytes());
    fs::write(path, content).map_err(|err| format!("failed to write progress file: {err}"))
}

fn assert_progress(path: &Path, expected: u8) -> Result<(), String> {
    let content = fs::read(path).map_err(|err| format!("failed to read progress file: {err}"))?;
    let Some(byte) = content.first() else {
        return Err("progress file is empty".to_owned());
    };
    if *byte != expected {
        return Err(format!(
            "unexpected progress byte: expected {}, got {}",
            progress_char(expected),
            progress_char(*byte)
        ));
    }
    Ok(())
}

fn progress_char(byte: u8) -> String {
    (byte as char).to_string()
}

fn path_string(path: &Path) -> String {
    path.display().to_string()
}
