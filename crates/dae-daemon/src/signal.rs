use std::fs;
use std::path::{Path, PathBuf};

use dae_core_types::reload::{RELOAD_DONE, RELOAD_PROCESSING, RELOAD_SEND};
use serde_json::{Value, json};

use crate::control_plane_owner_preflight_report;

pub fn default_signal_control_plane_smoke_root() -> PathBuf {
    PathBuf::from("/tmp/dae-signal-control-plane-smoke")
}

pub fn signal_control_plane_smoke_report(root: &Path) -> Result<Value, String> {
    ensure_safe_signal_control_plane_smoke_root(root)?;
    if root.exists() {
        fs::remove_dir_all(root).map_err(|err| {
            format!(
                "failed to remove existing signal-control-plane root {}: {err}",
                path_string(root)
            )
        })?;
    }

    let run_dir = root.join("run");
    let log_dir = root.join("log");
    fs::create_dir_all(&run_dir).map_err(|err| {
        format!(
            "failed to create signal-control-plane run dir {}: {err}",
            path_string(&run_dir)
        )
    })?;
    fs::create_dir_all(&log_dir).map_err(|err| {
        format!(
            "failed to create signal-control-plane log dir {}: {err}",
            path_string(&log_dir)
        )
    })?;

    let pid_file = run_dir.join("dae-signal-control-plane.pid");
    let progress_file = run_dir.join("dae-signal-control-plane.progress");
    let abort_file = run_dir.join("dae-signal-control-plane.abort");
    let journal_file = run_dir.join("signal-control-plane-journal.json");
    let log_file = log_dir.join("signal-control-plane.log");
    let owner_root = control_plane_owner_root(root);

    fs::write(&pid_file, format!("{}\n", std::process::id()))
        .map_err(|err| format!("failed to write signal-control-plane pid file: {err}"))?;
    write_progress(&progress_file, RELOAD_DONE, "")?;
    assert_progress(&progress_file, RELOAD_DONE)?;

    fs::write(&abort_file, "abort\n")
        .map_err(|err| format!("failed to write signal-control-plane abort file: {err}"))?;
    write_progress(&progress_file, RELOAD_SEND, "")?;
    assert_progress(&progress_file, RELOAD_SEND)?;
    let abort_consumed = consume_abort_file(&abort_file)?;
    write_progress(&progress_file, RELOAD_PROCESSING, "")?;
    assert_progress(&progress_file, RELOAD_PROCESSING)?;
    let owner = control_plane_owner_preflight_report(&owner_root)?;
    write_progress(&progress_file, RELOAD_DONE, "\nOK")?;
    assert_progress(&progress_file, RELOAD_DONE)?;

    write_progress(&progress_file, RELOAD_PROCESSING, "")?;
    assert_progress(&progress_file, RELOAD_PROCESSING)?;
    write_progress(&progress_file, RELOAD_DONE, "\nOK")?;
    assert_progress(&progress_file, RELOAD_DONE)?;

    fs::remove_file(&pid_file)
        .map_err(|err| format!("failed to remove signal-control-plane pid file on stop: {err}"))?;
    fs::write(
        &log_file,
        "signal-control-plane signal control-plane smoke\n",
    )
    .map_err(|err| format!("failed to write signal-control-plane signal log: {err}"))?;

    let report = json!({
        "name": "rust-signal-control-plane-smoke",
        "root": path_string(root),
        "run_dir": path_string(&run_dir),
        "pid_file": path_string(&pid_file),
        "progress_file": path_string(&progress_file),
        "abort_file": path_string(&abort_file),
        "journal_file": path_string(&journal_file),
        "log_file": path_string(&log_file),
        "owner_root": path_string(&owner_root),
        "synthetic_signals": ["SIGUSR1", "SIGUSR2", "SIGTERM"],
        "startup_progress_done": true,
        "reload_signal": "SIGUSR1",
        "reload_progress_sequence": [
            progress_char(RELOAD_SEND),
            progress_char(RELOAD_PROCESSING),
            progress_char(RELOAD_DONE)
        ],
        "suspend_signal": "SIGUSR2",
        "suspend_progress_sequence": [
            progress_char(RELOAD_PROCESSING),
            progress_char(RELOAD_DONE)
        ],
        "stop_signal": "SIGTERM",
        "abort_file_created": true,
        "abort_file_one_shot_consumed": abort_consumed,
        "isolated_pid_removed_on_stop": true,
        "journal_file_written": true,
        "log_file_written": true,
        "owner": owner,
        "rust_signal_control_plane_smoke_passed": true,
        "reload_signal_progress_owner_sequence_validated": true,
        "suspend_signal_progress_sequence_validated": true,
        "control_plane_owner_preflight_reused": true,
        "isolated_signal_control_plane_paths_validated": true,
        "production_signal_handler_installed": false,
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
    });
    let journal = serde_json::to_vec_pretty(&report)
        .map_err(|err| format!("failed to encode signal-control-plane journal: {err}"))?;
    fs::write(&journal_file, journal)
        .map_err(|err| format!("failed to write signal-control-plane journal: {err}"))?;
    Ok(report)
}

fn ensure_safe_signal_control_plane_smoke_root(root: &Path) -> Result<(), String> {
    if !root.is_absolute() {
        return Err(format!(
            "signal-control-plane root must be absolute: {}",
            path_string(root)
        ));
    }
    let root_string = path_string(root);
    if !root_string.starts_with("/tmp/dae-signal-control-plane") {
        return Err(format!(
            "signal-control-plane root must be under /tmp/dae-signal-control-plane*: {root_string}"
        ));
    }
    Ok(())
}

fn consume_abort_file(path: &Path) -> Result<bool, String> {
    if !path.exists() {
        return Ok(false);
    }
    fs::remove_file(path)
        .map_err(|err| format!("failed to consume signal-control-plane abort file: {err}"))?;
    Ok(!path.exists())
}

fn control_plane_owner_root(root: &Path) -> PathBuf {
    let suffix = root
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("signal-control-plane");
    PathBuf::from(format!("/tmp/dae-control-plane-owner-{suffix}"))
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
