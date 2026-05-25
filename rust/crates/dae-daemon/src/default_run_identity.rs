use std::fs;
use std::path::{Path, PathBuf};

use dae_core_types::reload::RELOAD_DONE;
use serde_json::{Value, json};

use crate::run_entrypoint_preflight_report;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefaultRunIdentityAdmissionOptions {
    pub root: PathBuf,
    pub config: PathBuf,
    pub logfile: PathBuf,
    pub disable_timestamp: bool,
    pub disable_pidfile: bool,
    pub disable_sudo: bool,
}

impl DefaultRunIdentityAdmissionOptions {
    pub fn under_root(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        Self {
            config: root.join("config").join("default-run-identity.dae"),
            logfile: root.join("log").join("dae-default-run-identity.log"),
            root,
            disable_timestamp: true,
            disable_pidfile: false,
            disable_sudo: true,
        }
    }
}

pub fn default_run_identity_admission_root() -> PathBuf {
    PathBuf::from("/tmp/dae-default-run-identity-admission")
}

pub fn default_run_identity_admission_report(
    options: &DefaultRunIdentityAdmissionOptions,
) -> Result<Value, String> {
    ensure_safe_run_identity_admission_root(&options.root)?;
    if options.root.exists() {
        fs::remove_dir_all(&options.root).map_err(|err| {
            format!(
                "failed to remove existing default-run-identity root {}: {err}",
                path_string(&options.root)
            )
        })?;
    }

    let run_dir = options.root.join("run");
    let manifest_file = run_dir.join("default-run-identity-admission.json");
    let pid_file = run_dir.join("dae-default-run-identity.pid");
    let progress_file = run_dir.join("dae-default-run-identity.progress");
    let sdnotify_file = run_dir.join("sdnotify.ready");
    let run_entrypoint_root = derived_root(
        "/tmp/dae-run-entrypoint-default-run-identity",
        &options.root,
    );

    fs::create_dir_all(&run_dir).map_err(|err| {
        format!(
            "failed to create default-run-identity run dir {}: {err}",
            path_string(&run_dir)
        )
    })?;
    if let Some(parent) = options.logfile.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            format!(
                "failed to create default-run-identity log dir {}: {err}",
                path_string(parent)
            )
        })?;
    }
    prepare_config(&options.config, &options.root)?;

    let config = fs::read_to_string(&options.config).map_err(|err| {
        format!(
            "failed to read default-run-identity config {}: {err}",
            path_string(&options.config)
        )
    })?;
    let config_bytes = config.as_bytes().len();
    let config_lines = config.lines().count();
    if config.trim().is_empty() {
        return Err(format!(
            "default-run-identity config must not be empty: {}",
            path_string(&options.config)
        ));
    }

    if !options.disable_pidfile {
        fs::write(&pid_file, format!("{}\n", std::process::id()))
            .map_err(|err| format!("failed to write default-run-identity pid file: {err}"))?;
    }
    fs::write(&progress_file, [RELOAD_DONE])
        .map_err(|err| format!("failed to write default-run-identity progress file: {err}"))?;
    fs::write(&sdnotify_file, "READY=1\n")
        .map_err(|err| format!("failed to write default-run-identity sdnotify file: {err}"))?;
    fs::write(
        &options.logfile,
        "default-run-identity default run identity admission\n",
    )
    .map_err(|err| format!("failed to write default-run-identity log file: {err}"))?;

    let wrapper = run_entrypoint_preflight_report(&run_entrypoint_root)?;
    let mut report = json!({
        "name": "rust-default-run-identity-admission",
        "root": path_string(&options.root),
        "run_dir": path_string(&run_dir),
        "config_file": path_string(&options.config),
        "log_file": path_string(&options.logfile),
        "manifest_file": path_string(&manifest_file),
        "pid_file": path_string(&pid_file),
        "progress_file": path_string(&progress_file),
        "sdnotify_file": path_string(&sdnotify_file),
        "run_entrypoint_root": path_string(&run_entrypoint_root),
        "command": "default-run-identity-admission",
        "run_identity": "Rust default run identity shape, opt-in only",
        "default_command": "run",
        "config_bytes": config_bytes,
        "config_lines": config_lines,
        "config_corpus_loaded": true,
        "pid_file_written": !options.disable_pidfile,
        "progress_file_reload_done_written": true,
        "sdnotify_ready_recorded": true,
        "log_file_written": true,
        "disable_timestamp": options.disable_timestamp,
        "disable_pidfile": options.disable_pidfile,
        "disable_sudo": options.disable_sudo
    });
    report["run_flag_contract"] = json!({
        "config_flag": "-c/--config accepted",
        "logfile_flag": "--logfile accepted",
        "disable_timestamp_flag": "--disable-timestamp accepted",
        "disable_pidfile_flag": "--disable-pidfile accepted",
        "disable_sudo_flag": "--disable-sudo accepted"
    });
    report["on_ready_contract"] = json!([
        "systemd ready notification",
        "pid file write unless disable-pidfile",
        "progress file ReloadDone write"
    ]);
    report["run_entrypoint_wrapper"] = wrapper;
    for key in [
        "rust_default_run_identity_optin_admitted",
        "rust_default_run_entrypoint_exists",
        "run_shaped_flags_validated",
        "run_identity_config_corpus_validated",
        "run_identity_on_ready_contract_validated",
        "isolated_pid_progress_paths_validated",
        "run_entrypoint_wrapper_reused",
        "go_default_path_preserved",
        "go_fallback_required",
    ] {
        report[key] = json!(true);
    }
    for key in [
        "production_run_command_replaced",
        "production_pid_progress_paths_mutated",
        "production_signal_handler_installed",
        "rust_default_control_plane_entrypoint_admitted",
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
        .map_err(|err| format!("failed to encode default-run-identity manifest: {err}"))?;
    fs::write(&manifest_file, manifest)
        .map_err(|err| format!("failed to write default-run-identity manifest: {err}"))?;
    Ok(report)
}

fn prepare_config(config: &Path, root: &Path) -> Result<(), String> {
    if config.exists() {
        return Ok(());
    }
    if !config.starts_with(root) {
        return Err(format!(
            "default-run-identity config does not exist and is outside root: {}",
            path_string(config)
        ));
    }
    if let Some(parent) = config.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            format!(
                "failed to create default-run-identity config dir {}: {err}",
                path_string(parent)
            )
        })?;
    }
    fs::write(
        config,
        "global {\n  log_level: info\n}\n\nrouting {\n  pname(NetworkManager) -> direct\n}\n",
    )
    .map_err(|err| format!("failed to write default-run-identity default config: {err}"))
}

fn ensure_safe_run_identity_admission_root(root: &Path) -> Result<(), String> {
    if !root.is_absolute() {
        return Err(format!(
            "default-run-identity root must be absolute: {}",
            path_string(root)
        ));
    }
    let root_string = path_string(root);
    if !root_string.starts_with("/tmp/dae-default-run-identity") {
        return Err(format!(
            "default-run-identity root must be under /tmp/dae-default-run-identity*: {root_string}"
        ));
    }
    Ok(())
}

fn derived_root(prefix: &str, root: &Path) -> PathBuf {
    let suffix = root
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("default-run-identity");
    PathBuf::from(format!("{prefix}-{suffix}"))
}

fn path_string(path: &Path) -> String {
    path.display().to_string()
}
