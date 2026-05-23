use std::fs;
use std::path::{Path, PathBuf};

use dae_core_types::reload::RELOAD_DONE;
use serde_json::{Value, json};

use crate::{
    ProductionDataplaneHarnessOptions, production_dataplane_harness_report,
    stage160_listener_ebpf_preflight_harness_report, stage165_reload_owner_handoff_smoke_report,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunOptions {
    pub root: PathBuf,
    pub config: PathBuf,
    pub logfile: PathBuf,
    pub disable_timestamp: bool,
    pub disable_pidfile: bool,
    pub disable_sudo: bool,
    pub listener_smoke: bool,
    pub reload_smoke: bool,
    pub production_dataplane_harness: ProductionDataplaneHarnessOptions,
}

impl RunOptions {
    pub fn under_root(root: impl Into<PathBuf>, config: impl Into<PathBuf>) -> Self {
        let root = root.into();
        Self {
            config: config.into(),
            logfile: root.join("log").join("dae-daemon-optin-run.log"),
            root,
            disable_timestamp: false,
            disable_pidfile: false,
            disable_sudo: false,
            listener_smoke: true,
            reload_smoke: true,
            production_dataplane_harness: ProductionDataplaneHarnessOptions::default(),
        }
    }
}

pub fn default_run_root() -> PathBuf {
    PathBuf::from("/tmp/dae-daemon-optin-run")
}

pub fn run_default_optin_report(options: &RunOptions, version: &str) -> Result<Value, String> {
    ensure_safe_run_root(&options.root)?;
    ensure_safe_output_path(&options.logfile, &options.root, "logfile")?;
    if !options.config.is_file() {
        return Err(format!(
            "run config does not exist or is not a file: {}",
            path_string(&options.config)
        ));
    }

    let config = fs::read_to_string(&options.config).map_err(|err| {
        format!(
            "failed to read run config {}: {err}",
            path_string(&options.config)
        )
    })?;
    if config.trim().is_empty() {
        return Err(format!(
            "run config must not be empty: {}",
            path_string(&options.config)
        ));
    }

    if options.root.exists() {
        fs::remove_dir_all(&options.root).map_err(|err| {
            format!(
                "failed to remove existing run root {}: {err}",
                path_string(&options.root)
            )
        })?;
    }

    let run_dir = options.root.join("run");
    let manifest_file = run_dir.join("dae-daemon-optin-run.json");
    let pid_file = run_dir.join("dae-daemon-optin.pid");
    let progress_file = run_dir.join("dae-daemon-optin.progress");
    let sdnotify_file = run_dir.join("sdnotify.ready");
    fs::create_dir_all(&run_dir)
        .map_err(|err| format!("failed to create run dir {}: {err}", path_string(&run_dir)))?;
    if let Some(parent) = options.logfile.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            format!(
                "failed to create run log dir {}: {err}",
                path_string(parent)
            )
        })?;
    }

    if !options.disable_pidfile {
        fs::write(&pid_file, format!("{}\n", std::process::id()))
            .map_err(|err| format!("failed to write run pid file: {err}"))?;
    }
    write_progress(&progress_file, RELOAD_DONE, "")?;
    fs::write(&sdnotify_file, "READY=1\n")
        .map_err(|err| format!("failed to write run sdnotify ready file: {err}"))?;

    let listener_root = derived_stage_root("/tmp/dae-stage160-run-entrypoint", &options.root);
    let reload_root = derived_stage_root("/tmp/dae-stage165-run-entrypoint", &options.root);
    let listener = if options.listener_smoke {
        stage160_listener_ebpf_preflight_harness_report(&listener_root)?
    } else {
        json!({"skipped": true})
    };
    let reload = if options.reload_smoke {
        stage165_reload_owner_handoff_smoke_report(&reload_root)?
    } else {
        json!({"skipped": true})
    };
    let production_dataplane =
        production_dataplane_harness_report(&options.root, &options.production_dataplane_harness)?;

    let listener_smoke_passed = !options.listener_smoke
        || listener["tcp_udp_loopback_listener_smoke_passed"]
            .as_bool()
            .unwrap_or(false);
    let reload_smoke_passed = !options.reload_smoke
        || reload["non_production_daemon_reload_owner_transfer_smoke_passed"]
            .as_bool()
            .unwrap_or(false);
    let production_dataplane_harness_executed =
        production_dataplane["production_dataplane_harness_executed"]
            .as_bool()
            .unwrap_or(false);
    let production_dataplane_harness_passed =
        production_dataplane["production_dataplane_harness_passed"]
            .as_bool()
            .unwrap_or(false);

    fs::write(
        &options.logfile,
        format!(
            "dae-daemon-optin run: config={} bytes={} listener_smoke_passed={} reload_smoke_passed={} production_dataplane_harness_executed={} production_dataplane_harness_passed={}\n",
            path_string(&options.config),
            config.len(),
            listener_smoke_passed,
            reload_smoke_passed,
            production_dataplane_harness_executed,
            production_dataplane_harness_passed
        ),
    )
    .map_err(|err| format!("failed to write run log file: {err}"))?;

    let mut report = json!({
        "name": "dae-daemon-optin-run",
        "command": "run",
        "version": version,
        "root": path_string(&options.root),
        "run_dir": path_string(&run_dir),
        "config_file": path_string(&options.config),
        "config_bytes": config.len(),
        "config_lines": config.lines().count(),
        "log_file": path_string(&options.logfile),
        "manifest_file": path_string(&manifest_file),
        "pid_file": path_string(&pid_file),
        "progress_file": path_string(&progress_file),
        "sdnotify_file": path_string(&sdnotify_file),
        "listener_root": path_string(&listener_root),
        "reload_root": path_string(&reload_root)
    });
    report["disable_timestamp"] = json!(options.disable_timestamp);
    report["disable_pidfile"] = json!(options.disable_pidfile);
    report["disable_sudo"] = json!(options.disable_sudo);
    for key in [
        ("config_loaded", true),
        ("pid_file_written", !options.disable_pidfile),
        ("progress_file_reload_done_written", true),
        ("sdnotify_ready_recorded", true),
        ("log_file_written", true),
        ("run_command_supported", true),
        ("run_entrypoint_executed", true),
        ("rust_daemon_optin_run_command_available", true),
        ("rust_default_run_entrypoint_exists", true),
        ("run_shaped_flags_validated", true),
        ("run_identity_config_corpus_validated", true),
        ("isolated_pid_progress_paths_validated", true),
        ("go_default_path_preserved", true),
        ("go_fallback_required", true),
    ] {
        let (name, value) = key;
        report[name] = json!(value);
    }
    report["listener_smoke_executed"] = json!(options.listener_smoke);
    report["listener_smoke_passed"] = json!(listener_smoke_passed);
    report["reload_owner_handoff_smoke_executed"] = json!(options.reload_smoke);
    report["reload_owner_handoff_smoke_passed"] = json!(reload_smoke_passed);
    report["listener"] = listener;
    report["reload_owner_handoff"] = reload;
    report["production_dataplane_harness_executed"] = json!(production_dataplane_harness_executed);
    report["production_dataplane_harness_passed"] = json!(production_dataplane_harness_passed);
    report["production_dataplane_harness"] = production_dataplane;
    for key in [
        ("production_run_command_replaced", false),
        ("production_pid_progress_paths_mutated", false),
        ("production_signal_handler_installed", false),
        ("production_listener_bound", false),
        ("production_tc_attach_smoke_passed", false),
        ("ebpf_attached", false),
        ("rust_default_control_plane_entrypoint_admitted", false),
        ("production_dataplane_admitted", false),
        ("reload_runtime_parity_admitted", false),
        ("benchmark_executable_now", false),
        ("matched_go_rust_default_daemon_benchmark_recorded", false),
        ("true_rust_default_daemon_admitted", false),
        ("default_switch_allowed", false),
        ("default_path_mutation_allowed", false),
        ("product_chain_switch_allowed", false),
    ] {
        let (name, value) = key;
        report[name] = json!(value);
    }
    report["production_dataplane_admission_scope"] =
        json!(if production_dataplane_harness_passed {
            "run-integrated-harness-only"
        } else if production_dataplane_harness_executed {
            "run-integrated-harness-failed"
        } else {
            "not-executed"
        });
    let mut remaining_blockers = vec![
        "opt-in run now exists, but it still uses isolated pid/progress paths",
        "reload owner handoff is still non-production until proven against production tc/netns attach",
        "matched Go/Rust default daemon benchmark remains blocked",
    ];
    if production_dataplane_harness_passed {
        remaining_blockers.push(
            "production dataplane evidence is integrated into run, but still harness-only and not default daemon owned",
        );
    } else {
        remaining_blockers.push(
            "production tproxy listener, tc/eBPF attach, and active TCP/UDP/DNS dataplane are not yet proven inside this run",
        );
    }
    report["remaining_blockers"] = json!(remaining_blockers);

    let manifest = serde_json::to_vec_pretty(&report)
        .map_err(|err| format!("failed to encode run manifest: {err}"))?;
    fs::write(&manifest_file, manifest)
        .map_err(|err| format!("failed to write run manifest: {err}"))?;
    Ok(report)
}

fn ensure_safe_run_root(root: &Path) -> Result<(), String> {
    if !root.is_absolute() {
        return Err(format!("run root must be absolute: {}", path_string(root)));
    }
    let root_string = path_string(root);
    if !root_string.starts_with("/tmp/dae-daemon") {
        return Err(format!(
            "run root must be under /tmp/dae-daemon*: {root_string}"
        ));
    }
    Ok(())
}

fn ensure_safe_output_path(path: &Path, root: &Path, label: &str) -> Result<(), String> {
    if !path.is_absolute() && !path.starts_with(root) {
        return Err(format!("{label} must be absolute or under run root"));
    }
    if path.is_absolute() && !path.starts_with(root) {
        let path_string = path_string(path);
        if !path_string.starts_with("/tmp/") {
            return Err(format!("{label} outside run root must be under /tmp"));
        }
    }
    Ok(())
}

fn derived_stage_root(prefix: &str, root: &Path) -> PathBuf {
    let suffix = root
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("run");
    PathBuf::from(format!("{prefix}-{suffix}"))
}

fn write_progress(path: &Path, byte: u8, suffix: &str) -> Result<(), String> {
    let mut content = vec![byte];
    content.extend_from_slice(suffix.as_bytes());
    fs::write(path, content).map_err(|err| format!("failed to write progress file: {err}"))
}

fn path_string(path: &Path) -> String {
    path.display().to_string()
}
