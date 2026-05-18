use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use dae_engine::{Engine, EngineOptions};
use serde_json::json;

use crate::progress::ReloadProgress;
use crate::runner::RunnerOutput;
use crate::validate_config_file;

const DEFAULT_ROOT: &str = "/tmp/dae-stage27-candidate";
const DEFAULT_TIMEOUT_MS: u64 = 1_000;

pub(crate) fn run_stage27_candidate(args: &[String]) -> RunnerOutput {
    let mut root = DEFAULT_ROOT.to_owned();
    let mut config = None::<String>;
    let mut pid_file = None::<String>;
    let mut progress_file = None::<String>;
    let mut log_file = None::<String>;
    let mut timeout_ms = DEFAULT_TIMEOUT_MS;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--root" => {
                let Some(value) = iter.next() else {
                    return RunnerOutput::usage("missing runtime stage27-run-candidate --root");
                };
                root = value.to_owned();
            }
            "--config" => {
                let Some(value) = iter.next() else {
                    return RunnerOutput::usage("missing runtime stage27-run-candidate --config");
                };
                config = Some(value.to_owned());
            }
            "--pid-file" => {
                let Some(value) = iter.next() else {
                    return RunnerOutput::usage("missing runtime stage27-run-candidate --pid-file");
                };
                pid_file = Some(value.to_owned());
            }
            "--progress-file" => {
                let Some(value) = iter.next() else {
                    return RunnerOutput::usage(
                        "missing runtime stage27-run-candidate --progress-file",
                    );
                };
                progress_file = Some(value.to_owned());
            }
            "--logfile" => {
                let Some(value) = iter.next() else {
                    return RunnerOutput::usage("missing runtime stage27-run-candidate --logfile");
                };
                log_file = Some(value.to_owned());
            }
            "--timeout-ms" => {
                let Some(value) = iter.next() else {
                    return RunnerOutput::usage(
                        "missing runtime stage27-run-candidate --timeout-ms",
                    );
                };
                timeout_ms = match value.parse() {
                    Ok(value) => value,
                    Err(_) => {
                        return RunnerOutput::usage(format!(
                            "invalid runtime stage27-run-candidate --timeout-ms: {value}"
                        ));
                    }
                };
            }
            _ if arg.starts_with("--root=") => {
                root = value_after_equals(arg).to_owned();
            }
            _ if arg.starts_with("--config=") => {
                config = Some(value_after_equals(arg).to_owned());
            }
            _ if arg.starts_with("--pid-file=") => {
                pid_file = Some(value_after_equals(arg).to_owned());
            }
            _ if arg.starts_with("--progress-file=") => {
                progress_file = Some(value_after_equals(arg).to_owned());
            }
            _ if arg.starts_with("--logfile=") => {
                log_file = Some(value_after_equals(arg).to_owned());
            }
            _ if arg.starts_with("--timeout-ms=") => {
                let value = value_after_equals(arg);
                timeout_ms = match value.parse() {
                    Ok(value) => value,
                    Err(_) => {
                        return RunnerOutput::usage(format!(
                            "invalid runtime stage27-run-candidate --timeout-ms: {value}"
                        ));
                    }
                };
            }
            _ => {
                return RunnerOutput::usage(format!(
                    "unsupported runtime stage27-run-candidate argument: {arg}"
                ));
            }
        }
    }

    let root_path = match temp_root(&root) {
        Ok(path) => path,
        Err(output) => return output,
    };
    let layout = CandidateRunLayout::new(root_path);
    let config_path = config
        .map(PathBuf::from)
        .unwrap_or_else(|| layout.config.clone());
    let pid_file = pid_file
        .map(PathBuf::from)
        .unwrap_or_else(|| layout.pid_file.clone());
    let progress_file = progress_file
        .map(PathBuf::from)
        .unwrap_or_else(|| layout.progress_file.clone());
    let log_file = log_file
        .map(PathBuf::from)
        .unwrap_or_else(|| layout.log_file.clone());

    for path in [&config_path, &pid_file, &progress_file, &log_file] {
        if let Err(output) = require_under_root(&layout.root, path) {
            return output;
        }
    }
    if timeout_ms == 0 || timeout_ms > 30_000 {
        return RunnerOutput::usage("runtime stage27-run-candidate --timeout-ms must be 1..30000");
    }
    if let Err(err) = validate_config_file(&config_path) {
        return RunnerOutput::stdout_error(format!("candidate config validation failed: {err}"));
    }
    if let Err(err) = prepare_files(&layout, &pid_file, &progress_file, &log_file) {
        return RunnerOutput::stdout_error(format!("prepare stage27 candidate files: {err}"));
    }

    let timeout = Duration::from_millis(timeout_ms);
    let engine = Arc::new(Engine::new(EngineOptions::default()));
    let runner = Arc::clone(&engine);
    let handle = std::thread::spawn(move || runner.run(true));

    if let Err(err) = write_progress(
        &progress_file,
        ReloadProgress::Processing,
        "stage27 dry runtime candidate processing",
    ) {
        return RunnerOutput::stdout_error(format!("write progress processing: {err}"));
    }
    let reload_result = engine.reload_with_timeout(timeout);
    let stop_result = engine.stop(timeout);
    let join_result = handle.join();
    let run_ok = matches!(join_result, Ok(Ok(())));
    let reload_ok = reload_result.is_ok();
    let stop_ok = stop_result.is_ok();
    let final_progress = if reload_ok && stop_ok && run_ok {
        ReloadProgress::Done
    } else {
        ReloadProgress::Error
    };
    if let Err(err) = write_progress(
        &progress_file,
        final_progress,
        if final_progress == ReloadProgress::Done {
            "stage27 dry runtime candidate done"
        } else {
            "stage27 dry runtime candidate error"
        },
    ) {
        return RunnerOutput::stdout_error(format!("write progress final: {err}"));
    }
    let mut log_lines = vec![
        "stage27 dry runtime candidate",
        "default_switch_allowed=false",
        "candidate_live_run_class=dry-runtime-only",
    ];
    if reload_ok {
        log_lines.push("reload=ok");
    } else {
        log_lines.push("reload=error");
    }
    if stop_ok {
        log_lines.push("stop=ok");
    } else {
        log_lines.push("stop=error");
    }
    if run_ok {
        log_lines.push("run=ok");
    } else {
        log_lines.push("run=error");
    }
    if let Err(err) = fs::write(&log_file, format!("{}\n", log_lines.join("\n"))) {
        return RunnerOutput::stdout_error(format!("write stage27 candidate log: {err}"));
    }

    let progress_content = fs::read_to_string(&progress_file).unwrap_or_default();
    RunnerOutput::ok(format!(
        "{}\n",
        json!({
            "name": "stage27-rust-dry-runtime-candidate-smoke",
            "stage": "stage27",
            "evidence_class": "opt-in-dry-runtime-candidate-smoke",
            "root": path_string(&layout.root),
            "default_switch_allowed": false,
            "default_path_mutated": false,
            "product_chain_switch_allowed": false,
            "candidate_live_run_class": "dry-runtime-only",
            "candidate_smoke_passed": reload_ok && stop_ok && run_ok,
            "true_rust_default_daemon_admitted": false,
            "go_default_path_preserved": true,
            "go_fallback_required": true,
            "live_tproxy_started": false,
            "live_ebpf_started": false,
            "live_outbound_started": false,
            "live_dns_listener_started": false,
            "paths": {
                "root": path_string(&layout.root),
                "config": path_string(&config_path),
                "pid_file": path_string(&pid_file),
                "progress_file": path_string(&progress_file),
                "log_file": path_string(&log_file),
                "run_dir": path_string(&layout.run_dir),
                "traffic_dir": path_string(&layout.traffic_dir),
                "socket_dir": path_string(&layout.socket_dir),
                "asset_dir": path_string(&layout.asset_dir),
                "cache_dir": path_string(&layout.cache_dir),
            },
            "runtime": {
                "config_valid": true,
                "pid_file_written": true,
                "pid_value": std::process::id(),
                "progress_first_byte": (final_progress.byte() as char).to_string(),
                "progress_content": progress_content,
                "dry_runtime_started": true,
                "reload_requested": true,
                "reload_ok": reload_ok,
                "stop_requested": true,
                "stop_ok": stop_ok,
                "run_thread_ok": run_ok,
                "timeout_ms": timeout_ms,
            },
            "production_safety": {
                "root_under_tmp": true,
                "config_under_root": true,
                "pid_progress_log_under_root": true,
                "no_systemd_mutation": true,
                "no_install_mutation": true,
                "no_release_label_mutation": true,
                "no_daewing_daed_default_mutation": true,
                "does_not_touch_var_run_dae_progress": true,
                "does_not_touch_var_run_dae_pid": true,
            },
            "remaining_blockers": [
                "dry-runtime-only smoke does not own tproxy eBPF DNS outbound or real traffic",
                "matched Go-vs-Rust default daemon benchmark is still missing",
                "outbound true dataplane admission is still incomplete",
                "clean dae-wing and daed product-chain recertification is still missing",
                "true Rust default daemon admission remains false"
            ],
        })
    ))
}

struct CandidateRunLayout {
    root: PathBuf,
    config: PathBuf,
    run_dir: PathBuf,
    pid_file: PathBuf,
    progress_file: PathBuf,
    log_file: PathBuf,
    traffic_dir: PathBuf,
    socket_dir: PathBuf,
    asset_dir: PathBuf,
    cache_dir: PathBuf,
}

impl CandidateRunLayout {
    fn new(root: PathBuf) -> Self {
        let run_dir = root.join("run");
        Self {
            config: root.join("config.dae"),
            pid_file: run_dir.join("dae-stage27.pid"),
            progress_file: run_dir.join("dae-stage27.progress"),
            log_file: root.join("logs").join("dae-stage27.log"),
            traffic_dir: root.join("traffic"),
            socket_dir: root.join("sockets"),
            asset_dir: root.join("assets"),
            cache_dir: root.join("cache"),
            run_dir,
            root,
        }
    }
}

fn prepare_files(
    layout: &CandidateRunLayout,
    pid_file: &Path,
    progress_file: &Path,
    log_file: &Path,
) -> std::io::Result<()> {
    fs::create_dir_all(&layout.run_dir)?;
    fs::create_dir_all(log_file.parent().unwrap_or(&layout.root))?;
    fs::create_dir_all(&layout.traffic_dir)?;
    fs::create_dir_all(&layout.socket_dir)?;
    fs::create_dir_all(&layout.asset_dir)?;
    fs::create_dir_all(&layout.cache_dir)?;
    fs::write(pid_file, format!("{}\n", std::process::id()))?;
    write_progress(
        progress_file,
        ReloadProgress::Send,
        "stage27 dry runtime candidate queued",
    )
}

fn write_progress(path: &Path, progress: ReloadProgress, message: &str) -> std::io::Result<()> {
    fs::write(path, format!("{}\n{message}", progress.byte() as char))
}

fn temp_root(root: &str) -> Result<PathBuf, RunnerOutput> {
    let root = PathBuf::from(root);
    if !root.is_absolute() {
        return Err(RunnerOutput::stdout_error(
            "stage27 candidate root must be an absolute /tmp path",
        ));
    }
    let root_string = path_string(&root);
    if root_string == "/tmp" || !root_string.starts_with("/tmp/") {
        return Err(RunnerOutput::stdout_error(
            "stage27 candidate root must stay under /tmp to avoid production mutation",
        ));
    }
    Ok(root)
}

fn require_under_root(root: &Path, path: &Path) -> Result<(), RunnerOutput> {
    if !path.is_absolute() {
        return Err(RunnerOutput::stdout_error(format!(
            "stage27 candidate path must be absolute: {}",
            path_string(path)
        )));
    }
    let root_string = path_string(root);
    let path_string = path_string(path);
    let root_prefix = format!("{root_string}/");
    if path_string == root_string || path_string.starts_with(&root_prefix) {
        Ok(())
    } else {
        Err(RunnerOutput::stdout_error(format!(
            "stage27 candidate path must stay under root {root_string}: {path_string}"
        )))
    }
}

fn value_after_equals(arg: &str) -> &str {
    arg.split_once('=').map(|(_, value)| value).unwrap_or("")
}

fn path_string(path: &Path) -> String {
    path.as_os_str().to_string_lossy().into_owned()
}
