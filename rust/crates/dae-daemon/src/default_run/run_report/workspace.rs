use super::*;
pub(crate) struct DefaultRunWorkspace {
    pub(super) config: String,
    pub(super) run_dir: PathBuf,
    pub(super) manifest_file: PathBuf,
    pub(super) run_config_file: PathBuf,
    pub(super) pid_file: PathBuf,
    pub(super) progress_file: PathBuf,
    pub(super) sdnotify_file: PathBuf,
    pub(super) listener_root: PathBuf,
    pub(super) reload_root: PathBuf,
}

pub(crate) fn prepare_default_run_workspace(
    options: &RunOptions,
) -> Result<DefaultRunWorkspace, String> {
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
    let run_config_file = run_dir.join("input-config.dae");
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
    fs::write(&run_config_file, &config)
        .map_err(|err| format!("failed to write run input config copy: {err}"))?;
    fs::set_permissions(&run_config_file, fs::Permissions::from_mode(0o600))
        .map_err(|err| format!("failed to chmod run input config copy: {err}"))?;
    write_progress(&progress_file, RELOAD_DONE, "")?;
    fs::write(&sdnotify_file, "READY=1\n")
        .map_err(|err| format!("failed to write run sdnotify ready file: {err}"))?;

    Ok(DefaultRunWorkspace {
        config,
        run_dir,
        manifest_file,
        run_config_file,
        pid_file,
        progress_file,
        sdnotify_file,
        listener_root: derived_support_root("/tmp/dae-listener-ebpf-preflight-run", &options.root),
        reload_root: derived_support_root("/tmp/dae-reload-owner-handoff-run", &options.root),
    })
}
