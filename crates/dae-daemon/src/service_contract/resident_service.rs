use super::*;
pub fn run_resident_service(options: &ResidentRunOptions) -> Result<(), String> {
    if options.disable_sudo && unsafe { libc::geteuid() } != 0 {
        return Err("auto-sudo is disabled and current user is not root".to_owned());
    }
    let runtime_config = load_config_file(&options.config)
        .map_err(|err| format!("resident run config validation failed: {err}"))?;
    let geodata_asset_dirs = resident_config_geodata_asset_dirs(&options.config);
    block_service_signals()?;
    let mut state = ResidentServiceState {
        runtime: Some(start_resident_production_runtime_with_asset_dirs(
            &runtime_config,
            geodata_asset_dirs.clone(),
        )?),
        config: runtime_config,
    };

    let started = (|| {
        if !options.disable_pidfile {
            write_text_file(&options.pid_file, &format!("{}", std::process::id()), 0o644)?;
        }
        write_progress(&options.progress_file, RELOAD_DONE, "")?;
        if let Some(path) = &options.ready_record_file {
            write_text_file(path, "READY=1\n", 0o644)?;
        }
        log_event(options, "service ready")?;
        notify_systemd("READY=1")?;
        Ok::<(), String>(())
    })();
    if let Err(err) = started {
        state.runtime.take();
        if !options.disable_pidfile {
            let _ = fs::remove_file(&options.pid_file);
        }
        return Err(err);
    }

    loop {
        let signal = wait_service_signal()?;
        match signal {
            libc::SIGUSR1 => handle_reload(options, &mut state)?,
            libc::SIGUSR2 => handle_suspend_compatibility(options)?,
            libc::SIGHUP => continue,
            libc::SIGTERM | libc::SIGINT | libc::SIGQUIT => {
                let _ = notify_systemd("STOPPING=1");
                let _ = log_event(options, "service stopping");
                state.runtime.take();
                if !options.disable_pidfile {
                    let _ = fs::remove_file(&options.pid_file);
                }
                return Ok(());
            }
            _ => continue,
        }
    }
}

pub(super) struct ResidentServiceState {
    pub(super) runtime: Option<ResidentProductionRuntime>,
    pub(super) config: Config,
}

pub fn reload_resident_service(options: &ReloadOptions) -> Result<String, String> {
    let pid = match options.pid {
        Some(pid) => pid,
        None => read_pid_file(&options.pid_file)?,
    };
    if options.abort_connections {
        write_text_file(&options.abort_file, "", 0o644)?;
    }
    if let Ok((code, _)) = read_progress(&options.progress_file)
        && code != RELOAD_DONE
        && code != RELOAD_ERROR
    {
        return Ok(format!(
            "{} shows another reload operation is in progress.\n",
            options.progress_file.display()
        ));
    }
    write_progress(&options.progress_file, RELOAD_SEND, "")?;
    let status = unsafe { libc::kill(pid, libc::SIGUSR1) };
    if status != 0 {
        return Err(io::Error::last_os_error().to_string());
    }

    let started = Instant::now();
    loop {
        if options
            .timeout
            .is_some_and(|timeout| started.elapsed() >= timeout)
        {
            return Err("reload progress timed out".to_owned());
        }
        thread::sleep(Duration::from_millis(200));
        let Ok((code, content)) = read_progress(&options.progress_file) else {
            return Ok("OK\n".to_owned());
        };
        if code == RELOAD_DONE || code == RELOAD_ERROR {
            return Ok(format!("{content}\n"));
        }
    }
}

pub(super) fn handle_reload(
    options: &ResidentRunOptions,
    state: &mut ResidentServiceState,
) -> Result<(), String> {
    notify_systemd("RELOADING=1")?;
    write_progress(&options.progress_file, RELOAD_PROCESSING, "")?;
    let _abort_connections = fs::remove_file(&options.abort_file).is_ok();
    match load_config_file(&options.config) {
        Ok(runtime_config) => {
            if let Err(err) = validate_resident_runtime_reload_config(&runtime_config) {
                write_progress(&options.progress_file, RELOAD_ERROR, &format!("\n{err}"))?;
                log_event(options, "reload failed")?;
                notify_systemd("READY=1")?;
                return Ok(());
            }
            if let Err(err) = swap_runtime_with_restore(
                &mut state.runtime,
                &mut state.config,
                runtime_config,
                |config| {
                    start_resident_production_runtime_with_asset_dirs(
                        config,
                        resident_config_geodata_asset_dirs(&options.config),
                    )
                },
            ) {
                write_progress(&options.progress_file, RELOAD_ERROR, &format!("\n{err}"))?;
                log_event(options, "reload failed")?;
                notify_systemd("READY=1")?;
                if state.runtime.is_none() {
                    return Err(err);
                }
                return Ok(());
            }
            write_progress(&options.progress_file, RELOAD_DONE, "\nOK")?;
            log_event(options, "reload completed")?;
        }
        Err(err) => {
            write_progress(&options.progress_file, RELOAD_ERROR, &format!("\n{err}"))?;
            log_event(options, "reload failed")?;
        }
    }
    notify_systemd("READY=1")
}

pub(super) fn resident_config_geodata_asset_dirs(config_path: &Path) -> Vec<PathBuf> {
    vec![resident_config_asset_dir(config_path)]
}

fn resident_config_asset_dir(config_path: &Path) -> PathBuf {
    if config_path
        .extension()
        .and_then(|extension| extension.to_str())
        == Some("dae")
    {
        return config_path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
    }
    config_path.to_path_buf()
}

pub(crate) fn validate_resident_runtime_reload_config(config: &Config) -> Result<(), String> {
    let lan_ifaces = configured_lan_ifaces(config);
    let wan_ifaces = configured_wan_ifaces(config)
        .map_err(|err| format!("resident reload rejected before current runtime swap: {err}"))?;
    validate_resident_runtime_interfaces(
        &lan_ifaces,
        &wan_ifaces,
        "resident reload rejected before current runtime swap",
    )
}

pub(super) fn swap_runtime_with_restore<R>(
    runtime: &mut Option<R>,
    current_config: &mut Config,
    next_config: Config,
    mut start_runtime: impl FnMut(&Config) -> Result<R, String>,
) -> Result<(), String> {
    let previous_config = current_config.clone();
    let previous_runtime = runtime.take();
    drop(previous_runtime);
    match start_runtime(&next_config) {
        Ok(next_runtime) => {
            *runtime = Some(next_runtime);
            *current_config = next_config;
            Ok(())
        }
        Err(start_err) => match start_runtime(&previous_config) {
            Ok(restored_runtime) => {
                *runtime = Some(restored_runtime);
                Err(format!(
                    "{start_err}\nrestore: restored previous resident runtime"
                ))
            }
            Err(restore_err) => Err(format!(
                "{start_err}\nrestore failed while restoring previous resident runtime: {restore_err}"
            )),
        },
    }
}

pub(super) fn handle_suspend_compatibility(options: &ResidentRunOptions) -> Result<(), String> {
    notify_systemd("RELOADING=1")?;
    write_progress(&options.progress_file, RELOAD_PROCESSING, "")?;
    let _ = fs::remove_file(&options.abort_file);
    write_progress(
        &options.progress_file,
        RELOAD_ERROR,
        "\nsuspend runtime transition is not implemented by Rust service contract",
    )?;
    log_event(options, "suspend rejected")?;
    notify_systemd("READY=1")
}

pub(super) fn write_progress(path: &Path, byte: u8, suffix: &str) -> Result<(), String> {
    let mut bytes = vec![byte];
    bytes.extend_from_slice(suffix.as_bytes());
    write_bytes_file(path, &bytes, 0o644)
}

pub(super) fn read_progress(path: &Path) -> Result<(u8, String), String> {
    let bytes =
        fs::read(path).map_err(|err| format!("failed to read {}: {err}", path.display()))?;
    let Some(code) = bytes.first().copied() else {
        return Err(format!("unexpected format: {}", path.display()));
    };
    let content = String::from_utf8_lossy(&bytes[1..])
        .trim_start_matches('\n')
        .to_owned();
    Ok((code, content))
}

pub(super) fn read_pid_file(path: &Path) -> Result<i32, String> {
    let text = fs::read_to_string(path)
        .map_err(|err| format!("failed to read pid file {}: {err}", path.display()))?;
    text.trim()
        .parse::<i32>()
        .map_err(|err| format!("failed to parse pid file {}: {err}", path.display()))
}

pub(super) fn log_event(options: &ResidentRunOptions, message: &str) -> Result<(), String> {
    let Some(path) = &options.logfile else {
        return Ok(());
    };
    let line = if options.disable_timestamp {
        format!("{message}\n")
    } else {
        format!("{} {message}\n", std::process::id())
    };
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| format!("failed to create log dir {}: {err}", parent.display()))?;
    }
    use std::io::Write;
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|err| format!("failed to open log {}: {err}", path.display()))?;
    file.write_all(line.as_bytes())
        .map_err(|err| format!("failed to write log {}: {err}", path.display()))
}

pub(super) fn write_text_file(path: &Path, content: &str, mode: u32) -> Result<(), String> {
    write_bytes_file(path, content.as_bytes(), mode)
}

pub(super) fn write_bytes_file(path: &Path, content: &[u8], mode: u32) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| format!("failed to create path {}: {err}", parent.display()))?;
    }
    fs::write(path, content).map_err(|err| format!("failed to write {}: {err}", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|err| format!("failed to chmod {}: {err}", path.display()))
}

pub(super) fn notify_systemd(state: &str) -> Result<(), String> {
    let Ok(address) = env::var("NOTIFY_SOCKET") else {
        return Ok(());
    };
    let socket =
        UnixDatagram::unbound().map_err(|err| format!("failed to create notify socket: {err}"))?;
    if address.starts_with('@') {
        #[cfg(target_os = "linux")]
        {
            use std::os::linux::net::SocketAddrExt;
            use std::os::unix::net::SocketAddr;

            let target = SocketAddr::from_abstract_name(&address.as_bytes()[1..])
                .map_err(|err| format!("failed to parse abstract notify socket: {err}"))?;
            socket
                .send_to_addr(state.as_bytes(), &target)
                .map_err(|err| format!("failed to notify systemd: {err}"))?;
            return Ok(());
        }
        #[cfg(not(target_os = "linux"))]
        return Err("abstract systemd notify sockets are unsupported on this platform".to_owned());
    }
    socket
        .send_to(state.as_bytes(), address)
        .map_err(|err| format!("failed to notify systemd: {err}"))?;
    Ok(())
}

pub(super) fn block_service_signals() -> Result<(), String> {
    let mut signals = unsafe { std::mem::zeroed::<libc::sigset_t>() };
    unsafe {
        libc::sigemptyset(&mut signals);
        for signal in [
            libc::SIGUSR1,
            libc::SIGUSR2,
            libc::SIGHUP,
            libc::SIGTERM,
            libc::SIGINT,
            libc::SIGQUIT,
        ] {
            libc::sigaddset(&mut signals, signal);
        }
        if libc::pthread_sigmask(libc::SIG_BLOCK, &signals, std::ptr::null_mut()) != 0 {
            return Err("failed to block resident service signals".to_owned());
        }
    }
    Ok(())
}

pub(super) fn wait_service_signal() -> Result<i32, String> {
    let mut signals = unsafe { std::mem::zeroed::<libc::sigset_t>() };
    let mut received = 0_i32;
    unsafe {
        libc::sigemptyset(&mut signals);
        for signal in [
            libc::SIGUSR1,
            libc::SIGUSR2,
            libc::SIGHUP,
            libc::SIGTERM,
            libc::SIGINT,
            libc::SIGQUIT,
        ] {
            libc::sigaddset(&mut signals, signal);
        }
        let status = libc::sigwait(&signals, &mut received);
        if status != 0 {
            return Err(format!(
                "failed to wait for resident service signal: {status}"
            ));
        }
    }
    Ok(received)
}
