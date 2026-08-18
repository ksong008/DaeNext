use super::*;

static CONTROL_FILE_WRITE_SEQUENCE: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(1);
const CONTROL_FILE_CREATE_ATTEMPTS: usize = 32;
pub fn run_resident_service(options: &ResidentRunOptions) -> Result<(), String> {
    if options.disable_sudo && unsafe { libc::geteuid() } != 0 {
        return Err("auto-sudo is disabled and current user is not root".to_owned());
    }
    // A-04: 在任何派生线程（网络探测 resolver 等）创建之前屏蔽服务信号，
    // 保证所有线程继承已屏蔽的掩码；否则 kill(SIGUSR1) 会被未屏蔽线程
    // 以默认动作（终止进程）接收。
    block_service_signals()?;
    let runtime_config = load_config_file(&options.config)
        .map_err(|err| format!("resident run config validation failed: {err}"))?;
    if !runtime_config.global.disable_waiting_network {
        wait_for_network_before_subscriptions()
            .map_err(|err| format!("waiting for network before subscriptions failed: {err}"))?;
    }
    let geodata_asset_dirs = resident_config_geodata_asset_dirs(&options.config);
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
        // A-05: kill(0/-1) 会群发信号到进程组/所有进程——拒绝非正 PID。
        Some(pid) if pid > 0 => pid,
        Some(pid) => {
            return Err(format!("refusing to signal non-positive pid {pid}"));
        }
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

    wait_for_reload_progress(&options.progress_file, options.timeout)
}

fn wait_for_reload_progress(
    progress_file: &Path,
    timeout: Option<Duration>,
) -> Result<String, String> {
    let started = Instant::now();
    let mut last_read_error: Option<String> = None;
    loop {
        if timeout.is_some_and(|timeout| started.elapsed() >= timeout) {
            return match last_read_error {
                Some(err) => Err(format!("reload progress timed out: {err}")),
                None => Err("reload progress timed out".to_owned()),
            };
        }
        thread::sleep(Duration::from_millis(200));
        match read_progress(progress_file) {
            Ok((code, content)) => {
                if code == RELOAD_DONE {
                    return Ok(format!("{content}\n"));
                }
                if code == RELOAD_ERROR {
                    // A-06: reload 失败必须以 Err 返回（CLI 非零退出）。
                    return Err(format!("reload failed on the daemon side: {content}"));
                }
            }
            // A transient read failure (e.g. the daemon atomically replacing
            // the file) must never be reported as success. Keep polling
            // until the overall timeout and surface the last error with
            // context instead of pretending the reload completed.
            Err(err) => last_read_error = Some(err),
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
            if !runtime_config.global.disable_waiting_network
                && let Err(err) = wait_for_network_before_subscriptions()
            {
                write_progress(
                    &options.progress_file,
                    RELOAD_ERROR,
                    &format!("\nwaiting for network before reload failed: {err}"),
                )?;
                log_event(options, "reload failed while waiting for network")?;
                notify_systemd("READY=1")?;
                return Ok(());
            }
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
    let pid = text
        .trim()
        .parse::<i32>()
        .map_err(|err| format!("failed to parse pid file {}: {err}", path.display()))?;
    // A-05: 拒绝非正 PID（kill 0/-1 群发）。
    if pid <= 0 {
        return Err(format!(
            "pid file {} contains non-positive pid {pid}",
            path.display()
        ));
    }
    Ok(pid)
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
    let mut options = fs::OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options
        .open(path)
        .map_err(|err| format!("failed to open log {}: {err}", path.display()))?;
    file.write_all(line.as_bytes())
        .map_err(|err| format!("failed to write log {}: {err}", path.display()))
}

pub(super) fn write_text_file(path: &Path, content: &str, mode: u32) -> Result<(), String> {
    write_bytes_file(path, content.as_bytes(), mode)
}

pub(super) fn write_bytes_file(path: &Path, content: &[u8], mode: u32) -> Result<(), String> {
    use std::io::Write;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)
        .map_err(|err| format!("failed to create path {}: {err}", parent.display()))?;
    let leaf = path
        .file_name()
        .and_then(|leaf| leaf.to_str())
        .ok_or_else(|| format!("control file has no UTF-8 leaf name: {}", path.display()))?;
    let (temporary, mut file) = (0..CONTROL_FILE_CREATE_ATTEMPTS)
        .find_map(|_| {
            let sequence =
                CONTROL_FILE_WRITE_SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let temporary = parent.join(format!(".{leaf}.tmp-{}-{sequence}", std::process::id()));
            let mut options = fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.custom_flags(libc::O_NOFOLLOW).mode(mode);
            }
            match options.open(&temporary) {
                Ok(file) => Some(Ok((temporary, file))),
                Err(err) if err.kind() == io::ErrorKind::AlreadyExists => None,
                Err(err) => Some(Err(format!(
                    "failed to create temporary control file {}: {err}",
                    temporary.display()
                ))),
            }
        })
        .unwrap_or_else(|| {
            Err(format!(
                "failed to reserve a temporary control file for {} after {} attempts",
                path.display(),
                CONTROL_FILE_CREATE_ATTEMPTS
            ))
        })?;
    let write_result = (|| {
        file.set_permissions(fs::Permissions::from_mode(mode))
            .map_err(|err| format!("failed to chmod {}: {err}", temporary.display()))?;
        file.write_all(content)
            .map_err(|err| format!("failed to write {}: {err}", temporary.display()))?;
        file.sync_all()
            .map_err(|err| format!("failed to sync {}: {err}", temporary.display()))?;
        fs::rename(&temporary, path).map_err(|err| {
            format!(
                "failed to atomically replace {} with {}: {err}",
                path.display(),
                temporary.display()
            )
        })?;
        let directory = fs::File::open(parent)
            .map_err(|err| format!("failed to open {}: {err}", parent.display()))?;
        directory
            .sync_all()
            .map_err(|err| format!("failed to sync {}: {err}", parent.display()))
    })();
    if write_result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    write_result
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

#[cfg(test)]
mod tests {
    use super::wait_for_reload_progress;
    use dae_core_types::reload::{RELOAD_DONE, RELOAD_ERROR, RELOAD_PROCESSING};
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;
    use std::time::Duration;

    fn test_root() -> PathBuf {
        // Unique per call: tests run in parallel and each one removes its
        // own tree, so a shared path would race between tests.
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "dae-daemon-reload-progress-test-{}-{unique}",
            std::process::id()
        ))
    }

    #[test]
    fn reload_progress_read_failure_times_out_with_context_instead_of_ok() {
        let root = test_root();
        fs::create_dir_all(&root).unwrap();
        // A directory cannot be read as a progress file, so every read
        // attempt fails. This must surface as an error with context, not as
        // a fake "OK\n" success.
        let progress_dir = root.join("progress-as-directory");
        fs::create_dir_all(&progress_dir).unwrap();
        let err =
            wait_for_reload_progress(&progress_dir, Some(Duration::from_millis(50))).unwrap_err();
        assert!(err.contains("reload progress timed out"), "err: {err}");
        assert!(err.contains("failed to read"), "err: {err}");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn reload_progress_recovers_from_transient_read_failure() {
        let root = test_root();
        fs::create_dir_all(&root).unwrap();
        // The daemon replaces the progress file; early reads fail while it
        // is not yet in place. The poller must keep waiting instead of
        // aborting or reporting success.
        let progress_file = root.join("progress.late");
        let writer_file = progress_file.clone();
        let writer = thread::spawn(move || {
            thread::sleep(Duration::from_millis(150));
            fs::write(&writer_file, [RELOAD_DONE, b'\n', b'O', b'K']).unwrap();
        });
        let result =
            wait_for_reload_progress(&progress_file, Some(Duration::from_secs(5))).unwrap();
        assert_eq!(result, "OK\n");
        writer.join().unwrap();
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn reload_progress_returns_done_or_error_content() {
        let root = test_root();
        fs::create_dir_all(&root).unwrap();
        let done_file = root.join("progress.done");
        fs::write(&done_file, [RELOAD_DONE, b'\n', b'O', b'K']).unwrap();
        assert_eq!(
            wait_for_reload_progress(&done_file, Some(Duration::from_secs(2))).unwrap(),
            "OK\n"
        );
        let error_file = root.join("progress.error");
        let mut error_bytes = vec![RELOAD_ERROR, b'\n'];
        error_bytes.extend_from_slice(b"boom");
        fs::write(&error_file, error_bytes).unwrap();
        // A-06: RELOAD_ERROR 必须以 Err 返回（CLI 非零退出）。
        let error =
            wait_for_reload_progress(&error_file, Some(Duration::from_secs(2))).unwrap_err();
        assert!(error.contains("boom"), "error = {error}");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn reload_progress_times_out_while_still_processing() {
        let root = test_root();
        fs::create_dir_all(&root).unwrap();
        let progress_file = root.join("progress.processing");
        fs::write(&progress_file, [RELOAD_PROCESSING, b'\n']).unwrap();
        let err =
            wait_for_reload_progress(&progress_file, Some(Duration::from_millis(50))).unwrap_err();
        assert!(err.contains("reload progress timed out"), "err: {err}");
        // Reads succeeded here, so the timeout error must not carry a
        // read-failure context.
        assert!(!err.contains("failed to read"), "err: {err}");
        let _ = fs::remove_dir_all(&root);
    }
}
