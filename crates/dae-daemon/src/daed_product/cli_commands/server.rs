use super::*;
pub(crate) fn run_product_server_command(args: &[String], _version: &str) -> DaedProductOutput {
    let startup_started_at = Instant::now();
    let mut options = match parse_run_args(args) {
        Ok(options) => options,
        Err(err) => return DaedProductOutput::usage(err),
    };
    options.config_dir = match prepare_config_directory(&options.config_dir) {
        Ok(config_dir) => config_dir,
        Err(err) => return DaedProductOutput::error(err),
    };
    if let Err(err) = ensure_state_schema(&options.state) {
        return DaedProductOutput::error(format!("init state failed: {err}"));
    }
    let geodata_dir = geodata_dir_for_web_root(&options.web_root);
    if let Err(err) = recover_geodata_transactions(&geodata_dir, &options.state) {
        return DaedProductOutput::error(format!(
            "recover interrupted geodata update failed: {err}"
        ));
    }
    if let Err(err) = initialize_log_store(&options.config_dir, &options.state) {
        return DaedProductOutput::error(format!("init log store failed: {err}"));
    }
    let product_log_runtime = match start_product_log_runtime(&options.config_dir, &options.state) {
        Ok(runtime) => runtime,
        Err(err) => {
            return DaedProductOutput::error(format!("start product log writer failed: {err}"));
        }
    };
    register_resident_event_product_log_sink(&options.config_dir, &options.state);
    if let Err(err) = block_product_signals() {
        return DaedProductOutput::error(format!("install signal control failed: {err}"));
    }
    let runtime = Arc::new(ProductRuntimeManager::new());
    if let Err(err) = install_product_signal_thread(
        Arc::clone(&runtime),
        options.state.clone(),
        options.config_dir.clone(),
    ) {
        return DaedProductOutput::error(format!("install signal control failed: {err}"));
    }
    if should_restore_runtime_on_start(&options.state).unwrap_or(false) {
        match restore_runtime_from_state(
            &runtime,
            &options.state,
            Some(&options.config_dir),
            ProductRuntimeLifecycleLogMode::StartupRestore,
        ) {
            Ok(report) => {
                drop(report);
                let _ = allocator_reclaim(AllocatorReclaimReason::StartupControlBuilt);
            }
            Err(err) => {
                record_startup_runtime_restore_failure(&options.config_dir, &options.state, &err);
            }
        }
    }
    let http_config = ProductHttpWorkerConfig::from_config(runtime.current_config().as_ref());
    let auth_runtime = match ProductAuthRuntime::start_for_http_config(http_config) {
        Ok(runtime) => runtime,
        Err(err) => {
            return DaedProductOutput::error(format!("start authentication runtime failed: {err}"));
        }
    };
    let runtime_sampler = match ProductRuntimeSampler::start(Arc::downgrade(&runtime)) {
        Ok(sampler) => sampler,
        Err(err) => {
            return DaedProductOutput::error(format!("start runtime sampler failed: {err}"));
        }
    };
    let mut app = AppState {
        config_dir: options.config_dir,
        state: options.state,
        web_root: options.web_root,
        api_only: options.api_only,
        control_socket: options.control_socket,
        runtime,
        runtime_sampler: Some(runtime_sampler),
        latency_jobs: Arc::new(LatencyJobManager::default()),
        http_metrics: Arc::new(ProductHttpMetrics::default()),
        auth_runtime,
        geodata_updates: Arc::new(geodata::ProductGeodataUpdateCoordinator::default()),
        geodata_status_cache: Arc::new(Mutex::new(GeodataStatusCache::default())),
        geodata_update_runtime: None,
    };
    app.geodata_update_runtime =
        match geodata::ProductGeodataUpdateRuntime::start_for_app(http_config, &app) {
            Ok(runtime) => Some(runtime),
            Err(err) => {
                return DaedProductOutput::error(format!(
                    "start geodata update runtime failed: {err}"
                ));
            }
        };
    let subscription_scheduler = match start_subscription_scheduler(
        app.state.clone(),
        app.config_dir.clone(),
        Arc::clone(&app.runtime),
    ) {
        Ok(scheduler) => scheduler,
        Err(err) => {
            return DaedProductOutput::error(format!("start subscription scheduler failed: {err}"));
        }
    };
    let server_result = serve_forever(&options.listen, app, startup_started_at);
    let scheduler_result = subscription_scheduler.shutdown();
    drop(product_log_runtime);
    match (server_result, scheduler_result) {
        (Ok(()), Ok(())) => DaedProductOutput::ok(String::new()),
        (Err(err), _) => DaedProductOutput::error(format!("run failed: {err}")),
        (Ok(()), Err(err)) => {
            DaedProductOutput::error(format!("stop subscription scheduler failed: {err}"))
        }
    }
}

pub(crate) fn record_startup_runtime_restore_failure(config_dir: &Path, state: &Path, err: &str) {
    let _ = append_lifecycle_log_for_config(
        config_dir,
        state,
        "error",
        &format!("[Startup] runtime restore failed; continuing with runtime stopped: {err}"),
    );
    let _ = mark_system_stopped(state);
}

pub(crate) fn restore_runtime_from_state(
    runtime: &ProductRuntimeManager,
    state: &Path,
    config_dir: Option<&Path>,
    log_mode: ProductRuntimeLifecycleLogMode,
) -> Result<Value, String> {
    let log_config_dir =
        config_dir.unwrap_or_else(|| state.parent().unwrap_or(Path::new(DEFAULT_CONFIG_DIR)));
    let lifecycle_started_at = Instant::now();
    let source = log_mode.source();
    let prepared = prepare_runtime_reload_to_apply(log_config_dir, state, runtime)
        .map_err(|err| err.to_string())?;
    let latency_seed = stored_successful_node_latency_seed_snapshots(state).unwrap_or_default();
    let control_plane_started_at = Instant::now();
    let reclaim_reason = if log_mode.is_startup() {
        AllocatorReclaimReason::StartupControlBuilt
    } else {
        AllocatorReclaimReason::ReloadCompleted
    };
    let applied = match apply_prepared_runtime_reload(
        runtime,
        state,
        config_dir,
        source,
        prepared,
        &latency_seed,
        reclaim_reason,
    ) {
        Ok(applied) => applied,
        Err(err) => {
            let mut fields = BTreeMap::new();
            fields.insert("source".to_owned(), source.to_owned());
            fields.insert("error".to_owned(), err.clone());
            if log_mode.is_startup() {
                let _ = append_startup_step_failed_for_config(
                    log_config_dir,
                    state,
                    "control-plane.create.total",
                    lifecycle_started_at,
                    &err,
                    fields.clone(),
                );
            }
            let _ = append_lifecycle_log_fields_for_config(
                log_config_dir,
                state,
                "error",
                if log_mode.is_startup() {
                    "[Startup] runtime restore failed"
                } else {
                    "[Reload] Failed to reload"
                },
                fields,
            );
            return Err(err);
        }
    };
    if log_mode.is_startup() {
        let _ = append_startup_runtime_evidence_logs_for_config(
            log_config_dir,
            state,
            &applied.runtime_report,
        );
        let _ = append_startup_reclaim_decision_log_for_config(
            log_config_dir,
            state,
            &applied.runtime_report,
            true,
        );
        let _ = append_startup_step_completed_for_config(
            log_config_dir,
            state,
            "post-startup.gc",
            control_plane_started_at,
            BTreeMap::new(),
        );
        let _ = append_startup_step_completed_for_config(
            log_config_dir,
            state,
            "control-plane.core",
            control_plane_started_at,
            BTreeMap::new(),
        );
    }
    if log_mode.is_startup() {
        let _ = append_startup_step_completed_for_config(
            log_config_dir,
            state,
            "control-plane.create.total",
            lifecycle_started_at,
            BTreeMap::new(),
        );
    }
    if !log_mode.returns_detailed_report() {
        drop(applied.runtime_report);
        drop(applied.materialized_report);
        return Ok(json!({
            "restored": true,
            "detailedReport": false,
            "allocatorReclaim": applied.allocator_reclaim,
        }));
    }
    Ok(json!({
        "restored": true,
        "detailedReport": true,
        "runtime": applied.runtime_report,
        "materialized": applied.materialized_report,
        "allocatorReclaim": applied.allocator_reclaim,
    }))
}

pub(crate) fn should_restore_runtime_on_start(state: &Path) -> io::Result<bool> {
    ensure_state_schema(state)?;
    let conn = open_state_connection(state)?;
    conn.query_row(
        "SELECT running FROM systems ORDER BY id LIMIT 1",
        [],
        |row| row.get::<_, i64>(0),
    )
    .optional()
    .map(|value| value.unwrap_or(0) != 0)
    .map_err(sqlite_io_error)
}

pub(crate) fn install_product_signal_thread(
    runtime: Arc<ProductRuntimeManager>,
    state: PathBuf,
    config_dir: PathBuf,
) -> io::Result<()> {
    block_product_signals()?;
    thread::spawn(move || {
        while let Ok(signal) = wait_product_signal() {
            match signal {
                libc::SIGHUP | libc::SIGUSR1 => continue,
                libc::SIGTERM | libc::SIGINT | libc::SIGQUIT => {
                    let stop = runtime.stop_and_wait_for_cleanup("signal-stop");
                    let _ = mark_runtime_process_stopped(&state);
                    let mut fields = BTreeMap::new();
                    fields.insert("signal".to_owned(), signal.to_string());
                    match &stop {
                        Ok(report) => {
                            fields.insert(
                                "was_running".to_owned(),
                                report["wasRunning"].as_bool().unwrap_or(false).to_string(),
                            );
                            if let Some(status) = report
                                .pointer("/cleanupReport/status")
                                .and_then(Value::as_str)
                            {
                                fields.insert("cleanup_status".to_owned(), status.to_owned());
                            }
                        }
                        Err(err) => {
                            fields.insert("cleanup_error".to_owned(), err.clone());
                        }
                    }
                    let _ = append_lifecycle_log_for_config(
                        &config_dir,
                        &state,
                        "info",
                        "[Stop] runtime process stopped by signal",
                    );
                    let _ = append_lifecycle_log_fields_for_config(
                        &config_dir,
                        &state,
                        if stop.is_ok() { "info" } else { "error" },
                        "[Stop] runtime signal cleanup completed",
                        fields,
                    );
                    std::process::exit(0);
                }
                _ => {}
            }
        }
    });
    Ok(())
}

pub(crate) fn block_product_signals() -> io::Result<()> {
    let mut signals = unsafe { std::mem::zeroed::<libc::sigset_t>() };
    unsafe {
        libc::sigemptyset(&mut signals);
        for signal in [
            libc::SIGUSR1,
            libc::SIGHUP,
            libc::SIGTERM,
            libc::SIGINT,
            libc::SIGQUIT,
        ] {
            libc::sigaddset(&mut signals, signal);
        }
        if libc::pthread_sigmask(libc::SIG_BLOCK, &signals, std::ptr::null_mut()) != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

pub(crate) fn wait_product_signal() -> io::Result<i32> {
    let mut signals = unsafe { std::mem::zeroed::<libc::sigset_t>() };
    let mut received = 0_i32;
    unsafe {
        libc::sigemptyset(&mut signals);
        for signal in [
            libc::SIGUSR1,
            libc::SIGHUP,
            libc::SIGTERM,
            libc::SIGINT,
            libc::SIGQUIT,
        ] {
            libc::sigaddset(&mut signals, signal);
        }
        let status = libc::sigwait(&signals, &mut received);
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status));
        }
    }
    Ok(received)
}

pub(crate) fn parse_run_args(args: &[String]) -> Result<RunOptions, String> {
    let mut config_dir = PathBuf::from(DEFAULT_CONFIG_DIR);
    let mut listen = DEFAULT_LISTEN.to_owned();
    let mut state: Option<PathBuf> = None;
    let mut web_root = std::env::var_os(PRODUCT_WEB_ROOT_ENV)
        .or_else(|| std::env::var_os(PRODUCT_WEB_ROOT_LEGACY_ENV))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_WEB_ROOT));
    let mut control_socket = std::env::var_os(PRODUCT_CONTROL_SOCKET_ENV).map(PathBuf::from);
    let mut api_only = false;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-c" | "--config" => {
                let Some(value) = iter.next() else {
                    return Err("missing run --config value".to_owned());
                };
                config_dir = value.into();
            }
            _ if arg.starts_with("--config=") => {
                config_dir = arg.split_once('=').unwrap().1.into();
            }
            "--listen" => {
                let Some(value) = iter.next() else {
                    return Err("missing run --listen value".to_owned());
                };
                listen = value.to_owned();
            }
            _ if arg.starts_with("--listen=") => {
                listen = arg.split_once('=').unwrap().1.to_owned();
            }
            "--state" => {
                let Some(value) = iter.next() else {
                    return Err("missing run --state value".to_owned());
                };
                state = Some(value.into());
            }
            _ if arg.starts_with("--state=") => {
                state = Some(arg.split_once('=').unwrap().1.into());
            }
            "--web-root" => {
                let Some(value) = iter.next() else {
                    return Err("missing run --web-root value".to_owned());
                };
                web_root = value.into();
            }
            _ if arg.starts_with("--web-root=") => {
                web_root = arg.split_once('=').unwrap().1.into();
            }
            "--control" | "--control-socket" => {
                let Some(value) = iter.next() else {
                    return Err("missing run --control value".to_owned());
                };
                control_socket = Some(value.into());
            }
            _ if arg.starts_with("--control=") => {
                control_socket = Some(arg.split_once('=').unwrap().1.into());
            }
            _ if arg.starts_with("--control-socket=") => {
                control_socket = Some(arg.split_once('=').unwrap().1.into());
            }
            "--api-only" => api_only = true,
            _ => return Err(format!("unsupported run argument: {arg}")),
        }
    }
    let state = state.unwrap_or_else(|| config_dir.join("daed.db"));
    let control_socket = control_socket.unwrap_or_else(|| PathBuf::from(DEFAULT_CONTROL_SOCKET));
    Ok(RunOptions {
        config_dir,
        listen,
        state,
        web_root,
        api_only,
        control_socket,
    })
}
