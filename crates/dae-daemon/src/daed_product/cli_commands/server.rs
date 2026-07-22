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
    if let Err(err) = block_product_signals() {
        return DaedProductOutput::error(format!("install signal control failed: {err}"));
    }
    let product_log_runtime = match start_product_log_runtime(&options.config_dir, &options.state) {
        Ok(runtime) => runtime,
        Err(err) => {
            return DaedProductOutput::error(format!("start product log writer failed: {err}"));
        }
    };
    register_resident_event_product_log_sink(&options.config_dir, &options.state);
    let runtime = Arc::new(ProductRuntimeManager::new_for_state(options.state.clone()));
    let runtime_required_for_readiness =
        should_restore_runtime_on_start(&options.state).unwrap_or(false);
    runtime.set_runtime_required_for_readiness(runtime_required_for_readiness);
    if runtime_required_for_readiness {
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
    if let Err(err) =
        runtime.start_startup_recovery(options.state.clone(), options.config_dir.clone())
    {
        return DaedProductOutput::error(format!("start runtime readiness recovery failed: {err}"));
    }
    let runtime_config = runtime.current_config();
    let http_config = ProductHttpWorkerConfig::from_config(runtime_config.as_deref());
    runtime.set_process_http_config(http_config);
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
    let control_runtime = match ProductControlRuntime::start_for_http_config(http_config) {
        Ok(runtime) => runtime,
        Err(err) => {
            return DaedProductOutput::error(format!(
                "start product control runtime failed: {err}"
            ));
        }
    };
    let shutdown = Arc::new(ProductShutdown::default());
    let mut app = AppState {
        config_dir: options.config_dir,
        state: options.state,
        web_root: options.web_root,
        api_only: options.api_only,
        control_socket: options.control_socket,
        shutdown: Arc::clone(&shutdown),
        runtime: Arc::clone(&runtime),
        runtime_sampler: Some(runtime_sampler),
        latency_jobs: Arc::new(LatencyJobManager::default()),
        http_metrics: Arc::new(ProductHttpMetrics::default()),
        ui_runtime: Arc::new(ProductUiRuntime::default()),
        auth_runtime,
        geodata_updates: Arc::new(geodata::ProductGeodataUpdateCoordinator::default()),
        geodata_status_cache: Arc::new(Mutex::new(GeodataStatusCache::default())),
        geodata_update_runtime: None,
        control_runtime: Arc::clone(&control_runtime),
    };
    let geodata_update_runtime =
        match geodata::ProductGeodataUpdateRuntime::start_for_app(http_config, &app) {
            Ok(runtime) => runtime,
            Err(err) => {
                drop(app);
                let _ = control_runtime.shutdown();
                return DaedProductOutput::error(format!(
                    "start geodata update runtime failed: {err}"
                ));
            }
        };
    app.geodata_update_runtime = Some(geodata_update_runtime);
    let subscription_scheduler = match start_subscription_scheduler(
        app.state.clone(),
        app.config_dir.clone(),
        Arc::clone(&app.runtime),
        Arc::clone(&control_runtime),
    ) {
        Ok(scheduler) => scheduler,
        Err(err) => {
            if let Some(runtime) = app.geodata_update_runtime.take() {
                let _ = runtime.shutdown();
            }
            drop(app);
            let _ = control_runtime.shutdown();
            return DaedProductOutput::error(format!("start subscription scheduler failed: {err}"));
        }
    };
    let signal_thread = match install_product_signal_thread(Arc::clone(&shutdown)) {
        Ok(signal_thread) => signal_thread,
        Err(err) => {
            shutdown.request(0);
            let _ = subscription_scheduler.shutdown();
            if let Some(runtime) = app.geodata_update_runtime.take() {
                let _ = runtime.shutdown();
            }
            drop(app);
            let _ = control_runtime.shutdown();
            return DaedProductOutput::error(format!("install signal control failed: {err}"));
        }
    };
    let state = app.state.clone();
    let config_dir = app.config_dir.clone();
    let app = Arc::new(app);
    let server_result = serve_forever(&options.listen, Arc::clone(&app), startup_started_at);
    shutdown.request(0);
    let scheduler_result = subscription_scheduler.shutdown();
    let signal_result = signal_thread.shutdown();
    let recovery_result = runtime.shutdown_recovery_supervisors();
    let geodata_result = app
        .geodata_update_runtime
        .as_ref()
        .map_or(Ok(()), |runtime| runtime.shutdown());
    let app_release_result = Arc::try_unwrap(app).map(drop).map_err(|_| {
        "product application owners remained referenced after HTTP shutdown".to_owned()
    });
    let control_result = control_runtime.shutdown();
    let stop_result = runtime.stop_and_wait_for_cleanup("product-shutdown");
    let metadata_result = mark_runtime_process_stopped(&state);
    let mut fields = BTreeMap::new();
    if let Some(signal) = shutdown.signal() {
        fields.insert("signal".to_owned(), signal.to_string());
    }
    match &stop_result {
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
    match &control_result {
        Ok(evidence) => {
            if let Some(status) = evidence.get("status").and_then(Value::as_str) {
                fields.insert("control_cleanup_status".to_owned(), status.to_owned());
            }
            for key in ["joined", "cancelled", "panicked", "forced"] {
                if let Some(count) = evidence
                    .get("tasks")
                    .and_then(|tasks| tasks.get(key))
                    .and_then(Value::as_u64)
                {
                    fields.insert(format!("control_tasks_{key}"), count.to_string());
                }
            }
        }
        Err(err) => {
            fields.insert("control_cleanup_error".to_owned(), err.to_string());
        }
    }
    let shutdown_ok = server_result.is_ok()
        && scheduler_result.is_ok()
        && signal_result.is_ok()
        && recovery_result.is_ok()
        && geodata_result.is_ok()
        && app_release_result.is_ok()
        && control_result.is_ok()
        && stop_result.is_ok()
        && metadata_result.is_ok();
    let _ = append_lifecycle_log_fields_for_config(
        &config_dir,
        &state,
        if shutdown_ok { "info" } else { "error" },
        "[Stop] product shutdown completed",
        fields,
    );
    drop(runtime);
    drop(product_log_runtime);
    let mut errors = Vec::new();
    if let Err(err) = server_result {
        errors.push(format!("HTTP server: {err}"));
    }
    if let Err(err) = scheduler_result {
        errors.push(format!("subscription scheduler: {err}"));
    }
    if let Err(err) = signal_result {
        errors.push(format!("signal thread: {err}"));
    }
    if let Err(err) = recovery_result {
        errors.push(format!("runtime recovery: {err}"));
    }
    if let Err(err) = geodata_result {
        errors.push(format!("geodata update runtime: {err}"));
    }
    if let Err(err) = app_release_result {
        errors.push(err);
    }
    if let Err(err) = control_result {
        errors.push(format!("product control runtime: {err}"));
    }
    if let Err(err) = stop_result {
        errors.push(format!("resident runtime: {err}"));
    }
    if let Err(err) = metadata_result {
        errors.push(format!("stopped metadata: {err}"));
    }
    if errors.is_empty() {
        DaedProductOutput::ok(String::new())
    } else {
        DaedProductOutput::error(format!("run shutdown failed: {}", errors.join("; ")))
    }
}

pub(crate) fn record_startup_runtime_restore_failure(config_dir: &Path, state: &Path, err: &str) {
    let _ = append_lifecycle_log_for_config(
        config_dir,
        state,
        "error",
        &format!("[Startup] runtime restore waiting for host readiness: {err}"),
    );
    let _ = set_metadata(state, "runtime_transition_phase", "waiting-for-host");
    let _ = set_metadata(state, "runtime_running", "false");
    let _ = set_metadata(state, "runtime_last_apply_error", err);
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
    let latency_seed = stored_successful_node_latency_seed_snapshots(state).unwrap_or_default();
    let control_plane_started_at = Instant::now();
    let reclaim_reason = if log_mode.is_startup() {
        AllocatorReclaimReason::StartupControlBuilt
    } else {
        AllocatorReclaimReason::ReloadCompleted
    };
    let applied = match coordinate_runtime_reload(
        runtime,
        state,
        config_dir,
        log_mode.apply_intent(),
        &latency_seed,
        reclaim_reason,
    ) {
        Ok(applied) => applied,
        Err(err) => {
            let error = err.to_string();
            let mut fields = BTreeMap::new();
            fields.insert("source".to_owned(), source.to_owned());
            fields.insert("error".to_owned(), error.clone());
            if log_mode.is_startup() {
                let _ = append_startup_step_failed_for_config(
                    log_config_dir,
                    state,
                    "control-plane.create.total",
                    lifecycle_started_at,
                    &error,
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
            return Err(error);
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
            "applied": applied.applied,
            "coalesced": applied.coalesced,
            "detailedReport": false,
            "pendingProcessTransition": applied.pending_process_transition,
            "allocatorReclaim": applied.allocator_reclaim,
        }));
    }
    Ok(json!({
        "restored": true,
        "applied": applied.applied,
        "coalesced": applied.coalesced,
        "detailedReport": true,
        "pendingProcessTransition": applied.pending_process_transition,
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

pub(crate) struct ProductSignalThread {
    stop: Arc<std::sync::atomic::AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl ProductSignalThread {
    fn shutdown(mut self) -> io::Result<()> {
        self.stop.store(true, Ordering::Release);
        if let Some(handle) = self.handle.as_ref() {
            #[cfg(unix)]
            {
                use std::os::unix::thread::JoinHandleExt;
                let status = unsafe { libc::pthread_kill(handle.as_pthread_t(), libc::SIGUSR1) };
                if status != 0 && status != libc::ESRCH {
                    return Err(io::Error::from_raw_os_error(status));
                }
            }
        }
        if let Some(handle) = self.handle.take() {
            handle
                .join()
                .map_err(|_| io::Error::other("product signal thread panicked"))?;
        }
        Ok(())
    }
}

impl Drop for ProductSignalThread {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let Some(handle) = self.handle.take() else {
            return;
        };
        #[cfg(unix)]
        {
            use std::os::unix::thread::JoinHandleExt;
            let _ = unsafe { libc::pthread_kill(handle.as_pthread_t(), libc::SIGUSR1) };
        }
        let _ = handle.join();
    }
}

pub(crate) fn install_product_signal_thread(
    shutdown: Arc<ProductShutdown>,
) -> io::Result<ProductSignalThread> {
    block_product_signals()?;
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let thread_stop = Arc::clone(&stop);
    let handle = thread::Builder::new()
        .name("daed-product-signal".to_owned())
        .spawn(move || {
            while !thread_stop.load(Ordering::Acquire) {
                let Ok(signal) = wait_product_signal() else {
                    return;
                };
                if thread_stop.load(Ordering::Acquire) {
                    return;
                }
                match signal {
                    libc::SIGHUP | libc::SIGUSR1 => continue,
                    libc::SIGTERM | libc::SIGINT | libc::SIGQUIT => {
                        shutdown.request(signal);
                        return;
                    }
                    _ => {}
                }
            }
        })?;
    Ok(ProductSignalThread {
        stop,
        handle: Some(handle),
    })
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
