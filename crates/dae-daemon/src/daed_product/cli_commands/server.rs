use super::*;
pub(crate) fn run_product_server_command(args: &[String], _version: &str) -> DaedProductOutput {
    let startup_started_at = Instant::now();
    let options = match parse_run_args(args) {
        Ok(options) => options,
        Err(err) => return DaedProductOutput::usage(err),
    };
    if let Err(err) = ensure_state_schema(&options.state) {
        return DaedProductOutput::error(format!("init state failed: {err}"));
    }
    if let Err(err) = initialize_log_store(&options.config_dir, &options.state) {
        return DaedProductOutput::error(format!("init log store failed: {err}"));
    }
    register_resident_event_product_log_sink(&options.config_dir, &options.state);
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
                let _ = append_lifecycle_log_for_config(
                    &options.config_dir,
                    &options.state,
                    "error",
                    &format!("[Startup] runtime restore failed: {err}"),
                );
                return DaedProductOutput::error(format!("startup runtime restore failed: {err}"));
            }
        }
    }
    start_subscription_scheduler(
        options.state.clone(),
        options.config_dir.clone(),
        Arc::clone(&runtime),
    );
    let app = AppState {
        config_dir: options.config_dir,
        state: options.state,
        web_root: options.web_root,
        api_only: options.api_only,
        runtime,
        latency_jobs: Arc::new(LatencyJobManager::default()),
        http_metrics: Arc::new(ProductHttpMetrics::default()),
        geodata_status_cache: Arc::new(Mutex::new(GeodataStatusCache::default())),
    };
    match serve_forever(&options.listen, app, startup_started_at) {
        Ok(()) => DaedProductOutput::ok(String::new()),
        Err(err) => DaedProductOutput::error(format!("run failed: {err}")),
    }
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
    refresh_log_policy_and_reset_runtime_cycle_logs(log_config_dir, state, Some(runtime))
        .map_err(|err| err.to_string())?;
    let preview = materialize_runtime(state, config_dir, true).map_err(|err| err.to_string())?;
    let content = preview["content"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| "runtime materializer did not return content".to_owned())?;
    let config = build_runtime_config_from_content(&content)?;
    let config_content = content.clone();
    drop(content);
    drop(preview);
    set_runtime_log_level_from_config(state, &config).map_err(|err| err.to_string())?;
    refresh_log_policy_and_reset_runtime_cycle_logs(log_config_dir, state, Some(runtime))
        .map_err(|err| err.to_string())?;
    let latency_seed = stored_successful_node_latency_seed_snapshots(state).unwrap_or_default();
    let control_plane_started_at = Instant::now();
    let outcome =
        runtime.reload_with_config_content(config, Some(config_content), source, &latency_seed)?;
    if log_mode.is_startup() {
        let _ =
            append_startup_runtime_evidence_logs_for_config(log_config_dir, state, &outcome.report);
        let _ = append_startup_reclaim_decision_log_for_config(
            log_config_dir,
            state,
            &outcome.report,
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
    let applied = match materialize_runtime(state, config_dir, false) {
        Ok(applied) => applied,
        Err(err) => {
            let mut fields = BTreeMap::new();
            fields.insert("source".to_owned(), source.to_owned());
            fields.insert("error".to_owned(), err.to_string());
            if log_mode.is_startup() {
                let _ = append_startup_step_failed_for_config(
                    log_config_dir,
                    state,
                    "control-plane.create.total",
                    lifecycle_started_at,
                    &err.to_string(),
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
                    "[Reload] Failed to materialize applied runtime config"
                },
                fields,
            );
            let _ = runtime.stop();
            let _ = mark_system_stopped(state);
            return Err(err.to_string());
        }
    };
    if log_mode.is_startup() {
        let _ = append_startup_step_completed_for_config(
            log_config_dir,
            state,
            "control-plane.create.total",
            lifecycle_started_at,
            BTreeMap::new(),
        );
    }
    let reclaim_reason = if log_mode.is_startup() {
        AllocatorReclaimReason::StartupControlBuilt
    } else {
        AllocatorReclaimReason::ReloadCompleted
    };
    if !log_mode.returns_detailed_report() {
        drop(outcome.report);
        drop(applied);
        let final_reclaim = allocator_reclaim(reclaim_reason);
        return Ok(json!({
            "restored": true,
            "detailedReport": false,
            "allocatorReclaim": final_reclaim,
        }));
    }
    let final_reclaim = allocator_reclaim(reclaim_reason);
    Ok(json!({
        "restored": true,
        "detailedReport": true,
        "runtime": outcome.report,
        "materialized": applied,
        "allocatorReclaim": final_reclaim,
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
                libc::SIGHUP | libc::SIGUSR1 => {
                    let reload_started_at = Instant::now();
                    let mut fields = BTreeMap::new();
                    fields.insert("signal".to_owned(), signal.to_string());
                    fields.insert("source".to_owned(), "signal".to_owned());
                    let _ = append_lifecycle_log_fields_for_config(
                        &config_dir,
                        &state,
                        "info",
                        "[Reload] Received signal reload request",
                        fields,
                    );
                    if !should_restore_runtime_on_start(&state).unwrap_or(false) {
                        let _ = append_lifecycle_log_for_config(
                            &config_dir,
                            &state,
                            "info",
                            "[Reload] signal reload skipped because persisted running state is false",
                        );
                        continue;
                    }
                    let result = restore_runtime_from_state(
                        &runtime,
                        &state,
                        Some(&config_dir),
                        ProductRuntimeLifecycleLogMode::ReloadSignal,
                    );
                    match result {
                        Ok(report) => {
                            drop(report);
                            let post_drop_reclaim =
                                allocator_reclaim(AllocatorReclaimReason::ReloadCompleted);
                            let mut fields = BTreeMap::new();
                            fields.insert("source".to_owned(), "signal".to_owned());
                            fields.insert("applied".to_owned(), "true".to_owned());
                            fields.insert(
                                "allocatorReclaim".to_owned(),
                                post_drop_reclaim["status"]
                                    .as_str()
                                    .unwrap_or("unknown")
                                    .to_owned(),
                            );
                            fields.insert(
                                "elapsed".to_owned(),
                                format!("{:?}", reload_started_at.elapsed()),
                            );
                            let _ = append_lifecycle_log_fields_for_config(
                                &config_dir,
                                &state,
                                "info",
                                "[Reload] Finished",
                                fields,
                            );
                        }
                        Err(err) => {
                            let mut fields = BTreeMap::new();
                            fields.insert("source".to_owned(), "signal".to_owned());
                            fields.insert("error".to_owned(), err.clone());
                            let _ = append_lifecycle_log_fields_for_config(
                                &config_dir,
                                &state,
                                "error",
                                "[Reload] Failed to reload",
                                fields,
                            );
                        }
                    }
                }
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
            "--api-only" => api_only = true,
            _ => return Err(format!("unsupported run argument: {arg}")),
        }
    }
    let state = state.unwrap_or_else(|| config_dir.join("daed.db"));
    Ok(RunOptions {
        config_dir,
        listen,
        state,
        web_root,
        api_only,
    })
}
