pub fn run_daed_product_with_args_and_version(
    args: impl IntoIterator<Item = impl Into<String>>,
    version: &str,
) -> DaedProductOutput {
    let args = args.into_iter().map(Into::into).collect::<Vec<_>>();
    match args.first().map(String::as_str) {
        Some("version") | Some("--version") | Some("-V") => {
            run_version_command(&args[1..], version)
        }
        Some("service-contract") => run_service_contract_command(&args[1..], version),
        Some("package-info") => run_package_info_command(&args[1..], version),
        Some("validate") => run_validate_command(&args[1..]),
        Some("resident-adapter-matrix") => run_resident_adapter_matrix_command(&args[1..]),
        Some("resident-adapter-udp-live") => run_resident_adapter_udp_live_command(&args[1..]),
        Some("state") => run_state_command(&args[1..]),
        Some("run") => run_product_server_command(&args[1..], version),
        Some("export") => run_export_command(&args[1..]),
        Some("resetpass") => run_resetpass_command(&args[1..]),
        Some("help") | Some("--help") | Some("-h") => DaedProductOutput::ok(help_text()),
        Some(command) => DaedProductOutput::usage(format!("unsupported daed command: {command}")),
        None => DaedProductOutput::usage("missing daed command"),
    }
}

fn run_version_command(args: &[String], version: &str) -> DaedProductOutput {
    if !args.is_empty() {
        return DaedProductOutput::usage("version accepts no arguments");
    }
    DaedProductOutput::ok(format!("{version}\n"))
}

fn run_service_contract_command(args: &[String], version: &str) -> DaedProductOutput {
    if !args.is_empty() && args != ["--json"] {
        return DaedProductOutput::usage("service-contract accepts only optional --json");
    }
    DaedProductOutput::ok(format!("{}\n", daed_service_contract(version)))
}

fn run_package_info_command(args: &[String], version: &str) -> DaedProductOutput {
    if !args.is_empty() && args != ["--json"] {
        return DaedProductOutput::usage("package-info accepts only optional --json");
    }
    DaedProductOutput::ok(format!("{}\n", daed_package_info(version)))
}

fn run_validate_command(args: &[String]) -> DaedProductOutput {
    let (path, json_output) = match parse_validate_args(args) {
        Ok(parsed) => parsed,
        Err(err) => return DaedProductOutput::usage(err),
    };
    match validate_product_config_path(&path) {
        Ok(report) if json_output => DaedProductOutput::ok(format!("{report}\n")),
        Ok(_) => DaedProductOutput::ok(String::new()),
        Err(err) => DaedProductOutput::error(format!("validate failed: {err}")),
    }
}

fn run_resident_adapter_matrix_command(args: &[String]) -> DaedProductOutput {
    let config = match parse_resident_adapter_matrix_args(args) {
        Ok(config) => config,
        Err(err) => return DaedProductOutput::usage(err),
    };
    match load_config_file(&config) {
        Ok(config_value) => DaedProductOutput::ok(format!(
            "{}\n",
            resident_live_adapter_config_assessment(&config_value, Some(&config))
        )),
        Err(err) => {
            DaedProductOutput::error(format!("resident adapter matrix config load failed: {err}"))
        }
    }
}

fn run_resident_adapter_udp_live_command(args: &[String]) -> DaedProductOutput {
    let (config, target, payload) = match parse_resident_adapter_udp_live_args(args) {
        Ok(parsed) => parsed,
        Err(err) => return DaedProductOutput::usage(err),
    };
    match load_config_file(&config) {
        Ok(config_value) => DaedProductOutput::ok(format!(
            "{}\n",
            resident_live_adapter_udp_probe(
                &config_value,
                target,
                payload.as_bytes(),
                Some(&config)
            )
        )),
        Err(err) => DaedProductOutput::error(format!(
            "resident adapter UDP live config load failed: {err}"
        )),
    }
}

fn run_state_command(args: &[String]) -> DaedProductOutput {
    match args.first().map(String::as_str) {
        Some("check") => match parse_state_check_args(&args[1..]) {
            Ok(state) => match state_check_report(&state) {
                Ok(report) => DaedProductOutput::ok(format!("{report}\n")),
                Err(err) => DaedProductOutput::error(format!("state check failed: {err}")),
            },
            Err(err) => DaedProductOutput::usage(err),
        },
        Some("migrate") => match parse_state_migrate_args(&args[1..]) {
            Ok((from_wing_db, to, force)) => match migrate_wing_db(&from_wing_db, &to, force) {
                Ok(report) => DaedProductOutput::ok(format!("{report}\n")),
                Err(err) => DaedProductOutput::error(format!("state migrate failed: {err}")),
            },
            Err(err) => DaedProductOutput::usage(err),
        },
        Some(command) => DaedProductOutput::usage(format!("unsupported state command: {command}")),
        None => DaedProductOutput::usage("state requires check or migrate"),
    }
}

fn parse_validate_args(args: &[String]) -> Result<(PathBuf, bool), String> {
    let mut config = None;
    let mut json_output = false;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-c" | "--config" => {
                let Some(value) = iter.next() else {
                    return Err("missing validate --config value".to_owned());
                };
                config = Some(PathBuf::from(value));
            }
            _ if arg.starts_with("--config=") => {
                config = arg.split_once('=').map(|(_, value)| PathBuf::from(value));
            }
            "--json" => json_output = true,
            other => return Err(format!("unsupported validate argument: {other}")),
        }
    }
    Ok((
        config.ok_or_else(|| "validate requires -c/--config".to_owned())?,
        json_output,
    ))
}

fn validate_product_config_path(path: &Path) -> Result<Value, String> {
    if path.is_file() {
        let entries = validate_config_file(path)?;
        return Ok(json!({
            "status": "pass",
            "kind": "dae-config-file",
            "path": path_string(path),
            "entries": entries,
            "readOnly": true,
            "mutationExecuted": false,
        }));
    }
    if path.is_dir() {
        return validate_product_config_dir(path);
    }
    Err(format!(
        "config path is neither file nor directory: {}",
        path_string(path)
    ))
}

fn validate_product_config_dir(config_dir: &Path) -> Result<Value, String> {
    let state = config_dir.join("daed.db");
    let state_present = state.is_file();
    let mut tables = Vec::new();
    let mut schema_ready = false;
    let mut user_count = Value::Null;
    if state_present {
        let conn = Connection::open_with_flags(&state, OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(|err| format!("failed to open state read-only: {err}"))?;
        tables = list_tables(&conn).map_err(|err| format!("failed to list state tables: {err}"))?;
        schema_ready = tables.iter().any(|name| name == "daed_product_metadata")
            && tables.iter().any(|name| name == "daed_schema_migrations")
            && tables.iter().any(|name| name == "users");
        if !schema_ready {
            return Err(format!(
                "state schema is not ready for read-only validation: {}",
                path_string(&state)
            ));
        }
        let users = conn
            .query_row("SELECT COUNT(*) FROM users", [], |row| row.get::<_, i64>(0))
            .map_err(|err| format!("failed to count users: {err}"))?;
        user_count = json!(users);
    }
    Ok(json!({
        "status": "pass",
        "kind": "daed-config-dir",
        "path": path_string(config_dir),
        "state": path_string(&state),
        "statePresent": state_present,
        "stateSchemaReady": schema_ready,
        "freshInstallStateOptional": !state_present,
        "userCount": user_count,
        "tables": tables,
        "primaryStateStore": PRIMARY_STATE_STORE,
        "protectedRollbackStateStore": PROTECTED_ROLLBACK_STATE_STORE,
        "rustDaedWritesWingDbByDefault": false,
        "readOnly": true,
        "mutationExecuted": false,
    }))
}

fn parse_resident_adapter_matrix_args(args: &[String]) -> Result<PathBuf, String> {
    let mut config = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "-c" | "--config" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(
                        "resident-adapter-matrix requires a value after -c/--config".to_owned()
                    );
                };
                config = Some(PathBuf::from(value));
            }
            "--json" => {}
            other => {
                return Err(format!(
                    "resident-adapter-matrix unsupported argument: {other}"
                ));
            }
        }
        index += 1;
    }
    config.ok_or_else(|| "resident-adapter-matrix requires -c/--config".to_owned())
}

fn parse_resident_adapter_udp_live_args(
    args: &[String],
) -> Result<(PathBuf, SocketAddrV4, String), String> {
    let mut config = None;
    let mut target = None;
    let mut payload = "daex-resident-udp-live".to_owned();
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "-c" | "--config" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(
                        "resident-adapter-udp-live requires a value after -c/--config".to_owned(),
                    );
                };
                config = Some(PathBuf::from(value));
            }
            "--target" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(
                        "resident-adapter-udp-live requires a value after --target".to_owned()
                    );
                };
                target = Some(value.parse::<SocketAddrV4>().map_err(|err| {
                    format!("resident-adapter-udp-live target must be IPv4 host:port: {err}")
                })?);
            }
            "--payload" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(
                        "resident-adapter-udp-live requires a value after --payload".to_owned()
                    );
                };
                if value.is_empty() {
                    return Err("resident-adapter-udp-live payload cannot be empty".to_owned());
                }
                payload = value.clone();
            }
            "--json" => {}
            other => {
                return Err(format!(
                    "resident-adapter-udp-live unsupported argument: {other}"
                ));
            }
        }
        index += 1;
    }
    Ok((
        config.ok_or_else(|| "resident-adapter-udp-live requires -c/--config".to_owned())?,
        target.ok_or_else(|| "resident-adapter-udp-live requires --target".to_owned())?,
        payload,
    ))
}

fn run_product_server_command(args: &[String], _version: &str) -> DaedProductOutput {
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
        if let Err(err) = restore_runtime_from_state(
            &runtime,
            &options.state,
            Some(&options.config_dir),
            ProductRuntimeLifecycleLogMode::StartupRestore,
        ) {
            let _ = append_lifecycle_log_for_config(
                &options.config_dir,
                &options.state,
                "error",
                &format!("[Startup] runtime restore failed: {err}"),
            );
            return DaedProductOutput::error(format!("startup runtime restore failed: {err}"));
        }
    }
    start_subscription_scheduler(options.state.clone(), options.config_dir.clone());
    let app = AppState {
        config_dir: options.config_dir,
        state: options.state,
        web_root: options.web_root,
        api_only: options.api_only,
        runtime,
        http_metrics: Arc::new(ProductHttpMetrics::default()),
    };
    match serve_forever(&options.listen, app, startup_started_at) {
        Ok(()) => DaedProductOutput::ok(String::new()),
        Err(err) => DaedProductOutput::error(format!("run failed: {err}")),
    }
}

fn restore_runtime_from_state(
    runtime: &ProductRuntimeManager,
    state: &Path,
    config_dir: Option<&Path>,
    log_mode: ProductRuntimeLifecycleLogMode,
) -> Result<Value, String> {
    let log_config_dir =
        config_dir.unwrap_or_else(|| state.parent().unwrap_or(Path::new(DEFAULT_CONFIG_DIR)));
    let lifecycle_started_at = Instant::now();
    let source = log_mode.source();
    let preview = materialize_runtime(state, config_dir, true).map_err(|err| err.to_string())?;
    let content = preview["content"]
        .as_str()
        .ok_or_else(|| "runtime materializer did not return content".to_owned())?;
    let config = build_runtime_config_from_content(content)?;
    set_runtime_log_level_from_config(state, &config).map_err(|err| err.to_string())?;
    let control_plane_started_at = Instant::now();
    let outcome = runtime.reload(config, source)?;
    if log_mode.is_startup() {
        let _ =
            append_startup_runtime_evidence_logs_for_config(log_config_dir, state, &outcome.report);
        let _ = append_startup_reclaim_decision_log_for_config(
            log_config_dir,
            state,
            &outcome.report,
            true,
        );
        let _ = append_startup_phase_completed_for_config(
            log_config_dir,
            state,
            "post-startup.gc",
            control_plane_started_at,
            BTreeMap::new(),
        );
        let _ = append_startup_phase_completed_for_config(
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
                let _ = append_startup_phase_failed_for_config(
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
        let _ = append_startup_phase_completed_for_config(
            log_config_dir,
            state,
            "control-plane.create.total",
            lifecycle_started_at,
            BTreeMap::new(),
        );
    }
    Ok(json!({
        "restored": true,
        "runtime": outcome.report,
        "materialized": applied,
    }))
}

fn should_restore_runtime_on_start(state: &Path) -> io::Result<bool> {
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

fn install_product_signal_thread(
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
                        Ok(_) => {
                            let mut fields = BTreeMap::new();
                            fields.insert("source".to_owned(), "signal".to_owned());
                            fields.insert("applied".to_owned(), "true".to_owned());
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
                    let _ = runtime.stop();
                    let _ = mark_runtime_process_stopped(&state);
                    let _ = append_lifecycle_log_for_config(
                        &config_dir,
                        &state,
                        "info",
                        "[Stop] runtime process stopped by signal",
                    );
                    std::process::exit(0);
                }
                _ => {}
            }
        }
    });
    Ok(())
}

fn block_product_signals() -> io::Result<()> {
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

fn wait_product_signal() -> io::Result<i32> {
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

fn run_export_command(args: &[String]) -> DaedProductOutput {
    match args.first().map(String::as_str) {
        Some("openapi") if args.len() == 1 => {
            DaedProductOutput::ok(format!("{}\n", product_openapi_skeleton()))
        }
        Some("flatdesc") if args.len() == 1 => {
            DaedProductOutput::ok(format!("{}\n", product_flatdesc()))
        }
        Some("outline") if args.len() == 1 => {
            DaedProductOutput::ok(format!("{}\n", product_outline()))
        }
        Some("package-manifest") if args.len() == 1 => {
            DaedProductOutput::ok(format!("{}\n", product_package_manifest()))
        }
        Some("admission-report") if args.len() == 1 => {
            DaedProductOutput::ok(format!("{}\n", product_admission_report()))
        }
        Some("webui-route-audit") if args.len() == 1 => {
            DaedProductOutput::ok(format!("{}\n", webui_route_audit_report()))
        }
        Some("systemd-unit") if args.len() == 1 => DaedProductOutput::ok(systemd_unit_text()),
        Some("docker-entrypoint") if args.len() == 1 => {
            DaedProductOutput::ok(docker_entrypoint_text())
        }
        Some(command) => DaedProductOutput::usage(format!("unsupported export command: {command}")),
        None => DaedProductOutput::usage(
            "export requires openapi, flatdesc, outline, package-manifest, admission-report, webui-route-audit, systemd-unit, or docker-entrypoint",
        ),
    }
}

fn run_resetpass_command(args: &[String]) -> DaedProductOutput {
    let mut config_dir = PathBuf::from(DEFAULT_CONFIG_DIR);
    let mut json_output = false;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-c" | "--config" => {
                let Some(value) = iter.next() else {
                    return DaedProductOutput::usage("missing resetpass --config value");
                };
                config_dir = value.into();
            }
            _ if arg.starts_with("--config=") => {
                config_dir = arg.split_once('=').unwrap().1.into();
            }
            "--json" => json_output = true,
            _ => return DaedProductOutput::usage(format!("unsupported resetpass argument: {arg}")),
        }
    }
    let state = config_dir.join("daed.db");
    match reset_all_user_passwords(&state) {
        Ok(report) if json_output => DaedProductOutput::ok(format!("{report}\n")),
        Ok(report) => {
            let mut out = String::new();
            let users = report["users"].as_array().cloned().unwrap_or_default();
            if users.is_empty() {
                out.push_str("No users found.\n");
            } else {
                for user in users {
                    out.push_str(&format!(
                        "Username: {}, Password: {}\n",
                        user["username"].as_str().unwrap_or(""),
                        user["password"].as_str().unwrap_or("")
                    ));
                }
            }
            DaedProductOutput::ok(out)
        }
        Err(err) => DaedProductOutput::error(format!("resetpass failed: {err}")),
    }
}

fn parse_run_args(args: &[String]) -> Result<RunOptions, String> {
    let mut config_dir = PathBuf::from(DEFAULT_CONFIG_DIR);
    let mut listen = DEFAULT_LISTEN.to_owned();
    let mut state: Option<PathBuf> = None;
    let mut web_root = std::env::var_os("DAED_WEB_ROOT")
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

fn parse_state_check_args(args: &[String]) -> Result<PathBuf, String> {
    let mut state: Option<PathBuf> = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--state" => {
                let Some(value) = iter.next() else {
                    return Err("missing state check --state value".to_owned());
                };
                state = Some(value.into());
            }
            _ if arg.starts_with("--state=") => {
                state = Some(arg.split_once('=').unwrap().1.into());
            }
            _ => return Err(format!("unsupported state check argument: {arg}")),
        }
    }
    state.ok_or_else(|| "state check requires --state".to_owned())
}

fn parse_state_migrate_args(args: &[String]) -> Result<(PathBuf, PathBuf, bool), String> {
    let mut from_wing_db: Option<PathBuf> = None;
    let mut to: Option<PathBuf> = None;
    let mut force = false;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--from-wing-db" => {
                let Some(value) = iter.next() else {
                    return Err("missing state migrate --from-wing-db value".to_owned());
                };
                from_wing_db = Some(value.into());
            }
            _ if arg.starts_with("--from-wing-db=") => {
                from_wing_db = Some(arg.split_once('=').unwrap().1.into());
            }
            "--to" => {
                let Some(value) = iter.next() else {
                    return Err("missing state migrate --to value".to_owned());
                };
                to = Some(value.into());
            }
            _ if arg.starts_with("--to=") => {
                to = Some(arg.split_once('=').unwrap().1.into());
            }
            "--force" => force = true,
            _ => return Err(format!("unsupported state migrate argument: {arg}")),
        }
    }
    let from_wing_db = from_wing_db
        .ok_or_else(|| "state migrate requires --from-wing-db /etc/daed/wing.db".to_owned())?;
    let to = to.ok_or_else(|| "state migrate requires --to /etc/daed/daed.db".to_owned())?;
    Ok((from_wing_db, to, force))
}
