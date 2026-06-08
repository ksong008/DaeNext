fn run_validate_command(args: &[String]) -> DaemonOutput {
    let mut config: Option<PathBuf> = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-c" | "--config" => {
                let Some(value) = iter.next() else {
                    return DaemonOutput::usage("missing validate --config value");
                };
                config = Some(value.into());
            }
            _ if arg.starts_with("--config=") => {
                config = arg.split_once('=').map(|(_, value)| value.into());
            }
            _ => return DaemonOutput::usage(format!("unsupported validate argument: {arg}")),
        }
    }
    let Some(config) = config else {
        return DaemonOutput::usage("validate requires -c/--config");
    };
    match validate_config_file(&config) {
        Ok(_) => DaemonOutput::ok(String::new()),
        Err(err) => DaemonOutput::error(format!("validate config failed: {err}")),
    }
}

fn run_reload_command(args: &[String]) -> DaemonOutput {
    let mut options = ReloadOptions::default();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-a" | "--abort" => options.abort_connections = true,
            "--service-pid-file" => {
                let Some(value) = iter.next() else {
                    return DaemonOutput::usage("missing reload --service-pid-file value");
                };
                options.pid_file = value.into();
            }
            _ if arg.starts_with("--service-pid-file=") => {
                options.pid_file = arg.split_once('=').unwrap().1.into();
            }
            "--service-progress-file" => {
                let Some(value) = iter.next() else {
                    return DaemonOutput::usage("missing reload --service-progress-file value");
                };
                options.progress_file = value.into();
            }
            _ if arg.starts_with("--service-progress-file=") => {
                options.progress_file = arg.split_once('=').unwrap().1.into();
            }
            "--service-abort-file" => {
                let Some(value) = iter.next() else {
                    return DaemonOutput::usage("missing reload --service-abort-file value");
                };
                options.abort_file = value.into();
            }
            _ if arg.starts_with("--service-abort-file=") => {
                options.abort_file = arg.split_once('=').unwrap().1.into();
            }
            "--timeout-ms" => {
                let Some(value) = iter.next() else {
                    return DaemonOutput::usage("missing reload --timeout-ms value");
                };
                options.timeout = match value.parse::<u64>() {
                    Ok(value) => Some(Duration::from_millis(value)),
                    Err(_) => return DaemonOutput::usage("invalid reload --timeout-ms value"),
                };
            }
            _ if arg.starts_with("--timeout-ms=") => {
                options.timeout = match arg.split_once('=').unwrap().1.parse::<u64>() {
                    Ok(value) => Some(Duration::from_millis(value)),
                    Err(_) => return DaemonOutput::usage("invalid reload --timeout-ms value"),
                };
            }
            _ if arg.starts_with('-') => {
                return DaemonOutput::usage(format!("unsupported reload argument: {arg}"));
            }
            _ if options.pid.is_none() => {
                options.pid = match arg.parse::<i32>() {
                    Ok(value) => Some(value),
                    Err(_) => return DaemonOutput::usage("invalid reload pid value"),
                };
            }
            _ => return DaemonOutput::usage("reload accepts at most one pid value"),
        }
    }
    match reload_resident_service(&options) {
        Ok(stdout) => DaemonOutput::ok(stdout),
        Err(err) => DaemonOutput::error(err),
    }
}
