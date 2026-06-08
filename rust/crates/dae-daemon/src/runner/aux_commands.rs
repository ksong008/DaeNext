fn parse_attach_backend(value: &str) -> Option<AttachBackend> {
    match value {
        "auto" => Some(AttachBackend::Auto),
        "tcx" => Some(AttachBackend::Tcx),
        "tc-netlink" | "tc_netlink" => Some(AttachBackend::TcNetlink),
        "tc-command-fallback" | "tc_command_fallback" => Some(AttachBackend::TcCommandFallback),
        _ => None,
    }
}

fn run_rust_native_control_plane_admission_command(args: &[String]) -> DaemonOutput {
    let mut root = default_rust_native_control_plane_admission_root();
    let mut iterations = 10_000_u32;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--root" => {
                let Some(value) = iter.next() else {
                    return DaemonOutput::usage(
                        "missing rust-native-control-plane-admission --root value",
                    );
                };
                root = value.into();
            }
            _ if arg.starts_with("--root=") => {
                root = arg.split_once('=').unwrap().1.into();
            }
            "--iterations" => {
                let Some(value) = iter.next() else {
                    return DaemonOutput::usage(
                        "missing rust-native-control-plane-admission --iterations value",
                    );
                };
                iterations = match value.parse() {
                    Ok(value) => value,
                    Err(_) => {
                        return DaemonOutput::usage(
                            "invalid rust-native-control-plane-admission --iterations value",
                        );
                    }
                };
            }
            _ if arg.starts_with("--iterations=") => {
                iterations = match arg.split_once('=').unwrap().1.parse() {
                    Ok(value) => value,
                    Err(_) => {
                        return DaemonOutput::usage(
                            "invalid rust-native-control-plane-admission --iterations value",
                        );
                    }
                };
            }
            _ => {
                return DaemonOutput::usage(format!(
                    "unsupported rust-native-control-plane-admission argument: {arg}"
                ));
            }
        }
    }
    match rust_native_control_plane_admission_report(&root, iterations) {
        Ok(report) => DaemonOutput::ok(format!("{report}\n")),
        Err(err) => DaemonOutput {
            stdout: String::new(),
            stderr: format!("{err}\n"),
            exit_code: 1,
        },
    }
}

fn run_reload_owner_benchmark_command(args: &[String]) -> DaemonOutput {
    let mut root = default_reload_owner_benchmark_root();
    let mut iterations = 3_u32;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--root" => {
                let Some(value) = iter.next() else {
                    return DaemonOutput::usage("missing reload-owner-benchmark --root value");
                };
                root = value.into();
            }
            _ if arg.starts_with("--root=") => {
                root = arg.split_once('=').unwrap().1.into();
            }
            "--iterations" => {
                let Some(value) = iter.next() else {
                    return DaemonOutput::usage(
                        "missing reload-owner-benchmark --iterations value",
                    );
                };
                iterations = match value.parse() {
                    Ok(value) => value,
                    Err(_) => {
                        return DaemonOutput::usage(
                            "invalid reload-owner-benchmark --iterations value",
                        );
                    }
                };
            }
            _ if arg.starts_with("--iterations=") => {
                iterations = match arg.split_once('=').unwrap().1.parse() {
                    Ok(value) => value,
                    Err(_) => {
                        return DaemonOutput::usage(
                            "invalid reload-owner-benchmark --iterations value",
                        );
                    }
                };
            }
            _ => {
                return DaemonOutput::usage(format!(
                    "unsupported reload-owner-benchmark argument: {arg}"
                ));
            }
        }
    }
    match reload_owner_benchmark_report(&root, iterations) {
        Ok(report) => DaemonOutput::ok(format!("{report}\n")),
        Err(err) => DaemonOutput {
            stdout: String::new(),
            stderr: format!("{err}\n"),
            exit_code: 1,
        },
    }
}

fn run_reload_owner_handoff_smoke_command(args: &[String]) -> DaemonOutput {
    let mut root = default_reload_owner_handoff_root();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--root" => {
                let Some(value) = iter.next() else {
                    return DaemonOutput::usage("missing reload-owner-handoff-smoke --root value");
                };
                root = value.into();
            }
            _ if arg.starts_with("--root=") => {
                root = arg.split_once('=').unwrap().1.into();
            }
            _ => {
                return DaemonOutput::usage(format!(
                    "unsupported reload-owner-handoff-smoke argument: {arg}"
                ));
            }
        }
    }
    match reload_owner_handoff_smoke_report(&root) {
        Ok(report) => DaemonOutput::ok(format!("{report}\n")),
        Err(err) => DaemonOutput {
            stdout: String::new(),
            stderr: format!("{err}\n"),
            exit_code: 1,
        },
    }
}

fn run_listener_ebpf_preflight_command(args: &[String]) -> DaemonOutput {
    let mut root = default_listener_ebpf_preflight_root();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--root" => {
                let Some(value) = iter.next() else {
                    return DaemonOutput::usage("missing listener-ebpf-preflight --root value");
                };
                root = value.into();
            }
            _ if arg.starts_with("--root=") => {
                root = arg.split_once('=').unwrap().1.into();
            }
            _ => {
                return DaemonOutput::usage(format!(
                    "unsupported listener-ebpf-preflight argument: {arg}"
                ));
            }
        }
    }
    match listener_ebpf_preflight_report(&root) {
        Ok(report) => DaemonOutput::ok(format!("{report}\n")),
        Err(err) => DaemonOutput {
            stdout: String::new(),
            stderr: format!("{err}\n"),
            exit_code: 1,
        },
    }
}

fn run_control_plane_entrypoint_admission_command(args: &[String]) -> DaemonOutput {
    let mut root = default_control_plane_entrypoint_admission_root();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--root" => {
                let Some(value) = iter.next() else {
                    return DaemonOutput::usage(
                        "missing control-plane-entrypoint-admission --root value",
                    );
                };
                root = value.into();
            }
            _ if arg.starts_with("--root=") => {
                root = arg.split_once('=').unwrap().1.into();
            }
            _ => {
                return DaemonOutput::usage(format!(
                    "unsupported control-plane-entrypoint-admission argument: {arg}"
                ));
            }
        }
    }
    match control_plane_entrypoint_admission_report(&root) {
        Ok(report) => DaemonOutput::ok(format!("{report}\n")),
        Err(err) => DaemonOutput {
            stdout: String::new(),
            stderr: format!("{err}\n"),
            exit_code: 1,
        },
    }
}

fn run_default_run_identity_admission_command(args: &[String]) -> DaemonOutput {
    let mut opts =
        DefaultRunIdentityAdmissionOptions::under_root(default_run_identity_admission_root());
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--root" => {
                let Some(value) = iter.next() else {
                    return DaemonOutput::usage(
                        "missing default-run-identity-admission --root value",
                    );
                };
                opts = DefaultRunIdentityAdmissionOptions::under_root(value);
            }
            _ if arg.starts_with("--root=") => {
                opts =
                    DefaultRunIdentityAdmissionOptions::under_root(arg.split_once('=').unwrap().1);
            }
            "-c" | "--config" => {
                let Some(value) = iter.next() else {
                    return DaemonOutput::usage(
                        "missing default-run-identity-admission --config value",
                    );
                };
                opts.config = value.into();
            }
            _ if arg.starts_with("--config=") => {
                opts.config = arg.split_once('=').unwrap().1.into();
            }
            "--logfile" => {
                let Some(value) = iter.next() else {
                    return DaemonOutput::usage(
                        "missing default-run-identity-admission --logfile value",
                    );
                };
                opts.logfile = value.into();
            }
            _ if arg.starts_with("--logfile=") => {
                opts.logfile = arg.split_once('=').unwrap().1.into();
            }
            "--disable-timestamp" => opts.disable_timestamp = true,
            "--disable-pidfile" => opts.disable_pidfile = true,
            "--disable-sudo" => opts.disable_sudo = true,
            _ => {
                return DaemonOutput::usage(format!(
                    "unsupported default-run-identity-admission argument: {arg}"
                ));
            }
        }
    }
    match default_run_identity_admission_report(&opts) {
        Ok(report) => DaemonOutput::ok(format!("{report}\n")),
        Err(err) => DaemonOutput {
            stdout: String::new(),
            stderr: format!("{err}\n"),
            exit_code: 1,
        },
    }
}

fn run_run_entrypoint_preflight_command(args: &[String]) -> DaemonOutput {
    let mut root = default_run_entrypoint_preflight_root();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--root" => {
                let Some(value) = iter.next() else {
                    return DaemonOutput::usage("missing run-entrypoint-preflight --root value");
                };
                root = value.into();
            }
            _ if arg.starts_with("--root=") => {
                root = arg.split_once('=').unwrap().1.into();
            }
            _ => {
                return DaemonOutput::usage(format!(
                    "unsupported run-entrypoint-preflight argument: {arg}"
                ));
            }
        }
    }
    match run_entrypoint_preflight_report(&root) {
        Ok(report) => DaemonOutput::ok(format!("{report}\n")),
        Err(err) => DaemonOutput {
            stdout: String::new(),
            stderr: format!("{err}\n"),
            exit_code: 1,
        },
    }
}

fn run_signal_control_plane_smoke_command(args: &[String]) -> DaemonOutput {
    let mut root = default_signal_control_plane_smoke_root();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--root" => {
                let Some(value) = iter.next() else {
                    return DaemonOutput::usage("missing signal-control-plane-smoke --root value");
                };
                root = value.into();
            }
            _ if arg.starts_with("--root=") => {
                root = arg.split_once('=').unwrap().1.into();
            }
            _ => {
                return DaemonOutput::usage(format!(
                    "unsupported signal-control-plane-smoke argument: {arg}"
                ));
            }
        }
    }
    match signal_control_plane_smoke_report(&root) {
        Ok(report) => DaemonOutput::ok(format!("{report}\n")),
        Err(err) => DaemonOutput {
            stdout: String::new(),
            stderr: format!("{err}\n"),
            exit_code: 1,
        },
    }
}

fn run_lifecycle_smoke_command(args: &[String]) -> DaemonOutput {
    let mut root = default_lifecycle_smoke_root();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--root" => {
                let Some(value) = iter.next() else {
                    return DaemonOutput::usage("missing lifecycle-smoke --root value");
                };
                root = value.into();
            }
            _ if arg.starts_with("--root=") => {
                root = arg.split_once('=').unwrap().1.into();
            }
            _ => {
                return DaemonOutput::usage(format!("unsupported lifecycle-smoke argument: {arg}"));
            }
        }
    }
    match lifecycle_smoke_report(&root) {
        Ok(report) => DaemonOutput::ok(format!("{report}\n")),
        Err(err) => DaemonOutput {
            stdout: String::new(),
            stderr: format!("{err}\n"),
            exit_code: 1,
        },
    }
}

fn run_control_plane_owner_preflight_command(args: &[String]) -> DaemonOutput {
    let mut root = default_control_plane_owner_preflight_root();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--root" => {
                let Some(value) = iter.next() else {
                    return DaemonOutput::usage(
                        "missing control-plane-owner-preflight --root value",
                    );
                };
                root = value.into();
            }
            _ if arg.starts_with("--root=") => {
                root = arg.split_once('=').unwrap().1.into();
            }
            _ => {
                return DaemonOutput::usage(format!(
                    "unsupported control-plane-owner-preflight argument: {arg}"
                ));
            }
        }
    }
    match control_plane_owner_preflight_report(&root) {
        Ok(report) => DaemonOutput::ok(format!("{report}\n")),
        Err(err) => DaemonOutput {
            stdout: String::new(),
            stderr: format!("{err}\n"),
            exit_code: 1,
        },
    }
}
