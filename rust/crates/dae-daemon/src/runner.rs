use crate::identity::daemon_identity;
use crate::lifecycle::{default_stage150_root, stage150_lifecycle_smoke_report};
use crate::preflight::stage149_identity_preflight_report;
use crate::{RunOptions, default_run_root, run_default_optin_report};
use crate::{
    Stage156DefaultRunIdentityOptions, default_stage156_root,
    stage156_default_run_identity_admission_report,
};
use crate::{default_stage151_root, stage151_control_plane_owner_preflight_report};
use crate::{default_stage152_root, stage152_signal_control_plane_smoke_report};
use crate::{default_stage153_root, stage153_run_entrypoint_preflight_report};
use crate::{default_stage157_root, stage157_control_plane_entrypoint_admission_report};
use crate::{default_stage160_root, stage160_listener_ebpf_preflight_harness_report};
use crate::{default_stage165_root, stage165_reload_owner_handoff_smoke_report};
use crate::{default_stage167_root, stage167_reload_owner_benchmark_report};
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonOutput {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
}

impl DaemonOutput {
    fn ok(stdout: String) -> Self {
        Self {
            stdout,
            stderr: String::new(),
            exit_code: 0,
        }
    }

    fn usage(message: impl Into<String>) -> Self {
        Self {
            stdout: String::new(),
            stderr: format!("{}\n", message.into()),
            exit_code: 2,
        }
    }
}

pub fn run_with_args_and_version(
    args: impl IntoIterator<Item = impl Into<String>>,
    version: &str,
) -> DaemonOutput {
    let args = args.into_iter().map(Into::into).collect::<Vec<_>>();
    match args.first().map(String::as_str) {
        Some("identity") if args.len() == 1 => {
            DaemonOutput::ok(format!("{}\n", daemon_identity(version)))
        }
        Some("run") => run_default_optin_command(&args[1..], version),
        Some("stage149-identity-preflight") if args.len() == 1 => {
            DaemonOutput::ok(format!("{}\n", stage149_identity_preflight_report(version)))
        }
        Some("stage150-lifecycle-smoke") => run_stage150_lifecycle_smoke_command(&args[1..]),
        Some("stage151-control-plane-owner-preflight") => {
            run_stage151_control_plane_owner_preflight_command(&args[1..])
        }
        Some("stage152-signal-control-plane-smoke") => {
            run_stage152_signal_control_plane_smoke_command(&args[1..])
        }
        Some("stage153-run-entrypoint-preflight") => {
            run_stage153_run_entrypoint_preflight_command(&args[1..])
        }
        Some("stage156-default-run-identity-admission") => {
            run_stage156_default_run_identity_admission_command(&args[1..])
        }
        Some("stage157-control-plane-entrypoint-admission") => {
            run_stage157_control_plane_entrypoint_admission_command(&args[1..])
        }
        Some("stage160-listener-ebpf-preflight-harness") => {
            run_stage160_listener_ebpf_preflight_harness_command(&args[1..])
        }
        Some("stage165-reload-owner-handoff-smoke") => {
            run_stage165_reload_owner_handoff_smoke_command(&args[1..])
        }
        Some("stage167-reload-owner-benchmark") => {
            run_stage167_reload_owner_benchmark_command(&args[1..])
        }
        Some("identity") | Some("stage149-identity-preflight") => {
            DaemonOutput::usage("unsupported dae-daemon-optin argument")
        }
        Some(command) => {
            DaemonOutput::usage(format!("unsupported dae-daemon-optin command: {command}"))
        }
        None => DaemonOutput::usage("missing dae-daemon-optin command"),
    }
}

fn run_default_optin_command(args: &[String], version: &str) -> DaemonOutput {
    let mut root = default_run_root();
    let mut config: Option<PathBuf> = None;
    let mut logfile: Option<PathBuf> = None;
    let mut disable_timestamp = false;
    let mut disable_pidfile = false;
    let mut disable_sudo = false;
    let mut listener_smoke = true;
    let mut reload_smoke = true;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-c" | "--config" => {
                let Some(value) = iter.next() else {
                    return DaemonOutput::usage("missing run --config value");
                };
                config = Some(value.into());
            }
            _ if arg.starts_with("--config=") => {
                config = arg.split_once('=').map(|(_, value)| value.into());
            }
            "--root" => {
                let Some(value) = iter.next() else {
                    return DaemonOutput::usage("missing run --root value");
                };
                root = value.into();
            }
            _ if arg.starts_with("--root=") => {
                root = arg.split_once('=').unwrap().1.into();
            }
            "--logfile" => {
                let Some(value) = iter.next() else {
                    return DaemonOutput::usage("missing run --logfile value");
                };
                logfile = Some(value.into());
            }
            _ if arg.starts_with("--logfile=") => {
                logfile = arg.split_once('=').map(|(_, value)| value.into());
            }
            "--disable-timestamp" => disable_timestamp = true,
            "--disable-pidfile" => disable_pidfile = true,
            "--disable-sudo" => disable_sudo = true,
            "--no-listener-smoke" => listener_smoke = false,
            "--no-reload-smoke" => reload_smoke = false,
            "--exit-after-ready" | "--once" => {}
            _ => return DaemonOutput::usage(format!("unsupported run argument: {arg}")),
        }
    }
    let Some(config) = config else {
        return DaemonOutput::usage("run requires -c/--config");
    };
    let mut options = RunOptions::under_root(root, config);
    if let Some(logfile) = logfile {
        options.logfile = logfile;
    }
    options.disable_timestamp = disable_timestamp;
    options.disable_pidfile = disable_pidfile;
    options.disable_sudo = disable_sudo;
    options.listener_smoke = listener_smoke;
    options.reload_smoke = reload_smoke;

    match run_default_optin_report(&options, version) {
        Ok(report) => DaemonOutput::ok(format!("{report}\n")),
        Err(err) => DaemonOutput {
            stdout: String::new(),
            stderr: format!("{err}\n"),
            exit_code: 1,
        },
    }
}

fn run_stage167_reload_owner_benchmark_command(args: &[String]) -> DaemonOutput {
    let mut root = default_stage167_root();
    let mut iterations = 3_u32;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--root" => {
                let Some(value) = iter.next() else {
                    return DaemonOutput::usage("missing stage167 --root value");
                };
                root = value.into();
            }
            _ if arg.starts_with("--root=") => {
                root = arg.split_once('=').unwrap().1.into();
            }
            "--iterations" => {
                let Some(value) = iter.next() else {
                    return DaemonOutput::usage("missing stage167 --iterations value");
                };
                iterations = match value.parse() {
                    Ok(value) => value,
                    Err(_) => return DaemonOutput::usage("invalid stage167 --iterations value"),
                };
            }
            _ if arg.starts_with("--iterations=") => {
                iterations = match arg.split_once('=').unwrap().1.parse() {
                    Ok(value) => value,
                    Err(_) => return DaemonOutput::usage("invalid stage167 --iterations value"),
                };
            }
            _ => {
                return DaemonOutput::usage(format!(
                    "unsupported stage167 reload owner benchmark argument: {arg}"
                ));
            }
        }
    }
    match stage167_reload_owner_benchmark_report(&root, iterations) {
        Ok(report) => DaemonOutput::ok(format!("{report}\n")),
        Err(err) => DaemonOutput {
            stdout: String::new(),
            stderr: format!("{err}\n"),
            exit_code: 1,
        },
    }
}

fn run_stage165_reload_owner_handoff_smoke_command(args: &[String]) -> DaemonOutput {
    let mut root = default_stage165_root();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--root" => {
                let Some(value) = iter.next() else {
                    return DaemonOutput::usage("missing stage165 --root value");
                };
                root = value.into();
            }
            _ if arg.starts_with("--root=") => {
                root = arg.split_once('=').unwrap().1.into();
            }
            _ => {
                return DaemonOutput::usage(format!(
                    "unsupported stage165 reload owner handoff argument: {arg}"
                ));
            }
        }
    }
    match stage165_reload_owner_handoff_smoke_report(&root) {
        Ok(report) => DaemonOutput::ok(format!("{report}\n")),
        Err(err) => DaemonOutput {
            stdout: String::new(),
            stderr: format!("{err}\n"),
            exit_code: 1,
        },
    }
}

fn run_stage160_listener_ebpf_preflight_harness_command(args: &[String]) -> DaemonOutput {
    let mut root = default_stage160_root();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--root" => {
                let Some(value) = iter.next() else {
                    return DaemonOutput::usage("missing stage160 --root value");
                };
                root = value.into();
            }
            _ if arg.starts_with("--root=") => {
                root = arg.split_once('=').unwrap().1.into();
            }
            _ => {
                return DaemonOutput::usage(format!(
                    "unsupported stage160 listener/eBPF preflight argument: {arg}"
                ));
            }
        }
    }
    match stage160_listener_ebpf_preflight_harness_report(&root) {
        Ok(report) => DaemonOutput::ok(format!("{report}\n")),
        Err(err) => DaemonOutput {
            stdout: String::new(),
            stderr: format!("{err}\n"),
            exit_code: 1,
        },
    }
}

fn run_stage157_control_plane_entrypoint_admission_command(args: &[String]) -> DaemonOutput {
    let mut root = default_stage157_root();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--root" => {
                let Some(value) = iter.next() else {
                    return DaemonOutput::usage("missing stage157 --root value");
                };
                root = value.into();
            }
            _ if arg.starts_with("--root=") => {
                root = arg.split_once('=').unwrap().1.into();
            }
            _ => {
                return DaemonOutput::usage(format!(
                    "unsupported stage157 control-plane entrypoint argument: {arg}"
                ));
            }
        }
    }
    match stage157_control_plane_entrypoint_admission_report(&root) {
        Ok(report) => DaemonOutput::ok(format!("{report}\n")),
        Err(err) => DaemonOutput {
            stdout: String::new(),
            stderr: format!("{err}\n"),
            exit_code: 1,
        },
    }
}

fn run_stage156_default_run_identity_admission_command(args: &[String]) -> DaemonOutput {
    let mut opts = Stage156DefaultRunIdentityOptions::under_root(default_stage156_root());
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--root" => {
                let Some(value) = iter.next() else {
                    return DaemonOutput::usage("missing stage156 --root value");
                };
                opts = Stage156DefaultRunIdentityOptions::under_root(value);
            }
            _ if arg.starts_with("--root=") => {
                opts =
                    Stage156DefaultRunIdentityOptions::under_root(arg.split_once('=').unwrap().1);
            }
            "-c" | "--config" => {
                let Some(value) = iter.next() else {
                    return DaemonOutput::usage("missing stage156 --config value");
                };
                opts.config = value.into();
            }
            _ if arg.starts_with("--config=") => {
                opts.config = arg.split_once('=').unwrap().1.into();
            }
            "--logfile" => {
                let Some(value) = iter.next() else {
                    return DaemonOutput::usage("missing stage156 --logfile value");
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
                    "unsupported stage156 default run identity argument: {arg}"
                ));
            }
        }
    }
    match stage156_default_run_identity_admission_report(&opts) {
        Ok(report) => DaemonOutput::ok(format!("{report}\n")),
        Err(err) => DaemonOutput {
            stdout: String::new(),
            stderr: format!("{err}\n"),
            exit_code: 1,
        },
    }
}

fn run_stage153_run_entrypoint_preflight_command(args: &[String]) -> DaemonOutput {
    let mut root = default_stage153_root();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--root" => {
                let Some(value) = iter.next() else {
                    return DaemonOutput::usage("missing stage153 --root value");
                };
                root = value.into();
            }
            _ if arg.starts_with("--root=") => {
                root = arg.split_once('=').unwrap().1.into();
            }
            _ => {
                return DaemonOutput::usage(format!(
                    "unsupported stage153 run entrypoint argument: {arg}"
                ));
            }
        }
    }
    match stage153_run_entrypoint_preflight_report(&root) {
        Ok(report) => DaemonOutput::ok(format!("{report}\n")),
        Err(err) => DaemonOutput {
            stdout: String::new(),
            stderr: format!("{err}\n"),
            exit_code: 1,
        },
    }
}

fn run_stage152_signal_control_plane_smoke_command(args: &[String]) -> DaemonOutput {
    let mut root = default_stage152_root();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--root" => {
                let Some(value) = iter.next() else {
                    return DaemonOutput::usage("missing stage152 --root value");
                };
                root = value.into();
            }
            _ if arg.starts_with("--root=") => {
                root = arg.split_once('=').unwrap().1.into();
            }
            _ => {
                return DaemonOutput::usage(format!(
                    "unsupported stage152 signal control-plane argument: {arg}"
                ));
            }
        }
    }
    match stage152_signal_control_plane_smoke_report(&root) {
        Ok(report) => DaemonOutput::ok(format!("{report}\n")),
        Err(err) => DaemonOutput {
            stdout: String::new(),
            stderr: format!("{err}\n"),
            exit_code: 1,
        },
    }
}

fn run_stage150_lifecycle_smoke_command(args: &[String]) -> DaemonOutput {
    let mut root = default_stage150_root();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--root" => {
                let Some(value) = iter.next() else {
                    return DaemonOutput::usage("missing stage150 --root value");
                };
                root = value.into();
            }
            _ if arg.starts_with("--root=") => {
                root = arg.split_once('=').unwrap().1.into();
            }
            _ => {
                return DaemonOutput::usage(format!(
                    "unsupported stage150 lifecycle argument: {arg}"
                ));
            }
        }
    }
    match stage150_lifecycle_smoke_report(&root) {
        Ok(report) => DaemonOutput::ok(format!("{report}\n")),
        Err(err) => DaemonOutput {
            stdout: String::new(),
            stderr: format!("{err}\n"),
            exit_code: 1,
        },
    }
}

fn run_stage151_control_plane_owner_preflight_command(args: &[String]) -> DaemonOutput {
    let mut root = default_stage151_root();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--root" => {
                let Some(value) = iter.next() else {
                    return DaemonOutput::usage("missing stage151 --root value");
                };
                root = value.into();
            }
            _ if arg.starts_with("--root=") => {
                root = arg.split_once('=').unwrap().1.into();
            }
            _ => {
                return DaemonOutput::usage(format!(
                    "unsupported stage151 control-plane owner argument: {arg}"
                ));
            }
        }
    }
    match stage151_control_plane_owner_preflight_report(&root) {
        Ok(report) => DaemonOutput::ok(format!("{report}\n")),
        Err(err) => DaemonOutput {
            stdout: String::new(),
            stderr: format!("{err}\n"),
            exit_code: 1,
        },
    }
}
