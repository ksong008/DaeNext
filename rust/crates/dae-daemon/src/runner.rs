use crate::identity::daemon_identity;
use crate::lifecycle::{default_stage150_root, stage150_lifecycle_smoke_report};
use crate::preflight::stage149_identity_preflight_report;
use crate::{default_stage151_root, stage151_control_plane_owner_preflight_report};
use crate::{default_stage152_root, stage152_signal_control_plane_smoke_report};

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
        Some("identity") | Some("stage149-identity-preflight") => {
            DaemonOutput::usage("unsupported dae-daemon-optin argument")
        }
        Some(command) => {
            DaemonOutput::usage(format!("unsupported dae-daemon-optin command: {command}"))
        }
        None => DaemonOutput::usage("missing dae-daemon-optin command"),
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
