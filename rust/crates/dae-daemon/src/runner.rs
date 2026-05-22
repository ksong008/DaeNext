use crate::identity::daemon_identity;
use crate::preflight::stage149_identity_preflight_report;

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
        Some("identity") | Some("stage149-identity-preflight") => {
            DaemonOutput::usage("unsupported dae-daemon-optin argument")
        }
        Some(command) => {
            DaemonOutput::usage(format!("unsupported dae-daemon-optin command: {command}"))
        }
        None => DaemonOutput::usage("missing dae-daemon-optin command"),
    }
}
