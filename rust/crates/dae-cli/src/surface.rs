use crate::progress::{ABORT_FILE, PID_FILE_PATH, SIGNAL_PROGRESS_FILE_PATH};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandSpec {
    pub name: &'static str,
    pub use_line: &'static str,
    pub short: &'static str,
    pub hidden: bool,
    pub valid_args: &'static [&'static str],
    pub flags: &'static [&'static str],
    pub children: Vec<CommandSpec>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CliSurface {
    pub root_use: &'static str,
    pub root_short: &'static str,
    pub completion_default_cmd_disabled: bool,
    pub pid_file: &'static str,
    pub signal_progress_file: &'static str,
    pub abort_file: &'static str,
    pub commands: Vec<CommandSpec>,
}

pub fn cli_surface() -> CliSurface {
    CliSurface {
        root_use: "dae [flags] [command [argument ...]]",
        root_short: "dae is a high-performance transparent proxy solution.",
        completion_default_cmd_disabled: true,
        pid_file: PID_FILE_PATH,
        signal_progress_file: SIGNAL_PROGRESS_FILE_PATH,
        abort_file: ABORT_FILE,
        commands: vec![
            CommandSpec {
                name: "completion",
                use_line: "completion [bash|zsh|fish]",
                short: "Output shell completion code for the specified shell (bash, zsh or fish)",
                hidden: true,
                valid_args: &["bash", "zsh", "fish"],
                flags: &[],
                children: Vec::new(),
            },
            CommandSpec {
                name: "export",
                use_line: "export",
                short: "To export some information for UI developers.",
                hidden: false,
                valid_args: &[],
                flags: &[],
                children: vec![CommandSpec {
                    name: "outline",
                    use_line: "outline",
                    short: "To export config structure.",
                    hidden: false,
                    valid_args: &[],
                    flags: &[],
                    children: Vec::new(),
                }],
            },
            CommandSpec {
                name: "honk",
                use_line: "honk",
                short: "Let dae call for you.",
                hidden: false,
                valid_args: &[],
                flags: &[],
                children: Vec::new(),
            },
            CommandSpec {
                name: "reload",
                use_line: "reload [pid]",
                short: "To reload config file without interrupt connections.",
                hidden: false,
                valid_args: &[],
                flags: &["abort"],
                children: Vec::new(),
            },
            CommandSpec {
                name: "run",
                use_line: "run",
                short: "To run dae in the foreground.",
                hidden: false,
                valid_args: &[],
                flags: &[
                    "config",
                    "disable-pidfile",
                    "disable-sudo",
                    "disable-timestamp",
                    "logfile",
                    "logfile-maxbackups",
                    "logfile-maxsize",
                ],
                children: Vec::new(),
            },
            CommandSpec {
                name: "suspend",
                use_line: "suspend [pid]",
                short: "To suspend dae. This command puts dae into no-load state. Recover it by 'dae reload'.",
                hidden: false,
                valid_args: &[],
                flags: &["abort"],
                children: Vec::new(),
            },
            CommandSpec {
                name: "sysdump",
                use_line: "sysdump",
                short: "To dump up system network config",
                hidden: false,
                valid_args: &[],
                flags: &[],
                children: Vec::new(),
            },
            CommandSpec {
                name: "validate",
                use_line: "validate",
                short: "To validate dae config.",
                hidden: false,
                valid_args: &[],
                flags: &["config"],
                children: Vec::new(),
            },
        ],
    }
}
