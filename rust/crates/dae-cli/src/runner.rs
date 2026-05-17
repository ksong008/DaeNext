use crate::{export_outline_json, validate_config_file};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunnerOutput {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl RunnerOutput {
    fn ok(stdout: String) -> Self {
        Self {
            exit_code: 0,
            stdout,
            stderr: String::new(),
        }
    }

    fn stdout_error(message: impl Into<String>) -> Self {
        Self {
            exit_code: 1,
            stdout: format!("{}\n", message.into()),
            stderr: String::new(),
        }
    }

    fn usage(message: impl Into<String>) -> Self {
        Self {
            exit_code: 2,
            stdout: String::new(),
            stderr: format!("{}\n", message.into()),
        }
    }
}

pub fn run_with_args<I, S>(args: I) -> RunnerOutput
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    run_with_args_and_version(args, "unknown")
}

pub fn run_with_args_and_version<I, S>(args: I, version: &str) -> RunnerOutput
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let args = args.into_iter().map(Into::into).collect::<Vec<_>>();
    match args.first().map(String::as_str) {
        Some("validate") => run_validate(&args[1..]),
        Some("export") => run_export(&args[1..], version),
        Some(command) => RunnerOutput::usage(format!("unsupported command: {command}")),
        None => RunnerOutput::usage("missing command"),
    }
}

fn run_validate(args: &[String]) -> RunnerOutput {
    let Some(path) = parse_config_arg(args) else {
        return RunnerOutput::stdout_error(
            r#"Argument "--config" or "-c" is required but not provided."#,
        );
    };
    match validate_config_file(path) {
        Ok(_) => RunnerOutput::ok(String::new()),
        Err(err) => RunnerOutput::stdout_error(err.to_string()),
    }
}

fn parse_config_arg(args: &[String]) -> Option<&str> {
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-c" | "--config" => return iter.next().map(String::as_str),
            _ if arg.starts_with("--config=") => {
                return arg.split_once('=').map(|(_, value)| value);
            }
            _ => {}
        }
    }
    None
}

fn run_export(args: &[String], version: &str) -> RunnerOutput {
    match args {
        [subcommand] if subcommand == "outline" => {
            RunnerOutput::ok(format!("{}\n", export_outline_json(version)))
        }
        [] => RunnerOutput::usage("missing export subcommand"),
        [subcommand, ..] => {
            RunnerOutput::usage(format!("unsupported export subcommand: {subcommand}"))
        }
    }
}
