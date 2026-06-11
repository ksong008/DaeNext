use super::*;
pub(crate) fn run_state_command(args: &[String]) -> DaedProductOutput {
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

pub(crate) fn parse_state_check_args(args: &[String]) -> Result<PathBuf, String> {
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

pub(crate) fn parse_state_migrate_args(
    args: &[String],
) -> Result<(PathBuf, PathBuf, bool), String> {
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
