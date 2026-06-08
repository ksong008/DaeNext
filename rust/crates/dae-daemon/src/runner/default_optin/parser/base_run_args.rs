use super::*;
pub(crate) fn parse_base_run_arg<'a>(
    arg: &str,
    iter: &mut std::slice::Iter<'a, String>,
    state: &mut DefaultOptinParsedArgs,
) -> Result<bool, DaemonOutput> {
    macro_rules! usage {
        ($($arg:tt)*) => {
            return Err(DaemonOutput::usage($($arg)*))
        };
    }
    match arg {
        "-c" | "--config" => {
            let Some(value) = iter.next() else {
                usage!("missing run --config value");
            };
            state.config = Some(value.into());
        }
        _ if arg.starts_with("--config=") => {
            state.config = arg.split_once('=').map(|(_, value)| value.into());
        }
        "--root" => {
            let Some(value) = iter.next() else {
                usage!("missing run --root value");
            };
            state.root = value.into();
            state.root_explicit = true;
        }
        _ if arg.starts_with("--root=") => {
            state.root = arg.split_once('=').unwrap().1.into();
            state.root_explicit = true;
        }
        "--logfile" => {
            let Some(value) = iter.next() else {
                usage!("missing run --logfile value");
            };
            state.logfile = Some(value.into());
        }
        _ if arg.starts_with("--logfile=") => {
            state.logfile = arg.split_once('=').map(|(_, value)| value.into());
        }
        "--service-pid-file" => {
            let Some(value) = iter.next() else {
                usage!("missing run --service-pid-file value");
            };
            state.service_pid_file = Some(value.into());
        }
        _ if arg.starts_with("--service-pid-file=") => {
            state.service_pid_file = arg.split_once('=').map(|(_, value)| value.into());
        }
        "--service-progress-file" => {
            let Some(value) = iter.next() else {
                usage!("missing run --service-progress-file value");
            };
            state.service_progress_file = Some(value.into());
        }
        _ if arg.starts_with("--service-progress-file=") => {
            state.service_progress_file = arg.split_once('=').map(|(_, value)| value.into());
        }
        "--service-abort-file" => {
            let Some(value) = iter.next() else {
                usage!("missing run --service-abort-file value");
            };
            state.service_abort_file = Some(value.into());
        }
        _ if arg.starts_with("--service-abort-file=") => {
            state.service_abort_file = arg.split_once('=').map(|(_, value)| value.into());
        }
        "--service-ready-file" => {
            let Some(value) = iter.next() else {
                usage!("missing run --service-ready-file value");
            };
            state.service_ready_file = Some(value.into());
        }
        _ if arg.starts_with("--service-ready-file=") => {
            state.service_ready_file = arg.split_once('=').map(|(_, value)| value.into());
        }
        "--disable-timestamp" => state.disable_timestamp = true,
        "--disable-pidfile" => state.disable_pidfile = true,
        "--disable-sudo" => state.disable_sudo = true,
        "--no-listener-smoke" => state.listener_smoke = false,
        "--no-reload-smoke" => state.reload_smoke = false,
        _ => return Ok(false),
    }
    Ok(true)
}
