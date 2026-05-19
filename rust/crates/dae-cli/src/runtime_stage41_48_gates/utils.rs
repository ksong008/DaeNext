use super::*;

pub(super) fn parse_common_args<F>(
    args: &[String],
    stage: &str,
    mut set: F,
) -> Result<(), RunnerOutput>
where
    F: FnMut(&str, String) -> Result<(), RunnerOutput>,
{
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if matches!(
            arg.as_str(),
            "--write-image"
                | "--require-admission"
                | "--execute-smoke"
                | "--ack-root-gate"
                | "--has-bpf-get-current-task"
                | "--no-bpf-get-current-task"
        ) {
            set(arg, String::new())?;
            continue;
        }
        if let Some((flag, value)) = arg.split_once('=') {
            set(flag, value.to_owned())?;
            continue;
        }
        let flag = arg.as_str();
        let value = iter
            .next()
            .cloned()
            .ok_or_else(|| RunnerOutput::usage(format!("missing value for {stage} {flag}")))?;
        set(flag, value)?;
    }
    Ok(())
}

pub(super) fn parse_param_arg(
    param: &mut ParamOptions,
    flag: &str,
    value: String,
) -> Result<(), RunnerOutput> {
    match flag {
        "--tproxy-port" => param.tproxy_port = parse_port(&value, flag)?,
        "--control-plane-pid" => param.control_plane_pid = parse_u32(&value, flag)?,
        "--dae0-ifindex" => param.dae0_ifindex = parse_u32(&value, flag)?,
        "--dae-netns-id" => param.dae_netns_id = parse_u32(&value, flag)?,
        "--dae0peer-mac" => param.dae0peer_mac = parse_mac(&value)?,
        "--has-bpf-get-current-task" => param.has_bpf_get_current_task = true,
        "--no-bpf-get-current-task" => param.has_bpf_get_current_task = false,
        _ => {
            return Err(RunnerOutput::usage(format!(
                "unsupported runtime stage41-48 argument: {flag}"
            )));
        }
    }
    Ok(())
}

pub(super) fn parse_port(value: &str, flag: &str) -> Result<u16, RunnerOutput> {
    value
        .parse::<u16>()
        .map_err(|err| RunnerOutput::usage(format!("invalid {flag}: {err}")))
        .and_then(|port| {
            if port == 0 {
                Err(RunnerOutput::usage(format!(
                    "invalid {flag}: must be non-zero"
                )))
            } else {
                Ok(port)
            }
        })
}

pub(super) fn parse_u32(value: &str, flag: &str) -> Result<u32, RunnerOutput> {
    value
        .parse::<u32>()
        .map_err(|err| RunnerOutput::usage(format!("invalid {flag}: {err}")))
        .and_then(|parsed| {
            if parsed == 0 {
                Err(RunnerOutput::usage(format!(
                    "invalid {flag}: must be non-zero"
                )))
            } else {
                Ok(parsed)
            }
        })
}

pub(super) fn parse_mac(value: &str) -> Result<[u8; 6], RunnerOutput> {
    let parts = value.split(':').collect::<Vec<_>>();
    if parts.len() != 6 {
        return Err(RunnerOutput::usage(
            "invalid --dae0peer-mac: expected six colon-separated hex octets",
        ));
    }
    let mut mac = [0_u8; 6];
    for (index, part) in parts.iter().enumerate() {
        if part.len() != 2 {
            return Err(RunnerOutput::usage(
                "invalid --dae0peer-mac: each octet must have two hex digits",
            ));
        }
        mac[index] = u8::from_str_radix(part, 16)
            .map_err(|err| RunnerOutput::usage(format!("invalid --dae0peer-mac: {err}")))?;
    }
    if mac == [0; 6] {
        return Err(RunnerOutput::usage(
            "invalid --dae0peer-mac: must be non-zero",
        ));
    }
    Ok(mac)
}

pub(super) fn push_check(
    checks: &mut Vec<Value>,
    name: &str,
    passed: bool,
    detail: Value,
    blockers: &mut Vec<String>,
    blocker: &str,
) {
    if !passed {
        blockers.push(blocker.to_owned());
    }
    checks.push(json!({
        "name": name,
        "status": if passed { "pass" } else { "fail" },
        "detail": detail,
        "blocker": if passed { Value::Null } else { Value::String(blocker.to_owned()) },
    }));
}

pub(super) fn tmp_root_allowed(path: &Path) -> bool {
    path.is_absolute()
        && path
            .parent()
            .map(|parent| parent == Path::new("/tmp"))
            .unwrap_or(false)
}

pub(super) fn command_exists(command: &str) -> bool {
    env::var_os("PATH").is_some_and(|paths| {
        env::split_paths(&paths).any(|dir| {
            let candidate = dir.join(command);
            candidate.is_file()
        })
    })
}

pub(super) fn iface_name_valid(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 15
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

pub(super) fn iface_exists(iface: &str) -> bool {
    Command::new("ip")
        .args(["link", "show", "dev", iface])
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

pub(super) fn iface_leftovers(iface: &str) -> Vec<String> {
    if iface_exists(iface) {
        vec![format!("iface:{iface}")]
    } else {
        Vec::new()
    }
}

pub(super) struct CommandSpec<'a> {
    program: &'a str,
    args: Vec<&'a str>,
}

impl<'a> CommandSpec<'a> {
    pub(super) fn new(program: &'a str, args: &[&'a str]) -> Self {
        Self {
            program,
            args: args.to_vec(),
        }
    }
}

pub(super) fn run_step(steps: &mut Vec<Value>, name: &str, spec: CommandSpec<'_>) -> bool {
    let output = Command::new(spec.program).args(&spec.args).output();
    let (status, code, stdout, stderr) = command_output(output);
    steps.push(json!({
        "name": name,
        "status": status,
        "program": spec.program,
        "args": spec.args,
        "exit_code": code,
        "stdout": stdout,
        "stderr": stderr,
    }));
    status == "pass"
}

pub(super) fn run_observation_step(
    steps: &mut Vec<Value>,
    name: &str,
    spec: CommandSpec<'_>,
) -> Value {
    let output = Command::new(spec.program).args(&spec.args).output();
    let (status, code, stdout, stderr) = command_output(output);
    let value = json!({
        "name": name,
        "status": status,
        "program": spec.program,
        "args": spec.args,
        "exit_code": code,
        "stdout": stdout,
        "stderr": stderr,
    });
    steps.push(value.clone());
    value
}

pub(super) fn command_output(
    output: std::io::Result<std::process::Output>,
) -> (&'static str, Option<i32>, String, String) {
    match output {
        Ok(output) => (
            if output.status.success() {
                "pass"
            } else {
                "fail"
            },
            output.status.code(),
            String::from_utf8_lossy(&output.stdout).trim().to_owned(),
            String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        ),
        Err(err) => ("fail", None, String::new(), err.to_string()),
    }
}

pub(super) fn mac_string(mac: [u8; 6]) -> String {
    mac.iter()
        .map(|octet| format!("{octet:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

pub(super) fn path_string(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}
