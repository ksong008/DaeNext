use super::*;

pub(super) fn wait_for_loaded_map_cleanup(discovered_map_ids: &[Option<u32>]) -> (Vec<u32>, bool) {
    let ids = discovered_map_ids
        .iter()
        .filter_map(|id| *id)
        .collect::<Vec<_>>();
    let mut current = map_ids().unwrap_or_default();
    if ids.iter().all(|id| !current.contains(id)) {
        return (current, true);
    }
    for _ in 0..20 {
        thread::sleep(Duration::from_millis(50));
        current = map_ids().unwrap_or_default();
        if ids.iter().all(|id| !current.contains(id)) {
            return (current, true);
        }
    }
    (current, false)
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

pub(super) fn iface_exists(iface: &str) -> bool {
    Command::new("ip")
        .args(["link", "show", "dev", iface])
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

pub(super) fn netns_exists(name: &str) -> bool {
    ["/var/run/netns", "/run/netns"]
        .into_iter()
        .any(|parent| PathBuf::from(parent).join(name).exists())
}

pub(super) fn resource_leftovers() -> Vec<String> {
    let mut leftovers = Vec::new();
    for iface in [
        PRODUCTION_HOST_IFACE,
        PRODUCTION_PEER_IFACE,
        LAN_HOST_IFACE,
        LAN_CLIENT_IFACE,
    ] {
        if iface_exists(iface) {
            leftovers.push(format!("iface:{iface}"));
        }
    }
    for netns in [PRODUCTION_NETNS, CLIENT_NETNS] {
        if netns_exists(netns) {
            leftovers.push(format!("netns:{netns}"));
        }
    }
    leftovers
}

pub(super) fn bpf_dae_snapshot() -> Vec<String> {
    let path = Path::new("/sys/fs/bpf/dae");
    let Ok(entries) = fs::read_dir(path) else {
        return Vec::new();
    };
    let mut names = entries
        .flatten()
        .filter_map(|entry| entry.file_name().into_string().ok())
        .collect::<Vec<_>>();
    names.sort();
    names
}

pub(super) fn tproxy_port_available(port: u16) -> bool {
    TcpListener::bind(("127.0.0.1", port)).is_ok() && UdpSocket::bind(("127.0.0.1", port)).is_ok()
}

pub(super) fn map_json(info: &RuntimeMapInfo) -> Value {
    json!({
        "id": info.id,
        "name": info.name,
        "map_type": info.map_type,
        "key_size": info.key_size,
        "value_size": info.value_size,
        "max_entries": info.max_entries,
        "flags": info.flags,
    })
}

pub(super) struct CommandSpec<'a> {
    pub(super) program: &'a str,
    pub(super) args: Vec<&'a str>,
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
    let value = run_observation_command(spec);
    let status = value["status"].as_str() == Some("pass");
    let mut with_name = value;
    with_name["name"] = json!(name);
    steps.push(with_name);
    status
}

pub(super) fn run_cleanup_step(steps: &mut Vec<Value>, name: &str, spec: CommandSpec<'_>) {
    let mut value = run_observation_command(spec);
    value["name"] = json!(name);
    steps.push(value);
}

pub(super) fn run_observation_step(
    steps: &mut Vec<Value>,
    name: &str,
    spec: CommandSpec<'_>,
) -> Value {
    let mut value = run_observation_command(spec);
    value["name"] = json!(name);
    steps.push(value.clone());
    value
}

pub(super) fn run_observation_command(spec: CommandSpec<'_>) -> Value {
    let output = Command::new(spec.program).args(&spec.args).output();
    let (status, code, stdout, stderr) = command_output(output);
    json!({
        "name": Value::Null,
        "status": status,
        "program": spec.program,
        "args": spec.args,
        "exit_code": code,
        "stdout": stdout,
        "stderr": stderr,
    })
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

pub(super) fn parse_step_u32(step: &Value) -> Result<u32, String> {
    if step["status"].as_str() != Some("pass") {
        return Err(step["stderr"]
            .as_str()
            .unwrap_or("command failed")
            .to_owned());
    }
    step["stdout"]
        .as_str()
        .unwrap_or_default()
        .trim()
        .parse::<u32>()
        .map_err(|err| err.to_string())
        .and_then(|value| {
            if value == 0 {
                Err("value must be non-zero".to_owned())
            } else {
                Ok(value)
            }
        })
}

pub(super) fn parse_step_mac(step: &Value) -> Result<[u8; 6], String> {
    if step["status"].as_str() != Some("pass") {
        return Err(step["stderr"]
            .as_str()
            .unwrap_or("command failed")
            .to_owned());
    }
    parse_mac(step["stdout"].as_str().unwrap_or_default())
}

pub(super) fn parse_mac(value: &str) -> Result<[u8; 6], String> {
    let parts = value.trim().split(':').collect::<Vec<_>>();
    if parts.len() != 6 {
        return Err("expected six colon-separated hex octets".to_owned());
    }
    let mut mac = [0_u8; 6];
    for (index, part) in parts.iter().enumerate() {
        if part.len() != 2 {
            return Err("each octet must have two hex digits".to_owned());
        }
        mac[index] = u8::from_str_radix(part, 16).map_err(|err| err.to_string())?;
    }
    if mac == [0; 6] {
        return Err("mac must be non-zero".to_owned());
    }
    Ok(mac)
}

pub(super) fn mac_string(mac: [u8; 6]) -> String {
    mac.iter()
        .map(|octet| format!("{octet:02x}"))
        .collect::<Vec<_>>()
        .join(":")
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
}

pub(super) fn parse_tcp_dial_mode(value: &str) -> Result<TcpDialMode, RunnerOutput> {
    value
        .parse::<TcpDialMode>()
        .map_err(|err| RunnerOutput::usage(err))
}

pub(super) fn next_value<'a>(
    iter: &mut impl Iterator<Item = &'a String>,
    usage: &str,
) -> Result<String, RunnerOutput> {
    iter.next()
        .cloned()
        .ok_or_else(|| RunnerOutput::usage(format!("missing value for {usage}")))
}

pub(super) fn value_after_equals(arg: &str, usage: &str) -> Result<String, RunnerOutput> {
    arg.split_once('=')
        .map(|(_, value)| value.to_owned())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| RunnerOutput::usage(format!("missing value for {usage}")))
}

pub(super) fn path_string(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}
