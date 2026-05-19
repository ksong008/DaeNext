use super::*;

#[derive(Clone)]
pub(super) struct ReportStatus {
    pub(super) path: Option<String>,
    pub(super) status: &'static str,
    pub(super) passed: bool,
    pub(super) blockers: Vec<Value>,
}

pub(super) fn read_report(path: Option<&Path>, pass_key: &str) -> ReportStatus {
    let Some(path) = path else {
        return ReportStatus {
            path: None,
            status: "not-provided",
            passed: false,
            blockers: Vec::new(),
        };
    };
    let path_text = path_string(path);
    let Ok(content) = fs::read_to_string(path) else {
        return ReportStatus {
            path: Some(path_text),
            status: "read-error",
            passed: false,
            blockers: Vec::new(),
        };
    };
    let Ok(json) = serde_json::from_str::<Value>(&content) else {
        return ReportStatus {
            path: Some(path_text),
            status: "parse-error",
            passed: false,
            blockers: Vec::new(),
        };
    };
    ReportStatus {
        path: Some(path_text),
        status: "loaded",
        passed: json[pass_key].as_bool().unwrap_or(false),
        blockers: json["blockers"].as_array().cloned().unwrap_or_default(),
    }
}

pub(super) struct CommandSpec<'a> {
    program: &'a str,
    args: &'a [&'a str],
}

impl<'a> CommandSpec<'a> {
    pub(super) fn new(program: &'a str, args: &'a [&'a str]) -> Self {
        Self { program, args }
    }
}

pub(super) fn run_step(
    steps: &mut Vec<Value>,
    name: &'static str,
    command: CommandSpec<'_>,
) -> bool {
    let output = Command::new(command.program).args(command.args).output();
    match output {
        Ok(output) => {
            let status = output.status.success();
            steps.push(command_output_json(name, command, status, &output));
            status
        }
        Err(err) => {
            steps.push(json!({
                "name": name,
                "command": command_line(command),
                "status": "error",
                "error": err.to_string(),
            }));
            false
        }
    }
}

pub(super) fn run_observation_step(
    steps: &mut Vec<Value>,
    name: &'static str,
    command: CommandSpec<'_>,
) -> Value {
    let output = Command::new(command.program).args(command.args).output();
    match output {
        Ok(output) => {
            let status = output.status.success();
            let value = command_output_json(name, command, status, &output);
            steps.push(value.clone());
            value
        }
        Err(err) => {
            let value = json!({
                "name": name,
                "command": command_line(command),
                "status": "error",
                "error": err.to_string(),
            });
            steps.push(value.clone());
            value
        }
    }
}

pub(super) fn command_output_json(
    name: &'static str,
    command: CommandSpec<'_>,
    status: bool,
    output: &std::process::Output,
) -> Value {
    json!({
        "name": name,
        "command": command_line(command),
        "status": if status { "pass" } else { "fail" },
        "exit_code": output.status.code(),
        "stdout": String::from_utf8_lossy(&output.stdout).trim(),
        "stderr": String::from_utf8_lossy(&output.stderr).trim(),
    })
}

pub(super) fn command_line(command: CommandSpec<'_>) -> String {
    std::iter::once(command.program)
        .chain(command.args.iter().copied())
        .collect::<Vec<_>>()
        .join(" ")
}

pub(super) fn push_check(
    checks: &mut Vec<Value>,
    name: &'static str,
    pass: bool,
    detail: Value,
    blockers: &mut Vec<String>,
    blocker: &'static str,
) {
    if !pass {
        blockers.push(blocker.to_owned());
    }
    checks.push(json!({
        "name": name,
        "status": if pass { "pass" } else { "block" },
        "detail": detail,
        "blocker": if pass { Value::Null } else { json!(blocker) },
    }));
}

pub(super) fn remaining_blockers() -> Vec<&'static str> {
    vec![
        "actual dae eBPF program attach to dae0/dae0peer is not executed",
        "listen socket map update with TCP/UDP listener fds is not executed",
        "active tproxy TCP UDP DNS traffic evidence is still missing",
        "outbound true dataplane admission is still incomplete",
        "matched Go default daemon vs true Rust candidate benchmark is still missing",
        "clean dae-wing and daed product-chain recertification is still missing",
    ]
}

pub(super) fn command_exists(program: &str) -> bool {
    let Some(path) = env::var_os("PATH") else {
        return false;
    };
    env::split_paths(&path).any(|dir| dir.join(program).is_file())
}

pub(super) fn tmp_root_allowed(path: &Path) -> bool {
    if !path.is_absolute() {
        return false;
    }
    let value = path_string(path);
    value != "/tmp" && value.starts_with("/tmp/")
}

pub(super) fn iface_name_valid(name: &str) -> bool {
    !name.is_empty() && name.len() <= 15
}

pub(super) fn iface_exists(name: &str) -> bool {
    PathBuf::from("/sys/class/net").join(name).exists()
}

pub(super) fn netns_exists(name: &str) -> bool {
    ["/var/run/netns", "/run/netns"]
        .into_iter()
        .any(|parent| PathBuf::from(parent).join(name).exists())
}

pub(super) fn resource_leftovers(netns: &str, host_iface: &str, peer_iface: &str) -> Vec<Value> {
    let mut leftovers = Vec::new();
    if iface_exists(host_iface) {
        leftovers.push(json!({"kind": "interface", "name": host_iface}));
    }
    if iface_exists(peer_iface) {
        leftovers.push(json!({"kind": "interface", "name": peer_iface}));
    }
    for parent in ["/var/run/netns", "/run/netns"] {
        let path = PathBuf::from(parent).join(netns);
        if path.exists() {
            leftovers.push(json!({"kind": "netns", "name": netns, "path": path_string(&path)}));
        }
    }
    leftovers
}

pub(super) fn next_value(
    iter: &mut std::slice::Iter<'_, String>,
    name: &'static str,
) -> Result<String, RunnerOutput> {
    iter.next()
        .cloned()
        .ok_or_else(|| RunnerOutput::usage(format!("missing runtime {name}")))
}

pub(super) fn value_after_equals(arg: &str, name: &'static str) -> Result<String, RunnerOutput> {
    arg.split_once('=')
        .map(|(_, value)| value.to_owned())
        .ok_or_else(|| RunnerOutput::usage(format!("missing runtime {name}")))
}

pub(super) fn path_string(path: &Path) -> String {
    path.as_os_str().to_string_lossy().into_owned()
}

pub(super) fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}
