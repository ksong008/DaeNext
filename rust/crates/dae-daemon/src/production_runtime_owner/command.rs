use std::env;
use std::fs;
use std::net::{TcpListener, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::Duration;

use dae_ebpf_support::map_ids;
use serde_json::{Value, json};

use super::host_ops::HostOps;
use super::{PRODUCTION_HOST_IFACE, PRODUCTION_NETNS, PRODUCTION_PEER_IFACE};

pub(super) use super::host_ops::HostOpSpec as CommandSpec;

pub(super) fn wait_for_loaded_map_cleanup(discovered_map_ids: &[Option<u32>]) -> (Vec<u32>, bool) {
    let ids = discovered_map_ids
        .iter()
        .filter_map(|id| *id)
        .collect::<Vec<_>>();
    let mut current = map_ids().unwrap_or_default();
    if ids.is_empty() {
        return (current, true);
    }
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
    blocker: &str,
) {
    checks.push(json!({
        "name": name,
        "status": if passed { "pass" } else { "fail" },
        "detail": detail,
        "blocker": if passed { Value::Null } else { Value::String(blocker.to_owned()) },
    }));
}

pub(super) fn run_step(steps: &mut Vec<Value>, name: &str, spec: CommandSpec) -> bool {
    let result = HostOps::run_named(name, spec);
    let passed = result.passed();
    steps.push(result.to_step_json());
    passed
}

pub(super) fn run_observation_step(steps: &mut Vec<Value>, name: &str, spec: CommandSpec) -> Value {
    let value = HostOps::observe_named(name, spec).to_step_json();
    steps.push(value.clone());
    value
}

pub(super) fn run_observation_command(spec: CommandSpec) -> Value {
    HostOps::observe(spec).to_step_json()
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

pub(super) fn production_resource_leftovers() -> Vec<String> {
    let mut leftovers = Vec::new();
    if iface_exists(PRODUCTION_HOST_IFACE) {
        leftovers.push(format!("iface:{PRODUCTION_HOST_IFACE}"));
    }
    if iface_exists(PRODUCTION_PEER_IFACE) {
        leftovers.push(format!("iface:{PRODUCTION_PEER_IFACE}"));
    }
    if netns_exists(PRODUCTION_NETNS) {
        leftovers.push(format!("netns:{PRODUCTION_NETNS}"));
    }
    leftovers
}

pub(super) fn runtime_resource_leftovers(include_active_tcp: bool) -> Vec<String> {
    let mut leftovers = production_resource_leftovers();
    if include_active_tcp {
        for iface in ["dae50lan0", "dae50cli0"] {
            if iface_exists(iface) {
                leftovers.push(format!("iface:{iface}"));
            }
        }
        if netns_exists("dae50client") {
            leftovers.push("netns:dae50client".to_owned());
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

fn parse_mac(value: &str) -> Result<[u8; 6], String> {
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

pub(super) fn ensure_safe_run_root(root: &Path) -> Result<(), String> {
    if !root.is_absolute() {
        return Err(format!(
            "production runtime owner run root must be absolute: {}",
            path_string(root)
        ));
    }
    let root_string = path_string(root);
    if !root_string.starts_with("/tmp/dae-daemon") {
        return Err(format!(
            "production runtime owner run root must be under /tmp/dae-daemon*: {root_string}"
        ));
    }
    Ok(())
}

pub(super) fn path_string(path: &Path) -> String {
    path.display().to_string()
}
