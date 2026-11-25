use std::env;
use std::fs;
use std::net::{TcpListener, UdpSocket};
use std::path::{Path, PathBuf};
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
    // `map_ids` failure must NOT be treated as "already cleaned": an
    // unreadable bpffs would otherwise produce a false-positive cleanup
    // verdict.  Report the failure as not-clean so the caller fails closed.
    let Ok(mut current) = map_ids() else {
        return (Vec::new(), false);
    };
    if ids.is_empty() {
        return (current, true);
    }
    if ids.iter().all(|id| !current.contains(id)) {
        return (current, true);
    }
    for _ in 0..20 {
        thread::sleep(Duration::from_millis(50));
        let Ok(next) = map_ids() else {
            return (current, false);
        };
        current = next;
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
    super::topology_netlink::ifindex(iface).is_ok()
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

pub(super) fn cleanup_stale_production_owner_after_crash(
    lan_ifaces: &[String],
    wan_ifaces: &[String],
) -> Result<(), String> {
    let leftovers = production_resource_leftovers();
    let pin_dirs = native_runtime_pin_dirs();
    if !should_cleanup_stale_production_owner(&leftovers, &pin_dirs) {
        return Ok(());
    }
    if !pin_dirs.is_empty() {
        detach_stale_host_filters(lan_ifaces, wan_ifaces)?;
    }
    let _ = super::topology_netlink::delete_link(PRODUCTION_HOST_IFACE);
    let _ = super::topology_netlink::delete_namespace(PRODUCTION_NETNS);
    for pin_dir in pin_dirs {
        let _ = fs::remove_dir_all(pin_dir.path);
    }
    Ok(())
}

#[cfg(feature = "native-ebpf")]
fn detach_stale_host_filters(lan_ifaces: &[String], wan_ifaces: &[String]) -> Result<(), String> {
    use dae_ebpf_support::{
        TcAttachDirection, TcAttachTarget, detach_stale_aya_tc_filter, tc_handle,
    };

    // The native LAN and WAN attach paths use these deterministic slots.
    for (ifaces, prefix, direction, priority, minor) in [
        (
            lan_ifaces,
            "tproxy_lan_ingress",
            TcAttachDirection::Ingress,
            2,
            0b100,
        ),
        (
            lan_ifaces,
            "tproxy_lan_egress",
            TcAttachDirection::Egress,
            1,
            0b010,
        ),
        (
            wan_ifaces,
            "tproxy_wan_ingress",
            TcAttachDirection::Ingress,
            1,
            0b010,
        ),
        (
            wan_ifaces,
            "tproxy_wan_egress",
            TcAttachDirection::Egress,
            2,
            0b100,
        ),
    ] {
        for iface in ifaces {
            let target = TcAttachTarget::host(iface, direction);
            detach_stale_aya_tc_filter(&target, priority, tc_handle(0x2023, minor), prefix)?;
        }
    }
    Ok(())
}

#[cfg(not(feature = "native-ebpf"))]
fn detach_stale_host_filters(_lan_ifaces: &[String], _wan_ifaces: &[String]) -> Result<(), String> {
    Err("stale native TC filters require a build with native eBPF support".to_owned())
}

fn should_cleanup_stale_production_owner(
    leftovers: &[String],
    pin_dirs: &[NativeRuntimePinDir],
) -> bool {
    if leftovers.is_empty()
        || pin_dirs
            .iter()
            .any(|pin_dir| !pin_dir.stale || pin_dir.cleanup_pending)
    {
        return false;
    }
    if !pin_dirs.is_empty() {
        return true;
    }
    leftovers.len() == 1 && leftovers[0] == format!("netns:{PRODUCTION_NETNS}")
}

struct NativeRuntimePinDir {
    path: PathBuf,
    stale: bool,
    cleanup_pending: bool,
}

fn native_runtime_pin_dirs() -> Vec<NativeRuntimePinDir> {
    let Ok(entries) = fs::read_dir("/sys/fs/bpf") else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name().into_string().ok()?;
            let pid = native_runtime_pin_pid(&name)?;
            Some(NativeRuntimePinDir {
                cleanup_pending: entry.path().join("cleanup-pending").exists(),
                path: entry.path(),
                stale: !PathBuf::from(format!("/proc/{pid}")).exists(),
            })
        })
        .collect()
}

fn native_runtime_pin_pid(name: &str) -> Option<u32> {
    let rest = name.strip_prefix("dae-native-runtime-")?;
    let (pid, _) = rest.split_once('-')?;
    pid.parse().ok()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_runtime_pin_pid_accepts_runtime_pin_names_only() {
        assert_eq!(
            native_runtime_pin_pid("dae-native-runtime-1234-0"),
            Some(1234)
        );
        assert_eq!(
            native_runtime_pin_pid("dae-native-runtime-98765-worker"),
            Some(98765)
        );
        assert_eq!(native_runtime_pin_pid("dae-native-runtime--0"), None);
        assert_eq!(native_runtime_pin_pid("dae-native-runtime-abcd-0"), None);
        assert_eq!(native_runtime_pin_pid("dae-native-runtime-1234"), None);
        assert_eq!(native_runtime_pin_pid("other-runtime-1234-0"), None);
    }

    #[test]
    fn stale_owner_cleanup_requires_leftovers_and_only_dead_native_pins() {
        let stale = NativeRuntimePinDir {
            path: PathBuf::from("/tmp/dae-native-runtime-1-0"),
            stale: true,
            cleanup_pending: false,
        };
        assert!(!should_cleanup_stale_production_owner(
            &[format!("iface:{PRODUCTION_HOST_IFACE}")],
            &[NativeRuntimePinDir {
                path: PathBuf::from("/tmp/dae-native-runtime-4-0"),
                stale: true,
                cleanup_pending: true,
            }],
        ));
        let active = NativeRuntimePinDir {
            path: PathBuf::from("/tmp/dae-native-runtime-2-0"),
            stale: false,
            cleanup_pending: false,
        };

        assert!(!should_cleanup_stale_production_owner(&[], &[stale]));
        assert!(!should_cleanup_stale_production_owner(
            &[format!("iface:{PRODUCTION_HOST_IFACE}")],
            &[]
        ));
        assert!(should_cleanup_stale_production_owner(
            &[format!("netns:{PRODUCTION_NETNS}")],
            &[]
        ));
        assert!(!should_cleanup_stale_production_owner(
            &[format!("netns:{PRODUCTION_NETNS}")],
            &[active]
        ));
        assert!(should_cleanup_stale_production_owner(
            &[format!("iface:{PRODUCTION_HOST_IFACE}")],
            &[NativeRuntimePinDir {
                path: PathBuf::from("/tmp/dae-native-runtime-3-0"),
                stale: true,
                cleanup_pending: false,
            }]
        ));
    }
}
