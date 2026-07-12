use super::*;
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

mod network_state;

const INTERFACE_MONITOR_POLL_MS: u64 = 2_000;
const SYSFS_INTERFACE_IFINDEX_FILE: &str = "ifindex";
const MONITOR_STATUS_PASS: &str = "pass";
const MONITOR_STATUS_DEGRADED: &str = "degraded";
const INTERFACE_STATE_ATTACHED: &str = "attached";
const INTERFACE_STATE_MISSING: &str = "missing";
const INTERFACE_STATE_STALE: &str = "stale";
const INTERFACE_STATE_UNVERIFIED: &str = "unverified";
const INTERFACE_ROLE_LAN: &str = "lan";
const INTERFACE_ROLE_WAN: &str = "wan";
const REATTACH_REASON_INTERFACE_MISSING: &str = "interface-missing";
const REATTACH_REASON_INITIAL_INTERFACE_MISSING: &str = "initial-interface-missing";
const REATTACH_REASON_CURRENT_UNVERIFIED: &str = "current-interface-unverified";
const REATTACH_REASON_INITIAL_UNVERIFIED: &str = "initial-interface-unverified";
const REATTACH_REASON_IFINDEX_CHANGED: &str = "ifindex-changed";
const REATTACH_REASON_INTERFACE_TYPE_CHANGED: &str = "interface-type-changed";
const REATTACH_REASON_LINK_LAYER_CHANGED: &str = "link-layer-changed";

#[derive(Clone, Debug)]
struct InterfaceMonitorSpec {
    iface: String,
    roles: Vec<&'static str>,
    initial: InterfaceObservation,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct InterfaceObservation {
    exists: bool,
    ifindex: Option<u32>,
    arphrd: Option<u16>,
    link_layer: Option<&'static str>,
    errors: Vec<String>,
}

pub(super) struct ResidentInterfaceMonitorRuntime {
    stop: Arc<AtomicBool>,
    state: Arc<Mutex<Value>>,
    handle: Option<JoinHandle<()>>,
}

impl std::fmt::Debug for ResidentInterfaceMonitorRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResidentInterfaceMonitorRuntime")
            .field("running", &self.handle.is_some())
            .field("state", &self.snapshot())
            .finish()
    }
}

impl ResidentInterfaceMonitorRuntime {
    pub(super) fn snapshot(&self) -> Value {
        self.state
            .lock()
            .map(|state| state.clone())
            .unwrap_or_else(|_| {
                json!({
                    "status": "unknown",
                    "error": "resident interface monitor state lock poisoned",
                })
            })
    }

    pub(super) fn shutdown(&mut self, cleanup_steps: &mut Vec<Value>) {
        self.stop.store(true, Ordering::Relaxed);
        let joined = self.handle.take().map(|handle| handle.join().is_ok());
        cleanup_steps.push(json!({
            "name": "resident-interface-monitor-shutdown",
            "status": if joined.unwrap_or(true) { "pass" } else { "warn" },
            "joined": joined,
        }));
    }
}

impl Drop for ResidentInterfaceMonitorRuntime {
    fn drop(&mut self) {
        let mut steps = Vec::new();
        self.shutdown(&mut steps);
    }
}

pub(super) fn start_resident_interface_monitor(
    lan_ifaces: &[String],
    wan_ifaces: &[String],
) -> ResidentInterfaceMonitorRuntime {
    let specs = interface_specs(sys_class_net_path(), lan_ifaces, wan_ifaces);
    let state = Arc::new(Mutex::new(interface_monitor_snapshot(
        sys_class_net_path(),
        &specs,
    )));
    let stop = Arc::new(AtomicBool::new(false));
    let thread_state = Arc::clone(&state);
    let thread_stop = Arc::clone(&stop);
    let handle = thread::Builder::new()
        .name("resident-interface-monitor".to_owned())
        .spawn(move || {
            while !thread_stop.load(Ordering::Relaxed) {
                if let Ok(mut guard) = thread_state.lock() {
                    *guard = interface_monitor_snapshot(sys_class_net_path(), &specs);
                }
                for _ in 0..20 {
                    if thread_stop.load(Ordering::Relaxed) {
                        return;
                    }
                    thread::sleep(Duration::from_millis(INTERFACE_MONITOR_POLL_MS / 20));
                }
            }
        })
        .ok();
    ResidentInterfaceMonitorRuntime {
        stop,
        state,
        handle,
    }
}

fn interface_specs(
    sys_class_net: &Path,
    lan_ifaces: &[String],
    wan_ifaces: &[String],
) -> Vec<InterfaceMonitorSpec> {
    let mut specs = BTreeMap::<String, Vec<&'static str>>::new();
    for iface in lan_ifaces {
        push_role(&mut specs, iface, INTERFACE_ROLE_LAN);
    }
    for iface in wan_ifaces {
        push_role(&mut specs, iface, INTERFACE_ROLE_WAN);
    }
    specs
        .into_iter()
        .map(|(iface, roles)| InterfaceMonitorSpec {
            initial: observe_interface(sys_class_net, &iface),
            iface,
            roles,
        })
        .collect()
}

fn push_role(specs: &mut BTreeMap<String, Vec<&'static str>>, iface: &str, role: &'static str) {
    let iface = iface.trim();
    if iface.is_empty() {
        return;
    }
    let roles = specs.entry(iface.to_owned()).or_default();
    if !roles.contains(&role) {
        roles.push(role);
    }
}

fn interface_monitor_snapshot(sys_class_net: &Path, specs: &[InterfaceMonitorSpec]) -> Value {
    let interfaces = specs
        .iter()
        .map(|spec| {
            let current = observe_interface(sys_class_net, &spec.iface);
            let status = interface_monitor_status(&spec.initial, &current);
            json!({
                "interface": spec.iface,
                "roles": spec.roles,
                "exists": current.exists,
                "state": status.state,
                "reattachRequired": status.reattach_required,
                "reattachReady": status.reattach_ready,
                "reattachReasons": status.reasons,
                "initial": interface_observation_json(&spec.initial),
                "current": interface_observation_json(&current),
                "expectedIfindex": spec.initial.ifindex,
                "observedIfindex": current.ifindex,
                "expectedArphrdType": spec.initial.arphrd,
                "observedArphrdType": current.arphrd,
                "expectedLinkLayer": spec.initial.link_layer,
                "observedLinkLayer": current.link_layer,
            })
        })
        .collect::<Vec<_>>();
    let reattach_required = interfaces
        .iter()
        .any(|iface| iface["reattachRequired"].as_bool().unwrap_or(false));
    let reattach_ready = reattach_required
        && interfaces
            .iter()
            .all(|iface| iface["reattachReady"].as_bool().unwrap_or(true));
    json!({
        "schemaVersion": 1,
        "status": if reattach_required { MONITOR_STATUS_DEGRADED } else { MONITOR_STATUS_PASS },
        "checkedAtUnix": unix_now_secs(),
        "pollIntervalMs": INTERFACE_MONITOR_POLL_MS,
        "reattachImplemented": true,
        "reattachRequired": reattach_required,
        "reattachReady": reattach_ready,
        "startupLazyBindAllowed": false,
        "interfaces": interfaces,
    })
}

#[derive(Debug)]
struct InterfaceMonitorStatus {
    state: &'static str,
    reattach_required: bool,
    reattach_ready: bool,
    reasons: Vec<&'static str>,
}

fn interface_monitor_status(
    initial: &InterfaceObservation,
    current: &InterfaceObservation,
) -> InterfaceMonitorStatus {
    let mut reasons = Vec::new();
    if !current.exists {
        reasons.push(REATTACH_REASON_INTERFACE_MISSING);
        return InterfaceMonitorStatus {
            state: INTERFACE_STATE_MISSING,
            reattach_required: true,
            reattach_ready: false,
            reasons,
        };
    }
    if !initial.exists {
        reasons.push(REATTACH_REASON_INITIAL_INTERFACE_MISSING);
    }
    if !current.errors.is_empty() {
        reasons.push(REATTACH_REASON_CURRENT_UNVERIFIED);
    }
    if !initial.errors.is_empty() {
        reasons.push(REATTACH_REASON_INITIAL_UNVERIFIED);
    }
    if initial.ifindex != current.ifindex {
        reasons.push(REATTACH_REASON_IFINDEX_CHANGED);
    }
    if initial.arphrd != current.arphrd {
        reasons.push(REATTACH_REASON_INTERFACE_TYPE_CHANGED);
    }
    if initial.link_layer != current.link_layer {
        reasons.push(REATTACH_REASON_LINK_LAYER_CHANGED);
    }
    if reasons.is_empty() {
        InterfaceMonitorStatus {
            state: INTERFACE_STATE_ATTACHED,
            reattach_required: false,
            reattach_ready: true,
            reasons,
        }
    } else {
        let reattach_ready = current.exists
            && current.errors.is_empty()
            && initial.exists
            && initial.errors.is_empty();
        InterfaceMonitorStatus {
            state: if current.errors.is_empty() {
                INTERFACE_STATE_STALE
            } else {
                INTERFACE_STATE_UNVERIFIED
            },
            reattach_required: true,
            reattach_ready,
            reasons,
        }
    }
}

fn observe_interface(sys_class_net: &Path, iface: &str) -> InterfaceObservation {
    let exists = iface_exists_in_sysfs_root(sys_class_net, iface);
    if !exists {
        return InterfaceObservation {
            exists,
            ifindex: None,
            arphrd: None,
            link_layer: None,
            errors: Vec::new(),
        };
    }

    let mut errors = Vec::new();
    let ifindex = match read_interface_u32(sys_class_net, iface, SYSFS_INTERFACE_IFINDEX_FILE) {
        Ok(value) => Some(value),
        Err(err) => {
            errors.push(err);
            None
        }
    };
    let arphrd = match interface_arphrd_from_sysfs_root(sys_class_net, iface) {
        Ok(value) => Some(value),
        Err(err) => {
            errors.push(err);
            None
        }
    };
    let link_layer = match interface_link_layer_from_sysfs_root(sys_class_net, iface) {
        Ok(layer) => Some(layer.suffix()),
        Err(err) => {
            if arphrd.is_none() {
                errors.push(err);
            }
            None
        }
    };
    InterfaceObservation {
        exists,
        ifindex,
        arphrd,
        link_layer,
        errors,
    }
}

fn interface_observation_json(observation: &InterfaceObservation) -> Value {
    json!({
        "exists": observation.exists,
        "ifindex": observation.ifindex,
        "arphrdType": observation.arphrd,
        "linkLayer": observation.link_layer,
        "errors": observation.errors,
    })
}

fn read_interface_u32(sys_class_net: &Path, iface: &str, file_name: &str) -> Result<u32, String> {
    let value = fs::read_to_string(sys_class_net.join(iface).join(file_name))
        .map_err(|err| format!("failed to read interface {file_name} for {iface}: {err}"))?;
    value
        .trim()
        .parse::<u32>()
        .map_err(|err| format!("failed to parse interface {file_name} for {iface}: {err}"))
}

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::production_runtime_owner::resident_interfaces::{
        ARPHRD_ETHER, ARPHRD_PPP, SYSFS_INTERFACE_TYPE_FILE,
    };

    const TEST_LAN: &str = "test_lan0";
    const TEST_WAN: &str = "test_wan0";

    #[test]
    fn monitor_marks_unchanged_interfaces_attached() {
        let dir = test_sys_class_net();
        write_iface(&dir, TEST_LAN, 11, ARPHRD_ETHER);
        write_iface(&dir, TEST_WAN, 12, ARPHRD_PPP);
        let specs = interface_specs(&dir, &[TEST_LAN.to_owned()], &[TEST_WAN.to_owned()]);

        let snapshot = interface_monitor_snapshot(&dir, &specs);

        assert_eq!(snapshot["status"], json!(MONITOR_STATUS_PASS));
        assert_eq!(snapshot["reattachRequired"], json!(false));
        assert_eq!(snapshot["reattachReady"], json!(false));
        let interfaces = snapshot["interfaces"].as_array().unwrap();
        assert_eq!(interfaces.len(), 2);
        assert!(interfaces.iter().all(|iface| {
            iface["state"] == json!(INTERFACE_STATE_ATTACHED)
                && iface["reattachRequired"] == json!(false)
                && iface["reattachReady"] == json!(true)
        }));
        let wan = interfaces
            .iter()
            .find(|iface| {
                iface["roles"]
                    .as_array()
                    .unwrap()
                    .contains(&json!(INTERFACE_ROLE_WAN))
            })
            .unwrap();
        assert_eq!(wan["expectedLinkLayer"], json!("l3"));
        assert_eq!(wan["observedLinkLayer"], json!("l3"));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn monitor_requires_reattach_when_interface_disappears() {
        let dir = test_sys_class_net();
        write_iface(&dir, TEST_WAN, 12, ARPHRD_PPP);
        let specs = interface_specs(&dir, &[], &[TEST_WAN.to_owned()]);
        fs::remove_dir_all(dir.join(TEST_WAN)).unwrap();

        let snapshot = interface_monitor_snapshot(&dir, &specs);
        let iface = &snapshot["interfaces"][0];

        assert_eq!(snapshot["status"], json!(MONITOR_STATUS_DEGRADED));
        assert_eq!(snapshot["reattachRequired"], json!(true));
        assert_eq!(snapshot["reattachReady"], json!(false));
        assert_eq!(iface["state"], json!(INTERFACE_STATE_MISSING));
        assert_eq!(iface["reattachRequired"], json!(true));
        assert_eq!(iface["reattachReady"], json!(false));
        assert!(
            iface["reattachReasons"]
                .as_array()
                .unwrap()
                .contains(&json!(REATTACH_REASON_INTERFACE_MISSING))
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn monitor_requires_reattach_when_interface_is_recreated() {
        let dir = test_sys_class_net();
        write_iface(&dir, TEST_WAN, 12, ARPHRD_PPP);
        let specs = interface_specs(&dir, &[], &[TEST_WAN.to_owned()]);
        write_iface(&dir, TEST_WAN, 21, ARPHRD_PPP);

        let snapshot = interface_monitor_snapshot(&dir, &specs);
        let iface = &snapshot["interfaces"][0];

        assert_eq!(snapshot["status"], json!(MONITOR_STATUS_DEGRADED));
        assert_eq!(snapshot["reattachReady"], json!(true));
        assert_eq!(iface["state"], json!(INTERFACE_STATE_STALE));
        assert_eq!(iface["reattachReady"], json!(true));
        assert_eq!(iface["expectedIfindex"], json!(12));
        assert_eq!(iface["observedIfindex"], json!(21));
        assert!(
            iface["reattachReasons"]
                .as_array()
                .unwrap()
                .contains(&json!(REATTACH_REASON_IFINDEX_CHANGED))
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn monitor_requires_reattach_when_link_layer_changes() {
        let dir = test_sys_class_net();
        write_iface(&dir, TEST_WAN, 12, ARPHRD_ETHER);
        let specs = interface_specs(&dir, &[], &[TEST_WAN.to_owned()]);
        write_iface(&dir, TEST_WAN, 12, ARPHRD_PPP);

        let snapshot = interface_monitor_snapshot(&dir, &specs);
        let iface = &snapshot["interfaces"][0];

        assert_eq!(iface["state"], json!(INTERFACE_STATE_STALE));
        assert_eq!(snapshot["reattachReady"], json!(true));
        assert_eq!(iface["reattachReady"], json!(true));
        assert_eq!(iface["expectedLinkLayer"], json!("l2"));
        assert_eq!(iface["observedLinkLayer"], json!("l3"));
        assert!(
            iface["reattachReasons"]
                .as_array()
                .unwrap()
                .contains(&json!(REATTACH_REASON_LINK_LAYER_CHANGED))
        );
        let _ = fs::remove_dir_all(dir);
    }

    fn test_sys_class_net() -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("daed-interface-monitor-test-{}", fastrand::u64(..)));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_iface(sys_class_net: &Path, iface: &str, ifindex: u32, arphrd: u16) {
        let iface_dir = sys_class_net.join(iface);
        fs::create_dir_all(&iface_dir).unwrap();
        fs::write(
            iface_dir.join(SYSFS_INTERFACE_IFINDEX_FILE),
            ifindex.to_string(),
        )
        .unwrap();
        fs::write(
            iface_dir.join(SYSFS_INTERFACE_TYPE_FILE),
            arphrd.to_string(),
        )
        .unwrap();
    }
}
