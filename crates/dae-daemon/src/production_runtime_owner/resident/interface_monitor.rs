use super::*;
use std::collections::BTreeMap;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const INTERFACE_MONITOR_POLL_MS: u64 = 2_000;

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
    let specs = interface_specs(lan_ifaces, wan_ifaces);
    let state = Arc::new(Mutex::new(interface_monitor_snapshot(&specs)));
    let stop = Arc::new(AtomicBool::new(false));
    let thread_state = Arc::clone(&state);
    let thread_stop = Arc::clone(&stop);
    let handle = thread::Builder::new()
        .name("resident-interface-monitor".to_owned())
        .spawn(move || {
            while !thread_stop.load(Ordering::Relaxed) {
                if let Ok(mut guard) = thread_state.lock() {
                    *guard = interface_monitor_snapshot(&specs);
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
    lan_ifaces: &[String],
    wan_ifaces: &[String],
) -> Vec<(String, Vec<&'static str>)> {
    let mut specs = BTreeMap::<String, Vec<&'static str>>::new();
    for iface in lan_ifaces {
        push_role(&mut specs, iface, "lan");
    }
    for iface in wan_ifaces {
        push_role(&mut specs, iface, "wan");
    }
    specs.into_iter().collect()
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

fn interface_monitor_snapshot(specs: &[(String, Vec<&'static str>)]) -> Value {
    let interfaces = specs
        .iter()
        .map(|(iface, roles)| {
            let exists = Path::new("/sys/class/net").join(iface).exists();
            json!({
                "interface": iface,
                "roles": roles,
                "exists": exists,
                "state": if exists { "attached" } else { "degraded" },
            })
        })
        .collect::<Vec<_>>();
    let degraded = interfaces
        .iter()
        .any(|iface| iface["state"].as_str() == Some("degraded"));
    json!({
        "schemaVersion": 1,
        "status": if degraded { "degraded" } else { "pass" },
        "checkedAtUnix": unix_now_secs(),
        "pollIntervalMs": INTERFACE_MONITOR_POLL_MS,
        "reattachImplemented": false,
        "startupLazyBindAllowed": false,
        "interfaces": interfaces,
    })
}

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
