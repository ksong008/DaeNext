use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use dae_config::Config;
use dae_ebpf_support::LiveLoadedTproxyListenSocketMap;
use serde_json::{Value, json};

use self::events::path_string;
use self::plan::build_resident_dataplane_plan;
use self::tcp::{ResidentTcpRouter, resident_tcp_accept_loop};
use self::udp::resident_udp_loop;
use super::resident_routing::build_resident_userspace_routing_matcher;

mod client;
mod direct;
mod dns;
mod events;
mod io;
mod plan;
mod tcp;
mod udp;
mod vision;

const VLESS_RESPONSE_VERSION: u8 = 0;
const RESIDENT_TCP_ACCEPT_SLEEP: Duration = Duration::from_millis(20);
const RESIDENT_IDLE_SLEEP: Duration = Duration::from_millis(5);
const RESIDENT_TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(300);
const RESIDENT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const RESIDENT_UDP_RESPONSE_TIMEOUT: Duration = Duration::from_secs(8);
const XTLS_RPRX_VISION: &str = "xtls-rprx-vision";
const VISION_COMMAND_CONTINUE: u8 = 0;
const VISION_COMMAND_END: u8 = 1;
const VISION_COMMAND_DIRECT: u8 = 2;
const TLS_RECORD_HEADER_LEN: usize = 5;
const TLS_RECORD_MAX_PAYLOAD_LEN: usize = 16 * 1024 + 2048;
const XUDP_MUX_TARGET: &str = "v1.mux.cool:666";
const XUDP_COMMAND_NEW: u8 = 1;
const XUDP_OPTION_DATA: u8 = 1;
const XUDP_NETWORK_UDP: u8 = 2;

#[derive(Debug)]
pub(super) struct ResidentDataplaneRuntime {
    stop: Arc<AtomicBool>,
    handles: Vec<JoinHandle<()>>,
    event_file: PathBuf,
}

impl ResidentDataplaneRuntime {
    pub(super) fn shutdown(&mut self, steps: &mut Vec<Value>) {
        self.stop.store(true, Ordering::Relaxed);
        let mut joined = 0_usize;
        let mut panicked = 0_usize;
        for handle in self.handles.drain(..) {
            match handle.join() {
                Ok(()) => joined += 1,
                Err(_) => panicked += 1,
            }
        }
        steps.push(json!({
            "name": "stop-resident-tcp-udp-dataplane-workers",
            "status": if panicked == 0 { "pass" } else { "fail" },
            "joined_worker_threads": joined,
            "panicked_worker_threads": panicked,
            "event_file": path_string(&self.event_file),
        }));
    }
}

pub(super) fn start_resident_dataplane_workers(
    handoff: &LiveLoadedTproxyListenSocketMap,
    config: &Config,
    artifact_dir: &Path,
    routing_tuple_map_id: Option<u32>,
) -> (Value, Option<ResidentDataplaneRuntime>) {
    let event_file = artifact_dir.join("resident-production-dataplane-events.jsonl");
    let _ = fs::remove_file(&event_file);
    let plan = match build_resident_dataplane_plan(config) {
        Ok(plan) => plan,
        Err(err) => {
            return (
                json!({
                    "status": "fail",
                    "enabled": false,
                    "error": err,
                    "event_file": path_string(&event_file),
                }),
                None,
            );
        }
    };
    if !plan.enabled {
        return (
            json!({
                "status": "pass",
                "enabled": false,
                "reason": plan.unsupported_reason,
                "event_file": path_string(&event_file),
            }),
            None,
        );
    }
    let Some(default_proxy) = plan.default_proxy else {
        return (
            json!({
                "status": "fail",
                "enabled": true,
                "error": "resident dataplane plan is enabled without a default proxy plan",
                "event_file": path_string(&event_file),
            }),
            None,
        );
    };
    let routing_matcher = match build_resident_userspace_routing_matcher(config) {
        Ok(matcher) => matcher,
        Err(err) => {
            return (
                json!({
                    "status": "fail",
                    "enabled": true,
                    "error": err,
                    "event_file": path_string(&event_file),
                }),
                None,
            );
        }
    };

    let tcp_listener = match handoff.listeners.tcp_listener.try_clone() {
        Ok(listener) => listener,
        Err(err) => {
            return (
                json!({
                    "status": "fail",
                    "enabled": true,
                    "error": format!("clone resident TCP listener: {err}"),
                    "event_file": path_string(&event_file),
                }),
                None,
            );
        }
    };
    let udp_socket = match handoff.listeners.udp_socket.try_clone() {
        Ok(socket) => socket,
        Err(err) => {
            return (
                json!({
                    "status": "fail",
                    "enabled": true,
                    "error": format!("clone resident UDP socket: {err}"),
                    "event_file": path_string(&event_file),
                }),
                None,
            );
        }
    };

    let stop = Arc::new(AtomicBool::new(false));
    let proxy = Arc::new(default_proxy);
    let dns = Arc::new(plan.dns);
    let tcp_router = match ResidentTcpRouter::new(
        plan.proxies,
        routing_tuple_map_id,
        routing_matcher,
        plan.tcp_dial_mode,
        plan.sniffing_timeout,
        config.global.so_mark_from_dae,
        config.global.mptcp,
    ) {
        Ok(router) => Arc::new(router),
        Err(err) => {
            return (
                json!({
                    "status": "fail",
                    "enabled": true,
                    "error": err,
                    "event_file": path_string(&event_file),
                }),
                None,
            );
        }
    };
    let event_lock = Arc::new(Mutex::new(()));
    let mut handles = Vec::new();
    {
        let stop = Arc::clone(&stop);
        let tcp_router = Arc::clone(&tcp_router);
        let event_file = event_file.clone();
        let event_lock = Arc::clone(&event_lock);
        handles.push(thread::spawn(move || {
            resident_tcp_accept_loop(tcp_listener, tcp_router, stop, event_file, event_lock)
        }));
    }
    {
        let stop = Arc::clone(&stop);
        let proxy = Arc::clone(&proxy);
        let dns = Arc::clone(&dns);
        let event_file = event_file.clone();
        let event_lock = Arc::clone(&event_lock);
        handles.push(thread::spawn(move || {
            resident_udp_loop(udp_socket, proxy, dns, stop, event_file, event_lock)
        }));
    }

    let default_proxy_utls = proxy.utls_fingerprint.as_ref().map(|fingerprint| {
        json!({
            "source": fingerprint.source,
            "requested": &fingerprint.requested,
            "name": &fingerprint.name,
            "canonical": &fingerprint.canonical,
            "family": &fingerprint.family,
            "client": &fingerprint.client,
            "randomized": fingerprint.randomized,
            "alpn_policy": &fingerprint.alpn_policy,
        })
    });
    let start = json!({
        "status": "pass",
        "enabled": true,
        "tcp_worker_started": true,
        "udp_worker_started": true,
        "event_file": path_string(&event_file),
        "routing_tuple_map_id": routing_tuple_map_id,
        "tcp_dial_mode": tcp_router.dial_mode_name(),
        "tcp_sniffing_timeout": format!("{:?}", tcp_router.sniffing_timeout()),
        "proxy_count": tcp_router.proxy_count(),
        "default_proxy": {
            "protocol": proxy.protocol,
            "group": proxy.group_name,
            "node_tag": proxy.node_tag,
            "server_host": proxy.server_host,
            "server_port": proxy.server_port,
            "server_name": proxy.server_name,
            "transport": proxy.net,
            "tls": proxy.tls,
            "flow": proxy.flow,
            "alpn": proxy.alpn,
            "allow_insecure": proxy.allow_insecure,
            "utls_fingerprint": default_proxy_utls,
            "mark": proxy.mark,
            "mptcp": proxy.mptcp,
        },
        "scope": "resident worker consumes live tproxy TCP/UDP sockets and relays through admitted Rust proxy handlers; unsupported protocols fail explicitly instead of faking proxy success",
    });
    (
        start,
        Some(ResidentDataplaneRuntime {
            stop,
            handles,
            event_file,
        }),
    )
}
