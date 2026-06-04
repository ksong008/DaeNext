use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use dae_config::Config;
use dae_ebpf_support::LiveLoadedTproxyListenSocketMap;
use serde_json::{Value, json};

pub(crate) use self::adapter_matrix::{
    resident_live_adapter_matrix_contract, resident_live_adapter_matrix_entries,
};
use self::events::path_string;
pub(crate) use self::events::{ResidentEventLogSink, set_event_log_sink};
use self::plan::build_resident_dataplane_plan;
use self::tcp::{ResidentTcpRouter, resident_tcp_accept_loop};
use self::udp::resident_udp_loop;
use super::resident_routing::build_resident_userspace_routing_matcher;

mod adapter_matrix;
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
const RESIDENT_TCP_FLOW_STACK_BYTES_ENV: &str = "DAE_RESIDENT_TCP_FLOW_STACK_BYTES";
const RESIDENT_TCP_FLOW_STACK_BYTES_DEFAULT: usize = 512 * 1024;
const RESIDENT_TCP_FLOW_STACK_BYTES_MIN: usize = 128 * 1024;
const RESIDENT_TCP_FLOW_STACK_BYTES_MAX: usize = 8 * 1024 * 1024;
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
    metrics: Arc<ResidentDataplaneMetrics>,
}

impl ResidentDataplaneRuntime {
    pub(super) fn metrics_snapshot(&self) -> Value {
        self.metrics.snapshot()
    }

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

#[derive(Debug, Default)]
pub(super) struct ResidentDataplaneMetrics {
    upload_total: AtomicU64,
    download_total: AtomicU64,
    active_tcp_connections: AtomicU64,
    active_udp_sessions: AtomicU64,
}

impl ResidentDataplaneMetrics {
    pub(super) fn tcp_opened(&self) {
        self.active_tcp_connections.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn tcp_closed(&self) {
        self.active_tcp_connections.fetch_sub(1, Ordering::Relaxed);
    }

    pub(super) fn udp_opened(&self) {
        self.active_udp_sessions.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn udp_closed(&self) {
        self.active_udp_sessions.fetch_sub(1, Ordering::Relaxed);
    }

    pub(super) fn add_upload(&self, bytes: usize) {
        self.upload_total.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    pub(super) fn add_download(&self, bytes: usize) {
        self.download_total
            .fetch_add(bytes as u64, Ordering::Relaxed);
    }

    fn snapshot(&self) -> Value {
        json!({
            "uploadTotal": self.upload_total.load(Ordering::Relaxed),
            "downloadTotal": self.download_total.load(Ordering::Relaxed),
            "activeTcpConnections": self.active_tcp_connections.load(Ordering::Relaxed),
            "activeUdpSessions": self.active_udp_sessions.load(Ordering::Relaxed),
        })
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
    let metrics = Arc::new(ResidentDataplaneMetrics::default());
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
    let tcp_flow_stack_bytes = resident_tcp_flow_stack_bytes();
    let mut handles = Vec::new();
    {
        let stop = Arc::clone(&stop);
        let tcp_router = Arc::clone(&tcp_router);
        let event_file = event_file.clone();
        let event_lock = Arc::clone(&event_lock);
        let metrics = Arc::clone(&metrics);
        handles.push(thread::spawn(move || {
            resident_tcp_accept_loop(
                tcp_listener,
                tcp_router,
                stop,
                event_file,
                event_lock,
                metrics,
                tcp_flow_stack_bytes,
            )
        }));
    }
    {
        let stop = Arc::clone(&stop);
        let proxy = Arc::clone(&proxy);
        let dns = Arc::clone(&dns);
        let event_file = event_file.clone();
        let event_lock = Arc::clone(&event_lock);
        let metrics = Arc::clone(&metrics);
        handles.push(thread::spawn(move || {
            resident_udp_loop(
                udp_socket, proxy, dns, stop, event_file, event_lock, metrics,
            )
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
        "tcp_flow_stack_bytes": tcp_flow_stack_bytes,
        "tcp_flow_stack_bytes_env": RESIDENT_TCP_FLOW_STACK_BYTES_ENV,
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
            metrics,
        }),
    )
}

pub(crate) fn resident_live_adapter_config_assessment(
    config: &Config,
    config_path: Option<&Path>,
) -> Value {
    let matrix = resident_live_adapter_matrix_contract();
    let matrix_entries = resident_live_adapter_matrix_entries()
        .iter()
        .map(|entry| {
            json!({
                "handler": entry.handler,
                "formal_matrix_handler": entry.formal_matrix_handler,
                "wired_ready": entry.wired_ready(),
                "live_ready": entry.live_ready(),
                "missing": entry.missing,
            })
        })
        .collect::<Vec<_>>();
    let mut report = json!({
        "schema": "resident-live-adapter-config-assessment-v1",
        "config": config_path.map(path_string),
        "read_only": true,
        "host_mutation_executed": false,
        "network_io_executed": false,
        "live_traffic_executed": false,
        "matrix_schema": matrix.schema,
        "resident_live_adapter_matrix_ready": matrix.matrix_ready,
        "resident_live_adapter_wired_matrix_ready": matrix.wired_matrix_ready,
        "resident_live_adapter_remote_live_matrix_ready": matrix.remote_live_matrix_ready,
        "resident_live_adapter_entries": matrix_entries,
    });

    match build_resident_dataplane_plan(config) {
        Ok(plan) if plan.enabled => {
            let proxies = plan
                .proxies
                .iter()
                .map(|(outbound, proxy)| {
                    let mut proxy = resident_proxy_plan_summary_json(proxy);
                    proxy["outbound_index"] = json!(outbound);
                    proxy
                })
                .collect::<Vec<_>>();
            let default_proxy = plan
                .default_proxy
                .as_ref()
                .map(resident_proxy_plan_summary_json)
                .unwrap_or(Value::Null);
            report["status"] = json!("admitted");
            report["planner_admitted"] = json!(true);
            report["selected_node_fail_closed"] = json!(true);
            report["resident_dataplane_enabled_by_config"] = json!(true);
            report["proxy_count"] = json!(plan.proxies.len());
            report["tcp_dial_mode"] = json!(plan.tcp_dial_mode.as_str());
            report["tcp_sniffing_timeout"] = json!(format!("{:?}", plan.sniffing_timeout));
            report["default_proxy"] = default_proxy;
            report["proxies"] = json!(proxies);
            report["blockers"] =
                json!(["remote live traffic matrix not executed by this read-only assessment"]);
        }
        Ok(plan) => {
            report["status"] = json!("not-applicable");
            report["planner_admitted"] = json!(false);
            report["selected_node_fail_closed"] = json!(true);
            report["resident_dataplane_enabled_by_config"] = json!(false);
            report["proxy_count"] = json!(plan.proxies.len());
            report["unsupported_reason"] = json!(plan.unsupported_reason);
            report["blockers"] = json!(["no selected proxy plan was admitted"]);
        }
        Err(err) => {
            report["status"] = json!("blocked");
            report["planner_admitted"] = json!(false);
            report["selected_node_fail_closed"] = json!(true);
            report["resident_dataplane_enabled_by_config"] = json!(false);
            report["planner_error"] = json!(err);
            report["blockers"] =
                json!(["selected node shape is not admitted by the live resident adapter"]);
        }
    }
    report
}

fn resident_proxy_plan_summary_json(proxy: &plan::ResidentProxyPlan) -> Value {
    let fingerprint = proxy.utls_fingerprint.as_ref().map(|fingerprint| {
        json!({
            "source": fingerprint.source,
            "requested": fingerprint.requested,
            "canonical": fingerprint.canonical,
            "family": fingerprint.family,
            "client": fingerprint.client,
            "randomized": fingerprint.randomized,
            "alpn_policy": fingerprint.alpn_policy,
        })
    });
    json!({
        "protocol": proxy.protocol,
        "group": proxy.group_name,
        "node_tag": proxy.node_tag,
        "transport": proxy.net,
        "security": proxy.tls,
        "flow": proxy.flow,
        "alpn": proxy.alpn,
        "allow_insecure": proxy.allow_insecure,
        "fingerprint_underlay": fingerprint.is_some(),
        "utls_fingerprint": fingerprint,
        "server_port": proxy.server_port,
        "server_name_present": !proxy.server_name.is_empty(),
        "mptcp": proxy.mptcp,
    })
}

fn resident_tcp_flow_stack_bytes() -> usize {
    std::env::var(RESIDENT_TCP_FLOW_STACK_BYTES_ENV)
        .ok()
        .and_then(|value| value.trim().parse::<usize>().ok())
        .unwrap_or(RESIDENT_TCP_FLOW_STACK_BYTES_DEFAULT)
        .clamp(
            RESIDENT_TCP_FLOW_STACK_BYTES_MIN,
            RESIDENT_TCP_FLOW_STACK_BYTES_MAX,
        )
}
