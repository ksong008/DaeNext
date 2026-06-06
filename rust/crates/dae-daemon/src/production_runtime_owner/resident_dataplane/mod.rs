use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::net::SocketAddrV4;
use std::path::{Path, PathBuf};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use dae_config::Config;
use dae_ebpf_support::LiveLoadedTproxyListenSocketMap;
use dae_outbound::{
    NetworkType, SourceShapeRegistryRow, source_shape_registry_contract, source_shape_registry_rows,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub(crate) use self::adapter_matrix::{
    resident_live_adapter_entry_missing, resident_live_adapter_entry_remote_live_matrix_ready,
    resident_live_adapter_matrix_contract, resident_live_adapter_matrix_entries,
    resident_live_matrix_evidence_from_env,
};
pub(crate) use self::events::{ResidentEventLogSink, set_event_log_sink};
use self::events::{append_event, path_string};
use self::plan::build_resident_dataplane_plan;
use self::tcp::{ResidentTcpRouter, probe_resident_proxy_tcp, resident_tcp_accept_loop};
use self::udp::{probe_resident_proxy_dns_udp, probe_resident_proxy_udp, resident_udp_loop};
use super::resident_routing::build_resident_userspace_routing_matcher;

mod adapter_matrix;
mod client;
mod direct;
mod dns;
mod events;
mod execution;
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
const RESIDENT_UDP_PACKET_WORKERS_ENV: &str = "DAE_RESIDENT_UDP_PACKET_WORKERS";
const RESIDENT_UDP_PACKET_WORKERS_DEFAULT: usize = 64;
const RESIDENT_UDP_PACKET_WORKERS_MIN: usize = 1;
const RESIDENT_UDP_PACKET_WORKERS_MAX: usize = 1024;
const RESIDENT_UDP_PACKET_STACK_BYTES_ENV: &str = "DAE_RESIDENT_UDP_PACKET_STACK_BYTES";
const RESIDENT_UDP_PACKET_STACK_BYTES_DEFAULT: usize = 256 * 1024;
const RESIDENT_UDP_PACKET_STACK_BYTES_MIN: usize = 128 * 1024;
const RESIDENT_UDP_PACKET_STACK_BYTES_MAX: usize = 4 * 1024 * 1024;
const RESIDENT_MANUAL_LATENCY_PROBE_CONCURRENCY: usize = 8;
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
static RESIDENT_RELOAD_GENERATION: AtomicU64 = AtomicU64::new(1);

pub(crate) fn resident_runtime_defaults_contract() -> Value {
    json!({
        "tcpFlow": {
            "stackBytes": {
                "env": RESIDENT_TCP_FLOW_STACK_BYTES_ENV,
                "default": RESIDENT_TCP_FLOW_STACK_BYTES_DEFAULT,
                "min": RESIDENT_TCP_FLOW_STACK_BYTES_MIN,
                "max": RESIDENT_TCP_FLOW_STACK_BYTES_MAX,
            },
        },
        "udpPacketTasks": {
            "limit": {
                "env": RESIDENT_UDP_PACKET_WORKERS_ENV,
                "default": RESIDENT_UDP_PACKET_WORKERS_DEFAULT,
                "min": RESIDENT_UDP_PACKET_WORKERS_MIN,
                "max": RESIDENT_UDP_PACKET_WORKERS_MAX,
            },
            "stackBytes": {
                "env": RESIDENT_UDP_PACKET_STACK_BYTES_ENV,
                "default": RESIDENT_UDP_PACKET_STACK_BYTES_DEFAULT,
                "min": RESIDENT_UDP_PACKET_STACK_BYTES_MIN,
                "max": RESIDENT_UDP_PACKET_STACK_BYTES_MAX,
            },
            "model": "bounded resident packet session manager keyed by graph id, outbound, peer, original destination, and packet semantics",
        },
    })
}

pub(crate) fn resident_runtime_environment_defaults() -> Vec<(&'static str, usize)> {
    vec![
        (
            RESIDENT_TCP_FLOW_STACK_BYTES_ENV,
            RESIDENT_TCP_FLOW_STACK_BYTES_DEFAULT,
        ),
        (
            RESIDENT_UDP_PACKET_WORKERS_ENV,
            RESIDENT_UDP_PACKET_WORKERS_DEFAULT,
        ),
        (
            RESIDENT_UDP_PACKET_STACK_BYTES_ENV,
            RESIDENT_UDP_PACKET_STACK_BYTES_DEFAULT,
        ),
    ]
}

#[derive(Debug)]
pub(super) struct ResidentDataplaneRuntime {
    stop: Arc<AtomicBool>,
    handles: Vec<JoinHandle<()>>,
    event_file: PathBuf,
    reload_generation: u64,
    metrics: Arc<ResidentDataplaneMetrics>,
    groups: Vec<Arc<plan::ResidentProxyGroupPlan>>,
    manual_probe_plans: BTreeMap<String, Result<plan::ResidentProxyProbePlan, String>>,
}

impl ResidentDataplaneRuntime {
    pub(super) fn metrics_snapshot(&self) -> Value {
        let mut snapshot = self.metrics.snapshot();
        snapshot["reloadGeneration"] = json!(self.reload_generation);
        snapshot["packetSessionManager"] = json!({
            "schemaVersion": 1,
            "manager": "bounded-resident-packet-session",
            "reloadGeneration": self.reload_generation,
        });
        snapshot
    }

    pub(super) fn node_latency_snapshots(&self) -> Vec<Value> {
        let reload_generation = self.reload_generation;
        preferred_latency_snapshots(
            self.groups
                .iter()
                .flat_map(|group| group.latency_snapshots())
                .map(|snapshot| resident_latency_snapshot_json(snapshot, reload_generation)),
        )
    }

    pub(super) fn probe_node_latencies(&self, links: &[String]) -> Vec<Value> {
        if links.is_empty() {
            return Vec::new();
        }
        let requested = links
            .iter()
            .filter(|link| !link.is_empty())
            .cloned()
            .collect::<HashSet<_>>();
        if requested.is_empty() {
            return Vec::new();
        }

        let checked_at = unix_now_secs();
        let mut snapshots = Vec::new();
        let mut tasks = Vec::new();
        for link in requested {
            match self.manual_probe_plans.get(&link) {
                Some(Ok(candidate)) => tasks.push(candidate.clone()),
                Some(Err(err)) => snapshots.push(manual_probe_unavailable_snapshot(
                    &link,
                    "native outbound probe not admitted for this node",
                    err,
                    checked_at,
                    self.reload_generation,
                )),
                None => snapshots.push(manual_probe_unavailable_snapshot(
                    &link,
                    "node is not present in the current runtime config",
                    "materialize/reload runtime before testing this node",
                    checked_at,
                    self.reload_generation,
                )),
            }
        }

        for chunk in tasks.chunks(RESIDENT_MANUAL_LATENCY_PROBE_CONCURRENCY) {
            let reload_generation = self.reload_generation;
            let mut chunk_snapshots = thread::scope(|scope| {
                let mut handles = Vec::new();
                for candidate in chunk.iter().cloned() {
                    let groups = &self.groups;
                    handles.push(scope.spawn(move || {
                        probe_resident_candidate_tcp_latency_snapshot(
                            groups,
                            candidate,
                            reload_generation,
                        )
                    }));
                }
                handles
                    .into_iter()
                    .filter_map(|handle| handle.join().ok())
                    .collect::<Vec<_>>()
            });
            snapshots.append(&mut chunk_snapshots);
        }
        preferred_latency_snapshots(snapshots)
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
    let Some(default_group) = plan.default_proxy_group().cloned() else {
        return (
            json!({
                "status": "fail",
                "enabled": true,
                "error": "resident dataplane plan is enabled without a default proxy group plan",
                "event_file": path_string(&event_file),
            }),
            None,
        );
    };
    let Some(default_proxy) = default_group.default_proxy_snapshot() else {
        return (
            json!({
                "status": "fail",
                "enabled": true,
                "error": "resident dataplane plan is enabled without an admitted default proxy candidate",
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
    let reload_generation = RESIDENT_RELOAD_GENERATION.fetch_add(1, Ordering::Relaxed);
    let metrics = Arc::new(ResidentDataplaneMetrics::default());
    let proxy = Arc::new(default_proxy);
    let proxy_group = Arc::new(default_group);
    let manual_probe_plans = plan::build_resident_manual_probe_plans(config);
    let manual_probe_plan_count = manual_probe_plans
        .values()
        .filter(|plan| plan.is_ok())
        .count();
    let manual_probe_unavailable_count = manual_probe_plans
        .len()
        .saturating_sub(manual_probe_plan_count);
    let runtime_groups = plan
        .proxies
        .values()
        .cloned()
        .map(Arc::new)
        .collect::<Vec<_>>();
    let health_groups = runtime_groups
        .iter()
        .filter(|group| group.needs_background_checks())
        .cloned()
        .collect::<Vec<_>>();
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
    let udp_packet_workers = resident_udp_packet_workers();
    let udp_packet_stack_bytes = resident_udp_packet_stack_bytes();
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
        let proxy_group = Arc::clone(&proxy_group);
        let dns = Arc::clone(&dns);
        let event_file = event_file.clone();
        let event_lock = Arc::clone(&event_lock);
        let metrics = Arc::clone(&metrics);
        handles.push(thread::spawn(move || {
            resident_udp_loop(
                udp_socket,
                proxy_group,
                dns,
                stop,
                event_file,
                event_lock,
                metrics,
                udp_packet_workers,
                udp_packet_stack_bytes,
            )
        }));
    }
    for health_group in &health_groups {
        let stop = Arc::clone(&stop);
        let health_group = Arc::clone(health_group);
        let event_file = event_file.clone();
        let event_lock = Arc::clone(&event_lock);
        handles.push(thread::spawn(move || {
            resident_group_health_check_loop(health_group, stop, event_file, event_lock)
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
        "udp_packet_workers": udp_packet_workers,
        "udp_packet_workers_env": RESIDENT_UDP_PACKET_WORKERS_ENV,
        "udp_packet_stack_bytes": udp_packet_stack_bytes,
        "udp_packet_stack_bytes_env": RESIDENT_UDP_PACKET_STACK_BYTES_ENV,
        "event_file": path_string(&event_file),
        "reload_generation": reload_generation,
        "routing_tuple_map_id": routing_tuple_map_id,
        "tcp_dial_mode": tcp_router.dial_mode_name(),
        "tcp_sniffing_timeout": format!("{:?}", tcp_router.sniffing_timeout()),
        "proxy_count": tcp_router.proxy_count(),
        "health_check_worker_count": health_groups.len(),
        "manual_probe_plan_count": manual_probe_plan_count,
        "manual_probe_unavailable_count": manual_probe_unavailable_count,
        "default_group": {
            "group": proxy_group.group_name,
            "group_policy": proxy_group.group_policy_name(),
            "candidate_count": proxy_group.candidate_count(),
            "admitted_candidate_count": proxy_group.admitted_candidate_count(),
            "annotation_latency_offset_count": proxy_group.annotation_latency_offset_count(),
            "alive_state_wired": proxy_group.alive_state_wired(),
            "latency_state_wired": proxy_group.latency_state_wired(),
            "background_check_required": proxy_group.needs_background_checks(),
            "check_interval": format!("{:?}", proxy_group.check_interval()),
        },
        "default_proxy": {
            "protocol": proxy.protocol,
            "group": proxy.group_name,
            "group_policy": proxy.group_policy,
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
            "executableGraph": proxy.executable_graph_value_for_reload_generation(reload_generation),
            "runtimeComponents": proxy.runtime_component_evidence_value_for_reload_generation(reload_generation),
        },
        "scope": "resident worker consumes live tproxy TCP/UDP sockets and relays through admitted Rust proxy handlers; unsupported protocols fail explicitly instead of faking proxy success",
    });
    (
        start,
        Some(ResidentDataplaneRuntime {
            stop,
            handles,
            event_file,
            reload_generation,
            metrics,
            groups: runtime_groups,
            manual_probe_plans,
        }),
    )
}

fn resident_group_health_check_loop(
    group: Arc<plan::ResidentProxyGroupPlan>,
    stop: Arc<AtomicBool>,
    event_file: PathBuf,
    event_lock: Arc<Mutex<()>>,
) {
    let interval = group.check_interval();
    let candidates = group.probe_candidates();
    append_event(
        &event_file,
        &event_lock,
        json!({
            "event": "resident_health_checker_started",
            "group": group.group_name,
            "group_policy": group.group_policy_name(),
            "candidate_count": group.candidate_count(),
            "admitted_candidate_count": group.admitted_candidate_count(),
            "check_interval": format!("{interval:?}"),
            "probe": "proxy-tcp-and-dns-udp-check",
            "tcp_check_target": candidates.first().map(|candidate| candidate.tcp_check.target.clone()),
            "udp_check_target": candidates.first().map(|candidate| candidate.udp_check.target.to_string()),
        }),
    );
    run_resident_group_health_checks(&group, &candidates);
    loop {
        if interval.is_zero() || sleep_until_stopped(&stop, interval) {
            return;
        }
        if stop.load(Ordering::Relaxed) {
            return;
        }
        run_resident_group_health_checks(&group, &candidates);
    }
}

fn run_resident_group_health_checks(
    group: &plan::ResidentProxyGroupPlan,
    candidates: &[plan::ResidentProxyProbePlan],
) {
    for candidate in candidates {
        let checked_at = unix_now_secs();
        let latency_ms = probe_resident_candidate_tcp_endpoint(candidate).ok();
        let _ = group.record_check_result(
            &candidate.node_tag,
            NetworkType::TCP4,
            latency_ms,
            checked_at,
        );
        let udp_checked_at = unix_now_secs();
        let udp_latency_ms = probe_resident_candidate_udp_endpoint(candidate).ok();
        let _ = group.record_check_result(
            &candidate.node_tag,
            NetworkType::DNS_UDP4,
            udp_latency_ms,
            udp_checked_at,
        );
    }
}

fn probe_resident_candidate_tcp_latency_snapshot(
    groups: &[Arc<plan::ResidentProxyGroupPlan>],
    candidate: plan::ResidentProxyProbePlan,
    reload_generation: u64,
) -> Value {
    let checked_at = unix_now_secs();
    let probe = probe_resident_candidate_tcp_endpoint(&candidate);
    let latency_ms = probe.as_ref().ok().copied();
    let link = candidate.link.clone();
    for group in groups {
        let _ =
            group.record_check_result_for_link(&link, NetworkType::TCP4, latency_ms, checked_at);
    }
    let display_name = candidate.node_tag.as_str();
    let graph_id = candidate.proxy.graph_id.as_str();
    let link_hash = candidate.link_hash.as_str();
    let redacted_source = candidate.redacted_link_source.as_str();
    json!({
        "name": display_name,
        "displayName": display_name,
        "graphId": graph_id,
        "reloadGeneration": reload_generation,
        "linkHash": link_hash,
        "linkIdentity": latency_link_identity_value(display_name, link_hash, redacted_source),
        "probeExecutor": resident_probe_executor_value(graph_id, reload_generation),
        "runtimeComponents": candidate
            .proxy
            .runtime_component_evidence_value_for_reload_generation(reload_generation),
        "latencyMs": latency_ms,
        "alive": latency_ms.is_some(),
        "checkedAtUnix": checked_at,
        "message": probe.err(),
        "scope": "proxy-tcp-check",
    })
}

fn manual_probe_unavailable_snapshot(
    link: &str,
    reason: &str,
    detail: &str,
    checked_at: i64,
    reload_generation: u64,
) -> Value {
    let display_name = display_name_from_link(link);
    let link_hash = link_hash(link);
    let graph_id = graph_id_from_link_hash(&link_hash);
    let redacted_source = redacted_link_source(link);
    json!({
        "name": display_name,
        "displayName": display_name,
        "graphId": graph_id,
        "reloadGeneration": reload_generation,
        "linkHash": link_hash,
        "linkIdentity": latency_link_identity_value(&display_name, &link_hash, &redacted_source),
        "probeExecutor": resident_probe_executor_value(&graph_id, reload_generation),
        "admission": {
            "status": "fail-closed",
            "unsupportedReason": detail,
        },
        "latencyMs": Value::Null,
        "alive": false,
        "checkedAtUnix": checked_at,
        "message": format!("{reason}: {detail}"),
        "scope": "proxy-tcp-check",
    })
}

fn resident_latency_snapshot_json(
    snapshot: plan::ResidentProxyLatencySnapshot,
    reload_generation: u64,
) -> Value {
    let display_name = snapshot.node_tag.as_str();
    let graph_id = snapshot.graph_id.as_str();
    let link_hash = snapshot.link_hash.as_str();
    let redacted_source = snapshot.redacted_link_source.as_str();
    json!({
        "name": display_name,
        "displayName": display_name,
        "graphId": graph_id,
        "reloadGeneration": reload_generation,
        "linkHash": link_hash,
        "linkIdentity": latency_link_identity_value(display_name, link_hash, redacted_source),
        "probeExecutor": resident_probe_executor_value(graph_id, reload_generation),
        "latencyMs": snapshot.latency_ms,
        "alive": snapshot.alive,
        "checkedAtUnix": snapshot.checked_at_unix,
        "message": snapshot.message,
    })
}

fn resident_probe_executor_value(graph_id: &str, reload_generation: u64) -> Value {
    json!({
        "schemaVersion": 1,
        "executor": "resident-executable-graph",
        "graphId": graph_id,
        "reloadGeneration": reload_generation,
        "sharesTrafficExecutor": true,
    })
}

fn preferred_latency_snapshots(values: impl IntoIterator<Item = Value>) -> Vec<Value> {
    let mut by_link_hash = BTreeMap::<String, Value>::new();
    for value in values {
        let Some(link_hash) = latency_snapshot_link_hash(&value) else {
            continue;
        };
        if link_hash.is_empty() {
            continue;
        }
        let replace = by_link_hash
            .get(link_hash)
            .map(|current| prefer_latency_snapshot(&value, current))
            .unwrap_or(true);
        if replace {
            by_link_hash.insert(link_hash.to_owned(), value);
        }
    }
    by_link_hash.into_values().collect()
}

fn latency_snapshot_link_hash(value: &Value) -> Option<&str> {
    value.get("linkHash").and_then(Value::as_str).or_else(|| {
        value
            .pointer("/linkIdentity/linkHash")
            .and_then(Value::as_str)
    })
}

fn prefer_latency_snapshot(next: &Value, current: &Value) -> bool {
    let next_latency = next.get("latencyMs").and_then(Value::as_i64);
    let current_latency = current.get("latencyMs").and_then(Value::as_i64);
    match (next_latency, current_latency) {
        (Some(_), None) => true,
        (None, Some(_)) => false,
        (Some(next), Some(current)) => next < current,
        (None, None) => {
            next.get("checkedAtUnix")
                .and_then(Value::as_i64)
                .unwrap_or(0)
                > current
                    .get("checkedAtUnix")
                    .and_then(Value::as_i64)
                    .unwrap_or(0)
        }
    }
}

fn latency_link_identity_value(
    display_name: &str,
    link_hash: &str,
    redacted_source: &str,
) -> Value {
    json!({
        "schemaVersion": 1,
        "displayName": display_name,
        "linkHash": link_hash,
        "redactedSource": redacted_source,
    })
}

pub(super) fn link_hash(link: &str) -> String {
    format!("sha256:{}", hex_encode(&Sha256::digest(link.as_bytes())))
}

fn graph_id_from_link_hash(link_hash: &str) -> String {
    let graph_hash = link_hash.trim_start_matches("sha256:");
    format!("resident-graph:{}", &graph_hash[..16.min(graph_hash.len())])
}

pub(super) fn redacted_link_source(link: &str) -> String {
    let Ok(url) = url::Url::parse(link) else {
        return "link:<redacted>".to_owned();
    };
    let mut value = format!("{}:<redacted>", url.scheme());
    if let Some(fragment) = url.fragment().filter(|fragment| !fragment.is_empty()) {
        value.push('#');
        value.push_str(fragment);
    }
    value
}

fn display_name_from_link(link: &str) -> String {
    url::Url::parse(link)
        .ok()
        .and_then(|url| url.fragment().map(str::to_owned))
        .filter(|fragment| !fragment.is_empty())
        .unwrap_or_else(|| "<redacted>".to_owned())
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn probe_resident_candidate_tcp_endpoint(
    candidate: &plan::ResidentProxyProbePlan,
) -> Result<i64, String> {
    let started = Instant::now();
    probe_resident_proxy_tcp(
        &candidate.proxy,
        &candidate.tcp_check.scheme,
        &candidate.tcp_check.target,
        &candidate.tcp_check.host,
        &candidate.tcp_check.path,
        &candidate.tcp_check.method,
        Duration::from_secs(4),
    )?;
    Ok(elapsed_millis(started.elapsed()))
}

fn probe_resident_candidate_udp_endpoint(
    candidate: &plan::ResidentProxyProbePlan,
) -> Result<i64, String> {
    let started = Instant::now();
    probe_resident_proxy_dns_udp(
        &candidate.proxy,
        candidate.udp_check.target,
        &candidate.udp_check.lookup_host,
    )?;
    Ok(elapsed_millis(started.elapsed()))
}

fn elapsed_millis(elapsed: Duration) -> i64 {
    elapsed.as_millis().min(i64::MAX as u128) as i64
}

fn unix_now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs().min(i64::MAX as u64) as i64)
        .unwrap_or(0)
}

fn sleep_until_stopped(stop: &AtomicBool, duration: Duration) -> bool {
    if duration.is_zero() {
        return stop.load(Ordering::Relaxed);
    }
    let started = Instant::now();
    while !stop.load(Ordering::Relaxed) {
        let elapsed = started.elapsed();
        if elapsed >= duration {
            return false;
        }
        thread::sleep((duration - elapsed).min(Duration::from_millis(100)));
    }
    true
}

#[cfg(test)]
mod remote_strategy_live_tests {
    use std::io::{Read, Write};
    use std::net::{Shutdown, TcpListener, TcpStream};
    use std::sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    };
    use std::thread;
    use std::time::Duration;

    use dae_config::Config;

    use super::*;

    struct LiveHttpProxy {
        port: u16,
        delay_ms: Arc<AtomicU64>,
    }

    impl LiveHttpProxy {
        fn set_delay_ms(&self, delay_ms: u64) {
            self.delay_ms.store(delay_ms, Ordering::Relaxed);
        }
    }

    #[test]
    fn remote_resident_group_strategy_matrix_uses_live_proxy_health_checks() {
        if std::env::var("DAE_REMOTE_STRATEGY_LIVE").as_deref() != Ok("1") {
            return;
        }

        let check_server = start_live_http_check_server();
        let node_a = start_live_http_proxy(140);
        let node_b = start_live_http_proxy(20);

        assert_strategy_selects(
            "fixed(0)",
            &format!(
                r#"
        filter: name(node_a, node_b)
        policy: fixed(0)
        "#
            ),
            &node_a,
            &node_b,
            check_server,
            "node_a",
        );
        assert_strategy_selects(
            "random",
            &format!(
                r#"
        filter: name(node_a, node_b)
        policy: random
        "#
            ),
            &node_a,
            &node_b,
            check_server,
            "any",
        );
        assert_strategy_selects(
            "min",
            &format!(
                r#"
        filter: name(node_a, node_b)
        policy: min
        "#
            ),
            &node_a,
            &node_b,
            check_server,
            "node_b",
        );
        assert_strategy_selects(
            "min_avg10",
            &format!(
                r#"
        filter: name(node_a, node_b)
        policy: min_avg10
        "#
            ),
            &node_a,
            &node_b,
            check_server,
            "node_b",
        );
        assert_strategy_selects(
            "min_moving_avg",
            &format!(
                r#"
        filter: name(node_a, node_b)
        policy: min_moving_avg
        "#
            ),
            &node_a,
            &node_b,
            check_server,
            "node_b",
        );
        assert_strategy_selects(
            "add_latency",
            &format!(
                r#"
        filter: name(node_a)
        filter: name(node_b) [add_latency: 250ms]
        policy: min
        "#
            ),
            &node_a,
            &node_b,
            check_server,
            "node_a",
        );

        node_a.set_delay_ms(140);
        node_b.set_delay_ms(110);
        let tolerance_config = live_strategy_config(
            &format!(
                r#"
        filter: name(node_a, node_b)
        policy: min
        check_tolerance: 80ms
        "#
            ),
            &node_a,
            &node_b,
            check_server,
        );
        let plan = build_resident_dataplane_plan(&tolerance_config).unwrap();
        let group = plan.default_proxy_group().unwrap();
        let probes = group.probe_candidates();
        run_resident_group_health_checks(group, &probes);
        assert_eq!(group.select_proxy_for_tcp().unwrap().node_tag, "node_a");
        node_b.set_delay_ms(20);
        run_resident_group_health_checks(group, &probes);
        assert_eq!(group.select_proxy_for_tcp().unwrap().node_tag, "node_b");
    }

    fn assert_strategy_selects(
        label: &str,
        group_body: &str,
        node_a: &LiveHttpProxy,
        node_b: &LiveHttpProxy,
        check_server: u16,
        expected: &str,
    ) {
        let config = live_strategy_config(group_body, node_a, node_b, check_server);
        let plan = build_resident_dataplane_plan(&config)
            .unwrap_or_else(|err| panic!("{label}: build plan: {err}"));
        let group = plan
            .default_proxy_group()
            .unwrap_or_else(|| panic!("{label}: missing default proxy group"));
        let probes = group.probe_candidates();
        run_resident_group_health_checks(group, &probes);
        if expected == "any" {
            let selected = group
                .select_proxy_for_tcp()
                .unwrap_or_else(|err| panic!("{label}: select tcp: {err}"));
            assert!(
                matches!(selected.node_tag.as_str(), "node_a" | "node_b"),
                "{label}: unexpected random selection {}",
                selected.node_tag
            );
            assert!(
                group
                    .latency_snapshots()
                    .iter()
                    .filter(|snapshot| snapshot.latency_ms.is_some())
                    .count()
                    >= 2,
                "{label}: expected live latency for both candidates"
            );
            return;
        }
        assert_eq!(
            group
                .select_proxy_for_tcp()
                .unwrap_or_else(|err| panic!("{label}: select tcp: {err}"))
                .node_tag,
            expected,
            "{label}: selected node"
        );
    }

    fn live_strategy_config(
        group_body: &str,
        node_a: &LiveHttpProxy,
        node_b: &LiveHttpProxy,
        check_server: u16,
    ) -> Config {
        let input = format!(
            r#"
        global {{
        lan_interface: daerust0
        tcp_check_url: 'http://127.0.0.1:{check_server}/generate_204,127.0.0.1'
        udp_check_dns: '127.0.0.1:53,127.0.0.1'
        check_interval: 1s
        }}
        node {{
        node_a: 'http://127.0.0.1:{node_a_port}'
        node_b: 'http://127.0.0.1:{node_b_port}'
        }}
        group {{
        proxy {{
        {group_body}
        }}
        }}
        routing {{
        l4proto(tcp) -> proxy
        fallback: direct
        }}
        "#,
            node_a_port = node_a.port,
            node_b_port = node_b.port,
        );
        let sections = dae_config::parser::parse_config(&input)
            .unwrap_or_else(|err| panic!("parse live strategy config: {err}"));
        dae_config::schema::build_config(&sections)
            .unwrap_or_else(|err| panic!("build live strategy config: {err}"))
    }

    fn start_live_http_check_server() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                thread::spawn(move || handle_live_http_check(stream));
            }
        });
        port
    }

    fn handle_live_http_check(mut stream: TcpStream) {
        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
        let _ = read_headers(&mut stream);
        let _ = stream.write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n");
        let _ = stream.flush();
        let _ = stream.shutdown(Shutdown::Both);
    }

    fn start_live_http_proxy(delay_ms: u64) -> LiveHttpProxy {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let delay_ms = Arc::new(AtomicU64::new(delay_ms));
        let delay_for_thread = Arc::clone(&delay_ms);
        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let delay_ms = Arc::clone(&delay_for_thread);
                thread::spawn(move || handle_live_http_proxy(stream, delay_ms));
            }
        });
        LiveHttpProxy { port, delay_ms }
    }

    fn handle_live_http_proxy(mut inbound: TcpStream, delay_ms: Arc<AtomicU64>) {
        let _ = inbound.set_read_timeout(Some(Duration::from_secs(5)));
        let request = match read_headers(&mut inbound) {
            Ok(request) => request,
            Err(_) => return,
        };
        let Some(target) = connect_target_from_request(&request) else {
            let _ = inbound.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n");
            return;
        };
        thread::sleep(Duration::from_millis(delay_ms.load(Ordering::Relaxed)));
        let mut outbound = match TcpStream::connect(target) {
            Ok(outbound) => outbound,
            Err(_) => {
                let _ = inbound.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n");
                return;
            }
        };
        let _ = outbound.set_read_timeout(Some(Duration::from_secs(5)));
        let _ = inbound.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n");
        let _ = inbound.flush();
        let mut inbound_reader = match inbound.try_clone() {
            Ok(stream) => stream,
            Err(_) => return,
        };
        let mut outbound_writer = match outbound.try_clone() {
            Ok(stream) => stream,
            Err(_) => return,
        };
        let upload = thread::spawn(move || {
            let _ = std::io::copy(&mut inbound_reader, &mut outbound_writer);
            let _ = outbound_writer.shutdown(Shutdown::Write);
        });
        let _ = std::io::copy(&mut outbound, &mut inbound);
        let _ = inbound.shutdown(Shutdown::Write);
        let _ = upload.join();
    }

    fn read_headers(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
        let mut request = Vec::new();
        let mut buf = [0_u8; 256];
        while request.len() < 8192 {
            let read = stream.read(&mut buf)?;
            if read == 0 {
                break;
            }
            request.extend_from_slice(&buf[..read]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        Ok(request)
    }

    fn connect_target_from_request(request: &[u8]) -> Option<String> {
        let text = String::from_utf8_lossy(request);
        let mut first_line = text.lines().next()?.split_whitespace();
        let method = first_line.next()?;
        let target = first_line.next()?;
        if method.eq_ignore_ascii_case("CONNECT") && !target.is_empty() {
            Some(target.to_owned())
        } else {
            None
        }
    }
}

pub(crate) fn resident_live_adapter_config_assessment(
    config: &Config,
    config_path: Option<&Path>,
) -> Value {
    let matrix = resident_live_adapter_matrix_contract();
    let live_evidence = resident_live_matrix_evidence_from_env();
    let node_shapes = plan::resident_node_link_shapes(config);
    let matrix_entries = resident_live_adapter_matrix_entries()
        .iter()
        .map(|entry| {
            let remote_live_matrix =
                resident_live_adapter_entry_remote_live_matrix_ready(entry, &live_evidence);
            let missing = resident_live_adapter_entry_missing(entry, &live_evidence);
            json!({
                "handler": entry.handler,
                "formal_matrix_handler": entry.formal_matrix_handler,
                "udp_semantics": entry.udp_semantics,
                "udp_path_ready": entry.udp_path_ready(),
                "wired_ready": entry.wired_ready(),
                "remote_live_matrix": remote_live_matrix,
                "live_ready": entry.wired_ready() && remote_live_matrix && missing.is_empty(),
                "missing": missing,
            })
        })
        .collect::<Vec<_>>();
    let full_matrix_rows = resident_full_matrix_config_rows(config, &node_shapes);
    let full_matrix_present_rows = full_matrix_rows
        .iter()
        .filter(|row| row["candidate_count"].as_u64().unwrap_or(0) > 0)
        .count();
    let full_matrix_admitted_rows = full_matrix_rows
        .iter()
        .filter(|row| row["planner_status"].as_str() == Some("admitted"))
        .count();
    let source_shape_registry = source_shape_registry_contract();
    let expanded_source_matrix_rows =
        resident_expanded_source_matrix_rows(&node_shapes, &full_matrix_rows);
    let expanded_source_matrix_status_counts =
        resident_matrix_status_counts(&expanded_source_matrix_rows);
    let expanded_source_matrix_complete = false;
    let matrix_scope = "current-config-formal-handler-matrix";
    let matrix_scope_contract = json!({
        "schemaVersion": 1,
        "scope": matrix_scope,
        "currentConfigMatrixOpen": true,
        "currentAdmittedBaselineOpen": true,
        "sourceShapeRegistryOpen": source_shape_registry.source_shape_registry_open,
        "expandedSourceMatrixOpen": source_shape_registry.expanded_source_matrix_open,
        "expandedSourceMatrixComplete": expanded_source_matrix_complete,
        "currentConfigRows": full_matrix_rows.len(),
        "currentConfigPresentRows": full_matrix_present_rows,
        "currentConfigAdmittedRows": full_matrix_admitted_rows,
        "formalHandlerRows": resident_live_adapter_matrix_entries().len(),
        "releaseGateMayUseAsSourceMatrix": false,
        "c10MayUseAsExpandedSourceMatrix": false,
    });
    let mut report = json!({
        "schema": "resident-live-adapter-config-assessment",
        "config": config_path.map(path_string),
        "read_only": true,
        "host_mutation_executed": false,
        "network_io_executed": false,
        "live_traffic_executed": false,
        "matrix_schema": matrix.schema,
        "resident_live_adapter_matrix_ready": matrix.matrix_ready,
        "resident_live_adapter_wired_matrix_ready": matrix.wired_matrix_ready,
        "resident_live_adapter_remote_live_matrix_ready": matrix.remote_live_matrix_ready,
        "resident_live_adapter_remote_live_matrix_evidence": {
            "env": live_evidence.env,
            "source": live_evidence.source,
            "schema": live_evidence.schema,
            "schemaVersion": live_evidence.schema_version,
            "candidateSha256": live_evidence.candidate_sha256,
            "rowCount": live_evidence.row_count,
            "passCount": live_evidence.pass_count,
            "allPass": live_evidence.all_pass,
            "valid": live_evidence.valid,
            "readyHandlers": live_evidence.ready_handlers.iter().cloned().collect::<Vec<_>>(),
            "error": live_evidence.error,
        },
        "resident_live_adapter_entries": matrix_entries,
    });
    report["matrix_scope"] = json!(matrix_scope);
    report["current_config_matrix_open"] = json!(true);
    report["current_admitted_baseline_open"] = json!(true);
    report["source_shape_registry_open"] = json!(source_shape_registry.source_shape_registry_open);
    report["expanded_source_matrix_open"] =
        json!(source_shape_registry.expanded_source_matrix_open);
    report["expanded_source_matrix_complete"] = json!(expanded_source_matrix_complete);
    report["matrix_scope_contract"] = matrix_scope_contract;
    report["full_matrix_open"] = json!(true);
    report["full_matrix_scope"] = json!(matrix_scope);
    report["full_matrix_is_expanded_source_matrix"] = json!(false);
    report["full_matrix_release_gate_source_ready"] = json!(false);
    report["full_matrix_c10_expanded_source_ready"] = json!(false);
    report["full_matrix_row_count"] = json!(full_matrix_rows.len());
    report["full_matrix_present_row_count"] = json!(full_matrix_present_rows);
    report["full_matrix_admitted_row_count"] = json!(full_matrix_admitted_rows);
    report["full_matrix_complete"] = json!(matrix.matrix_ready);
    report["full_matrix_completion_blocker"] = if matrix.matrix_ready {
        Value::Null
    } else {
        json!(
            "real live traffic evidence is required before the resident live adapter matrix can be complete"
        )
    };
    report["source_shape_registry_schema"] = json!(source_shape_registry.schema);
    report["source_shape_registry_schema_version"] = json!(source_shape_registry.schema_version);
    report["source_shape_registry_row_count"] = json!(source_shape_registry.rows.len());
    report["source_shape_registry_contract"] = source_shape_registry.to_value();
    report["expanded_source_matrix_row_count"] = json!(expanded_source_matrix_rows.len());
    report["expanded_source_matrix_status_counts"] = expanded_source_matrix_status_counts;
    report["expanded_source_matrix_release_gate_ready"] = json!(false);
    report["expanded_source_matrix_c10_ready"] = json!(false);
    report["source_matrix_completion_blocker"] = json!(
        "expanded source matrix has fail-closed rows and requires live host, benchmark, and rollback evidence"
    );
    report["expanded_source_matrix_rows"] = json!(expanded_source_matrix_rows);
    report["full_matrix_rows"] = json!(full_matrix_rows);

    match build_resident_dataplane_plan(config) {
        Ok(plan) if plan.enabled => {
            let proxies = plan
                .proxies
                .iter()
                .map(|(outbound, group)| {
                    let mut summary = resident_proxy_group_plan_summary_json(group);
                    summary["outbound_index"] = json!(outbound);
                    summary
                })
                .collect::<Vec<_>>();
            let default_proxy = plan
                .default_proxy_snapshot()
                .as_ref()
                .map(resident_proxy_plan_summary_json)
                .unwrap_or(Value::Null);
            let default_group = plan
                .default_proxy_group()
                .map(resident_proxy_group_plan_summary_json)
                .unwrap_or(Value::Null);
            report["status"] = json!("admitted");
            report["planner_admitted"] = json!(true);
            report["selected_node_fail_closed"] = json!(true);
            report["resident_dataplane_enabled_by_config"] = json!(true);
            report["proxy_count"] = json!(plan.proxies.len());
            report["tcp_dial_mode"] = json!(plan.tcp_dial_mode.as_str());
            report["tcp_sniffing_timeout"] = json!(format!("{:?}", plan.sniffing_timeout));
            report["default_proxy"] = default_proxy;
            report["default_group"] = default_group;
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

pub(crate) fn resident_live_adapter_udp_probe(
    config: &Config,
    target: SocketAddrV4,
    payload: &[u8],
    config_path: Option<&Path>,
) -> Value {
    let started = std::time::Instant::now();
    let node_shapes = plan::resident_node_link_shapes(config);
    let rows = resident_live_adapter_matrix_entries()
        .iter()
        .map(|entry| {
            let schemes = matrix_row_schemes(entry.formal_matrix_handler);
            let candidates = node_shapes
                .iter()
                .filter(|node| schemes.iter().any(|scheme| *scheme == node.scheme))
                .collect::<Vec<_>>();
            let mut blocked = Vec::new();
            for node in &candidates {
                match plan::build_resident_proxy_plan_for_node(
                    config,
                    entry.formal_matrix_handler.to_owned(),
                    node.tag.clone(),
                    node.link.clone(),
                ) {
                    Ok(proxy) => {
                        let mut probe = probe_resident_proxy_udp(&proxy, target, payload);
                        probe["formal_matrix_handler"] = json!(entry.formal_matrix_handler);
                        probe["node_tag"] = json!(node.tag);
                        probe["udp_live_adapter"] = json!(entry.udp_live_adapter);
                        probe["udp_semantics"] = json!(entry.udp_semantics);
                        probe["udp_path_ready"] = json!(entry.udp_path_ready());
                        return probe;
                    }
                    Err(err) => blocked.push(json!({
                        "node_tag": node.tag,
                        "scheme": node.scheme,
                        "error": sanitize_matrix_error(&err),
                    })),
                }
            }
            json!({
                "formal_matrix_handler": entry.formal_matrix_handler,
                "status": if candidates.is_empty() { "not-present" } else { "blocked" },
                "ok": false,
                "protocol_closed": false,
                "candidate_count": candidates.len(),
                "udp_live_adapter": entry.udp_live_adapter,
                "udp_semantics": entry.udp_semantics,
                "udp_path_ready": entry.udp_path_ready(),
                "blocked": blocked,
            })
        })
        .collect::<Vec<_>>();
    let pass_count = rows
        .iter()
        .filter(|row| row["status"].as_str() == Some("pass"))
        .count();
    let protocol_closed_count = rows
        .iter()
        .filter(|row| row["status"].as_str() == Some("protocol-closed"))
        .count();
    let failure_count = rows
        .iter()
        .filter(|row| row["ok"].as_bool() != Some(true))
        .count();
    let matrix = resident_live_adapter_matrix_contract();
    json!({
        "schema": "resident-live-adapter-udp-live",
        "config": config_path.map(path_string),
        "target": target.to_string(),
        "payload_len": payload.len(),
        "network_io_executed": true,
        "host_mutation_executed": false,
        "matrix_schema": matrix.schema,
        "row_count": rows.len(),
        "pass_count": pass_count,
        "protocol_closed_count": protocol_closed_count,
        "failure_count": failure_count,
        "matrix_pass": failure_count == 0 && rows.len() == matrix.entries.len(),
        "elapsed_ms": started.elapsed().as_millis(),
        "rows": rows,
    })
}

fn resident_full_matrix_config_rows(
    config: &Config,
    nodes: &[plan::ResidentNodeLinkShape],
) -> Vec<Value> {
    let live_evidence = resident_live_matrix_evidence_from_env();
    resident_live_adapter_matrix_entries()
        .iter()
        .map(|entry| {
            let remote_live_matrix =
                resident_live_adapter_entry_remote_live_matrix_ready(entry, &live_evidence);
            let missing = resident_live_adapter_entry_missing(entry, &live_evidence);
            let schemes = matrix_row_schemes(entry.formal_matrix_handler);
            let candidates = nodes
                .iter()
                .filter(|node| schemes.iter().any(|scheme| *scheme == node.scheme))
                .collect::<Vec<_>>();
            let candidate_reports = candidates
                .iter()
                .map(|node| resident_matrix_candidate_report(config, entry, node))
                .collect::<Vec<_>>();
            let admitted_count = candidate_reports
                .iter()
                .filter(|candidate| candidate["planner_status"].as_str() == Some("admitted"))
                .count();
            let blocked_count = candidate_reports
                .iter()
                .filter(|candidate| candidate["planner_status"].as_str() == Some("blocked"))
                .count();
            let planner_status = if candidates.is_empty() {
                "not-present"
            } else if admitted_count > 0 {
                "admitted"
            } else {
                "blocked"
            };
            let runtime_components_ready = candidate_reports
                .iter()
                .any(resident_matrix_candidate_runtime_components_ready);
            let generated_solver = resident_matrix_solver_value(
                entry,
                candidates.len(),
                admitted_count,
                blocked_count,
                runtime_components_ready,
                remote_live_matrix,
                missing.is_empty(),
            );
            let default_ready = generated_solver["defaultReady"].clone();
            let go_free_ready = generated_solver["goFreeReady"].clone();
            json!({
                "handler": entry.handler,
                "formal_matrix_handler": entry.formal_matrix_handler,
                "matrix_scope": "current-config-formal-handler-matrix",
                "opened": true,
                "source_supported": true,
                "source_supported_scope": "formal-handler-baseline",
                "source_shape_registry_status": "open",
                "expanded_source_matrix_state": "generated",
                "planner_status": planner_status,
                "wired_ready": entry.wired_ready(),
                "runtime_components_ready": runtime_components_ready,
                "live_ready": entry.wired_ready() && remote_live_matrix && missing.is_empty(),
                "remote_live_matrix": remote_live_matrix,
                "udp_live_adapter": entry.udp_live_adapter,
                "udp_semantics": entry.udp_semantics,
                "udp_path_ready": entry.udp_path_ready(),
                "candidate_count": candidates.len(),
                "admitted_count": admitted_count,
                "blocked_count": blocked_count,
                "selected_node_fail_closed": entry.selected_node_fail_closed,
                "fingerprint_behavior": entry.fingerprint_behavior,
                "generated_solver": generated_solver,
                "default_ready": default_ready,
                "go_free_ready": go_free_ready,
                "missing": missing,
                "candidates": candidate_reports,
            })
        })
        .collect()
}

fn resident_expanded_source_matrix_rows(
    nodes: &[plan::ResidentNodeLinkShape],
    current_config_rows: &[Value],
) -> Vec<Value> {
    source_shape_registry_rows()
        .iter()
        .map(|row| resident_expanded_source_matrix_row(row, nodes, current_config_rows))
        .collect()
}

fn resident_expanded_source_matrix_row(
    row: &SourceShapeRegistryRow,
    nodes: &[plan::ResidentNodeLinkShape],
    current_config_rows: &[Value],
) -> Value {
    let candidate_count = nodes
        .iter()
        .filter(|node| {
            row.link_schemes
                .iter()
                .any(|scheme| *scheme == node.scheme.as_str())
        })
        .count();
    let current_config_row = current_config_rows.iter().find(|current| {
        current["formal_matrix_handler"].as_str() == Some(row.protocol_family)
            || current["handler"].as_str() == Some(row.protocol_family)
    });
    let current_config_status = current_config_row
        .and_then(|current| current["planner_status"].as_str())
        .unwrap_or("not-present");
    let planner_status = match (row.source_support, row.resident_status) {
        ("not-source-supported", _) => "not-source-supported",
        ("source-supported", "blocked") => "blocked",
        ("source-supported", "admitted-baseline") if candidate_count == 0 => "not-present",
        ("source-supported", "admitted-baseline") => current_config_status,
        _ => "blocked",
    };
    let capability_reason_id = match planner_status {
        "admitted" | "not-present" => Value::Null,
        "not-source-supported" => json!("unsupported-source-policy"),
        _ => json!(row.blocker_id.unwrap_or("materialization-mismatch")),
    };
    let redacted_detail = match planner_status {
        "admitted" => "current config candidate is admitted by resident planner",
        "not-present" => "shape is source-supported but absent from current config",
        "not-source-supported" => "shape is rejected by Rust native source policy",
        _ => "shape remains fail-closed until its capability evidence is complete",
    };

    json!({
        "schemaVersion": 1,
        "shapeId": row.shape_id,
        "sourceSupport": row.source_support,
        "protocolFamily": row.protocol_family,
        "linkSchemes": row.link_schemes,
        "planner_status": planner_status,
        "candidate_count": candidate_count,
        "currentConfigStatus": current_config_status,
        "residentStatus": row.resident_status,
        "blockerId": row.blocker_id,
        "capabilityReasonId": capability_reason_id,
        "redactedDetail": redacted_detail,
        "redactedIdentity": row.redacted_identity,
        "endpoint": row.endpoint,
        "securityUnderlay": row.security_underlay,
        "streamWrapper": row.stream_wrapper,
        "packetSemantics": row.packet_semantics,
        "chainShape": row.chain_shape,
        "policySurface": row.policy_surface,
        "reloadLifecycle": row.reload_lifecycle,
        "parserCoverage": row.parser_coverage,
        "evidenceRequirements": row.evidence_requirements,
        "shapeStateLedger": row.state_ledger.to_value(),
        "componentExecutorProof": row.executor_proof.to_value(),
        "runtimeSelectionLedger": row.runtime_selection.to_value(),
        "capabilityLedger": row.capability.to_value(),
        "expandedLiveMatrixLedger": row.expanded_live_matrix.to_value(),
        "releaseGateReconciliation": row.release_gate.to_value(),
        "sourceRegistryRow": (*row).to_value(),
    })
}

fn resident_matrix_status_counts(rows: &[Value]) -> Value {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for row in rows {
        let status = row["planner_status"].as_str().unwrap_or("unknown");
        *counts.entry(status.to_owned()).or_default() += 1;
    }
    json!(counts)
}

fn resident_matrix_solver_value(
    entry: &adapter_matrix::ResidentLiveAdapterMatrixEntry,
    candidate_count: usize,
    admitted_count: usize,
    blocked_count: usize,
    runtime_components_ready: bool,
    remote_live_matrix: bool,
    remote_live_matrix_complete: bool,
) -> Value {
    let parser_covered = candidate_count > 0;
    let normalized_graph_ready = admitted_count > 0;
    let executable_graph_ready =
        normalized_graph_ready && entry.wired_ready() && runtime_components_ready;
    let admission_fail_closed = blocked_count > 0 || candidate_count == admitted_count;
    let tcp_loopback_ready = executable_graph_ready && entry.tcp_live_adapter;
    let udp_loopback_ready = executable_graph_ready && entry.udp_path_ready();
    let reload_cleanup_ready = executable_graph_ready;
    let benchmark_ready = false;
    let live_ready = executable_graph_ready && remote_live_matrix && remote_live_matrix_complete;
    let default_ready = live_ready && benchmark_ready;
    let go_free_ready = default_ready && entry.go_outbound_fallback_retired;
    let blockers = resident_matrix_solver_blockers(
        parser_covered,
        normalized_graph_ready,
        runtime_components_ready,
        executable_graph_ready,
        live_ready,
        benchmark_ready,
    );
    json!({
        "schemaVersion": 1,
        "sourceShape": entry.formal_matrix_handler,
        "parserCovered": parser_covered,
        "normalizedGraphReady": normalized_graph_ready,
        "runtimeComponentsReady": runtime_components_ready,
        "executableGraphReady": executable_graph_ready,
        "admissionFailClosed": admission_fail_closed,
        "tcpLoopbackReady": tcp_loopback_ready,
        "udpLoopbackReady": udp_loopback_ready,
        "reloadCleanupReady": reload_cleanup_ready,
        "benchmarkReady": benchmark_ready,
        "liveReady": live_ready,
        "defaultReady": default_ready,
        "goFreeReady": go_free_ready,
        "blockers": blockers,
    })
}

fn resident_matrix_solver_blockers(
    parser_covered: bool,
    normalized_graph_ready: bool,
    runtime_components_ready: bool,
    executable_graph_ready: bool,
    live_ready: bool,
    benchmark_ready: bool,
) -> Vec<&'static str> {
    let mut blockers = Vec::new();
    if !parser_covered {
        blockers.push("no source-supported candidate is present in this config");
    }
    if !normalized_graph_ready {
        blockers.push("no normalized resident graph was admitted");
    }
    if !runtime_components_ready {
        blockers.push("runtime component factory/session/probe evidence is missing or fail-closed");
    }
    if !executable_graph_ready {
        blockers.push("executable graph evidence is missing");
    }
    if !live_ready {
        blockers.push("remote live matrix evidence is missing or incomplete");
    }
    if !benchmark_ready {
        blockers.push("matched benchmark evidence is missing");
    }
    blockers
}

fn resident_matrix_candidate_runtime_components_ready(candidate: &Value) -> bool {
    if candidate["planner_status"].as_str() != Some("admitted") {
        return false;
    }
    let components = &candidate["runtimeComponents"];
    component_status_is_admitted(&components["underlayFactory"])
        && component_status_is_admitted(&components["streamWrapperFactory"])
        && component_status_is_admitted(&components["chainExecutor"])
        && generation_cache_contract_ready(&components["generationCache"])
        && component_status_is_admitted(&components["packetSessionManager"])
        && component_status_is_admitted(&components["probeExecutor"])
}

fn component_status_is_admitted(component: &Value) -> bool {
    component["status"].as_str() == Some("admitted")
}

fn generation_cache_contract_ready(component: &Value) -> bool {
    component["schemaVersion"].as_i64() == Some(1)
        && component["graphId"]
            .as_str()
            .is_some_and(|graph| !graph.is_empty())
        && component["owner"].as_str() == Some("resident-dataplane-runtime")
        && component["cacheScope"].as_str() == Some("graph-and-reload-generation")
        && component["cleanupPolicy"].as_str() == Some("drop-on-graph-diff-or-runtime-stop")
}

fn resident_matrix_candidate_report(
    config: &Config,
    entry: &adapter_matrix::ResidentLiveAdapterMatrixEntry,
    node: &plan::ResidentNodeLinkShape,
) -> Value {
    match plan::build_resident_proxy_plan_for_node(
        config,
        entry.formal_matrix_handler.to_owned(),
        node.tag.clone(),
        node.link.clone(),
    ) {
        Ok(proxy) => {
            let mut summary = resident_proxy_plan_summary_json(&proxy);
            summary["planner_status"] = json!("admitted");
            summary["scheme"] = json!(&node.scheme);
            summary["admission"] = json!({
                "status": "admitted",
                "failClosed": true,
                "unsupportedReason": Value::Null,
            });
            summary
        }
        Err(err) => json!({
            "planner_status": "blocked",
            "node_tag": &node.tag,
            "scheme": &node.scheme,
            "admission": {
                "status": "fail-closed",
                "failClosed": true,
                "unsupportedReason": sanitize_matrix_error(&err),
            },
            "error": sanitize_matrix_error(&err),
        }),
    }
}

fn matrix_row_schemes(formal_matrix_handler: &str) -> &'static [&'static str] {
    match formal_matrix_handler {
        "vless" => &["vless"],
        "shadowsocks" => &["ss", "shadowsocks"],
        "trojan" => &["trojan"],
        "vmess" => &["vmess"],
        "hysteria2" => &["hysteria2", "hy2"],
        "tuic" => &["tuic"],
        "juicity" => &["juicity"],
        "anytls" => &["anytls"],
        "http-proxy" => &["http", "https"],
        "socks5" => &["socks", "socks5"],
        _ => &[],
    }
}

fn sanitize_matrix_error(error: &str) -> String {
    if error.contains("://") {
        return "planner error contained a raw link and was redacted".to_owned();
    }
    error.to_owned()
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
        "group_policy": proxy.group_policy,
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
        "executableGraph": proxy.executable_graph_value(),
        "runtimeComponents": proxy.runtime_component_evidence_value(),
    })
}

fn resident_proxy_group_plan_summary_json(group: &plan::ResidentProxyGroupPlan) -> Value {
    let mut summary = group
        .default_proxy_snapshot()
        .as_ref()
        .map(resident_proxy_plan_summary_json)
        .unwrap_or_else(|| {
            json!({
                "group": group.group_name,
                "group_policy": group.group_policy_name(),
            })
        });
    summary["group"] = json!(group.group_name);
    summary["group_policy"] = json!(group.group_policy_name());
    summary["candidate_count"] = json!(group.candidate_count());
    summary["admitted_candidate_count"] = json!(group.admitted_candidate_count());
    summary["annotation_latency_offset_count"] = json!(group.annotation_latency_offset_count());
    summary["alive_state_wired"] = json!(group.alive_state_wired());
    summary["latency_state_wired"] = json!(group.latency_state_wired());
    summary["background_check_required"] = json!(group.needs_background_checks());
    summary["check_interval"] = json!(format!("{:?}", group.check_interval()));
    summary
}

fn resident_tcp_flow_stack_bytes() -> usize {
    bounded_env_usize(
        RESIDENT_TCP_FLOW_STACK_BYTES_ENV,
        RESIDENT_TCP_FLOW_STACK_BYTES_DEFAULT,
        RESIDENT_TCP_FLOW_STACK_BYTES_MIN,
        RESIDENT_TCP_FLOW_STACK_BYTES_MAX,
    )
}

fn resident_udp_packet_workers() -> usize {
    bounded_env_usize(
        RESIDENT_UDP_PACKET_WORKERS_ENV,
        RESIDENT_UDP_PACKET_WORKERS_DEFAULT,
        RESIDENT_UDP_PACKET_WORKERS_MIN,
        RESIDENT_UDP_PACKET_WORKERS_MAX,
    )
}

fn resident_udp_packet_stack_bytes() -> usize {
    bounded_env_usize(
        RESIDENT_UDP_PACKET_STACK_BYTES_ENV,
        RESIDENT_UDP_PACKET_STACK_BYTES_DEFAULT,
        RESIDENT_UDP_PACKET_STACK_BYTES_MIN,
        RESIDENT_UDP_PACKET_STACK_BYTES_MAX,
    )
}

fn bounded_env_usize(name: &str, default: usize, min: usize, max: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.trim().parse::<usize>().ok())
        .unwrap_or(default)
        .clamp(min, max)
}
