// UDP session manager keeps kernel sockets, routing maps, session queues, and metrics explicit.
#![allow(clippy::too_many_arguments)]

use std::collections::HashMap;
use std::io;
use std::path::Path;

#[cfg(not(test))]
use dae_datapath::TcpDialMode;
#[cfg(test)]
use dae_datapath::{OUTBOUND_BLOCK, OUTBOUND_CONTROL_PLANE_ROUTING, OUTBOUND_DIRECT, TcpDialMode};
use dae_ebpf_support::BpfRoutingResult;
use dae_routing::RoutingMatcher;
use serde_json::Value;
use tokio::io::unix::AsyncFd;

use super::super::plan::resident_data_udp_network_type;
use super::*;

mod dns_dispatcher;
mod dns_fast_path;
mod ingress;
mod router;
mod session_shards;
mod sniff;
use self::dns_dispatcher::{ResidentDnsFastPathDispatcher, ResidentDnsFastPathHandle};
use self::dns_fast_path::{
    minimal_resident_dns_routing_result, resident_udp_dns_fast_path_applies,
    resident_udp_dns_fast_path_can_bypass_missing_tuple,
};
use self::ingress::recv_udp_batch_with_original_dst_async;
use self::router::{ResidentUdpRouteSelection, ResidentUdpRouter, ResidentUdpSelection};
use self::session_shards::{
    ResidentUdpSessionShardHandle, ResidentUdpSessionShardPool, SharedUdpSniffedDomain,
};
use self::sniff::{UdpPendingSniffer, UdpSniffDecision, UdpSniffKey, udp_sniff_reroute_decision};

const UDP_ROUTE_CHOSEN_EVENT: &str = "udp_route_chosen";
const UDP_ROUTE_KIND_PROXY: &str = "proxy";
const UDP_ROUTE_KIND_BLOCK: &str = "block";
const UDP_ROUTE_KIND_DIRECT: &str = "direct";
const UDP_ROUTE_POLICY_FIXED: &str = "fixed";
const UDP_ROUTE_DIALER_BLOCK: &str = "block";
const UDP_ROUTE_DIALER_DIRECT: &str = "direct";
const UDP_ROUTE_REASON_BLOCK: &str = "selected block outbound";
const UDP_ROUTE_REASON_LIMIT: &str = "session limit reached";
const UDP_ROUTE_REASON_QUEUE_FULL: &str = "session queue full";
const UDP_ROUTE_REASON_DISPATCH_QUEUE_FULL: &str = "session dispatch queue full";
const UDP_ROUTE_REASON_SESSION_UNAVAILABLE: &str = "session actor closed during recreation";
const UDP_ROUTE_REASON_QUEUED: &str = "queued packet for resident UDP session";
const UDP_ROUTE_REASON_DNS_FAST_PATH: &str = "handled resident DNS packet without UDP session";
const UDP_SESSION_WORKER_THREAD_NAME: &str = "udp-session";

pub(super) fn run_resident_udp_session_manager(
    socket: UdpSocket,
    proxy_groups: SharedResidentProxyGroupMap,
    default_outbound: u8,
    routing_tuple_map_id: Option<u32>,
    routing_matcher: RoutingMatcher,
    dial_mode: TcpDialMode,
    so_mark_from_dae: u32,
    dns: Arc<ResidentDnsPlan>,
    stop: SharedResidentStopSignal,
    event_file: PathBuf,
    event_lock: Arc<Mutex<()>>,
    metrics: Arc<ResidentDataplaneMetrics>,
    active_sessions: Arc<AtomicUsize>,
    runtime_config: ResidentUdpRuntimeConfig,
    health_resuscitation: ResidentHealthResuscitationHandle,
    hysteria2_owner_registry: Hysteria2OwnerRegistryHandle,
    tuic_owner_registry: Option<TuicOwnerRegistryHandle>,
    juicity_owner_registry: Option<JuicityOwnerRegistryHandle>,
    anytls_owner_registry: Option<AnyTlsOwnerRegistryHandle>,
) -> Value {
    let mut runtime_builder = if runtime_config.runtime_worker_threads > 0 {
        let mut builder = tokio::runtime::Builder::new_multi_thread();
        builder
            .worker_threads(runtime_config.runtime_worker_threads)
            .thread_name(UDP_SESSION_WORKER_THREAD_NAME)
            .thread_stack_size(runtime_config.worker_stack_bytes);
        builder
    } else {
        tokio::runtime::Builder::new_current_thread()
    };
    let runtime = match runtime_builder.enable_io().enable_time().build() {
        Ok(runtime) => runtime,
        Err(err) => {
            let report = udp_session_manager_start_failure("runtime-build", err.to_string());
            append_event(
                &event_file,
                &event_lock,
                udp_session_manager_event("udp_session_manager_start_failed", &report),
            );
            return report;
        }
    };
    runtime.block_on(run_resident_udp_session_manager_async(
        socket,
        proxy_groups,
        default_outbound,
        routing_tuple_map_id,
        routing_matcher,
        dial_mode,
        so_mark_from_dae,
        dns,
        stop,
        event_file,
        event_lock,
        metrics,
        active_sessions,
        runtime_config,
        health_resuscitation,
        hysteria2_owner_registry,
        tuic_owner_registry,
        juicity_owner_registry,
        anytls_owner_registry,
    ))
}

async fn run_resident_udp_session_manager_async(
    socket: UdpSocket,
    proxy_groups: SharedResidentProxyGroupMap,
    default_outbound: u8,
    routing_tuple_map_id: Option<u32>,
    routing_matcher: RoutingMatcher,
    dial_mode: TcpDialMode,
    so_mark_from_dae: u32,
    dns: Arc<ResidentDnsPlan>,
    stop: SharedResidentStopSignal,
    event_file: PathBuf,
    event_lock: Arc<Mutex<()>>,
    metrics: Arc<ResidentDataplaneMetrics>,
    active_sessions: Arc<AtomicUsize>,
    runtime_config: ResidentUdpRuntimeConfig,
    health_resuscitation: ResidentHealthResuscitationHandle,
    hysteria2_owner_registry: Hysteria2OwnerRegistryHandle,
    tuic_owner_registry: Option<TuicOwnerRegistryHandle>,
    juicity_owner_registry: Option<JuicityOwnerRegistryHandle>,
    anytls_owner_registry: Option<AnyTlsOwnerRegistryHandle>,
) -> Value {
    let session_limit = runtime_config.session_limit;
    let session_queue_depth = runtime_config.session_queue_depth;
    let dns_fast_path_concurrency = runtime_config.dns_fast_path_concurrency;
    if let Err(err) = socket.set_nonblocking(true) {
        let report = udp_session_manager_start_failure("socket-nonblocking", err.to_string());
        append_event(
            &event_file,
            &event_lock,
            udp_session_manager_event("udp_socket_nonblocking_failed", &report),
        );
        return report;
    }
    let socket = match AsyncFd::new(socket) {
        Ok(socket) => socket,
        Err(err) => {
            let report = udp_session_manager_start_failure("async-fd", err.to_string());
            append_event(
                &event_file,
                &event_lock,
                udp_session_manager_event("udp_session_manager_async_fd_failed", &report),
            );
            return report;
        }
    };
    let router = match ResidentUdpRouter::new(
        proxy_groups,
        default_outbound,
        routing_tuple_map_id,
        routing_matcher,
        dial_mode,
        so_mark_from_dae,
        health_resuscitation,
    ) {
        Ok(router) => router,
        Err(err) => {
            let report = udp_session_manager_start_failure("router-build", err);
            append_event(
                &event_file,
                &event_lock,
                udp_session_manager_event("udp_session_manager_start_failed", &report),
            );
            return report;
        }
    };
    let default_proxy_group = router.default_proxy_group();
    append_event(
        &event_file,
        &event_lock,
        json!({
            "event": "udp_session_manager_started",
            "proxy_group": default_proxy_group.group_name,
            "group_policy": default_proxy_group.group_policy_name(),
            "candidate_count": default_proxy_group.candidate_count(),
            "admitted_candidate_count": default_proxy_group.admitted_candidate_count(),
            "default_outbound": default_outbound,
            "routing_tuple_map_id": router.routing_tuple_map_id(),
            "session_limit": session_limit,
            "dns_fast_path_concurrency": dns_fast_path_concurrency,
            "dns_fast_path_queue_depth": runtime_config.dns_fast_path_queue_depth,
            "forced_dns_session_lanes": runtime_config.runtime_shards,
            "generation": runtime_config.generation,
            "runtimeProfile": runtime_config.profile,
            "queuedPayloadAdmission": runtime_config.payload_admission.snapshot(),
            "packetSessionManager": {
                "schemaVersion": 1,
                "manager": "resident-udp-session-manager",
                "runtime": if runtime_config.runtime_worker_threads > 0 {
                    "tokio-owned-session-shards"
                } else {
                    "tokio-current-thread-single-shard"
                },
                "sessionShardCount": runtime_config.runtime_shards,
                "sessionWorkerThreads": runtime_config.runtime_worker_threads,
                "sessionLimit": session_limit,
                "perSessionQueueDepth": session_queue_depth,
                "replyQueueDepth": runtime_config.reply_queue_depth,
                "replySocketCacheCapacity": runtime_config.reply_socket_cache_capacity,
                "keyFields": [
                    "graphIdentityHash",
                    "outbound",
                    "peerSocketAddr",
                    "originalDestinationSocketAddr",
                    "packetSemantics",
                ],
            },
        }),
    );

    let mut sniffers: HashMap<UdpSniffKey, UdpPendingSniffer> = HashMap::new();
    let reply_dispatcher = UdpReplyDispatcher::start(
        runtime_config.reply_queue_depth,
        runtime_config.reply_socket_cache_capacity,
        runtime_config.reply_socket_idle_timeout,
        runtime_config.payload_admission.clone(),
        Arc::clone(&metrics),
    );
    let udp_reply = reply_dispatcher.handle();
    let dns_fast_path_dispatcher = ResidentDnsFastPathDispatcher::start(
        Arc::clone(&dns),
        udp_reply.clone(),
        Arc::clone(&metrics),
        dns_fast_path_concurrency,
        runtime_config.dns_fast_path_queue_depth,
    );
    let dns_fast_path = dns_fast_path_dispatcher.handle();
    let session_shards = ResidentUdpSessionShardPool::start(
        &runtime_config,
        Arc::clone(&dns),
        router.proxy_groups(),
        event_file.clone(),
        Arc::clone(&event_lock),
        Arc::clone(&metrics),
        udp_reply.clone(),
        Arc::clone(&active_sessions),
        hysteria2_owner_registry,
        tuic_owner_registry,
        juicity_owner_registry,
        anytls_owner_registry,
    );
    let session_shard_handle = session_shards.handle();
    let payload_pool = UdpPayloadPool::new(runtime_config.payload_pool_capacity());

    let mut stop_listener = stop.listener();
    while !stop.load(Ordering::Relaxed) {
        tokio::select! {
            batch = recv_udp_batch_with_original_dst_async(
                &socket,
                &payload_pool,
                runtime_config.ingress_drain_budget,
            ) => {
                match batch {
                    Ok(batch) => {
                        metrics.record_udp_ingress_batch(
                            batch.packets.len(),
                            batch.truncated,
                            batch.budget_hit,
                        );
                        for mut packet in batch.packets {
                            if packet
                                .payload
                                .admit(&runtime_config.payload_admission)
                                .is_err()
                            {
                                continue;
                            }
                            handle_manager_packet(
                                packet,
                                &router,
                                &event_file,
                                &event_lock,
                                &mut sniffers,
                                &dns_fast_path,
                                &session_shard_handle,
                                runtime_config.runtime_shards,
                            );
                        }
                        if batch.budget_hit {
                            tokio::task::yield_now().await;
                        }
                    }
                    Err(err) => {
                        if !stop.load(Ordering::Relaxed) {
                            append_event(
                                &event_file,
                                &event_lock,
                                json!({"event": "udp_receive_failed", "error": err}),
                            );
                        }
                    }
                }
            }
            _ = stop_listener.cancelled() => break,
        }
    }

    let shutdown_deadline = time::Instant::now() + runtime_config.shutdown_timeout;
    drop(sniffers);
    drop(session_shard_handle);
    let session_shard_shutdown = session_shards.shutdown(shutdown_deadline).await;
    drop(dns_fast_path);
    let dns_fast_path_shutdown = dns_fast_path_dispatcher.shutdown(shutdown_deadline).await;
    let dns_forwarder_shutdown = dns.shutdown_forwarders(shutdown_deadline).await;
    drop(udp_reply);
    let reply_shutdown = reply_dispatcher.shutdown(shutdown_deadline).await;
    let dns_fast_path_shutdown = match dns_fast_path_shutdown {
        Ok(completed) => json!({"status": "pass", "completed": completed}),
        Err(err) => json!({"status": "fail", "error": err}),
    };
    let reply_shutdown = match reply_shutdown {
        Ok(sockets) => json!({"status": "pass", "closedSockets": sockets}),
        Err(err) => json!({"status": "fail", "error": err.to_string()}),
    };
    let active_sessions = active_sessions.load(Ordering::Acquire);
    let queued_payload_admission = runtime_config.payload_admission.snapshot();
    let cleanup_passed = active_sessions == 0
        && runtime_config.payload_admission.current() == 0
        && cleanup_report_passed(&session_shard_shutdown)
        && cleanup_report_passed(&dns_fast_path_shutdown)
        && cleanup_report_passed(&dns_forwarder_shutdown)
        && cleanup_report_passed(&reply_shutdown);
    let report = json!({
        "status": if cleanup_passed { "pass" } else { "fail" },
        "activeSessions": active_sessions,
        "queuedPayloadAdmission": queued_payload_admission,
        "sessionShards": session_shard_shutdown,
        "dnsFastPathDispatcher": dns_fast_path_shutdown,
        "dnsForwarders": dns_forwarder_shutdown,
        "replyDispatcher": reply_shutdown,
    });
    append_event(
        &event_file,
        &event_lock,
        udp_session_manager_event("udp_session_manager_stopped", &report),
    );
    report
}

fn udp_session_manager_start_failure(stage: &'static str, error: String) -> Value {
    json!({
        "status": "fail",
        "stage": stage,
        "error": error,
    })
}

fn cleanup_report_passed(report: &Value) -> bool {
    report["status"].as_str() == Some("pass")
}

fn udp_session_manager_event(event: &'static str, report: &Value) -> Value {
    let mut value = report.clone();
    if let Some(object) = value.as_object_mut() {
        object.insert("event".to_owned(), json!(event));
    }
    value
}

fn handle_manager_packet(
    packet: UdpOriginalDstPacket,
    router: &ResidentUdpRouter,
    event_file: &Path,
    event_lock: &Arc<Mutex<()>>,
    sniffers: &mut HashMap<UdpSniffKey, UdpPendingSniffer>,
    dns_fast_path: &ResidentDnsFastPathHandle,
    session_shards: &ResidentUdpSessionShardHandle,
    forced_dns_session_lanes: usize,
) {
    let Some(original_dst) = packet.original_dst else {
        append_event(
            event_file,
            event_lock,
            json!({"event": "udp_packet_skipped", "reason": "missing original destination", "peer": resident_socket_addr_display(packet.peer)}),
        );
        return;
    };
    let initial = match router.lookup_routing_result(packet.peer, original_dst) {
        Ok(initial) => initial,
        Err(err) => {
            if resident_udp_dns_fast_path_can_bypass_missing_tuple(original_dst, &packet.payload) {
                minimal_resident_dns_routing_result()
            } else {
                append_udp_route_selection_failed(
                    event_file,
                    event_lock,
                    packet.peer,
                    original_dst,
                    None,
                    err,
                );
                return;
            }
        }
    };
    let ready = match udp_sniff_reroute_decision(packet, router, original_dst, initial, sniffers) {
        UdpSniffDecision::Ready(ready) => ready,
        UdpSniffDecision::Pending => return,
    };
    let sniffed_domain = if ready.sniffed_domain.is_empty() {
        None
    } else {
        Some(Arc::<str>::from(ready.sniffed_domain))
    };
    for packet in ready.packets {
        forward_manager_packet(
            packet,
            router,
            event_file,
            event_lock,
            dns_fast_path,
            session_shards,
            forced_dns_session_lanes,
            ready.initial,
            &sniffed_domain,
        );
    }
}

fn forward_manager_packet(
    packet: UdpOriginalDstPacket,
    router: &ResidentUdpRouter,
    event_file: &Path,
    event_lock: &Arc<Mutex<()>>,
    dns_fast_path: &ResidentDnsFastPathHandle,
    session_shards: &ResidentUdpSessionShardHandle,
    forced_dns_session_lanes: usize,
    initial: BpfRoutingResult,
    sniffed_domain: &SharedUdpSniffedDomain,
) {
    let sniffed_domain_str = sniffed_domain.as_deref().unwrap_or_default();
    let Some(original_dst) = packet.original_dst else {
        append_event(
            event_file,
            event_lock,
            json!({"event": "udp_packet_skipped", "reason": "missing original destination", "peer": resident_socket_addr_display(packet.peer), "dscp": initial.dscp}),
        );
        return;
    };
    let selection = match router.select_from_routing_result_with_domain(
        packet.peer,
        original_dst,
        initial,
        sniffed_domain_str,
    ) {
        Ok(selection) => selection,
        Err(err) => {
            append_udp_route_selection_failed(
                event_file,
                event_lock,
                packet.peer,
                original_dst,
                Some(initial.dscp),
                err,
            );
            return;
        }
    };
    let proxy_selection = match selection {
        ResidentUdpSelection::ResidentDns => {
            dns_fast_path.try_dispatch(packet, original_dst);
            return;
        }
        ResidentUdpSelection::Proxy(selection) => selection,
        ResidentUdpSelection::Direct(selection) => {
            let key =
                UdpDirectSessionKey::new(packet.peer, original_dst, selection.route.final_mark);
            let managed = ManagedDirectUdpPacket {
                packet,
                original_dst,
                dscp: initial.dscp,
            };
            session_shards.try_dispatch_direct(
                key,
                managed,
                selection.route,
                sniffed_domain.clone(),
            );
            return;
        }
        ResidentUdpSelection::Block(selection) => {
            append_event(
                event_file,
                event_lock,
                udp_route_chosen_event(
                    packet.peer,
                    original_dst,
                    &selection,
                    None,
                    None,
                    sniffed_domain_str,
                    initial.dscp,
                    false,
                    UDP_ROUTE_REASON_BLOCK,
                ),
            );
            append_event(
                event_file,
                event_lock,
                json!({
                    "event": "udp_packet_dropped",
                    "reason": "resident UDP selected block outbound",
                    "peer": resident_socket_addr_display(packet.peer),
                    "original_dst": resident_socket_addr_display(original_dst),
                    "initial_outbound": selection.initial_outbound,
                    "final_outbound": selection.final_outbound,
                    "network": resident_udp_network_name(original_dst),
                    "dscp": initial.dscp,
                }),
            );
            return;
        }
    };
    let proxy = Arc::clone(&proxy_selection.proxy);
    if resident_udp_dns_fast_path_applies(original_dst) && !proxy_selection.force_proxy_packet {
        append_event(
            event_file,
            event_lock,
            udp_route_chosen_event_without_packet_session(
                packet.peer,
                original_dst,
                &proxy_selection.route,
                &proxy,
                sniffed_domain_str,
                initial.dscp,
                UDP_ROUTE_REASON_DNS_FAST_PATH,
            ),
        );
        dns_fast_path.try_dispatch(packet, original_dst);
        return;
    }
    let key = if proxy_selection.force_proxy_packet
        && resident_udp_dns_fast_path_applies(original_dst)
    {
        let dispatch_lane = dns_request_dispatch_lane(&packet.payload, forced_dns_session_lanes);
        UdpSessionKey::with_dispatch_lane(&proxy, packet.peer, original_dst, dispatch_lane)
    } else {
        UdpSessionKey::new(&proxy, packet.peer, original_dst)
    };
    let managed = ManagedUdpPacket {
        packet,
        original_dst,
        proxy,
        proxy_outbound: proxy_selection.route.final_outbound,
        data_udp_network_type: if proxy_selection.force_proxy_packet {
            None
        } else if proxy_selection.selected_network_type.is_data_udp() {
            Some(proxy_selection.selected_network_type)
        } else {
            Some(resident_data_udp_network_type(original_dst))
        },
        force_proxy_packet: proxy_selection.force_proxy_packet,
        dscp: initial.dscp,
    };
    session_shards.try_dispatch_proxy(key, managed, proxy_selection.route, sniffed_domain.clone());
}

fn append_udp_route_selection_failed(
    event_file: &Path,
    event_lock: &Arc<Mutex<()>>,
    peer: SocketAddr,
    original_dst: SocketAddr,
    dscp: Option<u8>,
    err: String,
) {
    let mut event = json!({
        "event": "udp_exchange_failed",
        "peer": resident_socket_addr_display(peer),
        "original_dst": resident_socket_addr_display(original_dst),
        "error": err,
        "network": resident_udp_network_name(original_dst),
    });
    if let Some(dscp) = dscp {
        event["dscp"] = json!(dscp);
    }
    append_event(event_file, event_lock, event);
}

fn udp_route_chosen_event(
    peer: SocketAddr,
    original_dst: SocketAddr,
    route: &ResidentUdpRouteSelection,
    proxy: Option<&ResidentProxyPlan>,
    packet_session: Option<&UdpSessionKey>,
    sniffed_domain: &str,
    dscp: u8,
    task_queued: bool,
    reason: &str,
) -> serde_json::Value {
    let outbound_kind = if proxy.is_some() {
        UDP_ROUTE_KIND_PROXY
    } else {
        UDP_ROUTE_KIND_BLOCK
    };
    let outbound = proxy
        .map(|proxy| proxy.group_name.as_str())
        .unwrap_or(UDP_ROUTE_KIND_BLOCK);
    let policy = proxy
        .map(|proxy| proxy.group_policy.as_str())
        .unwrap_or(UDP_ROUTE_POLICY_FIXED);
    let dialer = proxy
        .map(|proxy| proxy.node_tag.as_str())
        .unwrap_or(UDP_ROUTE_DIALER_BLOCK);
    let mut event = json!({
        "event": UDP_ROUTE_CHOSEN_EVENT,
        "outbound_kind": outbound_kind,
        "peer": resident_socket_addr_display(peer),
        "original_dst": resident_socket_addr_display(original_dst),
        "direct_target": resident_socket_addr_display(original_dst),
        "initial_outbound": route.initial_outbound,
        "final_outbound": route.final_outbound,
        "final_mark": route.final_mark,
        "userspace_route_executed": route.userspace_route_executed,
        "userspace_route_must": route.userspace_route_must,
        "sniffed_domain": sniffed_domain,
        "network": resident_udp_network_name(original_dst),
        "outbound": outbound,
        "policy": policy,
        "dialer": dialer,
        "ip": resident_socket_addr_display(original_dst),
        "task_queued": task_queued,
        "reason": reason,
        "dscp": dscp,
    });
    if let Some(proxy) = proxy
        && let Some(map) = event.as_object_mut()
    {
        map.insert(
            "proxy_group".to_owned(),
            serde_json::Value::String(proxy.group_name.clone()),
        );
        map.insert(
            "group_policy".to_owned(),
            serde_json::Value::String(proxy.group_policy.clone()),
        );
        map.insert(
            "node_tag".to_owned(),
            serde_json::Value::String(proxy.node_tag.clone()),
        );
        map.insert(
            "protocol".to_owned(),
            serde_json::Value::String(proxy.protocol.to_owned()),
        );
        map.insert(
            "handler".to_owned(),
            serde_json::Value::String(resident_udp_proxy_handler_name(proxy).to_owned()),
        );
        map.insert(
            "graphId".to_owned(),
            serde_json::Value::String(proxy.graph_id.clone()),
        );
        let packet_session = packet_session
            .map(UdpSessionKey::to_value)
            .unwrap_or_else(|| UdpSessionKey::new(proxy, peer, original_dst).to_value());
        map.insert("packetSession".to_owned(), packet_session);
    }
    event
}

fn udp_direct_route_chosen_event(
    peer: SocketAddr,
    original_dst: SocketAddr,
    route: &ResidentUdpRouteSelection,
    key: &UdpDirectSessionKey,
    sniffed_domain: &str,
    dscp: u8,
    task_queued: bool,
    reason: &str,
) -> serde_json::Value {
    json!({
        "event": UDP_ROUTE_CHOSEN_EVENT,
        "outbound_kind": UDP_ROUTE_KIND_DIRECT,
        "peer": resident_socket_addr_display(peer),
        "original_dst": resident_socket_addr_display(original_dst),
        "direct_target": resident_socket_addr_display(original_dst),
        "initial_outbound": route.initial_outbound,
        "final_outbound": route.final_outbound,
        "final_mark": route.final_mark,
        "userspace_route_executed": route.userspace_route_executed,
        "userspace_route_must": route.userspace_route_must,
        "sniffed_domain": sniffed_domain,
        "network": resident_udp_network_name(original_dst),
        "outbound": UDP_ROUTE_KIND_DIRECT,
        "policy": UDP_ROUTE_POLICY_FIXED,
        "dialer": UDP_ROUTE_DIALER_DIRECT,
        "ip": resident_socket_addr_display(original_dst),
        "task_queued": task_queued,
        "reason": reason,
        "dscp": dscp,
        "packetSession": key.to_value(),
    })
}

fn udp_route_chosen_event_without_packet_session(
    peer: SocketAddr,
    original_dst: SocketAddr,
    route: &ResidentUdpRouteSelection,
    proxy: &ResidentProxyPlan,
    sniffed_domain: &str,
    dscp: u8,
    reason: &str,
) -> serde_json::Value {
    let mut event = udp_route_chosen_event(
        peer,
        original_dst,
        route,
        Some(proxy),
        None,
        sniffed_domain,
        dscp,
        false,
        reason,
    );
    if let Some(map) = event.as_object_mut() {
        map.remove("packetSession");
    }
    event
}

#[cfg(test)]
mod tests;
