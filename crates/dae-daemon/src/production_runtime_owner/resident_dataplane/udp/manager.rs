// UDP session manager keeps kernel sockets, routing maps, session queues, and metrics explicit.
#![allow(clippy::too_many_arguments)]

use std::collections::{BTreeMap, HashMap};
use std::io;
use std::path::Path;

#[cfg(not(test))]
use dae_datapath::TcpDialMode;
#[cfg(test)]
use dae_datapath::{OUTBOUND_BLOCK, OUTBOUND_CONTROL_PLANE_ROUTING, OUTBOUND_DIRECT, TcpDialMode};
use dae_ebpf_support::BpfRoutingResult;
use dae_routing::RoutingMatcher;
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;

use super::*;

mod dns_fast_path;
mod router;
mod sniff;
use self::dns_fast_path::{
    minimal_resident_dns_routing_result, resident_udp_dns_fast_path_applies,
    resident_udp_dns_fast_path_can_bypass_missing_tuple,
};
use self::router::{ResidentUdpRouteSelection, ResidentUdpRouter, ResidentUdpSelection};
use self::sniff::{UdpPendingSniffer, UdpSniffDecision, UdpSniffKey, udp_sniff_reroute_decision};

const UDP_ROUTE_CHOSEN_EVENT: &str = "udp_route_chosen";
const UDP_ROUTE_KIND_PROXY: &str = "proxy";
const UDP_ROUTE_KIND_BLOCK: &str = "block";
const UDP_ROUTE_POLICY_FIXED: &str = "fixed";
const UDP_ROUTE_DIALER_BLOCK: &str = "block";
const UDP_ROUTE_REASON_BLOCK: &str = "selected block outbound";
const UDP_ROUTE_REASON_LIMIT: &str = "session limit reached";
const UDP_ROUTE_REASON_QUEUE_FULL: &str = "session queue full";
const UDP_ROUTE_REASON_QUEUED: &str = "queued packet for resident UDP session";
const UDP_ROUTE_REASON_DNS_FAST_PATH: &str = "handled resident DNS packet without UDP session";
const UDP_ROUTE_REASON_FORCED_DNS_FAST_PATH: &str =
    "handled forced resident DNS packet without UDP session";

pub(super) fn run_resident_udp_session_manager(
    socket: UdpSocket,
    proxy_groups: Arc<BTreeMap<u8, ResidentProxyGroupPlan>>,
    default_outbound: u8,
    routing_tuple_map_id: Option<u32>,
    routing_matcher: RoutingMatcher,
    dial_mode: TcpDialMode,
    dns: Arc<ResidentDnsPlan>,
    stop: Arc<AtomicBool>,
    event_file: PathBuf,
    event_lock: Arc<Mutex<()>>,
    metrics: Arc<ResidentDataplaneMetrics>,
    active_sessions: Arc<AtomicUsize>,
    session_limit: usize,
    session_queue_depth: usize,
) {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
    {
        Ok(runtime) => runtime,
        Err(err) => {
            append_event(
                &event_file,
                &event_lock,
                json!({"event": "udp_session_manager_start_failed", "error": err.to_string()}),
            );
            return;
        }
    };
    runtime.block_on(run_resident_udp_session_manager_async(
        socket,
        proxy_groups,
        default_outbound,
        routing_tuple_map_id,
        routing_matcher,
        dial_mode,
        dns,
        stop,
        event_file,
        event_lock,
        metrics,
        active_sessions,
        session_limit.max(1),
        session_queue_depth.max(1),
    ));
}

async fn run_resident_udp_session_manager_async(
    socket: UdpSocket,
    proxy_groups: Arc<BTreeMap<u8, ResidentProxyGroupPlan>>,
    default_outbound: u8,
    routing_tuple_map_id: Option<u32>,
    routing_matcher: RoutingMatcher,
    dial_mode: TcpDialMode,
    dns: Arc<ResidentDnsPlan>,
    stop: Arc<AtomicBool>,
    event_file: PathBuf,
    event_lock: Arc<Mutex<()>>,
    metrics: Arc<ResidentDataplaneMetrics>,
    active_sessions: Arc<AtomicUsize>,
    session_limit: usize,
    session_queue_depth: usize,
) {
    if let Err(err) = socket.set_nonblocking(true) {
        append_event(
            &event_file,
            &event_lock,
            json!({"event": "udp_socket_nonblocking_failed", "error": err.to_string()}),
        );
        return;
    }
    let router = match ResidentUdpRouter::new(
        proxy_groups,
        default_outbound,
        routing_tuple_map_id,
        routing_matcher,
        dial_mode,
    ) {
        Ok(router) => router,
        Err(err) => {
            append_event(
                &event_file,
                &event_lock,
                json!({"event": "udp_session_manager_start_failed", "error": err}),
            );
            return;
        }
    };
    let socket = match AsyncFd::new(socket) {
        Ok(socket) => socket,
        Err(err) => {
            append_event(
                &event_file,
                &event_lock,
                json!({"event": "udp_session_manager_async_fd_failed", "error": err.to_string()}),
            );
            return;
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
            "packetSessionManager": {
                "schemaVersion": 1,
                "manager": "resident-udp-session-manager",
                "runtime": "tokio-current-thread",
                "sessionLimit": session_limit,
                "perSessionQueueDepth": session_queue_depth,
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

    let mut sessions: HashMap<UdpSessionKey, UdpSessionEntry> = HashMap::new();
    let mut sniffers: HashMap<UdpSniffKey, UdpPendingSniffer> = HashMap::new();
    let (cleanup_tx, mut cleanup_rx) = mpsc::channel::<UdpSessionKey>(session_limit);
    let payload_pool = UdpPayloadPool::new(
        session_limit
            .saturating_mul(session_queue_depth)
            .clamp(16, 1024),
    );

    while !stop.load(Ordering::Relaxed) {
        tokio::select! {
            Some(key) = cleanup_rx.recv() => {
                if let Some(mut entry) = sessions.remove(&key) {
                    let _ = (&mut entry.handle).await;
                }
            }
            packet = recv_udp_with_original_dst_async(&socket, &payload_pool) => {
                match packet {
                    Ok(packet) => handle_manager_packet(
                        packet,
                        &router,
                        &dns,
                        &event_file,
                        &event_lock,
                        &metrics,
                        &active_sessions,
                        &mut sessions,
                        &mut sniffers,
                        &cleanup_tx,
                        session_limit,
                        session_queue_depth,
                    ),
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
            _ = time::sleep(RESIDENT_IDLE_SLEEP) => {}
        }
    }

    let mut joined = 0_usize;
    let mut timed_out = 0_usize;
    let mut panicked = 0_usize;
    for (_, mut entry) in sessions.drain() {
        drop(entry.sender);
        match time::timeout(RESIDENT_UDP_RESPONSE_TIMEOUT, &mut entry.handle).await {
            Ok(Ok(())) => joined += 1,
            Ok(Err(_)) => panicked += 1,
            Err(_) => {
                entry.handle.abort();
                timed_out += 1;
            }
        }
    }
    append_event(
        &event_file,
        &event_lock,
        json!({
            "event": "udp_session_manager_stopped",
            "joined_sessions": joined,
            "timed_out_sessions": timed_out,
            "panicked_sessions": panicked,
            "active_sessions": active_sessions.load(Ordering::Relaxed),
        }),
    );
}

fn handle_manager_packet(
    packet: UdpOriginalDstPacket,
    router: &ResidentUdpRouter,
    dns: &Arc<ResidentDnsPlan>,
    event_file: &Path,
    event_lock: &Arc<Mutex<()>>,
    metrics: &Arc<ResidentDataplaneMetrics>,
    active_sessions: &Arc<AtomicUsize>,
    sessions: &mut HashMap<UdpSessionKey, UdpSessionEntry>,
    sniffers: &mut HashMap<UdpSniffKey, UdpPendingSniffer>,
    cleanup_tx: &mpsc::Sender<UdpSessionKey>,
    session_limit: usize,
    session_queue_depth: usize,
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
    for packet in ready.packets {
        forward_manager_packet(
            packet,
            router,
            dns,
            event_file,
            event_lock,
            metrics,
            active_sessions,
            sessions,
            cleanup_tx,
            session_limit,
            session_queue_depth,
            ready.initial,
            &ready.sniffed_domain,
        );
    }
}

fn forward_manager_packet(
    packet: UdpOriginalDstPacket,
    router: &ResidentUdpRouter,
    dns: &Arc<ResidentDnsPlan>,
    event_file: &Path,
    event_lock: &Arc<Mutex<()>>,
    metrics: &Arc<ResidentDataplaneMetrics>,
    active_sessions: &Arc<AtomicUsize>,
    sessions: &mut HashMap<UdpSessionKey, UdpSessionEntry>,
    cleanup_tx: &mpsc::Sender<UdpSessionKey>,
    session_limit: usize,
    session_queue_depth: usize,
    initial: BpfRoutingResult,
    sniffed_domain: &str,
) {
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
        sniffed_domain,
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
            spawn_resident_dns_datagram_handler(
                packet,
                original_dst,
                Arc::clone(dns),
                Arc::clone(metrics),
            );
            return;
        }
        ResidentUdpSelection::Proxy(selection) => selection,
        ResidentUdpSelection::Block(selection) => {
            append_event(
                event_file,
                event_lock,
                udp_route_chosen_event(
                    packet.peer,
                    original_dst,
                    &selection,
                    None,
                    sniffed_domain,
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
    if resident_udp_dns_fast_path_applies(original_dst) {
        let reason = if proxy_selection.force_proxy_packet {
            UDP_ROUTE_REASON_FORCED_DNS_FAST_PATH
        } else {
            UDP_ROUTE_REASON_DNS_FAST_PATH
        };
        append_event(
            event_file,
            event_lock,
            udp_route_chosen_event_without_packet_session(
                packet.peer,
                original_dst,
                &proxy_selection.route,
                &proxy,
                sniffed_domain,
                initial.dscp,
                reason,
            ),
        );
        if proxy_selection.force_proxy_packet {
            spawn_forced_resident_dns_proxy_datagram_handler(
                packet,
                proxy,
                original_dst,
                initial.dscp,
                Arc::clone(dns),
                event_file.to_path_buf(),
                Arc::clone(event_lock),
                Arc::clone(metrics),
            );
        } else {
            spawn_resident_dns_datagram_handler(
                packet,
                original_dst,
                Arc::clone(dns),
                Arc::clone(metrics),
            );
        }
        return;
    }
    let key = UdpSessionKey::new(&proxy, packet.peer, original_dst);
    if !sessions.contains_key(&key) {
        if sessions.len() >= session_limit {
            append_event(
                event_file,
                event_lock,
                udp_route_chosen_event(
                    packet.peer,
                    original_dst,
                    &proxy_selection.route,
                    Some(&proxy),
                    sniffed_domain,
                    initial.dscp,
                    false,
                    UDP_ROUTE_REASON_LIMIT,
                ),
            );
            append_event(
                event_file,
                event_lock,
                json!({
                    "event": "udp_packet_dropped",
                    "reason": "resident UDP session limit reached",
                    "peer": resident_socket_addr_display(packet.peer),
                    "original_dst": resident_socket_addr_display(original_dst),
                    "active_sessions": sessions.len(),
                    "session_limit": session_limit,
                    "packetSession": key.to_value(),
                    "dscp": initial.dscp,
                }),
            );
            return;
        }
        let (sender, receiver) = mpsc::channel::<ManagedUdpPacket>(session_queue_depth);
        let context = UdpSessionActorContext {
            dns: Arc::clone(dns),
            event_file: event_file.to_path_buf(),
            event_lock: Arc::clone(event_lock),
            metrics: Arc::clone(metrics),
            active_sessions: Arc::clone(active_sessions),
        };
        let actor_key = key.clone();
        let actor_cleanup_tx = cleanup_tx.clone();
        let handle = spawn_udp_session_actor(actor_key, context, receiver, actor_cleanup_tx);
        sessions.insert(key.clone(), UdpSessionEntry { sender, handle });
    }
    let peer = packet.peer;
    let managed = ManagedUdpPacket {
        packet,
        original_dst,
        proxy,
        force_proxy_packet: proxy_selection.force_proxy_packet,
        dscp: initial.dscp,
    };
    let Some(entry) = sessions.get(&key) else {
        return;
    };
    if let Err(err) = entry.sender.try_send(managed) {
        append_event(
            event_file,
            event_lock,
            udp_route_chosen_event(
                peer,
                original_dst,
                &proxy_selection.route,
                Some(&proxy_selection.proxy),
                sniffed_domain,
                initial.dscp,
                false,
                UDP_ROUTE_REASON_QUEUE_FULL,
            ),
        );
        append_event(
            event_file,
            event_lock,
            json!({
                "event": "udp_packet_dropped",
                "reason": "resident UDP session queue full",
                "error": err.to_string(),
                "session_limit": session_limit,
                "session_queue_depth": session_queue_depth,
                "packetSession": key.to_value(),
                "dscp": initial.dscp,
            }),
        );
    } else {
        append_event(
            event_file,
            event_lock,
            udp_route_chosen_event(
                peer,
                original_dst,
                &proxy_selection.route,
                Some(&proxy_selection.proxy),
                sniffed_domain,
                initial.dscp,
                true,
                UDP_ROUTE_REASON_QUEUED,
            ),
        );
    }
}

fn spawn_resident_dns_datagram_handler(
    packet: UdpOriginalDstPacket,
    original_dst: SocketAddr,
    dns: Arc<ResidentDnsPlan>,
    metrics: Arc<ResidentDataplaneMetrics>,
) {
    tokio::spawn(async move {
        metrics.add_upload(packet.payload.len());
        let response = match time::timeout(
            RESIDENT_UDP_RESPONSE_TIMEOUT,
            handle_resident_dns_udp_async(&dns, original_dst, &packet.payload),
        )
        .await
        {
            Ok(Ok(response)) => response,
            Ok(Err(_)) | Err(_) => match build_dns_server_failure_response(&packet.payload) {
                Ok(response) => response,
                Err(_) => return,
            },
        };
        if send_udp_reply(original_dst, packet.peer, &response).is_ok() {
            metrics.add_download(response.len());
        }
    });
}

fn spawn_forced_resident_dns_proxy_datagram_handler(
    packet: UdpOriginalDstPacket,
    proxy: Arc<ResidentProxyPlan>,
    original_dst: SocketAddr,
    dscp: u8,
    dns: Arc<ResidentDnsPlan>,
    event_file: PathBuf,
    event_lock: Arc<Mutex<()>>,
    metrics: Arc<ResidentDataplaneMetrics>,
) {
    tokio::spawn(async move {
        let mut executor = UdpSessionExecutor::new_proxy_packet(&proxy);
        let exchange = match time::timeout(
            RESIDENT_UDP_RESPONSE_TIMEOUT,
            execute_forced_dns_proxy_datagram(
                &mut executor,
                &dns,
                &proxy,
                original_dst,
                &packet.payload,
            ),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => Err(format!(
                "forced resident DNS proxy datagram timed out after {}ms",
                RESIDENT_UDP_RESPONSE_TIMEOUT.as_millis()
            )),
        };
        executor.shutdown().await;
        record_udp_dns_datagram_exchange_result(
            &proxy,
            packet,
            original_dst,
            dscp,
            event_file,
            event_lock,
            metrics,
            exchange,
        );
    });
}

async fn execute_forced_dns_proxy_datagram(
    executor: &mut UdpSessionExecutor,
    dns: &ResidentDnsPlan,
    proxy: &ResidentProxyPlan,
    original_dst: SocketAddr,
    payload: &[u8],
) -> Result<(&'static str, UdpExchangeResult), String> {
    let (event, response) = executor.execute(dns, proxy, original_dst, payload).await?;
    if response.reply_forwarded {
        return Ok((event, response.into_independent_datagram()));
    }
    loop {
        match executor.poll_response().await? {
            Some((event, response)) => return Ok((event, response.into_independent_datagram())),
            None => time::sleep(RESIDENT_IDLE_SLEEP).await,
        }
    }
}

async fn recv_udp_with_original_dst_async(
    socket: &AsyncFd<UdpSocket>,
    payload_pool: &UdpPayloadPool,
) -> Result<UdpOriginalDstPacket, String> {
    loop {
        let mut guard = socket
            .readable()
            .await
            .map_err(|err| format!("await UDP socket readiness: {err}"))?;
        match guard.try_io(|inner| {
            match try_recv_udp_with_original_dst_from_pool(inner.get_ref(), 2048, payload_pool) {
                Ok(packet) => Ok(packet),
                Err(err) if is_udp_would_block(&err) => {
                    Err(io::Error::from(io::ErrorKind::WouldBlock))
                }
                Err(err) => Err(io::Error::other(err)),
            }
        }) {
            Ok(Ok(packet)) => return Ok(packet),
            Ok(Err(err)) => return Err(err.to_string()),
            Err(_) => continue,
        }
    }
}

fn is_udp_would_block(err: &str) -> bool {
    err.contains("WouldBlock") || err.contains("Resource temporarily unavailable")
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
            serde_json::Value::String(proxy.protocol.clone()),
        );
        map.insert(
            "handler".to_owned(),
            serde_json::Value::String(resident_udp_handler_name(&proxy.handler).to_owned()),
        );
        map.insert(
            "graphId".to_owned(),
            serde_json::Value::String(proxy.graph_id.clone()),
        );
        map.insert(
            "packetSession".to_owned(),
            UdpSessionKey::new(proxy, peer, original_dst).to_value(),
        );
    }
    event
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
