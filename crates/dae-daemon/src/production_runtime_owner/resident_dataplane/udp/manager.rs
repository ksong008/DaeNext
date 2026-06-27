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
mod tests {
    use std::collections::BTreeMap;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use dae_outbound::NetworkType;

    use crate::production_runtime_owner::resident_dataplane::plan::ResidentXhttpSettingsPlan;

    use super::*;

    #[test]
    fn udp_session_key_uses_dns_semantics_for_local_dns_destination() {
        let proxy = test_udp_proxy(ResidentProxyProtocolPlan::VlessVisionTcpTls { key: [1; 16] });
        let peer = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 53000);
        let dns_dst = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 53);
        let key = UdpSessionKey::new(&proxy, peer, dns_dst);
        let value = key.to_value();

        assert_eq!(value["packetSemantics"], UdpPacketSemantics::Dns.as_str());
        assert_eq!(value["originalDestination"], dns_dst.to_string());
        assert_eq!(key.idle_timeout(), RESIDENT_UDP_DNS_SESSION_IDLE_TIMEOUT);
    }

    #[test]
    fn udp_session_key_separates_packet_semantics() {
        let peer = SocketAddr::new(Ipv4Addr::new(192, 0, 2, 10).into(), 53000);
        let original_dst = SocketAddr::new(Ipv4Addr::new(8, 8, 8, 8).into(), 443);
        let vless = test_udp_proxy(ResidentProxyProtocolPlan::VlessVisionTcpTls { key: [1; 16] });
        let socks = test_udp_proxy(ResidentProxyProtocolPlan::Socks5Tcp {
            username: String::new(),
            password: String::new(),
        });
        assert_ne!(
            UdpSessionKey::new(&vless, peer, original_dst),
            UdpSessionKey::new(&socks, peer, original_dst)
        );
        assert_eq!(
            UdpSessionKey::new(&vless, peer, original_dst).idle_timeout(),
            RESIDENT_UDP_SESSION_IDLE_TIMEOUT
        );
    }

    #[test]
    fn udp_session_key_emits_display_and_redacted_identity() {
        let peer_ip = Ipv4Addr::new(192, 0, 2, 10);
        let original_dst_ip = Ipv4Addr::new(192, 0, 2, 53);
        let peer = ipv4_mapped_socket_addr(peer_ip, 53000);
        let original_dst = ipv4_mapped_socket_addr(original_dst_ip, 443);
        let peer_display = ipv4_socket_display(peer_ip, 53000);
        let original_dst_display = ipv4_socket_display(original_dst_ip, 443);
        let proxy = test_udp_proxy(ResidentProxyProtocolPlan::VlessVisionTcpTls { key: [1; 16] });
        let key = UdpSessionKey::new(&proxy, peer, original_dst);
        let value = key.to_value();

        assert_eq!(value["schemaVersion"], 1);
        assert_eq!(value["manager"], "resident-udp-session-manager");
        assert_eq!(value["graphId"], "resident-graph:redacted");
        assert_eq!(value["graphLinkHash"], "sha256:redacted");
        assert_eq!(value["redactedLinkSource"], "source:<redacted>");
        assert_eq!(value["peer"], peer_display);
        assert_eq!(value["originalDestination"], original_dst_display);
        assert_eq!(value["sourceDisplay"], peer_display);
        assert_eq!(value["destinationDisplay"], original_dst_display);
        assert_eq!(value["packetSemantics"], "xudp");
        assert!(
            value["graphIdentityHash"]
                .as_str()
                .is_some_and(|hash| hash.starts_with("sha256:") && hash.len() > "sha256:".len())
        );
        assert!(
            value["sessionHash"]
                .as_str()
                .is_some_and(|hash| hash.starts_with("sha256:") && hash.len() > "sha256:".len())
        );
        assert_eq!(
            value["sessionIdentity"]["sessionHash"],
            value["sessionHash"]
        );
    }

    #[test]
    fn udp_would_block_classifier_accepts_platform_messages() {
        assert!(is_udp_would_block("operation would block: WouldBlock"));
        assert!(is_udp_would_block("Resource temporarily unavailable"));
        assert!(!is_udp_would_block("permission denied"));
    }

    #[test]
    fn udp_router_selects_proxy_from_routing_tuple_outbound() {
        let router = test_udp_router();
        let original_dst = SocketAddr::new(Ipv4Addr::new(142, 250, 72, 238).into(), 443);

        let selected_default = router
            .select_from_routing_result(original_dst, route_result(2, 0))
            .unwrap();
        let selected_sg = router
            .select_from_routing_result(original_dst, route_result(3, 0))
            .unwrap();

        assert_eq!(selected_proxy_group_name(selected_default), "proxy");
        assert_eq!(selected_proxy_group_name(selected_sg), "sg");
    }

    #[test]
    fn udp_router_blocks_when_kernel_selected_block() {
        let router = test_udp_router();
        let original_dst = SocketAddr::new(Ipv4Addr::new(203, 0, 113, 10).into(), 443);
        let selection = router
            .select_from_routing_result(original_dst, route_result(OUTBOUND_BLOCK, 0))
            .unwrap();

        match selection {
            ResidentUdpSelection::Block(route) => {
                assert_eq!(route.initial_outbound, OUTBOUND_BLOCK);
                assert_eq!(route.final_outbound, OUTBOUND_BLOCK);
            }
            ResidentUdpSelection::Proxy(_) => panic!("block outbound must not select a proxy"),
            ResidentUdpSelection::ResidentDns => {
                panic!("block outbound must not select resident DNS")
            }
        }
    }

    #[test]
    fn udp_router_fails_closed_for_direct_and_control_plane_routing() {
        let router = test_udp_router();
        let original_dst = SocketAddr::new(Ipv4Addr::new(203, 0, 113, 10).into(), 443);

        let direct = select_udp_route_err(&router, original_dst, route_result(OUTBOUND_DIRECT, 0));
        assert!(direct.contains("direct UDP execution is not implemented"));

        let control_plane = select_udp_route_err(
            &router,
            original_dst,
            route_result(OUTBOUND_CONTROL_PLANE_ROUTING, 0),
        );
        assert!(control_plane.contains("no UDP domain/SNI was available"));
    }

    #[test]
    fn udp_router_reroutes_control_plane_with_sniffed_domain() {
        let router = test_udp_router_with_matcher(
            domain_matcher("video.example.com", "user:3", 0x3333),
            TcpDialMode::Ip,
        );
        let peer = SocketAddr::new(Ipv4Addr::new(192, 0, 2, 10).into(), 53100);
        let original_dst = SocketAddr::new(Ipv4Addr::new(203, 0, 113, 10).into(), 443);
        let selection = router
            .select_from_routing_result_with_domain(
                peer,
                original_dst,
                route_result(OUTBOUND_CONTROL_PLANE_ROUTING, 0),
                "video.example.com",
            )
            .unwrap();

        match selection {
            ResidentUdpSelection::Proxy(selection) => {
                assert_eq!(selection.proxy.group_name, "sg");
                assert_eq!(selection.proxy.mark, 0x3333);
            }
            ResidentUdpSelection::Block(_) => panic!("domain reroute must select proxy"),
            ResidentUdpSelection::ResidentDns => panic!("domain reroute must select proxy"),
        }
    }

    #[test]
    fn udp_router_domain_plus_plus_reroutes_user_outbound_with_sniffed_domain() {
        let router = test_udp_router_with_matcher(
            domain_matcher("video.example.com", "user:3", 0),
            TcpDialMode::DomainPlusPlus,
        );
        let peer = SocketAddr::new(Ipv4Addr::new(192, 0, 2, 10).into(), 53100);
        let original_dst = SocketAddr::new(Ipv4Addr::new(203, 0, 113, 10).into(), 443);
        let selection = router
            .select_from_routing_result_with_domain(
                peer,
                original_dst,
                route_result(2, 0),
                "video.example.com",
            )
            .unwrap();

        match selection {
            ResidentUdpSelection::Proxy(selection) => {
                assert_eq!(selection.proxy.group_name, "sg");
                let key = UdpSessionKey::new(&selection.proxy, peer, original_dst);
                assert_eq!(key.original_destination(), original_dst);
            }
            ResidentUdpSelection::Block(_) => panic!("domain++ reroute must select proxy"),
            ResidentUdpSelection::ResidentDns => panic!("domain++ reroute must select proxy"),
        }
    }

    #[test]
    fn udp_router_overrides_proxy_mark_from_routing_result() {
        let router = test_udp_router();
        let original_dst = SocketAddr::new(Ipv4Addr::new(142, 250, 72, 238).into(), 443);
        let selection = router
            .select_from_routing_result(original_dst, route_result(3, 0x1234_5678))
            .unwrap();

        match selection {
            ResidentUdpSelection::Proxy(selection) => {
                assert_eq!(selection.proxy.group_name, "sg");
                assert_eq!(selection.proxy.mark, 0x1234_5678);
            }
            ResidentUdpSelection::Block(_) => panic!("route mark override must keep proxy route"),
            ResidentUdpSelection::ResidentDns => {
                panic!("route mark override must keep proxy route")
            }
        }
    }

    #[test]
    fn udp_router_keeps_dns_packets_on_resident_dns_path() {
        let router = test_udp_router();
        let dns_dst = SocketAddr::new(Ipv4Addr::new(192, 0, 2, 53).into(), 53);
        let selection = router
            .select_from_routing_result(dns_dst, route_result(OUTBOUND_BLOCK, 0))
            .unwrap();

        match selection {
            ResidentUdpSelection::ResidentDns => {}
            ResidentUdpSelection::Proxy(_) => panic!("non-must DNS must not select proxy"),
            ResidentUdpSelection::Block(_) => panic!("non-must DNS must use resident DNS"),
        }
    }

    #[test]
    fn udp_router_uses_destination_ip_family_for_proxy_group() {
        let router = test_udp_router_with_udp_family_latency_group();
        let v4_udp_dst = SocketAddr::new(Ipv4Addr::new(192, 0, 2, 53).into(), 443);
        let v6_udp_dst =
            SocketAddr::new(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 53).into(), 443);

        let v4_selection = router
            .select_from_routing_result(v4_udp_dst, route_result(2, 0))
            .unwrap();
        assert_eq!(selected_proxy_node_tag(v4_selection), "node_a");

        let v6_selection = router
            .select_from_routing_result(v6_udp_dst, route_result(2, 0))
            .unwrap();
        assert_eq!(selected_proxy_node_tag(v6_selection), "node_b");
    }

    #[test]
    fn udp_dns_fast_path_applies_to_all_dns() {
        let router = test_udp_router();
        let dns_dst = SocketAddr::new(Ipv4Addr::new(192, 0, 2, 53).into(), 53);
        let normal_dns = router
            .select_from_routing_result(dns_dst, route_result(OUTBOUND_BLOCK, 0))
            .unwrap();
        match normal_dns {
            ResidentUdpSelection::ResidentDns => {
                assert!(resident_udp_dns_fast_path_applies(dns_dst));
            }
            ResidentUdpSelection::Block(_) => panic!("non-must DNS should use resident DNS"),
            ResidentUdpSelection::Proxy(_) => panic!("non-must DNS should use resident DNS"),
        }

        let must_dns = router
            .select_from_routing_result(dns_dst, route_result_must(3, 0, 1))
            .unwrap();
        match must_dns {
            ResidentUdpSelection::Proxy(selection) => {
                assert!(resident_udp_dns_fast_path_applies(dns_dst));
                assert!(selection.force_proxy_packet);
            }
            ResidentUdpSelection::Block(_) => panic!("must DNS proxy route should select proxy"),
            ResidentUdpSelection::ResidentDns => {
                panic!("must DNS proxy route should select proxy")
            }
        }

        let non_dns_dst = SocketAddr::new(Ipv4Addr::new(192, 0, 2, 53).into(), 443);
        let non_dns = router
            .select_from_routing_result(non_dns_dst, route_result(3, 0))
            .unwrap();
        match non_dns {
            ResidentUdpSelection::Proxy(selection) => {
                assert!(!resident_udp_dns_fast_path_applies(non_dns_dst));
                assert!(!selection.force_proxy_packet);
            }
            ResidentUdpSelection::Block(_) => panic!("non-DNS proxy route should select proxy"),
            ResidentUdpSelection::ResidentDns => {
                panic!("non-DNS proxy route should select proxy")
            }
        }
    }

    #[test]
    fn udp_dns_fast_path_route_event_keeps_proxy_fields_without_packet_session() {
        let peer = SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 53100);
        let original_dst = SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 53);
        let proxy = test_udp_proxy_with_group("sg", 0x1234);
        let route = ResidentUdpRouteSelection {
            initial_outbound: 2,
            final_outbound: 3,
            final_mark: proxy.mark,
            userspace_route_executed: false,
            userspace_route_must: false,
        };

        let event = udp_route_chosen_event_without_packet_session(
            peer,
            original_dst,
            &route,
            &proxy,
            "",
            0,
            UDP_ROUTE_REASON_DNS_FAST_PATH,
        );

        assert_eq!(event["event"], UDP_ROUTE_CHOSEN_EVENT);
        assert_eq!(event["outbound_kind"], UDP_ROUTE_KIND_PROXY);
        assert_eq!(event["network"], resident_udp_network_name(original_dst));
        assert_eq!(event["proxy_group"], proxy.group_name);
        assert_eq!(event["group_policy"], proxy.group_policy);
        assert_eq!(event["node_tag"], proxy.node_tag);
        assert_eq!(event["task_queued"], false);
        assert_eq!(event["reason"], UDP_ROUTE_REASON_DNS_FAST_PATH);
        assert!(event.get("packetSession").is_none());
    }

    #[test]
    fn udp_router_keeps_must_dns_proxy_route_for_independent_datagram() {
        let router = test_udp_router();
        let dns_dst = SocketAddr::new(Ipv4Addr::new(192, 0, 2, 53).into(), 53);
        let block = router
            .select_from_routing_result(dns_dst, route_result_must(OUTBOUND_BLOCK, 0, 1))
            .unwrap();
        match block {
            ResidentUdpSelection::Block(route) => {
                assert_eq!(route.initial_outbound, OUTBOUND_BLOCK);
                assert_eq!(route.final_outbound, OUTBOUND_BLOCK);
            }
            ResidentUdpSelection::Proxy(_) => panic!("must block DNS must not use resident DNS"),
            ResidentUdpSelection::ResidentDns => {
                panic!("must block DNS must not use resident DNS")
            }
        }

        let proxy = router
            .select_from_routing_result(dns_dst, route_result_must(3, 0, 1))
            .unwrap();
        match proxy {
            ResidentUdpSelection::Proxy(selection) => {
                assert_eq!(selection.proxy.group_name, "sg");
                assert!(selection.force_proxy_packet);
                assert!(resident_udp_dns_fast_path_applies(dns_dst));
            }
            ResidentUdpSelection::Block(_) => panic!("user outbound DNS must select proxy"),
            ResidentUdpSelection::ResidentDns => {
                panic!("user outbound DNS must select proxy")
            }
        }
    }

    #[test]
    fn udp_route_chosen_event_exposes_route_and_session_fields() {
        let peer = SocketAddr::new(Ipv4Addr::new(192, 0, 2, 10).into(), 53100);
        let original_dst = SocketAddr::new(Ipv4Addr::new(203, 0, 113, 10).into(), 443);
        let proxy = test_udp_proxy_with_group("sg", 0x1234);
        let route = ResidentUdpRouteSelection {
            initial_outbound: 2,
            final_outbound: 3,
            final_mark: proxy.mark,
            userspace_route_executed: true,
            userspace_route_must: true,
        };

        let event = udp_route_chosen_event(
            peer,
            original_dst,
            &route,
            Some(&proxy),
            "video.example.com",
            46,
            true,
            "queued packet for resident UDP session",
        );

        assert_eq!(event["event"], "udp_route_chosen");
        assert_eq!(event["outbound_kind"], UDP_ROUTE_KIND_PROXY);
        assert_eq!(event["peer"], peer.to_string());
        assert_eq!(event["original_dst"], original_dst.to_string());
        assert_eq!(event["direct_target"], original_dst.to_string());
        assert_eq!(event["initial_outbound"], 2);
        assert_eq!(event["final_outbound"], 3);
        assert_eq!(event["final_mark"], proxy.mark);
        assert_eq!(event["userspace_route_executed"], true);
        assert_eq!(event["userspace_route_must"], true);
        assert_eq!(event["sniffed_domain"], "video.example.com");
        assert_eq!(event["network"], resident_udp_network_name(original_dst));
        assert_eq!(event["outbound"], proxy.group_name);
        assert_eq!(event["proxy_group"], proxy.group_name);
        assert_eq!(event["group_policy"], proxy.group_policy);
        assert_eq!(event["node_tag"], proxy.node_tag);
        assert_eq!(event["handler"], resident_udp_handler_name(&proxy.handler));
        assert_eq!(event["task_queued"], true);
        assert_eq!(event["reason"], UDP_ROUTE_REASON_QUEUED);
        assert_eq!(event["dscp"], 46);
        assert_eq!(
            event["packetSession"]["manager"],
            "resident-udp-session-manager"
        );
        assert_eq!(event["packetSession"]["outbound"], proxy.group_name);
        assert_eq!(
            event["packetSession"]["packetSemantics"],
            UdpPacketSemantics::UdpAssociate.as_str()
        );

        let block = ResidentUdpRouteSelection {
            initial_outbound: OUTBOUND_BLOCK,
            final_outbound: OUTBOUND_BLOCK,
            final_mark: 0,
            userspace_route_executed: false,
            userspace_route_must: false,
        };
        let event = udp_route_chosen_event(
            peer,
            original_dst,
            &block,
            None,
            "",
            0,
            false,
            UDP_ROUTE_REASON_BLOCK,
        );
        assert_eq!(event["outbound_kind"], UDP_ROUTE_KIND_BLOCK);
        assert_eq!(event["outbound"], UDP_ROUTE_KIND_BLOCK);
        assert_eq!(event["task_queued"], false);
        assert!(event.get("packetSession").is_none());

        let v6_peer = SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 53100);
        let v6_original_dst = SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 443);
        let event = udp_route_chosen_event(
            v6_peer,
            v6_original_dst,
            &route,
            Some(&proxy),
            "video.example.com",
            46,
            true,
            UDP_ROUTE_REASON_QUEUED,
        );
        assert_eq!(event["network"], resident_udp_network_name(v6_original_dst));
        assert_ne!(event["network"], resident_udp_network_name(original_dst));
    }

    fn ipv4_mapped_socket_addr(addr: Ipv4Addr, port: u16) -> SocketAddr {
        let mut octets = [0_u8; 16];
        octets[10] = 0xff;
        octets[11] = 0xff;
        octets[12..16].copy_from_slice(&addr.octets());
        SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port)
    }

    fn ipv4_socket_display(addr: Ipv4Addr, port: u16) -> String {
        SocketAddr::new(IpAddr::V4(addr), port).to_string()
    }

    fn test_udp_router() -> ResidentUdpRouter {
        test_udp_router_with_matcher(fallback_matcher("user:2", 0), TcpDialMode::Ip)
    }

    fn test_udp_router_with_matcher(
        routing_matcher: RoutingMatcher,
        dial_mode: TcpDialMode,
    ) -> ResidentUdpRouter {
        let mut groups = BTreeMap::new();
        groups.insert(
            2,
            ResidentProxyGroupPlan::fixed_single_for_test(test_udp_proxy_with_group("proxy", 0)),
        );
        groups.insert(
            3,
            ResidentProxyGroupPlan::fixed_single_for_test(test_udp_proxy_with_group("sg", 0x2222)),
        );
        ResidentUdpRouter::from_parts(Arc::new(groups), 2, 1, None, routing_matcher, dial_mode)
            .unwrap()
    }

    fn test_udp_router_with_udp_family_latency_group() -> ResidentUdpRouter {
        let sections = dae_config::parser::parse_config(
            r#"
            global {
            lan_interface: daerust0
            }
            node {
            node_a: 'socks5://127.0.0.1:1080'
            node_b: 'socks5://127.0.0.2:1080'
            }
            group {
            proxy {
                filter: name(node_a, node_b)
                policy: min
            }
            }
            routing {
            fallback: proxy
            }
            "#,
        )
        .unwrap();
        let config = dae_config::schema::build_config(&sections).unwrap();
        let plan = super::super::super::plan::build_resident_dataplane_plan(&config).unwrap();
        let group = plan.default_proxy_group().unwrap();
        group
            .record_check_result("node_a", NetworkType::DNS_UDP4, Some(20), 1)
            .unwrap();
        group
            .record_check_result("node_b", NetworkType::DNS_UDP4, Some(200), 2)
            .unwrap();
        group
            .record_check_result("node_a", NetworkType::DNS_UDP6, Some(300), 3)
            .unwrap();
        group
            .record_check_result("node_b", NetworkType::DNS_UDP6, Some(50), 4)
            .unwrap();
        ResidentUdpRouter::from_parts(
            Arc::new(plan.proxies.clone()),
            plan.default_outbound.unwrap(),
            1,
            None,
            fallback_matcher("direct", 0),
            TcpDialMode::Ip,
        )
        .unwrap()
    }

    fn fallback_matcher(outbound: &str, mark: u32) -> RoutingMatcher {
        RoutingMatcher::from_fixture_value(&json!({
            "matches": [
                {
                    "type": "fallback",
                    "outbound": outbound,
                    "mark": mark
                }
            ],
            "domain_sets": [],
            "lpm_sets": []
        }))
        .unwrap()
    }

    fn domain_matcher(domain: &str, outbound: &str, mark: u32) -> RoutingMatcher {
        RoutingMatcher::from_fixture_value(&json!({
            "matches": [
                {
                    "type": "domain_set",
                    "outbound": outbound,
                    "mark": mark
                },
                {
                    "type": "fallback",
                    "outbound": "user:2",
                    "mark": 0
                }
            ],
            "domain_sets": [
                {
                    "bit": 0,
                    "key": "full",
                    "patterns": [domain]
                }
            ],
            "lpm_sets": []
        }))
        .unwrap()
    }

    fn route_result(outbound: u8, mark: u32) -> BpfRoutingResult {
        route_result_must(outbound, mark, 0)
    }

    fn route_result_must(outbound: u8, mark: u32, must: u8) -> BpfRoutingResult {
        BpfRoutingResult {
            outbound,
            mark,
            must,
            ..Default::default()
        }
    }

    fn selected_proxy_group_name(selection: ResidentUdpSelection) -> String {
        match selection {
            ResidentUdpSelection::Proxy(selection) => selection.proxy.group_name.clone(),
            ResidentUdpSelection::Block(_) => panic!("expected proxy route"),
            ResidentUdpSelection::ResidentDns => panic!("expected proxy route"),
        }
    }

    fn selected_proxy_node_tag(selection: ResidentUdpSelection) -> String {
        match selection {
            ResidentUdpSelection::Proxy(selection) => selection.proxy.node_tag.clone(),
            ResidentUdpSelection::Block(_) => panic!("expected proxy route"),
            ResidentUdpSelection::ResidentDns => panic!("expected proxy route"),
        }
    }

    fn select_udp_route_err(
        router: &ResidentUdpRouter,
        original_dst: SocketAddr,
        result: BpfRoutingResult,
    ) -> String {
        match router.select_from_routing_result(original_dst, result) {
            Ok(_) => panic!("expected resident UDP route selection to fail"),
            Err(err) => err,
        }
    }

    fn test_udp_proxy_with_group(group_name: &str, mark: u32) -> ResidentProxyPlan {
        let mut proxy = test_udp_proxy(ResidentProxyProtocolPlan::Socks5Tcp {
            username: String::new(),
            password: String::new(),
        });
        proxy.group_name = group_name.to_owned();
        proxy.node_tag = group_name.to_owned();
        proxy.mark = mark;
        proxy
    }

    fn test_udp_proxy(handler: ResidentProxyProtocolPlan) -> ResidentProxyPlan {
        ResidentProxyPlan {
            graph_id: "resident-graph:redacted".to_owned(),
            graph_link_hash: "sha256:redacted".to_owned(),
            redacted_link_source: "source:<redacted>".to_owned(),
            protocol: "redacted".to_owned(),
            group_name: "proxy".to_owned(),
            group_policy: "fixed".to_owned(),
            node_tag: "redacted".to_owned(),
            server_host: String::new(),
            server_port: 0,
            server_name: String::new(),
            alpn: Vec::new(),
            flow: String::new(),
            net: "tcp".to_owned(),
            stream_host: String::new(),
            stream_path: String::new(),
            xhttp_download: None,
            xhttp_mode: ResidentXhttpMode::PacketUp,
            xhttp_settings: ResidentXhttpSettingsPlan::official_default(),
            xhttp_xmux: None,
            tls: String::new(),
            allow_insecure: false,
            tls_fragment: None,
            utls_fingerprint: None,
            reality: None,
            handler,
            chain_parent: None,
            mark: 0,
            mptcp: false,
        }
    }
}
