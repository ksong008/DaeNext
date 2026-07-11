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
use tokio::io::unix::AsyncFd;
use tokio::sync::{Semaphore, mpsc};

use super::super::plan::resident_data_udp_network_type;
use super::*;

mod dns_fast_path;
mod ingress;
mod resuscitation;
mod router;
mod sniff;
use self::dns_fast_path::{
    minimal_resident_dns_routing_result, resident_udp_dns_fast_path_applies,
    resident_udp_dns_fast_path_can_bypass_missing_tuple,
};
use self::ingress::recv_udp_batch_with_original_dst_async;
use self::resuscitation::ResidentUdpResuscitator;
use self::router::{ResidentUdpRouteSelection, ResidentUdpRouter, ResidentUdpSelection};
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
const UDP_ROUTE_REASON_QUEUED: &str = "queued packet for resident UDP session";
const UDP_ROUTE_REASON_DNS_FAST_PATH: &str = "handled resident DNS packet without UDP session";
const UDP_ROUTE_REASON_FORCED_DNS_FAST_PATH: &str =
    "handled forced resident DNS packet without UDP session";

pub(super) fn run_resident_udp_session_manager(
    socket: UdpSocket,
    proxy_groups: SharedResidentProxyGroupMap,
    default_outbound: u8,
    routing_tuple_map_id: Option<u32>,
    routing_matcher: RoutingMatcher,
    dial_mode: TcpDialMode,
    so_mark_from_dae: u32,
    dns: Arc<ResidentDnsPlan>,
    stop: Arc<AtomicBool>,
    event_file: PathBuf,
    event_lock: Arc<Mutex<()>>,
    metrics: Arc<ResidentDataplaneMetrics>,
    active_sessions: Arc<AtomicUsize>,
    session_limit: usize,
    session_queue_depth: usize,
    health_check_concurrency: usize,
    dns_fast_path_concurrency: usize,
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
        so_mark_from_dae,
        dns,
        stop,
        event_file,
        event_lock,
        metrics,
        active_sessions,
        session_limit.max(1),
        session_queue_depth.max(1),
        health_check_concurrency.max(1),
        dns_fast_path_concurrency.max(1),
    ));
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
    stop: Arc<AtomicBool>,
    event_file: PathBuf,
    event_lock: Arc<Mutex<()>>,
    metrics: Arc<ResidentDataplaneMetrics>,
    active_sessions: Arc<AtomicUsize>,
    session_limit: usize,
    session_queue_depth: usize,
    health_check_concurrency: usize,
    dns_fast_path_concurrency: usize,
) {
    if let Err(err) = socket.set_nonblocking(true) {
        append_event(
            &event_file,
            &event_lock,
            json!({"event": "udp_socket_nonblocking_failed", "error": err.to_string()}),
        );
        return;
    }
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
    let resuscitator = ResidentUdpResuscitator::start(
        Arc::clone(&proxy_groups),
        Arc::clone(&stop),
        event_file.clone(),
        Arc::clone(&event_lock),
        health_check_concurrency,
    );
    let router = match ResidentUdpRouter::new(
        proxy_groups,
        default_outbound,
        routing_tuple_map_id,
        routing_matcher,
        dial_mode,
        so_mark_from_dae,
        resuscitator.handle(),
    ) {
        Ok(router) => router,
        Err(err) => {
            append_event(
                &event_file,
                &event_lock,
                json!({"event": "udp_session_manager_start_failed", "error": err}),
            );
            resuscitator.stop();
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
            "dns_fast_path_concurrency": dns_fast_path_concurrency,
            "packetSessionManager": {
                "schemaVersion": 1,
                "manager": "resident-udp-session-manager",
                "runtime": "tokio-current-thread",
                "sessionLimit": session_limit,
                "perSessionQueueDepth": session_queue_depth,
                "replyQueueDepth": session_queue_depth,
                "replySocketCacheCapacity": session_limit,
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
    let mut direct_sessions: HashMap<UdpDirectSessionKey, UdpDirectSessionEntry> = HashMap::new();
    let mut sniffers: HashMap<UdpSniffKey, UdpPendingSniffer> = HashMap::new();
    let dns_fast_path_permits = Arc::new(Semaphore::new(dns_fast_path_concurrency));
    let reply_dispatcher =
        UdpReplyDispatcher::start(session_queue_depth, session_limit, Arc::clone(&metrics));
    let udp_reply = reply_dispatcher.handle();
    let (cleanup_tx, mut cleanup_rx) = mpsc::channel::<UdpSessionKey>(session_limit);
    let (direct_cleanup_tx, mut direct_cleanup_rx) =
        mpsc::channel::<UdpDirectSessionKey>(session_limit);
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
            Some(key) = direct_cleanup_rx.recv() => {
                if let Some(mut entry) = direct_sessions.remove(&key) {
                    let _ = (&mut entry.handle).await;
                }
            }
            batch = recv_udp_batch_with_original_dst_async(
                &socket,
                &payload_pool,
                session_queue_depth,
            ) => {
                match batch {
                    Ok(batch) => {
                        metrics.record_udp_ingress_batch(
                            batch.packets.len(),
                            batch.truncated,
                            batch.budget_hit,
                        );
                        for packet in batch.packets {
                            handle_manager_packet(
                                packet,
                                &router,
                                &dns,
                                &event_file,
                                &event_lock,
                                &metrics,
                                &udp_reply,
                                &active_sessions,
                                &mut sessions,
                                &mut direct_sessions,
                                &mut sniffers,
                                &dns_fast_path_permits,
                                &cleanup_tx,
                                &direct_cleanup_tx,
                                session_limit,
                                session_queue_depth,
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
    for (_, mut entry) in direct_sessions.drain() {
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
    drop(udp_reply);
    let reply_shutdown = reply_dispatcher.shutdown().await;
    append_event(
        &event_file,
        &event_lock,
        json!({
            "event": "udp_session_manager_stopped",
            "joined_sessions": joined,
            "timed_out_sessions": timed_out,
            "panicked_sessions": panicked,
            "active_sessions": active_sessions.load(Ordering::Relaxed),
            "reply_dispatcher": match reply_shutdown {
                Ok(sockets) => json!({"status": "pass", "closedSockets": sockets}),
                Err(err) => json!({"status": "fail", "error": err.to_string()}),
            },
        }),
    );
    resuscitator.stop();
}

fn handle_manager_packet(
    packet: UdpOriginalDstPacket,
    router: &ResidentUdpRouter,
    dns: &Arc<ResidentDnsPlan>,
    event_file: &Path,
    event_lock: &Arc<Mutex<()>>,
    metrics: &Arc<ResidentDataplaneMetrics>,
    udp_reply: &UdpReplyHandle,
    active_sessions: &Arc<AtomicUsize>,
    sessions: &mut HashMap<UdpSessionKey, UdpSessionEntry>,
    direct_sessions: &mut HashMap<UdpDirectSessionKey, UdpDirectSessionEntry>,
    sniffers: &mut HashMap<UdpSniffKey, UdpPendingSniffer>,
    dns_fast_path_permits: &Arc<Semaphore>,
    cleanup_tx: &mpsc::Sender<UdpSessionKey>,
    direct_cleanup_tx: &mpsc::Sender<UdpDirectSessionKey>,
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
            udp_reply,
            active_sessions,
            sessions,
            direct_sessions,
            dns_fast_path_permits,
            cleanup_tx,
            direct_cleanup_tx,
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
    udp_reply: &UdpReplyHandle,
    active_sessions: &Arc<AtomicUsize>,
    sessions: &mut HashMap<UdpSessionKey, UdpSessionEntry>,
    direct_sessions: &mut HashMap<UdpDirectSessionKey, UdpDirectSessionEntry>,
    dns_fast_path_permits: &Arc<Semaphore>,
    cleanup_tx: &mpsc::Sender<UdpSessionKey>,
    direct_cleanup_tx: &mpsc::Sender<UdpDirectSessionKey>,
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
                Arc::clone(dns_fast_path_permits),
                Arc::clone(metrics),
                udp_reply.clone(),
            );
            return;
        }
        ResidentUdpSelection::Proxy(selection) => selection,
        ResidentUdpSelection::Direct(selection) => {
            forward_direct_manager_packet(
                packet,
                original_dst,
                selection,
                event_file,
                event_lock,
                metrics,
                udp_reply,
                active_sessions,
                direct_sessions,
                direct_cleanup_tx,
                sessions.len() + direct_sessions.len(),
                session_limit,
                session_queue_depth,
                sniffed_domain,
                initial.dscp,
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
                Arc::clone(dns_fast_path_permits),
                event_file.to_path_buf(),
                Arc::clone(event_lock),
                Arc::clone(metrics),
                udp_reply.clone(),
            );
        } else {
            spawn_resident_dns_datagram_handler(
                packet,
                original_dst,
                Arc::clone(dns),
                Arc::clone(dns_fast_path_permits),
                Arc::clone(metrics),
                udp_reply.clone(),
            );
        }
        return;
    }
    let key = UdpSessionKey::new(&proxy, packet.peer, original_dst);
    if !sessions.contains_key(&key) {
        let existing_session_count = sessions.len() + direct_sessions.len();
        if existing_session_count >= session_limit {
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
                    "active_sessions": existing_session_count,
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
            proxy_groups: router.proxy_groups(),
            event_file: event_file.to_path_buf(),
            event_lock: Arc::clone(event_lock),
            metrics: Arc::clone(metrics),
            udp_reply: udp_reply.clone(),
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

fn forward_direct_manager_packet(
    packet: UdpOriginalDstPacket,
    original_dst: SocketAddr,
    selection: router::ResidentUdpDirectSelection,
    event_file: &Path,
    event_lock: &Arc<Mutex<()>>,
    metrics: &Arc<ResidentDataplaneMetrics>,
    udp_reply: &UdpReplyHandle,
    active_sessions: &Arc<AtomicUsize>,
    direct_sessions: &mut HashMap<UdpDirectSessionKey, UdpDirectSessionEntry>,
    direct_cleanup_tx: &mpsc::Sender<UdpDirectSessionKey>,
    existing_session_count: usize,
    session_limit: usize,
    session_queue_depth: usize,
    sniffed_domain: &str,
    dscp: u8,
) {
    let key = UdpDirectSessionKey::new(packet.peer, original_dst, selection.route.final_mark);
    if !direct_sessions.contains_key(&key) {
        if existing_session_count >= session_limit {
            append_event(
                event_file,
                event_lock,
                udp_direct_route_chosen_event(
                    packet.peer,
                    original_dst,
                    &selection.route,
                    &key,
                    sniffed_domain,
                    dscp,
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
                    "active_sessions": existing_session_count,
                    "session_limit": session_limit,
                    "packetSession": key.to_value(),
                    "dscp": dscp,
                }),
            );
            return;
        }
        let (sender, receiver) = mpsc::channel::<ManagedDirectUdpPacket>(session_queue_depth);
        let context = UdpDirectSessionActorContext {
            event_file: event_file.to_path_buf(),
            event_lock: Arc::clone(event_lock),
            metrics: Arc::clone(metrics),
            udp_reply: udp_reply.clone(),
            active_sessions: Arc::clone(active_sessions),
        };
        let actor_key = key.clone();
        let actor_cleanup_tx = direct_cleanup_tx.clone();
        let handle = spawn_udp_direct_session_actor(actor_key, context, receiver, actor_cleanup_tx);
        direct_sessions.insert(key.clone(), UdpDirectSessionEntry { sender, handle });
    }
    let peer = packet.peer;
    let managed = ManagedDirectUdpPacket {
        packet,
        original_dst,
        dscp,
    };
    let Some(entry) = direct_sessions.get(&key) else {
        return;
    };
    if let Err(err) = entry.sender.try_send(managed) {
        append_event(
            event_file,
            event_lock,
            udp_direct_route_chosen_event(
                peer,
                original_dst,
                &selection.route,
                &key,
                sniffed_domain,
                dscp,
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
                "dscp": dscp,
            }),
        );
    } else {
        append_event(
            event_file,
            event_lock,
            udp_direct_route_chosen_event(
                peer,
                original_dst,
                &selection.route,
                &key,
                sniffed_domain,
                dscp,
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
    permits: Arc<Semaphore>,
    metrics: Arc<ResidentDataplaneMetrics>,
    udp_reply: UdpReplyHandle,
) {
    let Ok(permit) = permits.try_acquire_owned() else {
        metrics.add_upload(packet.payload.len());
        if let Ok(response) = build_dns_server_failure_response(&packet.payload) {
            let response_len = response.len();
            tokio::spawn(async move {
                if udp_reply
                    .send(original_dst, packet.peer, response)
                    .await
                    .is_ok()
                {
                    metrics.add_download(response_len);
                }
            });
        }
        return;
    };
    tokio::spawn(async move {
        let _permit = permit;
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
        let response_len = response.len();
        if udp_reply
            .send(original_dst, packet.peer, response)
            .await
            .is_ok()
        {
            metrics.add_download(response_len);
        }
    });
}

fn spawn_forced_resident_dns_proxy_datagram_handler(
    packet: UdpOriginalDstPacket,
    proxy: Arc<ResidentProxyPlan>,
    original_dst: SocketAddr,
    dscp: u8,
    dns: Arc<ResidentDnsPlan>,
    permits: Arc<Semaphore>,
    event_file: PathBuf,
    event_lock: Arc<Mutex<()>>,
    metrics: Arc<ResidentDataplaneMetrics>,
    udp_reply: UdpReplyHandle,
) {
    let Ok(permit) = permits.try_acquire_owned() else {
        metrics.add_upload(packet.payload.len());
        if let Ok(response) = build_dns_server_failure_response(&packet.payload) {
            let response_len = response.len();
            tokio::spawn(async move {
                if udp_reply
                    .send(original_dst, packet.peer, response)
                    .await
                    .is_ok()
                {
                    metrics.add_download(response_len);
                }
            });
        }
        return;
    };
    tokio::spawn(async move {
        let _permit = permit;
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
            &udp_reply,
            exchange,
        )
        .await;
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
            serde_json::Value::String(resident_udp_proxy_handler_name(proxy).to_owned()),
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
