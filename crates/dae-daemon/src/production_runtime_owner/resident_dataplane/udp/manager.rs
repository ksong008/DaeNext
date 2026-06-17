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

mod router;
mod sniff;
use self::router::{ResidentUdpRouter, ResidentUdpSelection};
use self::sniff::{UdpPendingSniffer, UdpSniffDecision, UdpSniffKey, udp_sniff_reroute_decision};

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
            append_udp_route_selection_failed(
                event_file,
                event_lock,
                packet.peer,
                original_dst,
                err,
            );
            return;
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
            json!({"event": "udp_packet_skipped", "reason": "missing original destination", "peer": resident_socket_addr_display(packet.peer)}),
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
                err,
            );
            return;
        }
    };
    let proxy_selection = match selection {
        ResidentUdpSelection::Proxy(selection) => selection,
        ResidentUdpSelection::Block(selection) => {
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
                }),
            );
            return;
        }
    };
    let proxy = Arc::clone(&proxy_selection.proxy);
    let key = UdpSessionKey::new(&proxy, packet.peer, original_dst);
    if !sessions.contains_key(&key) {
        if sessions.len() >= session_limit {
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
    let managed = ManagedUdpPacket {
        packet,
        original_dst,
        proxy,
        force_proxy_packet: proxy_selection.force_proxy_packet,
    };
    let Some(entry) = sessions.get(&key) else {
        return;
    };
    if let Err(err) = entry.sender.try_send(managed) {
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
            }),
        );
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
    err: String,
) {
    append_event(
        event_file,
        event_lock,
        json!({
            "event": "udp_exchange_failed",
            "peer": resident_socket_addr_display(peer),
            "original_dst": resident_socket_addr_display(original_dst),
            "error": err,
            "network": resident_udp_network_name(original_dst),
        }),
    );
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

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
        }
    }

    #[test]
    fn udp_router_keeps_dns_packets_on_resident_dns_path() {
        let router = test_udp_router();
        let dns_dst = SocketAddr::new(Ipv4Addr::new(192, 0, 2, 53).into(), 53);
        let selection = router
            .select_from_routing_result(dns_dst, route_result(OUTBOUND_BLOCK, 0))
            .unwrap();

        assert_eq!(selected_proxy_group_name(selection), "proxy");
    }

    #[test]
    fn udp_router_respects_must_dns_as_plain_udp_route() {
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
        }

        let proxy = router
            .select_from_routing_result(dns_dst, route_result_must(3, 0, 1))
            .unwrap();
        match proxy {
            ResidentUdpSelection::Proxy(selection) => {
                assert_eq!(selection.proxy.group_name, "sg");
                assert!(selection.force_proxy_packet);
            }
            ResidentUdpSelection::Block(_) => panic!("user outbound DNS must select proxy"),
        }
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
