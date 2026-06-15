use std::collections::HashMap;
use std::io;

use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;

use super::*;

pub(super) fn run_resident_udp_session_manager(
    socket: UdpSocket,
    proxy_group: Arc<ResidentProxyGroupPlan>,
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
        proxy_group,
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
    proxy_group: Arc<ResidentProxyGroupPlan>,
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
    append_event(
        &event_file,
        &event_lock,
        json!({
            "event": "udp_session_manager_started",
            "proxy_group": proxy_group.group_name,
            "group_policy": proxy_group.group_policy_name(),
            "candidate_count": proxy_group.candidate_count(),
            "admitted_candidate_count": proxy_group.admitted_candidate_count(),
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
                        &proxy_group,
                        &dns,
                        &event_file,
                        &event_lock,
                        &metrics,
                        &active_sessions,
                        &mut sessions,
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
    proxy_group: &Arc<ResidentProxyGroupPlan>,
    dns: &Arc<ResidentDnsPlan>,
    event_file: &PathBuf,
    event_lock: &Arc<Mutex<()>>,
    metrics: &Arc<ResidentDataplaneMetrics>,
    active_sessions: &Arc<AtomicUsize>,
    sessions: &mut HashMap<UdpSessionKey, UdpSessionEntry>,
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
    let proxy = match proxy_group.select_proxy_for_udp() {
        Ok(proxy) => proxy,
        Err(err) => {
            append_udp_proxy_selection_failed(
                event_file,
                event_lock,
                packet.peer,
                original_dst,
                err,
                proxy_group,
            );
            return;
        }
    };
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
            event_file: event_file.clone(),
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

#[cfg(test)]
mod tests {
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
