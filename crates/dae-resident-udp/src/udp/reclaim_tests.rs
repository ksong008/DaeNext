use super::*;
use tokio::sync::mpsc;

const IDLE: Duration = Duration::from_millis(200);

fn packet(peer: SocketAddr, target: SocketAddr) -> UdpOriginalDstPacket {
    let receiver = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let sender = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    sender
        .send_to(b"subscribe", receiver.local_addr().unwrap())
        .unwrap();
    let mut packet = dae_datapath::udp_io::recv_udp_with_original_dst(&receiver, 2048).unwrap();
    packet.peer = peer;
    packet.original_dst = Some(target);
    packet
}

fn context(
    metrics: Arc<ResidentDataplaneMetrics>,
    reply: UdpReplyHandle,
) -> Arc<UdpSessionSharedContext> {
    Arc::new(UdpSessionSharedContext {
        event_file: PathBuf::from("/dev/null"),
        event_lock: Arc::new(Mutex::new(())),
        metrics,
        udp_reply: reply,
        active_sessions: Arc::new(AtomicUsize::new(0)),
        hysteria2_owner_registry: None,
        tuic_owner_registry: None,
        juicity_owner_registry: None,
        anytls_owner_registry: None,
        session_idle_timeout: IDLE,
        proxy_session_idle_timeout: IDLE,
        response_buffer_idle_timeout: Duration::from_millis(60),
        actor_stop: ResidentStopSignal::shared(),
    })
}

fn proxy(upstream: SocketAddr) -> ResidentProxyBinding {
    let mut plan =
        super::chain_execution_tests::proxy_plan(ResidentProxyProtocolPlan::ShadowsocksAeadTcp {
            cipher: "aes-128-gcm".to_owned(),
            password: "test-password".to_owned(),
            salt_len: 16,
        });
    plan.protocol = "shadowsocks";
    plan.server_host = upstream.ip().to_string();
    plan.server_port = upstream.port();
    super::chain_execution_tests::proxy_binding(&plan)
}

fn response(target: SocketAddr, payload: &[u8], sequence: u8) -> Vec<u8> {
    encode_udp_packet(
        "aes-128-gcm",
        "test-password",
        &[sequence; 16],
        &target.to_string(),
        payload,
    )
    .unwrap()
}

async fn downstream_keeps_session_alive(proxy_mode: bool, payload: &[u8], accepted: bool) {
    let metrics = Arc::new(ResidentDataplaneMetrics::default());
    let (reply, mut packets, reply_task) = super::reply::test_reply_handle(Arc::clone(&metrics));
    let context = context(Arc::clone(&metrics), reply);
    let upstream = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target = upstream.local_addr().unwrap();
    let peer = "127.0.0.1:32123".parse().unwrap();
    // Keep the channel sender alive so only the idle deadline ends the actor.
    let (actor, _proxy_sender, _direct_sender) = if proxy_mode {
        let binding = proxy(target);
        let key = UdpSessionKey::new(&binding, peer, target);
        let (sender, receiver) = mpsc::channel(1);
        let (cleanup, _rx) = mpsc::channel(1);
        let actor = spawn_udp_session_actor(key, 1, Arc::clone(&context), receiver, cleanup);
        sender
            .send(ManagedUdpPacket {
                work: None,
                packet: packet(peer, target),
                original_dst: target,
                proxy: binding,
                data_udp_network_type: None,
                data_udp_availability: ResidentDataUdpAvailabilityHandle::new(|_, _| {}),
                force_proxy_packet: true,
                dscp: 0,
            })
            .await
            .unwrap_or_else(|_| panic!("proxy enqueue"));
        (actor, Some(sender), None)
    } else {
        let key = UdpDirectSessionKey::new(peer, target, 0);
        let (sender, receiver) = mpsc::channel(1);
        let (cleanup, _rx) = mpsc::channel(1);
        let actor = spawn_udp_direct_session_actor(key, 1, Arc::clone(&context), receiver, cleanup);
        sender
            .send(ManagedDirectUdpPacket {
                work: None,
                packet: packet(peer, target),
                original_dst: target,
                dscp: 0,
            })
            .await
            .unwrap_or_else(|_| panic!("direct enqueue"));
        (actor, None, Some(sender))
    };
    let mut buf = [0; 2048];
    let (_, session_addr) = time::timeout(Duration::from_secs(1), upstream.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let invalid_sender = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    for sequence in 0..8 {
        time::sleep(Duration::from_millis(50)).await;
        if accepted {
            assert!(!actor.is_finished(), "downstream-only session expired");
        }
        let wire = if proxy_mode {
            response(
                if accepted {
                    target
                } else {
                    "127.0.0.1:1".parse().unwrap()
                },
                payload,
                sequence,
            )
        } else {
            payload.to_vec()
        };
        let sender = if !accepted && !proxy_mode {
            &invalid_sender
        } else {
            &upstream
        };
        sender.send_to(&wire, session_addr).await.unwrap();
        if !accepted {
            assert!(
                time::timeout(Duration::from_millis(10), packets.recv())
                    .await
                    .is_err()
            );
            continue;
        }
        let delivered = time::timeout(Duration::from_millis(100), packets.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(delivered, payload);
    }
    time::timeout(Duration::from_secs(1), actor)
        .await
        .expect("idle session did not expire")
        .unwrap();
    assert_eq!(
        metrics.traffic_counters().download_total,
        if accepted {
            8 * payload.len() as u64
        } else {
            0
        }
    );
    if accepted {
        assert_eq!(metrics.traffic_counters().packet_total, 8);
    } else {
        assert!(metrics.traffic_counters().packet_total > 0);
    }
    assert_eq!(metrics.traffic_counters().active_udp_sessions, 0);
    assert_eq!(metrics.traffic_counters().queue_depth, 0);
    reply_task.abort();
    let _ = reply_task.await;
}

#[tokio::test]
async fn direct_and_proxy_downstream_renew_idle_including_empty_datagrams() {
    for proxy_mode in [false, true] {
        for payload in [b"stream".as_slice(), b"".as_slice()] {
            downstream_keeps_session_alive(proxy_mode, payload, true).await;
        }
    }
}

#[tokio::test]
async fn direct_and_proxy_rejected_downstream_does_not_keep_actor_alive() {
    for proxy_mode in [false, true] {
        downstream_keeps_session_alive(proxy_mode, b"rejected", false).await;
    }
}

#[tokio::test]
async fn rejected_proxy_responses_and_pending_results_do_not_renew_session() {
    let metrics = Arc::new(ResidentDataplaneMetrics::default());
    let (reply, _packets, task) = super::reply::test_reply_handle(Arc::clone(&metrics));
    let binding = proxy("127.0.0.1:9876".parse().unwrap());
    let target = "127.0.0.1:9877".parse().unwrap();
    let initial = time::Instant::now() - Duration::from_secs(1);
    let mut last_activity = initial;
    for result in [
        UdpExchangeResult::pending_response("test"),
        UdpExchangeResult::new(vec![], "test")
            .with_decoded_response_identity(Some("127.0.0.1:9878".parse().unwrap()), None),
    ] {
        record_udp_session_response_result(
            &binding,
            target,
            target,
            PathBuf::from("/dev/null"),
            Arc::new(Mutex::new(())),
            Arc::clone(&metrics),
            &reply,
            &json!({}),
            Ok((ResidentEventKind::UdpPacketFinished, result)),
            &mut last_activity,
        )
        .await;
        assert_eq!(last_activity, initial);
    }
    assert_eq!(metrics.traffic_counters().queue_depth, 0);
    task.abort();
    let _ = task.await;
}

#[tokio::test]
async fn proxy_buffer_idle_deadline_slides_and_reallocation_waits_for_data() {
    let upstream = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target = upstream.local_addr().unwrap();
    let binding = proxy(target);
    let mut executor = UdpSessionExecutor::new_proxy_packet(&binding);
    executor
        .execute_proxy_packet(&binding, target, b"request")
        .await
        .unwrap();
    let mut buf = [0; 2048];
    let (_, session) = upstream.recv_from(&mut buf).await.unwrap();
    let timeout = Duration::from_millis(60);
    let initial = executor.response_buffer_reclaim_deadline(timeout).unwrap();
    time::sleep(Duration::from_millis(20)).await;
    upstream
        .send_to(&response(target, b"activity", 1), session)
        .await
        .unwrap();
    executor.wait_response().await.unwrap();
    let renewed = executor.response_buffer_reclaim_deadline(timeout).unwrap();
    assert!(renewed > initial);
    assert!(!executor.reclaim_response_buffer_if_idle(initial, timeout));
    assert!(executor.reclaim_response_buffer_if_idle(renewed, timeout));
    assert!(!executor.has_response_buffer());
    assert!(
        time::timeout(Duration::from_millis(20), executor.wait_response())
            .await
            .is_err()
    );
    assert!(!executor.has_response_buffer());
    let payload = vec![7; 60 * 1024];
    upstream
        .send_to(&response(target, &payload, 2), session)
        .await
        .unwrap();
    let (_, received) = executor.wait_response().await.unwrap().unwrap();
    assert_eq!(received.payload_for_test(), payload);
}
