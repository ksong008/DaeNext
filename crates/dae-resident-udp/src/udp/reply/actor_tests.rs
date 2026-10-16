use super::*;
use dae_resident_core::RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE;

#[tokio::test]
async fn reply_dispatcher_shutdown_joins_without_open_sockets() {
    let metrics = Arc::new(ResidentDataplaneMetrics::default());
    let dispatcher = UdpReplyDispatcher::start(
        2,
        2,
        2,
        Duration::from_secs(1),
        2,
        ResidentUdpPayloadAdmission::new(1, 1024),
        metrics,
    );
    assert_eq!(
        dispatcher
            .shutdown(time::Instant::now() + RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE)
            .await["closedSockets"],
        0
    );
}

#[tokio::test]
async fn reply_dispatcher_preserves_joined_ownership_at_expired_deadline() {
    let metrics = Arc::new(ResidentDataplaneMetrics::default());
    let dispatcher = UdpReplyDispatcher::start(
        2,
        2,
        2,
        Duration::from_secs(1),
        2,
        ResidentUdpPayloadAdmission::new(1, 1024),
        metrics,
    );

    let report = dispatcher.shutdown(time::Instant::now()).await;

    assert_eq!(report["status"], "pass");
    assert_eq!(report["safetyStatus"], "pass");
    assert_eq!(report["taskJoined"], true);
    assert!(matches!(
        report["completionMode"].as_str(),
        Some("graceful" | "forced-bounded")
    ));
    assert!(report.get("error").is_none());
}

#[tokio::test]
async fn reply_handle_waits_for_bounded_queue_capacity() {
    let (sender, mut receiver) = mpsc::channel(1);
    let metrics = Arc::new(ResidentDataplaneMetrics::default());
    let handle = UdpReplyHandle {
        senders: Arc::new(vec![sender]),
        closing: Arc::new(AtomicBool::new(false)),
        metrics: Arc::clone(&metrics),
        payload_admission: ResidentUdpPayloadAdmission::new(1, 1024),
    };
    let target: SocketAddr = "127.0.0.1:53".parse().unwrap();
    let peer: SocketAddr = "127.0.0.1:10000".parse().unwrap();
    let (response, _response_rx) = oneshot::channel();
    handle.senders[0]
        .try_send(UdpReplyRequest {
            work: ResidentUdpWorkGuard::new(
                Arc::clone(&handle.metrics),
                ResidentUdpWorkStage::Reply,
            ),
            original_dst: target,
            peer,
            payload: vec![1],
            _payload_admission: ResidentUdpPayloadAdmission::new(1, 1024)
                .try_acquire(1)
                .unwrap(),
            deadline: time::Instant::now() + RESIDENT_UDP_RESPONSE_TIMEOUT,
            response: Some(UdpReplyCompletion::Result(response)),
            download_bytes_on_success: 0,
        })
        .unwrap();

    let send = tokio::spawn(async move { handle.send(target, peer, vec![2]).await });
    tokio::task::yield_now().await;
    assert!(!send.is_finished());

    let first = receiver.recv().await.unwrap();
    let UdpReplyCompletion::Result(response) = first.response.unwrap() else {
        panic!("expected result completion");
    };
    let _ = response.send(Ok(()));
    let second = receiver.recv().await.unwrap();
    let UdpReplyCompletion::Result(response) = second.response.unwrap() else {
        panic!("expected result completion");
    };
    let _ = response.send(Ok(()));

    send.await.unwrap().unwrap();
    assert_eq!(metrics.snapshot()["udpReplyQueueFull"].as_u64().unwrap(), 0);
    assert_eq!(metrics.snapshot()["udpReplyQueued"].as_u64().unwrap(), 1);
}

#[test]
fn only_socket_errors_are_emitted_as_per_packet_events() {
    assert!(!UdpReplyError::QueueFull.should_log());
    assert!(
        !UdpReplyError::PayloadLimit(ResidentUdpPayloadAdmissionError {
            requested: 2,
            current: 1,
            limit: 1,
        })
        .should_log()
    );
    assert!(!UdpReplyError::ResponseTimedOut.should_log());
    assert!(UdpReplyError::Socket("fatal".to_owned()).should_log());
}

#[tokio::test]
async fn detached_reply_uses_the_bounded_queue_without_a_waiter_task() {
    let (sender, mut receiver) = mpsc::channel(1);
    let metrics = Arc::new(ResidentDataplaneMetrics::default());
    let payload_admission = ResidentUdpPayloadAdmission::new(1, 1024);
    let handle = UdpReplyHandle {
        senders: Arc::new(vec![sender]),
        closing: Arc::new(AtomicBool::new(false)),
        metrics,
        payload_admission: payload_admission.clone(),
    };
    let target: SocketAddr = "127.0.0.1:53".parse().unwrap();
    let peer: SocketAddr = "127.0.0.1:10000".parse().unwrap();

    handle
        .try_send_detached(target, peer, vec![1, 2, 3], true)
        .unwrap();
    let request = receiver.recv().await.unwrap();
    assert_eq!(payload_admission.current(), 3);
    assert!(request.response.is_none());
    assert_eq!(request.download_bytes_on_success, 3);
    drop(request);
    assert_eq!(payload_admission.current(), 0);
}

#[test]
fn reply_shard_hash_is_stable_and_separates_address_families() {
    let ipv4_target: SocketAddr = "127.0.0.1:53".parse().unwrap();
    let ipv4_peer: SocketAddr = "127.0.0.1:10000".parse().unwrap();
    let ipv6_target: SocketAddr = "[::ffff:127.0.0.1]:53".parse().unwrap();
    let ipv6_peer: SocketAddr = "[::ffff:127.0.0.1]:10000".parse().unwrap();

    assert_eq!(
        stable_udp_reply_shard(ipv4_target, ipv4_peer, 2),
        stable_udp_reply_shard(ipv4_target, ipv4_peer, 2)
    );
    assert_ne!(
        stable_udp_reply_hash(ipv4_target, ipv4_peer),
        stable_udp_reply_hash(ipv6_target, ipv6_peer)
    );
}

#[test]
fn reply_shard_partitions_preserve_total_queue_and_cache_capacity() {
    for total in [1, 2, 3, 7, 512] {
        for requested_shards in [1, 2, 4] {
            let shard_count = requested_shards.min(total);
            let partitioned_total = (0..shard_count)
                .map(|index| partitioned_udp_reply_capacity(total, index, requested_shards))
                .sum::<usize>();
            assert_eq!(partitioned_total, total);
        }
    }
}

#[tokio::test]
async fn blocked_reply_shard_does_not_delay_an_independent_shard() {
    let (first_sender, mut first_receiver) = mpsc::channel(1);
    let (second_sender, mut second_receiver) = mpsc::channel(1);
    let metrics = Arc::new(ResidentDataplaneMetrics::default());
    let payload_admission = ResidentUdpPayloadAdmission::new(1, 1024);
    let handle = UdpReplyHandle {
        senders: Arc::new(vec![first_sender, second_sender]),
        closing: Arc::new(AtomicBool::new(false)),
        metrics,
        payload_admission: payload_admission.clone(),
    };
    let target: SocketAddr = "127.0.0.1:53".parse().unwrap();
    let peers = (10_000..=u16::MAX)
        .map(|port| SocketAddr::from(([127, 0, 0, 1], port)))
        .fold([None, None], |mut selected, peer| {
            let shard = stable_udp_reply_shard(target, peer, 2);
            if selected[shard].is_none() {
                selected[shard] = Some(peer);
            }
            selected
        });
    let first_peer = peers[0].expect("a tuple must hash to the first shard");
    let second_peer = peers[1].expect("a tuple must hash to the second shard");
    let occupied_payload = payload_admission.try_acquire(1).unwrap();
    handle.senders[0]
        .try_send(UdpReplyRequest {
            work: ResidentUdpWorkGuard::new(
                Arc::clone(&handle.metrics),
                ResidentUdpWorkStage::Reply,
            ),
            original_dst: target,
            peer: first_peer,
            payload: vec![1],
            _payload_admission: occupied_payload,
            deadline: time::Instant::now() + RESIDENT_UDP_RESPONSE_TIMEOUT,
            response: None,
            download_bytes_on_success: 0,
        })
        .unwrap();

    let blocked_handle = handle.clone();
    let blocked =
        tokio::spawn(async move { blocked_handle.send(target, first_peer, vec![2]).await });
    tokio::task::yield_now().await;
    assert!(!blocked.is_finished());

    let progressing_handle = handle.clone();
    let progressing =
        tokio::spawn(async move { progressing_handle.send(target, second_peer, vec![3]).await });
    let mut second_request = second_receiver.recv().await.unwrap();
    let UdpReplyCompletion::Result(response) = second_request.response.take().unwrap() else {
        panic!("expected result completion");
    };
    response.send(Ok(())).unwrap();
    drop(second_request);
    progressing.await.unwrap().unwrap();
    assert!(!blocked.is_finished());

    drop(first_receiver.recv().await.unwrap());
    let mut first_request = first_receiver.recv().await.unwrap();
    let UdpReplyCompletion::Result(response) = first_request.response.take().unwrap() else {
        panic!("expected result completion");
    };
    response.send(Ok(())).unwrap();
    drop(first_request);
    blocked.await.unwrap().unwrap();
    assert_eq!(payload_admission.current(), 0);
}
