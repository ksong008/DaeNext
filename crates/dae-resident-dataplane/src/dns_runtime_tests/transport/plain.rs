use dae_resident_dns::runtime::transport::plain::*;

use super::test_support::{Socks5TcpRelay, dns_proxy_binding, socks5_dns_proxy};
use super::*;
use dae_resident_core::RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE;
use std::time::Duration;

fn direct_tcp_test_upstream(target: SocketAddr) -> ResidentDnsUpstream {
    ResidentDnsUpstream {
        index: 0,
        tag: "direct-connect-classification".to_owned(),
        target: ResidentDnsUpstreamTarget::new(
            target.to_string(),
            target.ip().to_string(),
            target.port(),
            Some(target),
            target,
            0,
            Duration::from_secs(60),
        ),
        scheme: ResidentDnsUpstreamScheme::Tcp,
        path: Arc::from(""),
    }
}

#[tokio::test]
async fn direct_tcp_refusal_is_a_typed_target_connect_failure() {
    let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let target = listener.local_addr().unwrap();
    drop(listener);
    let error = open_dns_tcp_stream_with_context_async(
        &direct_tcp_test_upstream(target),
        target,
        0,
        ProxyDnsRequestContext::from_timeout(Duration::from_secs(1)),
    )
    .await
    .unwrap_err();

    assert_eq!(error.stage(), ProxyDnsRequestStage::Connect);
    assert_eq!(error.failure(), ProxyDnsRequestFailure::Network);
}

#[tokio::test]
async fn direct_tcp_connect_deadline_is_typed_before_socket_work() {
    let target = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), DNS_DEFAULT_PORT);
    let error = open_dns_tcp_stream_with_context_async(
        &direct_tcp_test_upstream(target),
        target,
        0,
        ProxyDnsRequestContext::from_timeout(Duration::ZERO),
    )
    .await
    .unwrap_err();

    assert_eq!(error.stage(), ProxyDnsRequestStage::Connect);
    assert_eq!(error.failure(), ProxyDnsRequestFailure::Deadline);
}

#[tokio::test]
async fn forward_dns_udp_retries_after_timeout() {
    let upstream = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let target = upstream.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let mut buf = [0_u8; 64];
        let _ = upstream.recv_from(&mut buf).await.unwrap();
        let (read, peer) = upstream.recv_from(&mut buf).await.unwrap();
        upstream.send_to(&buf[..read], peer).await.unwrap();
    });

    let response = forward_dns_udp_with_attempts_async(
        target,
        b"fixture-query",
        0,
        2,
        std::time::Duration::from_millis(20),
    )
    .await
    .unwrap();

    assert_eq!(response, b"fixture-query");
    server.await.unwrap();
}

#[tokio::test]
async fn forward_dns_udp_reports_attempt_count_after_timeouts() {
    let upstream = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let target = upstream.local_addr().unwrap();
    let _server = tokio::spawn(async move {
        let mut buf = [0_u8; 64];
        while upstream.recv_from(&mut buf).await.is_ok() {}
    });

    let err = forward_dns_udp_with_attempts_async(
        target,
        b"fixture-query",
        0,
        2,
        std::time::Duration::from_millis(5),
    )
    .await
    .unwrap_err();

    assert!(err.contains("after 2 attempts"));
}

#[tokio::test]
async fn forward_dns_udp_discards_stale_response_id() {
    let upstream = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let target = upstream.local_addr().unwrap();
    let query = build_dns_query_packet(0x1234, "example.com", DNS_QTYPE_A).unwrap();
    let response = dns_a_response_for_query(&query, [192, 0, 2, 1]);
    let mut stale = response.clone();
    stale[0..2].copy_from_slice(&0xabcd_u16.to_be_bytes());
    let server = tokio::spawn(async move {
        let mut buf = [0_u8; DNS_RESPONSE_READ_LIMIT];
        let (_, peer) = upstream.recv_from(&mut buf).await.unwrap();
        upstream.send_to(&stale, peer).await.unwrap();
        upstream.send_to(&response, peer).await.unwrap();
    });

    let response = forward_dns_udp_with_attempts_async(
        target,
        &query,
        0,
        1,
        std::time::Duration::from_millis(100),
    )
    .await
    .unwrap();

    assert_eq!(response[0..2], 0x1234_u16.to_be_bytes());
    server.await.unwrap();
}

#[tokio::test]
async fn forward_dns_udp_discards_unexpected_peer_response() {
    let upstream = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let target = upstream.local_addr().unwrap();
    let other_peer = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let query = build_dns_query_packet(0x4321, "example.com", DNS_QTYPE_A).unwrap();
    let unexpected = dns_a_response_for_query(&query, [192, 0, 2, 1]);
    let expected = dns_a_response_for_query(&query, [192, 0, 2, 2]);
    let server = tokio::spawn(async move {
        let mut buf = [0_u8; DNS_RESPONSE_READ_LIMIT];
        let (_, peer) = upstream.recv_from(&mut buf).await.unwrap();
        other_peer.send_to(&unexpected, peer).await.unwrap();
        time::sleep(std::time::Duration::from_millis(10)).await;
        upstream.send_to(&expected, peer).await.unwrap();
    });

    let response = forward_dns_udp_with_attempts_async(
        target,
        &query,
        0,
        1,
        std::time::Duration::from_millis(100),
    )
    .await
    .unwrap();

    assert_eq!(response, dns_a_response_for_query(&query, [192, 0, 2, 2]));
    server.await.unwrap();
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn direct_dns_udp_forwarder_recreates_a_fatal_actor_for_the_same_target() {
    let reserved = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let target = reserved.local_addr().unwrap();
    drop(reserved);
    let mut runtime = ResidentDnsUdpRuntimeConfig::standalone();
    runtime.direct_shards = 1;
    runtime.actor_worker_threads = 1;
    runtime.attempts = 1;
    runtime.attempt_timeout = Duration::from_millis(500);
    let metrics = Arc::new(ResidentDataplaneMetrics::default());
    let executor = Arc::new(ResidentDnsUdpActorExecutor::new(
        runtime.clone(),
        Arc::clone(&metrics),
    ));
    let forwarder = ResidentDnsUdpForwarder {
        owner_observation: ResidentDnsTransportOwnerObservation::new(
            Arc::clone(&metrics),
            std::mem::size_of::<ResidentDnsUdpForwarder>()
                .saturating_add(std::mem::size_of::<ResidentDnsUdpForwarderShard>()),
        ),
        target,
        mark: 0,
        next_shard: std::sync::atomic::AtomicUsize::new(0),
        executor: Arc::clone(&executor),
        shards: vec![ResidentDnsUdpForwarderShard {
            handle: AsyncMutex::new(None),
            opened: std::sync::atomic::AtomicBool::new(false),
            inflight: std::sync::atomic::AtomicUsize::new(0),
        }],
        runtime_config: runtime.clone(),
    };
    let query = build_dns_query_packet(0x6161, "fatal-recreate.example", DNS_QTYPE_A).unwrap();
    let failed_handle = forwarder.handle(0).await.unwrap();
    assert!(failed_handle.exchange_once(&query).await.is_err());
    time::timeout(Duration::from_secs(1), async {
        while !failed_handle.is_closed() {
            time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("fatal DNS UDP actor did not close");

    let upstream = tokio::net::UdpSocket::bind(target).await.unwrap();
    let server = tokio::spawn(async move {
        let mut request = vec![0_u8; DNS_RESPONSE_READ_LIMIT];
        let (read, peer) = upstream.recv_from(&mut request).await.unwrap();
        let response = dns_a_response_for_query(&request[..read], [192, 0, 2, 44]);
        upstream.send_to(&response, peer).await.unwrap();
    });
    let response = forwarder
        .exchange(
            &query,
            ProxyDnsRequestContext::from_timeout(RESIDENT_UDP_RESPONSE_TIMEOUT),
        )
        .await
        .unwrap();

    assert_eq!(&response[0..2], &0x6161_u16.to_be_bytes());
    server.await.unwrap();
    let snapshot = metrics.snapshot();
    assert_eq!(snapshot["dnsUdpActorFatalExits"], 1);
    assert_eq!(snapshot["dnsUdpForwarderRecreated"], 1);
    let deadline = time::Instant::now() + RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE;
    assert_eq!(executor.shutdown(deadline).await["status"], "pass");
}

#[tokio::test]
async fn direct_dns_udp_shards_expand_under_concurrency_and_release_idle_excess() {
    let upstream = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let target = upstream.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let mut packets = Vec::new();
        let mut buffer = vec![0_u8; DNS_RESPONSE_READ_LIMIT];
        for _ in 0..2 {
            let (read, peer) = upstream.recv_from(&mut buffer).await.unwrap();
            packets.push((buffer[..read].to_vec(), peer));
        }
        for (index, (query, peer)) in packets.into_iter().rev().enumerate() {
            let response = dns_a_response_for_query(&query, [192, 0, 2, 110 + index as u8]);
            upstream.send_to(&response, peer).await.unwrap();
        }
    });
    let mut runtime = ResidentDnsUdpRuntimeConfig::standalone();
    runtime.direct_shards = 2;
    runtime.attempts = 1;
    runtime.shard_idle_timeout = Duration::from_millis(20);
    let metrics = Arc::new(ResidentDataplaneMetrics::default());
    let executor = Arc::new(ResidentDnsUdpActorExecutor::new(
        runtime.clone(),
        Arc::clone(&metrics),
    ));
    let forwarder = ResidentDnsUdpForwarder {
        owner_observation: ResidentDnsTransportOwnerObservation::new(
            Arc::clone(&metrics),
            std::mem::size_of::<ResidentDnsUdpForwarder>(),
        ),
        target,
        mark: 0,
        next_shard: std::sync::atomic::AtomicUsize::new(0),
        executor: Arc::clone(&executor),
        shards: (0..2)
            .map(|_| ResidentDnsUdpForwarderShard {
                handle: AsyncMutex::new(None),
                opened: std::sync::atomic::AtomicBool::new(false),
                inflight: std::sync::atomic::AtomicUsize::new(0),
            })
            .collect(),
        runtime_config: runtime,
    };
    let first = build_dns_query_packet(0x7401, "first-udp-shard.example", DNS_QTYPE_A).unwrap();
    let second = build_dns_query_packet(0x7402, "second-udp-shard.example", DNS_QTYPE_A).unwrap();
    let context = ProxyDnsRequestContext::from_timeout(Duration::from_secs(1));
    let (first_response, second_response) = tokio::join!(
        forwarder.exchange(&first, context),
        forwarder.exchange(&second, context),
    );
    assert_eq!(&first_response.unwrap()[0..2], &0x7401_u16.to_be_bytes());
    assert_eq!(&second_response.unwrap()[0..2], &0x7402_u16.to_be_bytes());
    server.await.unwrap();
    assert!(
        forwarder
            .shards
            .iter()
            .all(|shard| shard.opened.load(std::sync::atomic::Ordering::Acquire))
    );
    assert_eq!(metrics.snapshot()["dnsUdpActorsOpened"], 2);

    time::timeout(Duration::from_millis(200), async {
        while metrics.snapshot()["dnsUdpActorsClosed"] == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("idle excess DNS UDP shard did not close");
    forwarder.refresh_closed_shards();
    assert!(
        forwarder.shards[0]
            .opened
            .load(std::sync::atomic::Ordering::Acquire)
    );
    assert!(
        !forwarder.shards[1]
            .opened
            .load(std::sync::atomic::Ordering::Acquire)
    );
    assert_eq!(
        executor
            .shutdown(time::Instant::now() + RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE)
            .await["status"],
        "pass"
    );
}

fn dns_a_response_for_query(query: &[u8], address: [u8; 4]) -> Vec<u8> {
    let view = DnsPacketView::parse(query).unwrap();
    let mut response = Vec::new();
    response.extend_from_slice(&query[0..2]);
    response.extend_from_slice(&0x8180_u16.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    response.extend_from_slice(&query[12..view.answer_offset()]);
    response.extend_from_slice(&0xc00c_u16.to_be_bytes());
    response.extend_from_slice(&DNS_QTYPE_A.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&60_u32.to_be_bytes());
    response.extend_from_slice(&4_u16.to_be_bytes());
    response.extend_from_slice(&address);
    response
}

#[tokio::test]
async fn forward_dns_tcp_tries_next_resolved_target_after_connect_failure() {
    let closed = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap()
        .local_addr()
        .unwrap();
    let server_listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let server_addr = server_listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = server_listener.accept().await.unwrap();
        let mut len = [0_u8; 2];
        stream.read_exact(&mut len).await.unwrap();
        let len = u16::from_be_bytes(len) as usize;
        let mut payload = vec![0_u8; len];
        stream.read_exact(&mut payload).await.unwrap();
        let response = dns_a_response_for_query(&payload, [192, 0, 2, 60]);
        stream
            .write_all(&(response.len() as u16).to_be_bytes())
            .await
            .unwrap();
        stream.write_all(&response).await.unwrap();
    });

    let upstream = ResidentDnsUpstream {
        index: 0,
        tag: "test".to_owned(),
        target: ResidentDnsUpstreamTarget {
            authority: Arc::from("test.example:53"),
            host: "test.example".to_owned(),
            port: 53,
            literal_addr: None,
            fallback_resolver: "127.0.0.1:53".parse().unwrap(),
            resolver_mark: 0,
            resolved_addrs: Arc::default(),
        },
        scheme: ResidentDnsUpstreamScheme::Tcp,
        path: Arc::from(""),
    };
    upstream
        .target
        .resolved_addrs
        .seed(vec![closed, server_addr], Duration::from_secs(60))
        .await;

    let plan = ResidentDnsPlan::asis(0);
    let forwarders = Arc::new(test_resident_dns_forwarder_cache());
    let query = build_dns_query_packet(0x6060, "next-target.example", DNS_QTYPE_A).unwrap();
    let response = forward_dns_tcp_async(
        &upstream,
        &query,
        &plan,
        &forwarders,
        ProxyDnsRequestContext::from_timeout(RESIDENT_UDP_RESPONSE_TIMEOUT),
    )
    .await
    .unwrap();

    assert_eq!(&response[0..2], &0x6060_u16.to_be_bytes());
    server.await.unwrap();
}

#[tokio::test]
async fn proxied_dns_tcp_reuses_one_pipeline_for_out_of_order_responses() {
    let upstream_listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let target = upstream_listener.local_addr().unwrap();
    let upstream_server = tokio::spawn(async move {
        let (mut stream, _) = upstream_listener.accept().await.unwrap();
        let mut frame_reader = DnsTcpFrameReader::default();
        let warm = frame_reader.read_frame(&mut stream).await.unwrap().unwrap();
        let warm_response = dns_a_response_for_query(&warm, [192, 0, 2, 70]);
        write_dns_tcp_payload_async(&mut stream, &warm_response)
            .await
            .unwrap();
        let first = frame_reader.read_frame(&mut stream).await.unwrap().unwrap();
        let second = frame_reader.read_frame(&mut stream).await.unwrap().unwrap();
        let second_response = dns_a_response_for_query(&second, [192, 0, 2, 72]);
        let first_response = dns_a_response_for_query(&first, [192, 0, 2, 71]);
        write_dns_tcp_payload_async(&mut stream, &second_response)
            .await
            .unwrap();
        write_dns_tcp_payload_async(&mut stream, &first_response)
            .await
            .unwrap();
    });
    let relay = Socks5TcpRelay::start().await;
    let upstream = ResidentDnsUpstream {
        index: 0,
        tag: "proxied-pipeline".to_owned(),
        target: ResidentDnsUpstreamTarget {
            authority: Arc::from(target.to_string()),
            host: target.ip().to_string(),
            port: target.port(),
            literal_addr: Some(target),
            fallback_resolver: "127.0.0.1:53".parse().unwrap(),
            resolver_mark: 0,
            resolved_addrs: Arc::default(),
        },
        scheme: ResidentDnsUpstreamScheme::Tcp,
        path: Arc::from(""),
    };
    let binding = dns_proxy_binding(socks5_dns_proxy(relay.address()), 1);
    let selection = ResidentDnsUpstreamSelection::Proxy { binding };
    let cache = Arc::new(test_resident_dns_forwarder_cache());
    let forwarder = cache
        .tcp_forwarder(&upstream, target, 0, &selection)
        .unwrap();
    let warm = build_dns_query_packet(0x7000, "warm.example", DNS_QTYPE_A).unwrap();
    let warm_response = forwarder
        .exchange(
            &warm,
            ProxyDnsRequestContext::from_timeout(Duration::from_secs(2)),
        )
        .await
        .unwrap();
    assert_eq!(&warm_response[0..2], &0x7000_u16.to_be_bytes());

    let first = build_dns_query_packet(0x7100, "first.example", DNS_QTYPE_A).unwrap();
    let second = build_dns_query_packet(0x7200, "second.example", DNS_QTYPE_A).unwrap();
    let first_exchange = forwarder.exchange(
        &first,
        ProxyDnsRequestContext::from_timeout(Duration::from_secs(2)),
    );
    let second_exchange = forwarder.exchange(
        &second,
        ProxyDnsRequestContext::from_timeout(Duration::from_secs(2)),
    );
    let (first_response, second_response) = tokio::join!(first_exchange, second_exchange);
    assert_eq!(&first_response.unwrap()[0..2], &0x7100_u16.to_be_bytes());
    assert_eq!(&second_response.unwrap()[0..2], &0x7200_u16.to_be_bytes());
    upstream_server.await.unwrap();
    assert_eq!(relay.connections(), 1);
    let deadline = time::Instant::now() + RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE;
    assert_eq!(cache.shutdown(deadline).await["status"], "pass");
}

#[tokio::test]
async fn proxied_dns_tcp_pool_expands_before_waiting_on_a_full_pipeline() {
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let target = listener.local_addr().unwrap();
    let response_barrier = Arc::new(tokio::sync::Barrier::new(3));
    let server_barrier = Arc::clone(&response_barrier);
    let server = tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        for index in 0..2_u8 {
            let (mut stream, _) = listener.accept().await.unwrap();
            let response_barrier = Arc::clone(&server_barrier);
            connections.spawn(async move {
                let mut frame_reader = DnsTcpFrameReader::default();
                let query = frame_reader.read_frame(&mut stream).await.unwrap().unwrap();
                response_barrier.wait().await;
                let response = dns_a_response_for_query(&query, [192, 0, 2, 100 + index]);
                write_dns_tcp_payload_async(&mut stream, &response)
                    .await
                    .unwrap();
            });
        }
        server_barrier.wait().await;
        while connections.join_next().await.is_some() {}
    });
    let relay = Socks5TcpRelay::start().await;
    let upstream = ResidentDnsUpstream {
        index: 0,
        tag: "proxied-pool".to_owned(),
        target: ResidentDnsUpstreamTarget {
            authority: Arc::from(target.to_string()),
            host: target.ip().to_string(),
            port: target.port(),
            literal_addr: Some(target),
            fallback_resolver: "127.0.0.1:53".parse().unwrap(),
            resolver_mark: 0,
            resolved_addrs: Arc::default(),
        },
        scheme: ResidentDnsUpstreamScheme::Tcp,
        path: Arc::from(""),
    };
    let forwarder = Arc::new(ResidentDnsTcpForwarder {
        owner_observation: ResidentDnsTransportOwnerObservation::new(
            Arc::new(ResidentDataplaneMetrics::default()),
            std::mem::size_of::<ResidentDnsTcpForwarder>(),
        ),
        upstream,
        target,
        mark: 0,
        connection_kind: ResidentDnsTcpConnectionKind::Proxy {
            binding: dns_proxy_binding(socks5_dns_proxy(relay.address()), 1),
            transport: resident_dns_proxy_tcp_transport(ResidentTransportOwnerRegistries::default()),
        },
        connection_limit: 2,
        request_limit: 1,
        connections: AsyncMutex::new(Vec::new()),
        open_lock: AsyncMutex::new(()),
        closing: std::sync::atomic::AtomicBool::new(false),
    });
    let first = build_dns_query_packet(0x7301, "first-proxy-pool.example", DNS_QTYPE_A).unwrap();
    let first_forwarder = Arc::clone(&forwarder);
    let first_exchange = tokio::spawn(async move {
        first_forwarder
            .exchange(
                &first,
                ProxyDnsRequestContext::from_timeout(Duration::from_secs(2)),
            )
            .await
    });
    time::timeout(Duration::from_secs(1), async {
        loop {
            let ready = forwarder
                .connections
                .lock()
                .await
                .first()
                .is_some_and(|connection| connection.handle.pending() == 1);
            if ready {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("first proxied DNS TCP pipeline did not reach capacity");
    let second = build_dns_query_packet(0x7302, "second-proxy-pool.example", DNS_QTYPE_A).unwrap();
    let second_response = forwarder
        .exchange(
            &second,
            ProxyDnsRequestContext::from_timeout(Duration::from_secs(2)),
        )
        .await
        .unwrap();
    let first_response = first_exchange.await.unwrap().unwrap();
    assert_eq!(&first_response[0..2], &0x7301_u16.to_be_bytes());
    assert_eq!(&second_response[0..2], &0x7302_u16.to_be_bytes());
    server.await.unwrap();
    assert_eq!(relay.connections(), 2);

    forwarder
        .closing
        .store(true, std::sync::atomic::Ordering::Release);
    let mut connections = std::mem::take(&mut *forwarder.connections.lock().await);
    for connection in &connections {
        connection.handle.close();
    }
    for connection in &mut connections {
        let _ = time::timeout(Duration::from_secs(1), &mut connection.task)
            .await
            .expect("proxied DNS TCP pipeline did not join after close")
            .expect("proxied DNS TCP pipeline task panicked");
        assert_eq!(connection.handle.pending(), 0);
    }
}

#[tokio::test]
async fn direct_dns_tcp_pool_expands_before_waiting_on_a_full_connection() {
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let target = listener.local_addr().unwrap();
    let accepted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let accepted_count = Arc::clone(&accepted);
    let response_barrier = Arc::new(tokio::sync::Barrier::new(3));
    let server_barrier = Arc::clone(&response_barrier);
    let server = tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().await.unwrap();
            accepted_count.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
            let response_barrier = Arc::clone(&server_barrier);
            connections.spawn(async move {
                let mut frame_reader = DnsTcpFrameReader::default();
                let query = frame_reader.read_frame(&mut stream).await.unwrap().unwrap();
                response_barrier.wait().await;
                let response = dns_a_response_for_query(&query, [192, 0, 2, 90]);
                write_dns_tcp_payload_async(&mut stream, &response)
                    .await
                    .unwrap();
            });
        }
        server_barrier.wait().await;
        while connections.join_next().await.is_some() {}
    });
    let upstream = ResidentDnsUpstream {
        index: 0,
        tag: "direct-pool".to_owned(),
        target: ResidentDnsUpstreamTarget {
            authority: Arc::from(target.to_string()),
            host: target.ip().to_string(),
            port: target.port(),
            literal_addr: Some(target),
            fallback_resolver: "127.0.0.1:53".parse().unwrap(),
            resolver_mark: 0,
            resolved_addrs: Arc::default(),
        },
        scheme: ResidentDnsUpstreamScheme::Tcp,
        path: Arc::from(""),
    };
    let metrics = Arc::new(ResidentDataplaneMetrics::default());
    let forwarder = ResidentDnsTcpForwarder {
        owner_observation: ResidentDnsTransportOwnerObservation::new(
            metrics,
            std::mem::size_of::<ResidentDnsTcpForwarder>(),
        ),
        upstream,
        target,
        mark: 0,
        connection_kind: ResidentDnsTcpConnectionKind::Direct,
        connection_limit: 2,
        request_limit: 1,
        connections: AsyncMutex::new(Vec::new()),
        open_lock: AsyncMutex::new(()),
        closing: std::sync::atomic::AtomicBool::new(false),
    };
    let first = build_dns_query_packet(0x8100, "first-pool.example", DNS_QTYPE_A).unwrap();
    let second = build_dns_query_packet(0x8200, "second-pool.example", DNS_QTYPE_A).unwrap();
    let first_exchange = forwarder.exchange(
        &first,
        ProxyDnsRequestContext::from_timeout(Duration::from_secs(2)),
    );
    let second_exchange = forwarder.exchange(
        &second,
        ProxyDnsRequestContext::from_timeout(Duration::from_secs(2)),
    );
    let (first_response, second_response) = tokio::join!(first_exchange, second_exchange);
    assert_eq!(&first_response.unwrap()[0..2], &0x8100_u16.to_be_bytes());
    assert_eq!(&second_response.unwrap()[0..2], &0x8200_u16.to_be_bytes());
    server.await.unwrap();
    assert_eq!(accepted.load(std::sync::atomic::Ordering::Acquire), 2);
    for connection in forwarder.connections.lock().await.iter() {
        connection.handle.close();
    }
}
