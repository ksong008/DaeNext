use super::*;

use crate::RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE;
use crate::dns::transport::test_support::{
    DnsQuicTestProtocol, DnsQuicTestServer, Socks5UdpRelay, dns_proxy_binding, dns_test_response,
    socks5_dns_proxy,
};
use crate::quic_endpoint_metrics_snapshot;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn routed_doh3_reuses_one_outer_relay_and_inner_client_for_large_responses() {
    let generation = 7_343;
    let expected_small = dns_test_response(1_500, 0x53);
    let expected_large = dns_test_response(4_096, 0x64);
    let server = DnsQuicTestServer::start_with_response_delay(
        DnsQuicTestProtocol::Doh3,
        vec![expected_small.clone(), expected_large.clone()],
        std::time::Duration::from_millis(200),
    )
    .await;
    let socks = Socks5UdpRelay::start().await;
    let proxy = socks5_dns_proxy(socks.address());
    let binding = dns_proxy_binding(Arc::clone(&proxy), generation);
    let upstream = parse_dns_upstream(
        0,
        "routed-doh3",
        &format!("h3://{}:443/dns-query", server.server_name()),
        server.address(),
        0,
    )
    .unwrap();
    let selection = ResidentDnsUpstreamSelection::Proxy {
        binding: binding.clone(),
    };
    let cache = test_resident_dns_forwarder_cache();
    let forwarder = cache
        .proxy_h3_forwarder(&upstream, server.address(), binding, &selection)
        .unwrap();
    forwarder.lock().await.client_config_override = Some(server.client_config());
    let first_query = build_dns_query_packet(0x3431, "small.example", DNS_QTYPE_A).unwrap();
    let second_query = build_dns_query_packet(0x3432, "large.example", DNS_QTYPE_AAAA).unwrap();

    let first = forward_cached_proxy_dns_h3(
        &upstream,
        &first_query,
        Arc::clone(&forwarder),
        ProxyDnsRequestContext::from_timeout(std::time::Duration::from_secs(3)),
    )
    .await
    .unwrap();
    let first_connection_id = forwarder
        .lock()
        .await
        .connection
        .as_ref()
        .unwrap()
        .stable_id();
    let second = forward_cached_proxy_dns_h3(
        &upstream,
        &second_query,
        Arc::clone(&forwarder),
        ProxyDnsRequestContext::from_timeout(std::time::Duration::from_secs(3)),
    )
    .await
    .unwrap();
    let second_connection_id = forwarder
        .lock()
        .await
        .connection
        .as_ref()
        .unwrap()
        .stable_id();

    assert_eq!(first.len(), expected_small.len());
    assert_eq!(&first[..2], &first_query[..2]);
    assert_eq!(&first[2..], &expected_small[2..]);
    assert_eq!(second.len(), expected_large.len());
    assert_eq!(&second[..2], &second_query[..2]);
    assert_eq!(&second[2..], &expected_large[2..]);
    assert_eq!(first_connection_id, second_connection_id);
    assert_eq!(server.connections(), 1);
    assert_eq!(server.requests(), 2);
    assert_eq!(socks.control_connections(), 1);
    assert!(socks.datagrams_forwarded() > 0);
    let cancelled_upstream = upstream.clone();
    let cancelled_forwarder = Arc::clone(&forwarder);
    let cancelled = tokio::spawn(async move {
        let query = build_dns_query_packet(0x3435, "cancelled.example", DNS_QTYPE_A).unwrap();
        forward_cached_proxy_dns_h3(
            &cancelled_upstream,
            &query,
            cancelled_forwarder,
            ProxyDnsRequestContext::from_timeout(std::time::Duration::from_secs(3)),
        )
        .await
    });
    let surviving_upstream = upstream.clone();
    let surviving_forwarder = Arc::clone(&forwarder);
    let surviving = tokio::spawn(async move {
        let query = build_dns_query_packet(0x3436, "surviving.example", DNS_QTYPE_A).unwrap();
        forward_cached_proxy_dns_h3(
            &surviving_upstream,
            &query,
            surviving_forwarder,
            ProxyDnsRequestContext::from_timeout(std::time::Duration::from_secs(3)),
        )
        .await
    });
    time::timeout(std::time::Duration::from_secs(2), async {
        while server.requests() < 4 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    cancelled.abort();
    assert!(cancelled.await.unwrap_err().is_cancelled());
    assert!(surviving.await.unwrap().is_ok());
    assert_eq!(server.connections(), 1);
    assert_eq!(socks.control_connections(), 1);
    assert_eq!(
        forwarder
            .lock()
            .await
            .connection
            .as_ref()
            .unwrap()
            .stable_id(),
        second_connection_id
    );
    server.close_current();
    let third_query = build_dns_query_packet(0x3433, "rebuild-a.example", DNS_QTYPE_A).unwrap();
    let fourth_query = build_dns_query_packet(0x3434, "rebuild-b.example", DNS_QTYPE_AAAA).unwrap();
    let (third, fourth) = tokio::join!(
        forward_cached_proxy_dns_h3(
            &upstream,
            &third_query,
            Arc::clone(&forwarder),
            ProxyDnsRequestContext::from_timeout(std::time::Duration::from_secs(3)),
        ),
        forward_cached_proxy_dns_h3(
            &upstream,
            &fourth_query,
            Arc::clone(&forwarder),
            ProxyDnsRequestContext::from_timeout(std::time::Duration::from_secs(3)),
        ),
    );
    assert!(third.is_ok(), "{third:?}");
    assert!(fourth.is_ok(), "{fourth:?}");
    let rebuilt_connection_id = forwarder
        .lock()
        .await
        .connection
        .as_ref()
        .unwrap()
        .stable_id();
    assert_ne!(rebuilt_connection_id, second_connection_id);
    assert_eq!(server.connections(), 2);
    assert_eq!(server.requests(), 6);
    assert_eq!(socks.control_connections(), 2);
    assert_eq!(cache.metrics.snapshot()["dnsTransportOwnersCurrent"], 1);
    let live = quic_endpoint_metrics_snapshot(generation);
    assert_eq!(live["liveStates"]["ready"], 1);
    assert_eq!(live["endpointDriverTasks"]["live"], 1);

    let report = cache
        .shutdown(time::Instant::now() + RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE)
        .await;
    assert_eq!(report["status"], "pass", "{report}");
    assert_eq!(cache.metrics.snapshot()["dnsTransportOwnersCurrent"], 0);
    assert_eq!(cache.metrics.snapshot()["dnsTransportOwnerBytesCurrent"], 0);
    let closed = quic_endpoint_metrics_snapshot(generation);
    assert_eq!(closed["liveStates"]["total"], 0);
    assert_eq!(closed["endpointDriverTasks"]["live"], 0);
    assert_eq!(closed["chargedBytes"]["total"], 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn routed_doh3_owner_survives_the_first_caller_runtime() {
    let generation = 7_344;
    let expected = dns_test_response(1_500, 0x6a);
    let server = DnsQuicTestServer::start_with_response_delay(
        DnsQuicTestProtocol::Doh3,
        vec![expected.clone()],
        std::time::Duration::ZERO,
    )
    .await;
    let socks = Socks5UdpRelay::start().await;
    let proxy = socks5_dns_proxy(socks.address());
    let binding = dns_proxy_binding(Arc::clone(&proxy), generation);
    let upstream = parse_dns_upstream(
        0,
        "routed-doh3-caller-runtime",
        &format!("h3://{}:443/dns-query", server.server_name()),
        server.address(),
        0,
    )
    .unwrap();
    let selection = ResidentDnsUpstreamSelection::Proxy {
        binding: binding.clone(),
    };
    let cache = Arc::new(test_resident_dns_forwarder_cache());
    let forwarder = cache
        .proxy_h3_forwarder(&upstream, server.address(), binding, &selection)
        .unwrap();
    forwarder.lock().await.client_config_override = Some(server.client_config());

    let first_upstream = upstream.clone();
    let first_forwarder = Arc::clone(&forwarder);
    let (first, first_connection_id) = tokio::task::spawn_blocking(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async move {
                let query =
                    build_dns_query_packet(0x3441, "caller-a.example", DNS_QTYPE_A).unwrap();
                let response = forward_dns_h3_to_proxy_async(
                    &first_upstream,
                    &query,
                    Arc::clone(&first_forwarder),
                    ProxyDnsRequestContext::from_timeout(std::time::Duration::from_secs(3)),
                )
                .await
                .unwrap();
                let connection_id = first_forwarder
                    .lock()
                    .await
                    .connection
                    .as_ref()
                    .unwrap()
                    .stable_id();
                (response, connection_id)
            })
    })
    .await
    .unwrap();
    assert_eq!(first.len(), expected.len());
    assert_eq!(server.connections(), 1);
    assert_eq!(socks.control_connections(), 1);
    assert_eq!(
        quic_endpoint_metrics_snapshot(generation)["endpointDriverTasks"]["live"],
        1
    );

    let second_upstream = upstream.clone();
    let second_forwarder = Arc::clone(&forwarder);
    let (second, second_connection_id) = tokio::task::spawn_blocking(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async move {
                let query =
                    build_dns_query_packet(0x3442, "caller-b.example", DNS_QTYPE_AAAA).unwrap();
                let response = forward_dns_h3_to_proxy_async(
                    &second_upstream,
                    &query,
                    Arc::clone(&second_forwarder),
                    ProxyDnsRequestContext::from_timeout(std::time::Duration::from_secs(3)),
                )
                .await
                .unwrap();
                let connection_id = second_forwarder
                    .lock()
                    .await
                    .connection
                    .as_ref()
                    .unwrap()
                    .stable_id();
                (response, connection_id)
            })
    })
    .await
    .unwrap();

    assert_eq!(second.len(), expected.len());
    assert_eq!(second_connection_id, first_connection_id);
    assert_eq!(server.connections(), 1);
    assert_eq!(server.requests(), 2);
    assert_eq!(socks.control_connections(), 1);

    let report = cache
        .shutdown(time::Instant::now() + RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE)
        .await;
    assert_eq!(report["status"], "pass", "{report}");
    assert_eq!(cache.metrics.snapshot()["dnsTransportOwnersCurrent"], 0);
    assert_eq!(cache.metrics.snapshot()["dnsTransportOwnerBytesCurrent"], 0);
    let closed = quic_endpoint_metrics_snapshot(generation);
    assert_eq!(closed["liveStates"]["total"], 0);
    assert_eq!(closed["endpointDriverTasks"]["live"], 0);
    assert_eq!(closed["chargedBytes"]["total"], 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn routed_doh3_five_generation_cycles_release_every_owner_resource() {
    let response = dns_test_response(1_500, 0x75);
    let server = DnsQuicTestServer::start_with_response_delay(
        DnsQuicTestProtocol::Doh3,
        vec![response.clone()],
        std::time::Duration::ZERO,
    )
    .await;
    let socks = Socks5UdpRelay::start().await;

    for cycle in 0..5_u64 {
        let generation = 7_350 + cycle;
        let proxy = socks5_dns_proxy(socks.address());
        let binding = dns_proxy_binding(Arc::clone(&proxy), generation);
        let upstream = parse_dns_upstream(
            0,
            "routed-doh3-reload",
            &format!("h3://{}:443/dns-query", server.server_name()),
            server.address(),
            0,
        )
        .unwrap();
        let selection = ResidentDnsUpstreamSelection::Proxy {
            binding: binding.clone(),
        };
        let cache = test_resident_dns_forwarder_cache();
        let forwarder = cache
            .proxy_h3_forwarder(&upstream, server.address(), binding, &selection)
            .unwrap();
        forwarder.lock().await.client_config_override = Some(server.client_config());
        let query = build_dns_query_packet(
            0x3500_u16.saturating_add(cycle as u16),
            "reload.example",
            DNS_QTYPE_A,
        )
        .unwrap();
        let received = forward_cached_proxy_dns_h3(
            &upstream,
            &query,
            Arc::clone(&forwarder),
            ProxyDnsRequestContext::from_timeout(std::time::Duration::from_secs(3)),
        )
        .await
        .unwrap();
        assert_eq!(received.len(), response.len());
        assert_eq!(&received[..2], &query[..2]);
        assert_eq!(cache.metrics.snapshot()["dnsTransportOwnersCurrent"], 1);

        let report = cache
            .shutdown(time::Instant::now() + RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE)
            .await;
        assert_eq!(report["status"], "pass", "cycle={cycle} report={report}");
        assert_eq!(cache.metrics.snapshot()["dnsTransportOwnersCurrent"], 0);
        assert_eq!(cache.metrics.snapshot()["dnsTransportOwnerBytesCurrent"], 0);
        let closed = quic_endpoint_metrics_snapshot(generation);
        assert_eq!(closed["liveStates"]["total"], 0, "cycle={cycle}");
        assert_eq!(closed["endpointDriverTasks"]["live"], 0, "cycle={cycle}");
        assert_eq!(closed["chargedBytes"]["total"], 0, "cycle={cycle}");
    }

    assert_eq!(server.connections(), 5);
    assert_eq!(server.requests(), 5);
    assert_eq!(socks.control_connections(), 5);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn generation_shutdown_closes_an_evicted_inflight_doh3_owner() {
    let generation = 7_361;
    let response = dns_test_response(1_500, 0x86);
    let server = DnsQuicTestServer::start_with_response_delay(
        DnsQuicTestProtocol::Doh3,
        vec![response],
        std::time::Duration::ZERO,
    )
    .await;
    let socks = Socks5UdpRelay::start().await;
    let proxy = socks5_dns_proxy(socks.address());
    let binding = dns_proxy_binding(Arc::clone(&proxy), generation);
    let upstream = parse_dns_upstream(
        0,
        "routed-doh3-eviction",
        &format!("h3://{}:443/dns-query", server.server_name()),
        server.address(),
        0,
    )
    .unwrap();
    let selection = ResidentDnsUpstreamSelection::Proxy {
        binding: binding.clone(),
    };
    let cache = test_resident_dns_forwarder_cache();
    let retained = cache
        .proxy_h3_forwarder(&upstream, server.address(), binding, &selection)
        .unwrap();
    retained.lock().await.client_config_override = Some(server.client_config());
    let query = build_dns_query_packet(0x3611, "evicted.example", DNS_QTYPE_A).unwrap();
    forward_cached_proxy_dns_h3(
        &upstream,
        &query,
        Arc::clone(&retained),
        ProxyDnsRequestContext::from_timeout(std::time::Duration::from_secs(3)),
    )
    .await
    .unwrap();

    let tcp = parse_dns_upstream(
        1,
        "tcp-fill",
        "tcp://127.0.0.1:53",
        "127.0.0.1:53".parse().unwrap(),
        0,
    )
    .unwrap();
    let direct = ResidentDnsUpstreamSelection::Direct { mark: 0 };
    for port in 1..=DNS_FORWARDER_CACHE_MAX_ENTRIES {
        cache
            .tcp_forwarder(
                &tcp,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port as u16),
                0,
                &direct,
            )
            .unwrap();
    }
    let evicted = cache.metrics.snapshot();
    assert_eq!(cache.len(), DNS_FORWARDER_CACHE_MAX_ENTRIES);
    assert_eq!(evicted["dnsTransportOwnersEvictedCurrent"], 1);
    assert_eq!(
        evicted["dnsTransportOwnersCurrent"],
        DNS_FORWARDER_CACHE_MAX_ENTRIES + 1
    );
    assert_eq!(
        quic_endpoint_metrics_snapshot(generation)["liveStates"]["ready"],
        1
    );

    let report = cache
        .shutdown(time::Instant::now() + RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE)
        .await;
    assert_eq!(report["status"], "pass", "{report}");
    assert_eq!(report["entriesClosed"], DNS_FORWARDER_CACHE_MAX_ENTRIES);
    assert_eq!(report["retiredOwnersClosed"], 1);
    assert_eq!(cache.metrics.snapshot()["dnsTransportOwnersCurrent"], 0);
    assert_eq!(
        cache.metrics.snapshot()["dnsTransportOwnersEvictedCurrent"],
        0
    );
    assert_eq!(cache.metrics.snapshot()["dnsTransportOwnerBytesCurrent"], 0);
    let closed = quic_endpoint_metrics_snapshot(generation);
    assert_eq!(closed["liveStates"]["total"], 0);
    assert_eq!(closed["endpointDriverTasks"]["live"], 0);
    assert_eq!(closed["chargedBytes"]["total"], 0);
    assert!(retained.lock().await.connection.is_none());
}
