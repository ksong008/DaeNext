use dae_resident_dns::runtime::transport::cache::*;

use super::*;
use crate::dns_runtime_tests::transport::test_support::{
    Socks5UdpRelay, dns_a_test_response, dns_proxy_binding, socks5_dns_proxy,
};
use dae_resident_core::RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE;
use dae_resident_plan::{ResidentProxyProtocolPlan, ResidentXhttpMode, ResidentXhttpSettingsPlan};
use std::cell::Cell;

fn policy_closed_http_proxy() -> Arc<ResidentProxyPlan> {
    let mut proxy = ResidentProxyPlan {
        graph_id: "resident-graph:redacted".to_owned(),
        graph_link_hash: "sha256:redacted".to_owned(),
        redacted_link_source: "source:<redacted>".to_owned(),
        protocol: "http-proxy",
        group_name: "proxy".to_owned(),
        group_policy: "fixed".to_owned(),
        node_tag: "redacted".to_owned(),
        server_host: Ipv4Addr::LOCALHOST.to_string(),
        server_port: 9,
        server_name: String::new(),
        alpn: Vec::new(),
        flow: String::new(),
        net: "tcp".to_owned(),
        stream_host: String::new(),
        stream_path: String::new(),
        grpc_mode: dae_outbound_core::GrpcMode::Gun,
        xhttp_download: None,
        xhttp_mode: ResidentXhttpMode::PacketUp,
        xhttp_settings: ResidentXhttpSettingsPlan::official_default(),
        xhttp_xmux: None,
        tls: "none".to_owned(),
        allow_insecure: false,
        tls_fragment: None,
        utls_fingerprint: None,
        ech: None,
        reality: None,
        handler: ResidentProxyProtocolPlan::HttpProxyTcp {
            username: String::new(),
            password: String::new(),
            transport: false,
            transport_host: String::new(),
            transport_path: String::new(),
        },
        execution: None,
        chain_parent: None,
        mark: 0,
        mptcp: false,
    };
    proxy.materialize_execution();
    Arc::new(proxy)
}

#[test]
fn tcp_udp_upstream_caches_udp_and_tcp_forwarders_separately() {
    let cache = test_resident_dns_forwarder_cache();
    let upstream = parse_dns_upstream(
        0,
        "mixed",
        "tcp+udp://127.0.0.1:53",
        "127.0.0.1:53".parse().unwrap(),
        0,
    )
    .unwrap();
    let target = "127.0.0.1:53".parse().unwrap();
    let selection = ResidentDnsUpstreamSelection::Direct { mark: 0 };

    cache
        .udp_forwarder(&upstream, target, 0, &selection)
        .unwrap();
    cache
        .tcp_forwarder(&upstream, target, 0, &selection)
        .unwrap();
    assert_eq!(cache.len(), 2);
}

#[test]
fn asis_udp_forwarder_is_reused_by_target_and_mark() {
    let cache = test_resident_dns_forwarder_cache();
    let target = "127.0.0.1:53".parse().unwrap();

    let first = cache.asis_udp_forwarder(target, 0x1234).unwrap();
    let second = cache.asis_udp_forwarder(target, 0x1234).unwrap();
    let different_mark = cache.asis_udp_forwarder(target, 0x5678).unwrap();

    assert!(Arc::ptr_eq(&first, &second));
    assert!(!Arc::ptr_eq(&first, &different_mark));
    assert_eq!(cache.len(), 2);
}

#[test]
fn cache_hit_reuses_key_strings_without_rewriting_lru_tree() {
    let cache = test_resident_dns_forwarder_cache();
    let upstream = parse_dns_upstream(
        0,
        "shared-key",
        "udp://127.0.0.1:53",
        "127.0.0.1:53".parse().unwrap(),
        0,
    )
    .unwrap();
    let target = "127.0.0.1:53".parse().unwrap();
    let selection = ResidentDnsUpstreamSelection::Direct { mark: 0 };

    cache
        .udp_forwarder(&upstream, target, 0, &selection)
        .unwrap();
    cache
        .udp_forwarder(&upstream, target, 0, &selection)
        .unwrap();
    cache
        .udp_forwarder(&upstream, target, 0, &selection)
        .unwrap();
    cache
        .udp_forwarder(&upstream, target, 0, &selection)
        .unwrap();

    let state = cache.state.lock().unwrap();
    assert_eq!(state.entries.len(), 1);
    assert_eq!(state.lru.len(), 1);
    let (indexed_tick, indexed_key) = state.lru.first().unwrap();
    let entry = state.entries.get(indexed_key).unwrap();
    assert!(entry.last_used > *indexed_tick);
    assert!(Arc::ptr_eq(
        &indexed_key.authority,
        &upstream.target.authority
    ));
    assert!(Arc::ptr_eq(&indexed_key.path, &upstream.path));
}

#[test]
fn policy_closed_proxy_dns_udp_is_rejected_before_cache_or_actor_creation() {
    let cache = test_resident_dns_forwarder_cache();
    let target = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), DNS_DEFAULT_PORT);
    let upstream = parse_dns_upstream(0, "closed", &format!("udp://{target}"), target, 0).unwrap();
    let proxy = policy_closed_http_proxy();
    let binding = dns_proxy_binding(Arc::clone(&proxy), 0);
    let selection = ResidentDnsUpstreamSelection::Proxy {
        binding: binding.clone(),
    };

    let err = cache
        .proxy_udp_forwarder(&upstream, target, binding, &selection)
        .err()
        .expect("policy-closed DNS UDP must be rejected");

    assert!(err.contains("typed UDP agreement"), "{err}");
    assert!(err.contains("http-connect-udp-protocol-closed"), "{err}");
    assert_eq!(cache.len(), 0);
    assert_eq!(cache.metrics.snapshot()["dnsUdpActorsOpened"], 0);
}

#[test]
fn cache_hit_does_not_construct_a_discarded_forwarder() {
    let cache = test_resident_dns_forwarder_cache();
    let upstream = parse_dns_upstream(
        0,
        "lazy",
        "tcp://127.0.0.1:53",
        "127.0.0.1:53".parse().unwrap(),
        0,
    )
    .unwrap();
    let target = "127.0.0.1:53".parse().unwrap();
    let selection = ResidentDnsUpstreamSelection::Direct { mark: 0 };
    let key = routed_dns_forwarder_key(
        &upstream,
        target,
        0,
        &selection,
        ResidentDnsForwarderTransport::Tcp,
    );
    let builds = Cell::new(0_usize);
    let build = || {
        builds.set(builds.get() + 1);
        Ok(Arc::new(ResidentDnsTcpForwarder {
            owner_observation: ResidentDnsTransportOwnerObservation::new(
                Arc::clone(&cache.metrics),
                std::mem::size_of::<ResidentDnsTcpForwarder>(),
            ),
            upstream: upstream.clone(),
            target,
            mark: 0,
            connection_kind: ResidentDnsTcpConnectionKind::Direct,
            connection_limit: cache.resources.tcp_connections_per_route(),
            request_limit: cache.resources.tcp_requests_per_connection(),
            connections: AsyncMutex::new(Vec::new()),
            open_lock: AsyncMutex::new(()),
            closing: std::sync::atomic::AtomicBool::new(false),
        }))
    };
    let extract = |kind: &ResidentDnsForwarderEntryKind| match kind {
        ResidentDnsForwarderEntryKind::Tcp(forwarder) => Some(Arc::clone(forwarder)),
        _ => None,
    };

    let first = cache
        .get_or_insert_forwarder_lazy(
            key.clone(),
            "TCP",
            build,
            extract,
            ResidentDnsForwarderEntryKind::Tcp,
        )
        .unwrap();
    let second = cache
        .get_or_insert_forwarder_lazy(
            key,
            "TCP",
            build,
            extract,
            ResidentDnsForwarderEntryKind::Tcp,
        )
        .unwrap();

    assert!(Arc::ptr_eq(&first, &second));
    assert_eq!(builds.get(), 1);
}

#[test]
fn concurrent_misses_share_one_inserted_forwarder() {
    let cache = Arc::new(test_resident_dns_forwarder_cache());
    let upstream = parse_dns_upstream(
        0,
        "concurrent",
        "udp://127.0.0.1:53",
        "127.0.0.1:53".parse().unwrap(),
        0,
    )
    .unwrap();
    let target = "127.0.0.1:53".parse().unwrap();
    let selection = ResidentDnsUpstreamSelection::Direct { mark: 0 };

    // All workers miss at the same time (barrier) so several of them build
    // outside the lock; the double-checked insertion must still end up with
    // exactly one entry and every caller must receive the same forwarder.
    const WORKERS: usize = 8;
    let barrier = Arc::new(std::sync::Barrier::new(WORKERS));
    let handles = (0..WORKERS)
        .map(|_| {
            let cache = Arc::clone(&cache);
            let upstream = upstream.clone();
            let selection = selection.clone();
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                cache
                    .udp_forwarder(&upstream, target, 0, &selection)
                    .unwrap()
            })
        })
        .collect::<Vec<_>>();
    let forwarders = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect::<Vec<_>>();

    assert!(
        forwarders
            .iter()
            .all(|forwarder| Arc::ptr_eq(&forwarders[0], forwarder)),
        "all concurrent callers must receive the same forwarder"
    );
    assert_eq!(
        cache.len(),
        1,
        "double-checked insert must win exactly once"
    );
}

#[test]
fn evicted_inflight_quic_owner_remains_charged_until_the_last_arc_drops() {
    let cache = test_resident_dns_forwarder_cache();
    let metrics = Arc::clone(&cache.metrics);
    let quic = parse_dns_upstream(
        0,
        "quic-owner",
        "quic://127.0.0.1:853",
        "127.0.0.1:53".parse().unwrap(),
        0,
    )
    .unwrap();
    let retained = cache.quic_forwarder(&quic, 0).unwrap();
    assert_eq!(cache.metrics.snapshot()["dnsTransportOwnersCurrent"], 1);

    let tcp = parse_dns_upstream(
        1,
        "tcp-fill",
        "tcp://127.0.0.1:53",
        "127.0.0.1:53".parse().unwrap(),
        0,
    )
    .unwrap();
    let selection = ResidentDnsUpstreamSelection::Direct { mark: 0 };
    for port in 1..=DNS_FORWARDER_CACHE_MAX_ENTRIES {
        let target = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port as u16);
        cache.tcp_forwarder(&tcp, target, 0, &selection).unwrap();
    }

    let evicted = cache.metrics.snapshot();
    assert_eq!(cache.len(), DNS_FORWARDER_CACHE_MAX_ENTRIES);
    assert_eq!(
        evicted["dnsTransportOwnersCurrent"],
        DNS_FORWARDER_CACHE_MAX_ENTRIES + 1
    );
    assert_eq!(evicted["dnsTransportOwnersEvictedCurrent"], 1);
    let evicted_bytes = evicted["dnsTransportOwnerBytesCurrent"].as_u64().unwrap();
    assert!(evicted_bytes > 0);
    drop(retained);
    let released = cache.metrics.snapshot();
    assert_eq!(
        released["dnsTransportOwnersCurrent"],
        DNS_FORWARDER_CACHE_MAX_ENTRIES
    );
    assert_eq!(released["dnsTransportOwnersEvictedCurrent"], 0);
    assert!(released["dnsTransportOwnerBytesCurrent"].as_u64().unwrap() < evicted_bytes);
    drop(cache);
    assert_eq!(metrics.snapshot()["dnsTransportOwnersCurrent"], 0);
    assert_eq!(metrics.snapshot()["dnsTransportOwnerBytesCurrent"], 0);
}

#[test]
fn retired_forwarders_are_scanned_after_evictions_even_when_all_are_live() {
    let cache = test_resident_dns_forwarder_cache();
    let upstream = parse_dns_upstream(
        0,
        "retired-scan",
        "quic://127.0.0.1:853",
        "127.0.0.1:853".parse().unwrap(),
        0,
    )
    .unwrap();
    let mut held = Vec::new();
    for mark in 0..DNS_FORWARDER_CACHE_MAX_ENTRIES + 31 {
        held.push(cache.quic_forwarder(&upstream, mark as u32).unwrap());
    }
    {
        let state = cache.state.lock().unwrap();
        assert_eq!(state.retired_scan_pending, 31);
        assert_eq!(state.retired.len(), 31);
    }
    held.drain(..31);
    held.push(
        cache
            .quic_forwarder(&upstream, (DNS_FORWARDER_CACHE_MAX_ENTRIES + 31) as u32)
            .unwrap(),
    );
    let state = cache.state.lock().unwrap();
    assert_eq!(state.retired_scan_pending, 0);
    assert_eq!(state.retired.len(), 1);
    assert!(state.retired[0].is_alive());
}

#[tokio::test(flavor = "current_thread")]
async fn proxied_quic_and_h3_forwarders_reuse_separate_complete_keys() {
    let cache = test_resident_dns_forwarder_cache();
    let target = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 853);
    let doq = parse_dns_upstream(
        0,
        "proxy-doq",
        "quic://127.0.0.1:853",
        "127.0.0.1:53".parse().unwrap(),
        0,
    )
    .unwrap();
    let doh3 = parse_dns_upstream(
        1,
        "proxy-doh3",
        "h3://127.0.0.1:443/dns-query",
        "127.0.0.1:53".parse().unwrap(),
        0,
    )
    .unwrap();
    let proxy = policy_closed_http_proxy();
    let binding = dns_proxy_binding(Arc::clone(&proxy), 0);
    let selection = ResidentDnsUpstreamSelection::Proxy {
        binding: binding.clone(),
    };

    let first_doq = cache
        .proxy_quic_forwarder(&doq, target, binding.clone(), &selection)
        .unwrap();
    let second_doq = cache
        .proxy_quic_forwarder(&doq, target, binding.clone(), &selection)
        .unwrap();
    let first_doh3 = cache
        .proxy_h3_forwarder(&doh3, target, binding.clone(), &selection)
        .unwrap();
    let second_doh3 = cache
        .proxy_h3_forwarder(&doh3, target, binding, &selection)
        .unwrap();

    assert!(Arc::ptr_eq(&first_doq, &second_doq));
    assert!(Arc::ptr_eq(&first_doh3, &second_doh3));
    assert_eq!(cache.len(), 2);
    assert_eq!(cache.metrics.snapshot()["dnsTransportOwnersCurrent"], 2);
    drop(first_doq);
    drop(second_doq);
    drop(first_doh3);
    drop(second_doh3);
    let report = cache
        .shutdown(time::Instant::now() + RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE)
        .await;
    assert_eq!(report["status"], "pass");
    assert_eq!(cache.metrics.snapshot()["dnsTransportOwnersCurrent"], 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn overlapping_background_dns_health_leases_share_then_retire_forwarder() {
    let upstream = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let target = upstream.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let mut query = vec![0_u8; DNS_RESPONSE_READ_LIMIT];
        for _ in 0..2 {
            let (read, peer) = upstream.recv_from(&mut query).await.unwrap();
            let response = dns_a_test_response(&query[..read], [192, 0, 2, 80]);
            upstream.send_to(&response, peer).await.unwrap();
        }
    });
    let socks = Socks5UdpRelay::start().await;
    let proxy = socks5_dns_proxy(socks.address());
    let binding = dns_proxy_binding(Arc::clone(&proxy), 7_370);
    let cache = Arc::new(test_resident_dns_forwarder_cache());
    let first = cache
        .acquire_health_proxy_udp_forwarder(target, binding.clone())
        .await
        .unwrap();
    let second = cache
        .acquire_health_proxy_udp_forwarder(target, binding)
        .await
        .unwrap();
    assert!(Arc::ptr_eq(&first.forwarder(), &second.forwarder()));
    assert_eq!(cache.len(), 0);
    assert_eq!(cache.health_len(), 1);
    assert_eq!(
        cache.metrics.snapshot()["proxyDnsHealthForwardersCurrent"],
        1
    );
    assert_eq!(cache.metrics.snapshot()["proxyDnsHealthLeasesCurrent"], 2);

    dae_resident_dns::probe_resident_proxy_dns_udp_with_forwarder_async(
        first.forwarder(),
        "health.example",
    )
    .await
    .unwrap();
    dae_resident_dns::probe_resident_proxy_dns_udp_with_forwarder_async(
        second.forwarder(),
        "health.example",
    )
    .await
    .unwrap();
    server.await.unwrap();

    let active = cache.metrics.snapshot();
    assert_eq!(active["dnsTransportOwnersCurrent"], 1);
    assert_eq!(active["proxyDnsUdpExecutorsOpened"], 1);
    assert_eq!(active["proxyDnsUdpExecutorsReused"], 1);
    assert_eq!(socks.control_connections(), 1);
    first.release().await.unwrap();
    assert_eq!(cache.health_len(), 1);
    assert_eq!(cache.metrics.snapshot()["proxyDnsHealthLeasesCurrent"], 1);
    second.release().await.unwrap();
    assert_eq!(cache.health_len(), 0);
    assert_eq!(
        cache.metrics.snapshot()["proxyDnsHealthForwardersCurrent"],
        0
    );
    assert_eq!(cache.metrics.snapshot()["proxyDnsHealthLeasesCurrent"], 0);
    assert_eq!(cache.metrics.snapshot()["dnsTransportOwnersCurrent"], 0);
    assert_eq!(cache.metrics.snapshot()["dnsTransportOwnerBytesCurrent"], 0);
    assert_eq!(
        cache.metrics.snapshot()["dnsUdpActorsOpened"],
        cache.metrics.snapshot()["dnsUdpActorsClosed"]
    );
    let report = cache
        .shutdown(time::Instant::now() + RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE)
        .await;
    assert_eq!(report["status"], "pass", "{report}");
    assert_eq!(report["entriesClosed"], 0);
    assert_eq!(report["healthEntriesClosed"], 0);
    assert_eq!(cache.metrics.snapshot()["dnsTransportOwnersCurrent"], 0);
    assert_eq!(cache.metrics.snapshot()["dnsTransportOwnerBytesCurrent"], 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_background_dns_health_releases_its_actor_and_executor() {
    let upstream = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let target = upstream.local_addr().unwrap();
    let (received_tx, received_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let mut query = vec![0_u8; DNS_RESPONSE_READ_LIMIT];
        let _ = upstream.recv_from(&mut query).await.unwrap();
        let _ = received_tx.send(());
        std::future::pending::<()>().await;
    });
    let socks = Socks5UdpRelay::start().await;
    let proxy = socks5_dns_proxy(socks.address());
    let binding = dns_proxy_binding(proxy, 7_371);
    let cache = Arc::new(test_resident_dns_forwarder_cache());
    let lease = cache
        .acquire_health_proxy_udp_forwarder(target, binding)
        .await
        .unwrap();
    let probe = tokio::spawn(async move {
        let result = dae_resident_dns::probe_resident_proxy_dns_udp_with_forwarder_async(
            lease.forwarder(),
            "cancelled-health.example",
        )
        .await;
        let _ = lease.release().await;
        result
    });
    tokio::time::timeout(std::time::Duration::from_secs(2), received_rx)
        .await
        .unwrap()
        .unwrap();
    probe.abort();
    let _ = probe.await;

    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        loop {
            let snapshot = cache.metrics.snapshot();
            if cache.health_len() == 0
                && snapshot["proxyDnsHealthForwardersCurrent"] == 0
                && snapshot["proxyDnsHealthLeasesCurrent"] == 0
                && snapshot["dnsTransportOwnersCurrent"] == 0
                && snapshot["dnsUdpActorsOpened"] == snapshot["dnsUdpActorsClosed"]
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    server.abort();
    let _ = server.await;
}

#[tokio::test(flavor = "current_thread")]
async fn cache_shutdown_closes_direct_udp_actors_and_rejects_new_entries() {
    let upstream = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let target = upstream.local_addr().unwrap();
    let cache = test_resident_dns_forwarder_cache();
    let handle = cache.udp_executor.open_handle(target, 0).await.unwrap();
    let query = build_dns_query_packet(0x5151, "cache-shutdown.example", DNS_QTYPE_A).unwrap();
    let request_handle = handle.clone();
    let request = tokio::spawn(async move { request_handle.exchange_once(&query).await });
    let mut received = vec![0_u8; 512];
    upstream.recv_from(&mut received).await.unwrap();

    let report = cache
        .shutdown(time::Instant::now() + RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE)
        .await;
    let request_error = request.await.unwrap().unwrap_err();
    let second = cache
        .shutdown(time::Instant::now() + RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE)
        .await;
    let upstream_model =
        parse_dns_upstream(0, "closed", &format!("udp://{target}"), target, 0).unwrap();
    let selection = ResidentDnsUpstreamSelection::Direct { mark: 0 };
    let reopen_error = match cache.udp_forwarder(&upstream_model, target, 0, &selection) {
        Ok(_) => panic!("closed DNS forwarder cache accepted a new entry"),
        Err(err) => err,
    };

    assert_eq!(report["status"], "pass");
    assert!(request_error.contains("shutting down"), "{request_error}");
    assert!(handle.is_closed());
    assert_eq!(second["alreadyClosed"], true);
    assert!(reopen_error.contains("closing"), "{reopen_error}");
}

#[tokio::test(flavor = "current_thread")]
async fn https_shutdown_does_not_report_an_h2_lock_timeout_as_joined() {
    let cache = test_resident_dns_forwarder_cache();
    let target = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443);
    let upstream = parse_dns_upstream(
        0,
        "https-lock",
        "https://127.0.0.1:443/dns-query",
        target,
        0,
    )
    .unwrap();
    let selection = ResidentDnsUpstreamSelection::Direct { mark: 0 };
    let forwarder = cache
        .https_forwarder(&upstream, target, 0, &selection)
        .unwrap();
    let h2_guard = forwarder.h2.lock().await;

    let report = shutdown_dns_https_forwarder(Arc::clone(&forwarder), time::Instant::now()).await;

    assert_eq!(report["status"], "fail");
    assert_eq!(report["h2LockAcquired"], false);
    assert_eq!(report["h2DriverJoined"], true);
    drop(h2_guard);
}

#[tokio::test(flavor = "current_thread")]
async fn cache_shutdown_uses_one_deadline_for_every_forwarder() {
    let cache = test_resident_dns_forwarder_cache();
    let upstream = parse_dns_upstream(
        0,
        "tcp-deadline",
        "tcp://127.0.0.1:53",
        "127.0.0.1:53".parse().unwrap(),
        0,
    )
    .unwrap();
    let selection = ResidentDnsUpstreamSelection::Direct { mark: 0 };
    let first = cache
        .tcp_forwarder(
            &upstream,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53),
            0,
            &selection,
        )
        .unwrap();
    let second = cache
        .tcp_forwarder(
            &upstream,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 54),
            0,
            &selection,
        )
        .unwrap();
    let first_connections = first.connections.lock().await;
    let second_connections = second.connections.lock().await;
    let started = std::time::Instant::now();

    let report = cache
        .shutdown(time::Instant::now() + std::time::Duration::from_millis(5))
        .await;

    assert_eq!(report["status"], "fail");
    assert_eq!(report["forwardersFailed"], 2);
    assert!(started.elapsed() < std::time::Duration::from_millis(100));
    let forwarders = report["forwarders"].as_array().unwrap();
    assert_eq!(forwarders.len(), 2);
    assert!(forwarders.iter().all(|forwarder| {
        forwarder["status"] == "fail" && forwarder["connectionsLocked"] == false
    }));
    drop(second_connections);
    drop(first_connections);
}
