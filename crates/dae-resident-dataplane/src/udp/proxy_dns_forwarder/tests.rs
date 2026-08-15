use super::*;
use crate::RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE;
use crate::plan::ResidentXhttpSettingsPlan;
use crate::udp::ResidentUdpPayloadAdmission;
use dae_dns::DnsPacketView;
use dae_outbound::shadowsocks::{decode_udp_packet, encode_udp_packet};
use std::{
    net::{IpAddr, Ipv4Addr},
    time::Duration,
};

const TEST_CIPHER: &str = "aes-128-gcm";
const TEST_PASSWORD: &str = "fixture-password";
const TEST_DNS_QTYPE_A: u16 = 1;

fn proxy_plan(server: SocketAddr) -> ResidentProxyPlan {
    let mut proxy = ResidentProxyPlan {
        graph_id: "resident-graph:redacted".to_owned(),
        graph_link_hash: "sha256:redacted".to_owned(),
        redacted_link_source: "source:<redacted>".to_owned(),
        protocol: "ss",
        group_name: "proxy".to_owned(),
        group_policy: "fixed".to_owned(),
        node_tag: "redacted".to_owned(),
        server_host: server.ip().to_string(),
        server_port: server.port(),
        server_name: String::new(),
        alpn: Vec::new(),
        flow: String::new(),
        net: "tcp".to_owned(),
        stream_host: String::new(),
        stream_path: String::new(),
        grpc_mode: GrpcMode::Gun,
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
        handler: ResidentProxyProtocolPlan::ShadowsocksAeadTcp {
            cipher: TEST_CIPHER.to_owned(),
            password: TEST_PASSWORD.to_owned(),
            salt_len: 16,
        },
        execution: None,
        chain_parent: None,
        mark: 0,
        mptcp: false,
    };
    proxy.materialize_execution();
    proxy
}

fn juicity_proxy_plan(server: SocketAddr) -> ResidentProxyPlan {
    let mut proxy = proxy_plan(server);
    proxy.protocol = "juicity";
    proxy.net = "quic".to_owned();
    proxy.handler = ResidentProxyProtocolPlan::JuicityQuicTcp {
        uuid: "00000000-0000-0000-0000-000000000001".to_owned(),
        password: "fixture-password".to_owned(),
        allow_insecure: true,
        congestion: dae_outbound::juicity::JuicityCongestionController::Bbr,
        pinned_certchain_sha256: String::new(),
    };
    proxy.materialize_execution();
    proxy
}

fn policy_closed_proxy_plan(server: SocketAddr) -> ResidentProxyPlan {
    let mut proxy = proxy_plan(server);
    proxy.protocol = "http-proxy";
    proxy.handler = ResidentProxyProtocolPlan::HttpProxyTcp {
        username: String::new(),
        password: String::new(),
        transport: false,
        transport_host: String::new(),
        transport_path: String::new(),
    };
    proxy.materialize_execution();
    proxy
}

#[test]
fn policy_closed_proxy_cannot_construct_a_dns_udp_forwarder() {
    let runtime = ResidentDnsUdpRuntimeConfig::standalone();
    let metrics = Arc::new(ResidentDataplaneMetrics::default());
    let actor_executor = Arc::new(ResidentDnsUdpActorExecutor::new(
        runtime.clone(),
        Arc::clone(&metrics),
    ));
    let err = ResidentProxyDnsUdpForwarder::new(
        Arc::new(policy_closed_proxy_plan(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            9,
        ))),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53),
        runtime,
        Arc::clone(&metrics),
        actor_executor,
    )
    .err()
    .expect("policy-closed factory must reject DNS UDP forwarder construction");

    assert!(err.contains("typed UDP agreement"), "{err}");
    assert!(err.contains("http-connect-udp-protocol-closed"), "{err}");
    assert_eq!(metrics.snapshot()["dnsUdpActorsOpened"], 0);
}

#[tokio::test(flavor = "current_thread")]
async fn proxy_dns_udp_forwarder_uses_bounded_generation_owned_actors() {
    let mut runtime = ResidentDnsUdpRuntimeConfig::standalone();
    runtime.proxy_actor_limit = 3;
    runtime.actor_worker_threads = 1;
    let metrics = Arc::new(ResidentDataplaneMetrics::default());
    let actor_executor = Arc::new(ResidentDnsUdpActorExecutor::new(
        runtime.clone(),
        Arc::clone(&metrics),
    ));
    let forwarder = ResidentProxyDnsUdpForwarder::new(
        Arc::new(proxy_plan(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            9,
        ))),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53),
        runtime,
        Arc::clone(&metrics),
        Arc::clone(&actor_executor),
    )
    .unwrap();

    assert_eq!(forwarder.actor_count(), 1);
    let first = forwarder.actor_handle(0).await.unwrap();
    let reused = forwarder.actor_handle(0).await.unwrap();
    assert!(!first.is_closed());
    assert!(!reused.is_closed());
    assert_eq!(metrics.snapshot()["dnsUdpActorsOpened"], 1);

    let deadline = time::Instant::now() + RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE;
    let report = forwarder.shutdown(deadline).await;
    let executor_report = actor_executor.shutdown(deadline).await;
    let exchange_error = forwarder.exchange(&[0_u8; 12]).await.unwrap_err();

    assert_eq!(report["status"], "pass");
    assert_eq!(report["actorsOpened"], 1);
    assert_eq!(report["actorsClosed"], 1);
    assert_eq!(report["actorMode"], "multiplexed-session");
    assert_eq!(executor_report["status"], "pass");
    assert!(first.is_closed());
    assert!(exchange_error.contains("closing"), "{exchange_error}");
    let snapshot = metrics.snapshot();
    assert_eq!(
        snapshot["dnsUdpActorsOpened"],
        snapshot["dnsUdpActorsClosed"]
    );
}

#[tokio::test(flavor = "current_thread")]
async fn request_scoped_proxy_dns_udp_uses_the_profile_actor_limit() {
    let mut runtime = ResidentDnsUdpRuntimeConfig::standalone();
    runtime.proxy_actor_limit = 3;
    runtime.actor_worker_threads = 1;
    let metrics = Arc::new(ResidentDataplaneMetrics::default());
    let actor_executor = Arc::new(ResidentDnsUdpActorExecutor::new(
        runtime.clone(),
        Arc::clone(&metrics),
    ));
    let forwarder = ResidentProxyDnsUdpForwarder::new(
        Arc::new(juicity_proxy_plan(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            9,
        ))),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53),
        runtime,
        metrics,
        actor_executor,
    )
    .unwrap();

    assert_eq!(forwarder.actor_count(), 3);
    assert!(forwarder.request_scoped_actor_pool);
    let (first, first_guard) = forwarder.acquire_actor_slot();
    let (second, second_guard) = forwarder.acquire_actor_slot();
    assert_ne!(first, second);
    drop(second_guard);
    drop(first_guard);
}

#[tokio::test(flavor = "current_thread")]
async fn expired_proxy_dns_request_is_rejected_before_actor_creation() {
    let runtime = ResidentDnsUdpRuntimeConfig::standalone();
    let payload_admission = runtime.payload_admission.clone();
    let metrics = Arc::new(ResidentDataplaneMetrics::default());
    let actor_executor = Arc::new(ResidentDnsUdpActorExecutor::new(
        runtime.clone(),
        Arc::clone(&metrics),
    ));
    let forwarder = ResidentProxyDnsUdpForwarder::new(
        Arc::new(proxy_plan(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            9,
        ))),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53),
        runtime,
        Arc::clone(&metrics),
        Arc::clone(&actor_executor),
    )
    .unwrap();

    let error = forwarder
        .exchange_with_context(
            &[0_u8; 12],
            ProxyDnsRequestContext::from_deadline(time::Instant::now()),
        )
        .await
        .unwrap_err();

    assert_eq!(error.failure(), ProxyDnsRequestFailure::Deadline);
    assert_eq!(error.stage(), ProxyDnsRequestStage::Retry);
    let snapshot = metrics.snapshot();
    assert_eq!(snapshot["dnsUdpActorsOpened"], 0);
    assert_eq!(snapshot["proxyDnsUdpQueuedCurrent"], 0);
    assert_eq!(snapshot["proxyDnsUdpPendingCurrent"], 0);
    assert_eq!(payload_admission.current(), 0);

    let deadline = time::Instant::now() + RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE;
    assert_eq!(forwarder.shutdown(deadline).await["status"], "pass");
    assert_eq!(actor_executor.shutdown(deadline).await["status"], "pass");
}

#[tokio::test(flavor = "current_thread")]
async fn pending_metadata_admission_fails_before_the_network_executor_opens() {
    let query = dns_query(0x5001, "metadata-limit.example");
    let mut runtime = ResidentDnsUdpRuntimeConfig::standalone();
    runtime.proxy_actor_limit = 1;
    runtime.actor_worker_threads = 1;
    runtime.attempts = 1;
    runtime.payload_admission = ResidentUdpPayloadAdmission::new(0, query.len() + 1);
    let payload_admission = runtime.payload_admission.clone();
    let metrics = Arc::new(ResidentDataplaneMetrics::default());
    let actor_executor = Arc::new(ResidentDnsUdpActorExecutor::new(
        runtime.clone(),
        Arc::clone(&metrics),
    ));
    let forwarder = ResidentProxyDnsUdpForwarder::new(
        Arc::new(proxy_plan(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            9,
        ))),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53),
        runtime,
        Arc::clone(&metrics),
        Arc::clone(&actor_executor),
    )
    .unwrap();

    let error = forwarder
        .exchange_with_context(
            &query,
            ProxyDnsRequestContext::from_timeout(Duration::from_secs(1)),
        )
        .await
        .unwrap_err();

    assert_eq!(error.stage(), ProxyDnsRequestStage::Pending);
    assert_eq!(error.failure(), ProxyDnsRequestFailure::Capacity);
    assert!(
        error
            .to_string()
            .contains("pending metadata byte limit reached"),
        "{error}"
    );
    let snapshot = metrics.snapshot();
    assert_eq!(snapshot["proxyDnsUdpExecutorsOpened"], 0);
    assert_eq!(snapshot["proxyDnsUdpQueuedCurrent"], 0);
    assert_eq!(snapshot["proxyDnsUdpPendingCurrent"], 0);
    assert_eq!(snapshot["proxyDnsUdpPendingMetadataBytesCurrent"], 0);
    assert_eq!(payload_admission.current(), 0);

    let deadline = time::Instant::now() + RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE;
    assert_eq!(forwarder.shutdown(deadline).await["status"], "pass");
    assert_eq!(actor_executor.shutdown(deadline).await["status"], "pass");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn abandoned_queued_proxy_dns_request_does_not_reach_the_executor() {
    let upstream = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let (release_server, wait_for_release) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let _ = wait_for_release.await;
        drop(upstream);
    });

    let mut runtime = ResidentDnsUdpRuntimeConfig::standalone();
    runtime.proxy_actor_limit = 1;
    runtime.actor_worker_threads = 1;
    runtime.pending_limit = 1;
    runtime.queue_depth = 2;
    runtime.attempts = 1;
    let payload_admission = runtime.payload_admission.clone();
    let metrics = Arc::new(ResidentDataplaneMetrics::default());
    let actor_executor = Arc::new(ResidentDnsUdpActorExecutor::new(
        runtime.clone(),
        Arc::clone(&metrics),
    ));
    let forwarder = Arc::new(
        ResidentProxyDnsUdpForwarder::new(
            Arc::new(proxy_plan(upstream_addr)),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53),
            runtime,
            Arc::clone(&metrics),
            Arc::clone(&actor_executor),
        )
        .unwrap(),
    );

    let first_forwarder = Arc::clone(&forwarder);
    let first = tokio::spawn(async move {
        let query = dns_query(0x5101, "pending.example");
        first_forwarder
            .exchange_with_context(
                &query,
                ProxyDnsRequestContext::from_timeout(Duration::from_secs(5)),
            )
            .await
    });
    time::timeout(Duration::from_secs(1), async {
        while metrics.snapshot()["proxyDnsUdpPendingCurrent"] != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();

    let second_forwarder = Arc::clone(&forwarder);
    let second = tokio::spawn(async move {
        second_forwarder
            .exchange_with_context(
                &[0_u8],
                ProxyDnsRequestContext::from_timeout(Duration::from_secs(5)),
            )
            .await
    });
    time::timeout(Duration::from_secs(1), async {
        while metrics.snapshot()["proxyDnsUdpQueuedCurrent"] != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();

    second.abort();
    let _ = second.await;
    first.abort();
    let _ = first.await;
    time::timeout(Duration::from_secs(1), async {
        loop {
            let snapshot = metrics.snapshot();
            if snapshot["proxyDnsUdpQueuedCurrent"] == 0
                && snapshot["proxyDnsUdpPendingCurrent"] == 0
                && snapshot["proxyDnsUdpAbandoned"].as_u64().unwrap_or(0) >= 2
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();

    let snapshot = metrics.snapshot();
    assert_eq!(snapshot["proxyDnsUdpExecutorsOpened"], 1);
    assert_eq!(snapshot["proxyDnsUdpExecutorsReused"], 0);
    assert_eq!(snapshot["proxyDnsUdpQueuedBytesCurrent"], 0);
    assert_eq!(snapshot["proxyDnsUdpPendingBytesCurrent"], 0);
    assert_eq!(payload_admission.current(), 0);
    let _ = release_server.send(());
    server.await.unwrap();

    let deadline = time::Instant::now() + RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE;
    assert_eq!(forwarder.shutdown(deadline).await["status"], "pass");
    assert_eq!(actor_executor.shutdown(deadline).await["status"], "pass");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn second_routed_proxy_dns_attempt_cannot_restart_the_caller_deadline() {
    let upstream = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let mut runtime = ResidentDnsUdpRuntimeConfig::standalone();
    runtime.proxy_actor_limit = 1;
    runtime.actor_worker_threads = 1;
    runtime.attempts = 1;
    let metrics = Arc::new(ResidentDataplaneMetrics::default());
    let actor_executor = Arc::new(ResidentDnsUdpActorExecutor::new(
        runtime.clone(),
        Arc::clone(&metrics),
    ));
    let forwarder = ResidentProxyDnsUdpForwarder::new(
        Arc::new(proxy_plan(upstream_addr)),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53),
        runtime,
        Arc::clone(&metrics),
        Arc::clone(&actor_executor),
    )
    .unwrap();
    let context = ProxyDnsRequestContext::from_timeout(Duration::from_millis(20));

    let first_error = forwarder
        .exchange_with_context(&dns_query(0x5201, "first-upstream.example"), context)
        .await
        .unwrap_err();
    assert_eq!(first_error.failure(), ProxyDnsRequestFailure::Deadline);
    let executors_opened = metrics.snapshot()["proxyDnsUdpExecutorsOpened"]
        .as_u64()
        .unwrap();
    assert_eq!(executors_opened, 1);

    let second_error = forwarder
        .exchange_with_context(&dns_query(0x5202, "second-upstream.example"), context)
        .await
        .unwrap_err();
    assert_eq!(second_error.failure(), ProxyDnsRequestFailure::Deadline);
    assert_eq!(second_error.stage(), ProxyDnsRequestStage::Retry);
    assert_eq!(
        metrics.snapshot()["proxyDnsUdpExecutorsOpened"]
            .as_u64()
            .unwrap(),
        executors_opened
    );

    drop(upstream);
    let deadline = time::Instant::now() + RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE;
    assert_eq!(forwarder.shutdown(deadline).await["status"], "pass");
    assert_eq!(actor_executor.shutdown(deadline).await["status"], "pass");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_proxy_dns_udp_actor_multiplexes_out_of_order_responses_without_head_of_line_waiting() {
    let upstream = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let (second_sent, second_response_sent) = tokio::sync::oneshot::channel();
    let (release_first, first_release) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let mut first_wire = vec![0_u8; 4096];
        let mut second_wire = vec![0_u8; 4096];
        let (first_len, peer) = upstream.recv_from(&mut first_wire).await.unwrap();
        let (second_len, second_peer) = upstream.recv_from(&mut second_wire).await.unwrap();
        assert_eq!(peer, second_peer);
        let first =
            decode_udp_packet(TEST_CIPHER, TEST_PASSWORD, &first_wire[..first_len]).unwrap();
        let second =
            decode_udp_packet(TEST_CIPHER, TEST_PASSWORD, &second_wire[..second_len]).unwrap();
        let first_response = dns_a_response_for_query(&first.payload, [192, 0, 2, 1]);
        let second_response = dns_a_response_for_query(&second.payload, [192, 0, 2, 2]);
        let first_wire = encode_udp_packet(
            TEST_CIPHER,
            TEST_PASSWORD,
            &[0x31; 16],
            &first.target,
            &first_response,
        )
        .unwrap();
        let second_wire = encode_udp_packet(
            TEST_CIPHER,
            TEST_PASSWORD,
            &[0x32; 16],
            &second.target,
            &second_response,
        )
        .unwrap();
        upstream.send_to(&second_wire, peer).await.unwrap();
        let _ = second_sent.send(());
        let _ = first_release.await;
        upstream.send_to(&first_wire, peer).await.unwrap();
    });
    let mut runtime = ResidentDnsUdpRuntimeConfig::standalone();
    runtime.proxy_actor_limit = 1;
    runtime.actor_worker_threads = 1;
    runtime.attempts = 1;
    let payload_admission = runtime.payload_admission.clone();
    let metrics = Arc::new(ResidentDataplaneMetrics::default());
    let actor_executor = Arc::new(ResidentDnsUdpActorExecutor::new(
        runtime.clone(),
        Arc::clone(&metrics),
    ));
    let forwarder = Arc::new(
        ResidentProxyDnsUdpForwarder::new(
            Arc::new(proxy_plan(upstream_addr)),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53),
            runtime,
            Arc::clone(&metrics),
            Arc::clone(&actor_executor),
        )
        .unwrap(),
    );
    let first = dns_query(0x1111, "first.example");
    let second = dns_query(0x2222, "second.example");
    let first_len = first.len();
    let first_forwarder = Arc::clone(&forwarder);
    let first_response = tokio::spawn(async move { first_forwarder.exchange(&first).await });
    time::timeout(Duration::from_secs(1), async {
        while metrics.snapshot()["proxyDnsUdpPendingCurrent"] != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();

    let second_forwarder = Arc::clone(&forwarder);
    let second_response = tokio::spawn(async move { second_forwarder.exchange(&second).await });
    second_response_sent.await.unwrap();
    let second_response = time::timeout(Duration::from_secs(1), second_response)
        .await
        .unwrap()
        .unwrap()
        .unwrap();

    assert_eq!(&second_response[0..2], &0x2222_u16.to_be_bytes());
    time::timeout(Duration::from_secs(1), async {
        while metrics.snapshot()["proxyDnsUdpPendingCurrent"] != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let while_first_is_pending = metrics.snapshot();
    assert_eq!(while_first_is_pending["proxyDnsUdpQueuedCurrent"], 0);
    assert_eq!(while_first_is_pending["proxyDnsUdpQueuedBytesCurrent"], 0);
    assert_eq!(while_first_is_pending["proxyDnsUdpPendingCurrent"], 1);
    assert_eq!(
        while_first_is_pending["proxyDnsUdpPendingBytesCurrent"],
        first_len
    );
    let pending_metadata = while_first_is_pending["proxyDnsUdpPendingMetadataBytesCurrent"]
        .as_u64()
        .unwrap() as usize;
    assert!(pending_metadata > 0);
    assert_eq!(payload_admission.current(), first_len + pending_metadata);

    release_first.send(()).unwrap();
    let first_response = time::timeout(Duration::from_secs(1), first_response)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(&first_response[0..2], &0x1111_u16.to_be_bytes());
    server.await.unwrap();
    time::timeout(Duration::from_secs(1), async {
        loop {
            let snapshot = metrics.snapshot();
            if snapshot["proxyDnsUdpPendingCurrent"] == 0
                && snapshot["proxyDnsUdpPendingBytesCurrent"] == 0
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let snapshot = metrics.snapshot();
    assert_eq!(snapshot["dnsUdpActorsOpened"], 1);
    assert_eq!(snapshot["proxyDnsUdpExecutorsOpened"], 1);
    assert!(snapshot["proxyDnsUdpExecutorsReused"].as_u64().unwrap_or(0) >= 1);
    assert_eq!(snapshot["dnsUdpPendingMaximum"], 2);
    assert_eq!(snapshot["proxyDnsUdpQueuedCurrent"], 0);
    assert_eq!(snapshot["proxyDnsUdpQueuedBytesCurrent"], 0);
    assert_eq!(snapshot["proxyDnsUdpPendingCurrent"], 0);
    assert_eq!(snapshot["proxyDnsUdpPendingBytesCurrent"], 0);
    assert_eq!(snapshot["proxyDnsUdpPendingMetadataBytesCurrent"], 0);
    assert_eq!(snapshot["proxyDnsUdpResponseBytesCurrent"], 0);
    assert_eq!(payload_admission.current(), 0);

    let deadline = time::Instant::now() + RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE;
    assert_eq!(forwarder.shutdown(deadline).await["status"], "pass");
    assert_eq!(actor_executor.shutdown(deadline).await["status"], "pass");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxy_dns_udp_preserves_large_responses_and_releases_payload_bytes() {
    let upstream = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let response_sizes = [1500_usize, 4096_usize];
    let server = tokio::spawn(async move {
        let mut wire = vec![0_u8; u16::MAX as usize];
        for (index, response_size) in response_sizes.into_iter().enumerate() {
            let (wire_len, peer) = upstream.recv_from(&mut wire).await.unwrap();
            let request = decode_udp_packet(TEST_CIPHER, TEST_PASSWORD, &wire[..wire_len]).unwrap();
            let mut response = dns_a_response_for_query(&request.payload, [192, 0, 2, 10]);
            assert!(response.len() <= response_size);
            response.resize(response_size, 0);
            let encoded = encode_udp_packet(
                TEST_CIPHER,
                TEST_PASSWORD,
                &[0x41_u8.saturating_add(index as u8); 16],
                &request.target,
                &response,
            )
            .unwrap();
            upstream.send_to(&encoded, peer).await.unwrap();
        }
    });

    let mut runtime = ResidentDnsUdpRuntimeConfig::standalone();
    runtime.proxy_actor_limit = 1;
    runtime.actor_worker_threads = 1;
    runtime.attempts = 1;
    let payload_admission = runtime.payload_admission.clone();
    let metrics = Arc::new(ResidentDataplaneMetrics::default());
    let actor_executor = Arc::new(ResidentDnsUdpActorExecutor::new(
        runtime.clone(),
        Arc::clone(&metrics),
    ));
    let forwarder = ResidentProxyDnsUdpForwarder::new(
        Arc::new(proxy_plan(upstream_addr)),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53),
        runtime,
        Arc::clone(&metrics),
        Arc::clone(&actor_executor),
    )
    .unwrap();

    for (index, response_size) in response_sizes.into_iter().enumerate() {
        let request_id = 0x4100_u16.saturating_add(index as u16);
        let query = dns_query(request_id, &format!("large-{response_size}.example"));
        let response = forwarder.exchange(&query).await.unwrap();
        assert_eq!(response.len(), response_size);
        assert_eq!(&response[0..2], &request_id.to_be_bytes());
    }
    server.await.unwrap();

    let snapshot = metrics.snapshot();
    assert_eq!(snapshot["proxyDnsUdpQueuedCurrent"], 0);
    assert_eq!(snapshot["proxyDnsUdpQueuedBytesCurrent"], 0);
    assert_eq!(snapshot["proxyDnsUdpPendingCurrent"], 0);
    assert_eq!(snapshot["proxyDnsUdpPendingBytesCurrent"], 0);
    assert_eq!(snapshot["proxyDnsUdpPendingMetadataBytesCurrent"], 0);
    assert_eq!(snapshot["proxyDnsUdpResponseBytesCurrent"], 0);
    assert!(
        snapshot["proxyDnsUdpPendingMetadataBytesMaximum"]
            .as_u64()
            .unwrap()
            > 0
    );
    assert!(
        snapshot["proxyDnsUdpResponseBytesMaximum"]
            .as_u64()
            .unwrap()
            >= 4096
    );
    assert_eq!(payload_admission.current(), 0);

    let deadline = time::Instant::now() + RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE;
    assert_eq!(forwarder.shutdown(deadline).await["status"], "pass");
    assert_eq!(actor_executor.shutdown(deadline).await["status"], "pass");
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
    response.extend_from_slice(&TEST_DNS_QTYPE_A.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&60_u32.to_be_bytes());
    response.extend_from_slice(&4_u16.to_be_bytes());
    response.extend_from_slice(&address);
    response
}

fn dns_query(id: u16, domain: &str) -> Vec<u8> {
    let mut query = Vec::new();
    query.extend_from_slice(&id.to_be_bytes());
    query.extend_from_slice(&0x0100_u16.to_be_bytes());
    query.extend_from_slice(&1_u16.to_be_bytes());
    query.extend_from_slice(&0_u16.to_be_bytes());
    query.extend_from_slice(&0_u16.to_be_bytes());
    query.extend_from_slice(&0_u16.to_be_bytes());
    for label in domain.split('.') {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0);
    query.extend_from_slice(&TEST_DNS_QTYPE_A.to_be_bytes());
    query.extend_from_slice(&1_u16.to_be_bytes());
    query
}
