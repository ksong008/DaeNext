async fn run_proxy_dns_cleanup<F>(
    context: ProxyDnsRequestContext,
    cleanup: F,
) -> Result<(), ProxyDnsRequestError>
where
    F: std::future::Future<Output = Result<(), String>> + Send + 'static,
{
    let mut task = tokio::spawn(cleanup);
    match time::timeout_at(context.deadline(), &mut task).await {
        Ok(Ok(Ok(()))) => Ok(()),
        Ok(Ok(Err(error))) => Err(ProxyDnsRequestError::new(
            ProxyDnsRequestStage::Cleanup,
            ProxyDnsRequestFailure::Network,
            error,
        )),
        Ok(Err(error)) => Err(ProxyDnsRequestError::new(
            ProxyDnsRequestStage::Cleanup,
            ProxyDnsRequestFailure::Network,
            format!("join proxy DNS cleanup task: {error}"),
        )),
        Err(_) => {
            drop(task);
            Err(ProxyDnsRequestError::deadline(
                ProxyDnsRequestStage::Cleanup,
            ))
        }
    }
}

use dae_resident_dns::runtime::transport::quic::proxy::*;

use super::*;
use crate::dns_runtime_tests::transport::test_support::{
    DnsQuicTestProtocol, DnsQuicTestServer, Socks5UdpRelay, dns_proxy_binding, dns_test_response,
    socks5_dns_proxy,
};
use crate::quic_endpoint_metrics_snapshot;
use dae_resident_core::RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE;

#[tokio::test]
async fn expired_deadline_detaches_but_does_not_cancel_cleanup() {
    let (release, wait_for_release) = tokio::sync::oneshot::channel();
    let (finished, wait_for_finish) = tokio::sync::oneshot::channel();
    let context = ProxyDnsRequestContext::from_deadline(time::Instant::now());
    let error = run_proxy_dns_cleanup(context, async move {
        let _ = wait_for_release.await;
        let _ = finished.send(());
        Ok(())
    })
    .await
    .unwrap_err();

    assert_eq!(error.stage(), ProxyDnsRequestStage::Cleanup);
    assert_eq!(error.failure(), ProxyDnsRequestFailure::Deadline);
    release.send(()).unwrap();
    time::timeout(std::time::Duration::from_secs(1), wait_for_finish)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn cleanup_failure_remains_typed() {
    let context = ProxyDnsRequestContext::from_timeout(std::time::Duration::from_secs(1));
    let error = run_proxy_dns_cleanup(context, async { Err("fixture cleanup failure".into()) })
        .await
        .unwrap_err();

    assert_eq!(error.stage(), ProxyDnsRequestStage::Cleanup);
    assert_eq!(error.failure(), ProxyDnsRequestFailure::Network);
    assert!(error.to_string().contains("fixture cleanup failure"));
}

#[test]
fn cleanup_uncertainty_is_terminal_when_the_exchange_also_failed() {
    let exchange_error = ProxyDnsRequestError::new(
        ProxyDnsRequestStage::Read,
        ProxyDnsRequestFailure::Network,
        "fixture exchange failure",
    );
    let cleanup_error = ProxyDnsRequestError::new(
        ProxyDnsRequestStage::Cleanup,
        ProxyDnsRequestFailure::Network,
        "fixture cleanup failure",
    );
    let error = append_cleanup_error(exchange_error, Err(cleanup_error));

    assert_eq!(error.stage(), ProxyDnsRequestStage::Cleanup);
    assert_eq!(error.failure(), ProxyDnsRequestFailure::Network);
    assert!(error.to_string().contains("fixture exchange failure"));
    assert!(error.to_string().contains("cleanup_error="));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn routed_doq_reuses_one_outer_relay_and_inner_connection_for_large_responses() {
    let generation = 7_341;
    let expected_small = dns_test_response(1_500, 0x31);
    let expected_large = dns_test_response(4_096, 0x42);
    let server = DnsQuicTestServer::start_with_response_delay(
        DnsQuicTestProtocol::Doq,
        vec![expected_small.clone(), expected_large.clone()],
        std::time::Duration::from_millis(200),
    )
    .await;
    let socks = Socks5UdpRelay::start().await;
    let proxy = socks5_dns_proxy(socks.address());
    let binding = dns_proxy_binding(Arc::clone(&proxy), generation);
    let upstream = parse_dns_upstream(
        0,
        "routed-doq",
        &format!("quic://{}:853", server.server_name()),
        server.address(),
        0,
    )
    .unwrap();
    let selection = ResidentDnsUpstreamSelection::Proxy {
        binding: binding.clone(),
    };
    let cache = test_resident_dns_forwarder_cache();
    let forwarder = cache
        .proxy_quic_forwarder(&upstream, server.address(), binding, &selection)
        .unwrap();
    forwarder.lock().await.client_config_override = Some(server.client_config());
    let first_query = build_dns_query_packet(0x3411, "small.example", DNS_QTYPE_A).unwrap();
    let second_query = build_dns_query_packet(0x3412, "large.example", DNS_QTYPE_AAAA).unwrap();

    let first = forward_dns_quic_to_proxy_async(
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
    let second = forward_dns_quic_to_proxy_async(
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
        let query = build_dns_query_packet(0x3415, "cancelled.example", DNS_QTYPE_A).unwrap();
        forward_dns_quic_to_proxy_async(
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
        let query = build_dns_query_packet(0x3416, "surviving.example", DNS_QTYPE_A).unwrap();
        forward_dns_quic_to_proxy_async(
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
    let third_query = build_dns_query_packet(0x3413, "rebuild-a.example", DNS_QTYPE_A).unwrap();
    let fourth_query = build_dns_query_packet(0x3414, "rebuild-b.example", DNS_QTYPE_AAAA).unwrap();
    let (third, fourth) = tokio::join!(
        forward_dns_quic_to_proxy_async(
            &upstream,
            &third_query,
            Arc::clone(&forwarder),
            ProxyDnsRequestContext::from_timeout(std::time::Duration::from_secs(3)),
        ),
        forward_dns_quic_to_proxy_async(
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
    assert_eq!(
        report["forwarders"][0]["endpointReleased"], true,
        "{report}"
    );
    assert_eq!(
        report["forwarders"][0]["bridgeCompletion"], "joined",
        "{report}"
    );
    assert_eq!(report["forwarders"][0]["forced"], false, "{report}");
    assert_eq!(cache.metrics.snapshot()["dnsTransportOwnersCurrent"], 0);
    assert_eq!(cache.metrics.snapshot()["dnsTransportOwnerBytesCurrent"], 0);
    let closed = quic_endpoint_metrics_snapshot(generation);
    assert_eq!(closed["liveStates"]["total"], 0);
    assert_eq!(closed["endpointDriverTasks"]["live"], 0);
    assert_eq!(closed["chargedBytes"]["total"], 0);
}
