use super::*;
use crate::RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE;
use dae_dns::DnsPacketView;
use std::net::Ipv4Addr;

const TEST_UPSTREAM_COUNT: usize = 24;

mod cancellation;

#[tokio::test(flavor = "current_thread")]
async fn shared_executor_is_lazy_and_reuses_one_worker_pool() {
    let executor = ResidentDnsUdpActorExecutor::for_test_worker_count(2);
    assert_eq!(executor.pool_worker_count().await, None);
    let first_upstream = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let second_upstream = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let first = executor
        .open_handle(first_upstream.local_addr().unwrap(), 0)
        .await
        .unwrap();
    let second = executor
        .open_handle(second_upstream.local_addr().unwrap(), 0)
        .await
        .unwrap();

    assert_eq!(executor.pool_worker_count().await, Some(2));
    assert!(!first.is_closed());
    assert!(!second.is_closed());
}

#[tokio::test(flavor = "current_thread")]
async fn shared_executor_runs_multiplex_exchange_on_worker_pool() {
    let upstream = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let target = upstream.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let mut query = vec![0_u8; crate::dns::DNS_MAX_UDP_MESSAGE_SIZE];
        let (read, peer) = upstream.recv_from(&mut query).await.unwrap();
        let response = dns_a_response_for_query(&query[..read], [192, 0, 2, 44]);
        upstream.send_to(&response, peer).await.unwrap();
    });
    let executor = ResidentDnsUdpActorExecutor::for_test_worker_count(2);
    let handle = executor.open_handle(target, 0).await.unwrap();
    let query =
        crate::dns::build_dns_query_packet(0x6262, "executor.example", crate::dns::DNS_QTYPE_A)
            .unwrap();
    let response = handle.exchange(&query).await.unwrap();

    assert_eq!(&response[..2], &0x6262_u16.to_be_bytes());
    server.await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn shared_executor_bounds_workers_across_upstreams_and_closes_actors() {
    let executor = ResidentDnsUdpActorExecutor::for_test_worker_count(2);
    let mut upstreams = Vec::with_capacity(TEST_UPSTREAM_COUNT);
    let mut handles = Vec::with_capacity(TEST_UPSTREAM_COUNT);

    for _ in 0..TEST_UPSTREAM_COUNT {
        let upstream = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        handles.push(
            executor
                .open_handle(upstream.local_addr().unwrap(), 0)
                .await
                .unwrap(),
        );
        upstreams.push(upstream);
    }

    let pool_identity = executor.pool_identity().await.unwrap();
    assert_eq!(executor.pool_worker_count().await, Some(2));
    assert_eq!(executor.pool_identity().await, Some(pool_identity));
    assert!(handles.iter().all(|handle| !handle.is_closed()));

    drop(executor);
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while handles.iter().any(|handle| !handle.is_closed()) {
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("shared DNS UDP actors did not close with their executor");
}

#[tokio::test(flavor = "current_thread")]
async fn shared_executor_shutdown_fails_pending_and_joins_actor_runtime() {
    let upstream = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let target = upstream.local_addr().unwrap();
    let executor = Arc::new(ResidentDnsUdpActorExecutor::for_test_worker_count(2));
    let handle = executor.open_handle(target, 0).await.unwrap();
    let query =
        crate::dns::build_dns_query_packet(0x7373, "shutdown.example", crate::dns::DNS_QTYPE_A)
            .unwrap();
    let exchange_handle = handle.clone();
    let exchange = tokio::spawn(async move { exchange_handle.exchange_once(&query).await });
    let mut received = vec![0_u8; 512];
    upstream.recv_from(&mut received).await.unwrap();

    let report = executor
        .shutdown(tokio::time::Instant::now() + RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE)
        .await;
    let error = exchange.await.unwrap().unwrap_err();

    assert_eq!(report["status"], "pass");
    assert_eq!(report["timedOut"], 0);
    assert!(error.contains("shutting down"), "{error}");
    assert!(handle.is_closed());
    assert_eq!(executor.pool_worker_count().await, None);
    let metrics = executor.metrics.snapshot();
    assert_eq!(metrics["dnsUdpPendingCurrent"], 0);
    assert_eq!(metrics["dnsUdpActorsOpened"], metrics["dnsUdpActorsClosed"]);
}

#[tokio::test(flavor = "current_thread")]
async fn shared_executor_shutdown_is_idempotent_and_rejects_new_actors() {
    let upstream = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let target = upstream.local_addr().unwrap();
    let executor = ResidentDnsUdpActorExecutor::for_test_worker_count(1);
    let deadline = tokio::time::Instant::now() + RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE;

    let first = executor.shutdown(deadline).await;
    let second = executor
        .shutdown(tokio::time::Instant::now() + RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE)
        .await;
    let open_error = match executor.open_handle(target, 0).await {
        Ok(_) => panic!("closed DNS UDP actor executor accepted a new actor"),
        Err(err) => err,
    };

    assert_eq!(first["status"], "pass");
    assert_eq!(second["status"], "pass");
    assert!(open_error.contains("closing"), "{open_error}");
    assert_eq!(executor.pool_worker_count().await, None);
}

#[tokio::test(flavor = "current_thread")]
async fn configured_pending_limit_bounds_one_actor_without_extra_workers() {
    let upstream = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let target = upstream.local_addr().unwrap();
    let mut runtime = ResidentDnsUdpRuntimeConfig::standalone();
    runtime.actor_worker_threads = 1;
    runtime.queue_depth = 4;
    runtime.pending_limit = 1;
    runtime.attempts = 1;
    runtime.attempt_timeout = std::time::Duration::from_secs(5);
    let metrics = Arc::new(ResidentDataplaneMetrics::default());
    let executor = Arc::new(ResidentDnsUdpActorExecutor::new(
        runtime,
        Arc::clone(&metrics),
    ));
    let handle = executor.open_handle(target, 0).await.unwrap();

    let mut requests = Vec::new();
    for index in 0..3_u16 {
        let handle = handle.clone();
        let query = crate::dns::build_dns_query_packet(
            0x4000 + index,
            &format!("pending-{index}.example"),
            crate::dns::DNS_QTYPE_A,
        )
        .unwrap();
        requests.push(tokio::spawn(
            async move { handle.exchange_once(&query).await },
        ));
    }
    let mut received = vec![0_u8; 512];
    upstream.recv_from(&mut received).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;

    let snapshot = metrics.snapshot();
    assert_eq!(snapshot["dnsUdpPendingCurrent"], 1);
    assert_eq!(snapshot["dnsUdpPendingMaximum"], 1);
    assert_eq!(executor.pool_worker_count().await, Some(1));

    let report = executor
        .shutdown(tokio::time::Instant::now() + RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE)
        .await;
    for request in requests {
        assert!(request.await.unwrap().is_err());
    }
    let snapshot = metrics.snapshot();
    assert_eq!(report["status"], "pass");
    assert_eq!(snapshot["dnsUdpPendingCurrent"], 0);
    assert!(
        snapshot["dnsUdpShutdownRequestsFailed"]
            .as_u64()
            .unwrap_or(0)
            >= 1
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
    response.extend_from_slice(&crate::dns::DNS_QTYPE_A.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&60_u32.to_be_bytes());
    response.extend_from_slice(&4_u16.to_be_bytes());
    response.extend_from_slice(&address);
    response
}
