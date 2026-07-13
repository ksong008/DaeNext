use super::*;
use crate::production_runtime_owner::resident_dataplane::RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE;

const LEGACY_DNS_RESPONSE_READ_LIMIT: usize = 4096;

fn test_metrics() -> Arc<ResidentDataplaneMetrics> {
    Arc::new(ResidentDataplaneMetrics::default())
}

fn test_pending_capacity() -> usize {
    ResidentDnsUdpRuntimeConfig::standalone().pending_limit
}

fn test_attempt_timeout() -> Duration {
    ResidentDnsUdpRuntimeConfig::standalone().attempt_timeout
}

#[test]
fn udp_request_id_allocator_enforces_capacity_and_releases_ids() {
    let mut allocator = UdpRequestIdAllocator::default();
    let now = time::Instant::now();
    let first = allocator.allocate_at(1, now).unwrap();
    assert!(allocator.allocate_at(1, now).is_err());
    assert!(allocator.is_occupied(first));

    allocator.release_at(first, now);
    assert!(!allocator.is_occupied(first));
    assert!(allocator.is_quarantined(first));
    allocator.next_id = first;
    let second = allocator.allocate_at(1, now).unwrap();
    assert_ne!(second, first);
    allocator.release_at(second, now);

    let after_quarantine = now + test_attempt_timeout();
    allocator.reap_quarantine(after_quarantine);
    assert!(!allocator.is_quarantined(first));
    allocator.next_id = first;
    assert_eq!(allocator.allocate_at(1, after_quarantine).unwrap(), first);
}

#[test]
fn udp_deadline_cleanup_ignores_stale_generation_for_reused_id() {
    let mut allocator = UdpRequestIdAllocator::default();
    let id = allocator.allocate(test_pending_capacity()).unwrap();
    let mut pending = HashMap::new();
    let mut deadlines = VecDeque::new();
    let now = time::Instant::now();
    let live_deadline = now + test_attempt_timeout();
    let (response, _receiver) = tokio::sync::oneshot::channel();

    pending.insert(
        id,
        PendingUdpRequest {
            upstream_id: id,
            original_id: id,
            generation: 2,
            deadline: live_deadline,
            questions: Vec::new(),
            response,
        },
    );
    deadlines.push_back(PendingUdpDeadline {
        id,
        generation: 1,
        deadline: now,
    });
    deadlines.push_back(PendingUdpDeadline {
        id,
        generation: 2,
        deadline: live_deadline,
    });

    expire_pending_udp_requests(
        &mut pending,
        &mut deadlines,
        &mut allocator,
        &test_metrics(),
    );

    assert!(pending.contains_key(&id));
    assert!(allocator.is_occupied(id));
    assert_eq!(
        next_udp_multiplex_deadline(&mut deadlines, &pending),
        Some(live_deadline)
    );
}

#[test]
fn udp_multiplex_validation_rejects_question_mismatch() {
    const UPSTREAM_ID: u16 = 0x5151;
    const ORIGINAL_ID: u16 = 0x1515;
    const EXPECTED_QNAME: &str = "expected.example";
    const DIFFERENT_QNAME: &str = "different.example";

    let expected_query = build_dns_query_packet(ORIGINAL_ID, EXPECTED_QNAME, DNS_QTYPE_A).unwrap();
    let expected_view = DnsPacketView::parse(&expected_query).unwrap();
    let (response, _receiver) = tokio::sync::oneshot::channel();
    let pending = PendingUdpRequest {
        upstream_id: UPSTREAM_ID,
        original_id: ORIGINAL_ID,
        generation: 1,
        deadline: time::Instant::now() + test_attempt_timeout(),
        questions: pending_dns_questions(&expected_view),
        response,
    };
    let different_query =
        build_dns_query_packet(UPSTREAM_ID, DIFFERENT_QNAME, DNS_QTYPE_A).unwrap();
    let different_response = dns_a_response_for_query(&different_query, [192, 0, 2, 1]);

    assert!(validate_and_restore_udp_multiplex_response(&pending, &different_response).is_err());
}

#[tokio::test]
async fn mismatched_late_response_does_not_remove_reused_pending_id() {
    let mut allocator = UdpRequestIdAllocator::default();
    let upstream_id = allocator.allocate(test_pending_capacity()).unwrap();
    let original_id = 0x4141;
    let expected_query =
        build_dns_query_packet(original_id, "current.example", DNS_QTYPE_A).unwrap();
    let expected_view = DnsPacketView::parse(&expected_query).unwrap();
    let (response, receiver) = tokio::sync::oneshot::channel();
    let mut pending = HashMap::from([(
        upstream_id,
        PendingUdpRequest {
            upstream_id,
            original_id,
            generation: 2,
            deadline: time::Instant::now() + test_attempt_timeout(),
            questions: pending_dns_questions(&expected_view),
            response,
        },
    )]);
    let stale_query = build_dns_query_packet(upstream_id, "stale.example", DNS_QTYPE_A).unwrap();
    let stale_response = dns_a_response_for_query(&stale_query, [192, 0, 2, 1]);

    let metrics = test_metrics();
    handle_udp_multiplex_response(&mut pending, &mut allocator, &stale_response, &metrics);
    assert!(pending.contains_key(&upstream_id));
    assert!(allocator.is_occupied(upstream_id));

    let mut current_query = expected_query.clone();
    rewrite_dns_packet_id_in_place(&mut current_query, upstream_id);
    let current_response = dns_a_response_for_query(&current_query, [192, 0, 2, 2]);
    handle_udp_multiplex_response(&mut pending, &mut allocator, &current_response, &metrics);
    assert!(!pending.contains_key(&upstream_id));
    assert!(!allocator.is_occupied(upstream_id));
    let restored = receiver.await.unwrap().unwrap();
    assert_eq!(&restored[0..2], &original_id.to_be_bytes());
}

#[tokio::test]
async fn udp_multiplex_handles_out_of_order_responses() {
    let upstream = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let target = upstream.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let mut first = vec![0_u8; DNS_RESPONSE_READ_LIMIT];
        let mut second = vec![0_u8; DNS_RESPONSE_READ_LIMIT];
        let (first_len, peer) = upstream.recv_from(&mut first).await.unwrap();
        let (second_len, _) = upstream.recv_from(&mut second).await.unwrap();
        let first_response = dns_a_response_for_query(&first[..first_len], [192, 0, 2, 1]);
        let second_response = dns_a_response_for_query(&second[..second_len], [192, 0, 2, 2]);
        upstream.send_to(&second_response, peer).await.unwrap();
        upstream.send_to(&first_response, peer).await.unwrap();
    });
    let handle = open_udp_multiplex_handle(target, 0).await.unwrap();
    let first = build_dns_query_packet(0x1111, "first.example", DNS_QTYPE_A).unwrap();
    let second = build_dns_query_packet(0x2222, "second.example", DNS_QTYPE_A).unwrap();
    let (first_response, second_response) =
        tokio::join!(handle.exchange(&first), handle.exchange(&second));

    assert_eq!(&first_response.unwrap()[0..2], &0x1111_u16.to_be_bytes());
    assert_eq!(&second_response.unwrap()[0..2], &0x2222_u16.to_be_bytes());
    server.await.unwrap();
}

#[tokio::test]
async fn udp_multiplex_discards_stale_response() {
    let upstream = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let target = upstream.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let mut request = vec![0_u8; DNS_RESPONSE_READ_LIMIT];
        let (read, peer) = upstream.recv_from(&mut request).await.unwrap();
        let mut stale = dns_a_response_for_query(&request[..read], [192, 0, 2, 1]);
        stale[0..2].copy_from_slice(&0xffff_u16.to_be_bytes());
        let response = dns_a_response_for_query(&request[..read], [192, 0, 2, 2]);
        upstream.send_to(&stale, peer).await.unwrap();
        upstream.send_to(&response, peer).await.unwrap();
    });
    let handle = open_udp_multiplex_handle(target, 0).await.unwrap();
    let query = build_dns_query_packet(0x3333, "stale.example", DNS_QTYPE_A).unwrap();
    let response = handle.exchange(&query).await.unwrap();

    assert_eq!(&response[0..2], &0x3333_u16.to_be_bytes());
    server.await.unwrap();
}

#[tokio::test]
async fn udp_multiplex_preserves_response_larger_than_legacy_buffer() {
    let upstream = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let target = upstream.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let mut request = vec![0_u8; DNS_RESPONSE_READ_LIMIT];
        let (read, peer) = upstream.recv_from(&mut request).await.unwrap();
        let response = large_dns_response_for_query(&request[..read]);
        assert!(response.len() > LEGACY_DNS_RESPONSE_READ_LIMIT);
        upstream.send_to(&response, peer).await.unwrap();
    });
    let handle = open_udp_multiplex_handle(target, 0).await.unwrap();
    let query = build_dns_query_packet(0x5151, "large.example", DNS_QTYPE_A).unwrap();
    let response = handle.exchange(&query).await.unwrap();

    assert!(response.len() > LEGACY_DNS_RESPONSE_READ_LIMIT);
    assert_eq!(&response[0..2], &0x5151_u16.to_be_bytes());
    server.await.unwrap();
}

#[tokio::test]
async fn udp_multiplex_queue_saturation_fails_with_a_bounded_wait_and_counter() {
    let upstream = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let target = upstream.local_addr().unwrap();
    let mut runtime = ResidentDnsUdpRuntimeConfig::standalone();
    runtime.actor_worker_threads = 1;
    runtime.queue_depth = 1;
    runtime.pending_limit = 1;
    runtime.attempts = 1;
    runtime.attempt_timeout = Duration::from_secs(5);
    let metrics = test_metrics();
    let executor = Arc::new(ResidentDnsUdpActorExecutor::new(
        runtime,
        Arc::clone(&metrics),
    ));
    let handle = executor.open_handle(target, 0).await.unwrap();
    let first_query = build_dns_query_packet(0x7101, "first-full.example", DNS_QTYPE_A).unwrap();
    let first_handle = handle.clone();
    let first = tokio::spawn(async move { first_handle.exchange_once(&first_query).await });
    let mut received = vec![0_u8; DNS_RESPONSE_READ_LIMIT];
    upstream.recv_from(&mut received).await.unwrap();

    let second_query = build_dns_query_packet(0x7102, "second-full.example", DNS_QTYPE_A).unwrap();
    let (second_response, second_receiver) = tokio::sync::oneshot::channel();
    handle
        .sender
        .send(UdpMultiplexRequest {
            payload: second_query,
            response: second_response,
        })
        .await
        .unwrap();
    assert_eq!(handle.sender.capacity(), 0);
    let mut saturated = handle.clone();
    saturated.attempt_timeout = Duration::from_millis(10);
    let third_query = build_dns_query_packet(0x7103, "third-full.example", DNS_QTYPE_A).unwrap();
    let error = saturated.exchange_once(&third_query).await.unwrap_err();

    assert!(error.contains("queue wait timeout"), "{error}");
    assert_eq!(metrics.snapshot()["dnsUdpQueueWaitTimeouts"], 1);
    let report = executor
        .shutdown(time::Instant::now() + RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE)
        .await;
    assert_eq!(report["status"], "pass");
    assert!(first.await.unwrap().is_err());
    assert!(second_receiver.await.unwrap().is_err());
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

fn large_dns_response_for_query(query: &[u8]) -> Vec<u8> {
    const FIXTURE_RDATA_LEN: usize = 5000;
    const FIXTURE_PRIVATE_QTYPE: u16 = 65_280;

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
    response.extend_from_slice(&FIXTURE_PRIVATE_QTYPE.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&60_u32.to_be_bytes());
    response.extend_from_slice(&(FIXTURE_RDATA_LEN as u16).to_be_bytes());
    response.resize(response.len() + FIXTURE_RDATA_LEN, 0x5a);
    response
}
