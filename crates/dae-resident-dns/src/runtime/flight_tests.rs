use super::*;
use std::time::Duration;

fn query(id: u16) -> Vec<u8> {
    build_dns_query_packet(id, "Recovery.example", DNS_QTYPE_A).unwrap()
}

fn key(request: &DnsPacketView<'_>) -> ResidentDnsResponseCacheKey {
    dns_response_cache_key_for_request_action(
        request,
        &ResidentDnsRequestAction::AsIs,
        "127.0.0.1:53".parse().unwrap(),
    )
    .unwrap()
}

#[tokio::test]
async fn cancelled_dns_leader_elects_only_one_replacement_for_live_followers() {
    let plan = ResidentDnsPlan::asis(0);
    let query = query(123);
    let request = DnsPacketView::parse(&query).unwrap();
    let key = key(&request);
    let old = plan.cache.begin_flight(key.clone()).unwrap();
    let context = ProxyDnsRequestContext::from_timeout(Duration::from_secs(1));
    let mut followers = (0..32)
        .map(|_| Box::pin(acquire(&plan, &key, &request, context)))
        .collect::<Vec<_>>();
    for follower in &mut followers {
        assert!(futures_util::poll!(follower.as_mut()).is_pending());
    }
    assert_eq!(plan.cache.flight_follower_count(), 32);
    drop(old);
    let Acquired::Leader {
        mut permit,
        recovered,
    } = followers.remove(0).await.unwrap()
    else {
        panic!("replacement leader missing")
    };
    assert!(recovered);
    for follower in &mut followers {
        assert!(futures_util::poll!(follower.as_mut()).is_pending());
    }
    assert_eq!(plan.cache.inflight_len(), 1);
    assert_eq!(plan.cache.flight_follower_count(), 31);
    let response = build_reject_response(&query, &request).unwrap();
    permit.publish(Ok(&response)).unwrap();
    for follower in followers {
        let Acquired::Response {
            response: actual,
            recovered,
        } = follower.await.unwrap()
        else {
            panic!("duplicate leader")
        };
        assert!(recovered);
        assert_eq!(actual, response);
    }
    drop(permit);
    assert_eq!(plan.cache.inflight_len(), 0);
    assert_eq!(plan.cache.flight_follower_count(), 0);
    assert_eq!(plan.cache.flight_retained_bytes(), 0);
}

#[tokio::test]
async fn ordinary_dns_flight_failure_is_not_replayed_even_with_cancellation_text() {
    let plan = ResidentDnsPlan::asis(0);
    let query = query(124);
    let request = DnsPacketView::parse(&query).unwrap();
    let key = key(&request);
    let mut leader = plan.cache.begin_flight(key.clone()).unwrap();
    let follower = acquire(
        &plan,
        &key,
        &request,
        ProxyDnsRequestContext::from_timeout(Duration::from_secs(1)),
    );
    tokio::pin!(follower);
    assert!(futures_util::poll!(&mut follower).is_pending());
    leader
        .publish(Err(
            "resident DNS flight leader ended before publishing a result",
        ))
        .unwrap();
    assert!(follower.await.is_err());
    assert_eq!(plan.cache.inflight_len(), 0);
}

#[tokio::test]
async fn second_dns_leader_cancellation_does_not_elect_a_third_or_reset_deadline() {
    let plan = ResidentDnsPlan::asis(0);
    let query = query(125);
    let request = DnsPacketView::parse(&query).unwrap();
    let key = key(&request);
    let old = plan.cache.begin_flight(key.clone()).unwrap();
    let context = ProxyDnsRequestContext::from_timeout(Duration::from_secs(1));
    let mut first = Box::pin(acquire(&plan, &key, &request, context));
    let mut second = Box::pin(acquire(&plan, &key, &request, context));
    assert!(futures_util::poll!(first.as_mut()).is_pending());
    assert!(futures_util::poll!(second.as_mut()).is_pending());
    drop(old);
    let Acquired::Leader {
        permit,
        recovered: true,
    } = first.await.unwrap()
    else {
        panic!("replacement missing")
    };
    assert!(futures_util::poll!(second.as_mut()).is_pending());
    drop(permit);
    assert!(second.await.is_err());
    assert_eq!(plan.cache.inflight_len(), 0);
    let expired = ProxyDnsRequestContext::from_timeout(Duration::ZERO);
    assert!(acquire(&plan, &key, &request, expired).await.is_err());
    assert_eq!(plan.cache.inflight_len(), 0);
}

#[tokio::test]
async fn asis_validation_failure_is_published_to_followers_in_both_execution_paths() {
    for trace in [false, true] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = listener.local_addr().unwrap();
        let plan = ResidentDnsPlan::asis(0);
        let payload = query(129);
        let request = DnsPacketView::parse(&payload).unwrap();
        let key = dns_response_cache_key_for_request_action(
            &request,
            &ResidentDnsRequestAction::AsIs,
            target,
        )
        .unwrap();
        let (received, ready) = tokio::sync::oneshot::channel();
        let (release, released) = tokio::sync::oneshot::channel();
        let upstream = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let len = stream.read_u16().await.unwrap();
            let mut query = vec![0; len as usize];
            stream.read_exact(&mut query).await.unwrap();
            received.send(()).unwrap();
            released.await.unwrap();
            // Correct framing but a query instead of a response: this reaches
            // the ordinary validation error exit after the flight is created.
            stream.write_u16(query.len() as u16).await.unwrap();
            stream.write_all(&query).await.unwrap();
        });
        let leader = async {
            if trace {
                let summary = ResidentDnsTraceSummary::from_request(&plan, &request).unwrap();
                handle_resident_dns_request_without_preference_trace(
                    &plan,
                    target,
                    &payload,
                    &request,
                    Some(ResidentDnsAsisTransport::Tcp),
                    summary,
                )
                .await
                .map(|result| result.response)
            } else {
                handle_resident_dns_tcp_async(&plan, target, &payload).await
            }
        };
        tokio::pin!(leader);
        tokio::select! {
            result = &mut leader => panic!("leader ended before upstream barrier: {result:?}"),
            _ = ready => {},
        }
        let follower = acquire(
            &plan,
            &key,
            &request,
            ProxyDnsRequestContext::from_timeout(Duration::from_secs(1)),
        );
        tokio::pin!(follower);
        assert!(futures_util::poll!(&mut follower).is_pending());
        release.send(()).unwrap();
        let error = leader.await.unwrap_err();
        let Err(follower_error) = follower.await else {
            panic!("normal error elected a replacement");
        };
        assert_eq!(follower_error, error);
        assert_eq!(plan.cache.inflight_len(), 0);
        assert_eq!(plan.cache.flight_follower_count(), 0);
        assert_eq!(plan.cache.flight_retained_bytes(), 0);
        upstream.await.unwrap();
    }
}
