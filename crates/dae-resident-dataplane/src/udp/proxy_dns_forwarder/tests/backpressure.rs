use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pending_response_completes_while_another_send_is_backpressured() {
    let upstream = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let binding =
        ResidentProxyBinding::configuration(Arc::new(proxy_plan(upstream.local_addr().unwrap())))
            .unwrap();
    let (release_response, response_gate) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let mut wire = [0; 4096];
        let (len, peer) = upstream.recv_from(&mut wire).await.unwrap();
        let first = decode_udp_packet(TEST_CIPHER, TEST_PASSWORD, &wire[..len]).unwrap();
        let answer = dns_a_response_for_query(&first.payload, [192, 0, 2, 1]);
        let answer = encode_udp_packet(
            TEST_CIPHER,
            TEST_PASSWORD,
            &[0x61; 16],
            &first.target,
            &answer,
        )
        .unwrap();
        response_gate.await.unwrap();
        upstream.send_to(&answer, peer).await.unwrap();
    });
    let metrics = Arc::new(ResidentDataplaneMetrics::default());
    let runtime = ResidentDnsUdpRuntimeConfig::standalone();
    let admission = runtime.payload_admission.clone();
    let (blocked, blocked_gate) = tokio::sync::oneshot::channel();
    let (release_send, send_gate) = tokio::sync::oneshot::channel();
    let mut hook = Some((blocked, send_gate));
    let registration = super::super::actor::start_proxy_dns_udp_actor_with_send(
        binding,
        "127.0.0.1:53".parse().unwrap(),
        runtime,
        Arc::clone(&metrics),
        None,
        None,
        None,
        None,
        move |executor, binding, target, payload| {
            let Some(mut send) = executor.begin_dns_send(binding, target, payload)? else {
                return Ok(None);
            };
            if let Some((blocked, gate)) = hook.take() {
                let future = send.future;
                send.future = Box::pin(async move {
                    let _ = blocked.send(());
                    let _ = gate.await;
                    future.await
                });
            }
            Ok(Some(send))
        },
    );
    let first_handle = registration.handle.clone();
    let first = tokio::spawn(async move {
        first_handle
            .exchange_once(
                &dns_query(1, "first.test"),
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
    let second_handle = registration.handle.clone();
    let second = tokio::spawn(async move {
        second_handle
            .exchange_once(
                &dns_query(2, "second.test"),
                ProxyDnsRequestContext::from_timeout(Duration::from_secs(5)),
            )
            .await
    });
    blocked_gate.await.unwrap();
    release_response.send(()).unwrap();
    let result = time::timeout(Duration::from_millis(500), first)
        .await
        .expect("A response must complete before releasing B's send backpressure")
        .unwrap()
        .unwrap();
    assert_eq!(&result[..2], &1_u16.to_be_bytes());
    assert_eq!(metrics.snapshot()["proxyDnsUdpExecutorsReset"], 0);
    second.abort();
    let _ = second.await;
    let _ = release_send.send(());
    registration.handle.close();
    assert!(
        !time::timeout(Duration::from_secs(1), registration.task)
            .await
            .unwrap()
            .unwrap()
    );
    server.await.unwrap();
    assert_eq!(admission.current(), 0);
}

#[derive(Clone, Copy)]
enum Action {
    CancelA,
    ExpireA,
    CancelB,
    ExpireB,
    LocalError,
    IdleError,
    SessionError,
    Stop,
}

async fn check_backpressure(action: Action) {
    let upstream = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let binding =
        ResidentProxyBinding::configuration(Arc::new(proxy_plan(upstream.local_addr().unwrap())))
            .unwrap();
    let (received, receive_gate) = tokio::sync::oneshot::channel();
    let (release_a, response_gate) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let mut wire = [0; 4096];
        let mut first = true;
        let mut gate = Some((received, response_gate));
        let mut expected_peer = None;
        loop {
            let (len, peer) = upstream.recv_from(&mut wire).await.unwrap();
            if !matches!(action, Action::IdleError) {
                assert_eq!(
                    *expected_peer.get_or_insert(peer),
                    peer,
                    "session must retain its UDP socket"
                );
            }
            let query = decode_udp_packet(TEST_CIPHER, TEST_PASSWORD, &wire[..len]).unwrap();
            let answer = dns_a_response_for_query(&query.payload, [192, 0, 2, 1]);
            let answer = encode_udp_packet(
                TEST_CIPHER,
                TEST_PASSWORD,
                &[0x62; 16],
                &query.target,
                &answer,
            )
            .unwrap();
            if first {
                first = false;
                let (received, gate) = gate.take().unwrap();
                let _ = received.send(());
                let _ = gate.await;
            }
            upstream.send_to(&answer, peer).await.unwrap();
        }
    });
    let metrics = Arc::new(ResidentDataplaneMetrics::default());
    let runtime = ResidentDnsUdpRuntimeConfig::standalone();
    let admission = runtime.payload_admission.clone();
    let (blocked, block_gate) = tokio::sync::oneshot::channel();
    let (release_b, send_gate) = tokio::sync::oneshot::channel();
    let mut hook = Some((blocked, send_gate));
    let registration = super::super::actor::start_proxy_dns_udp_actor_with_send(
        binding,
        "127.0.0.1:53".parse().unwrap(),
        runtime,
        Arc::clone(&metrics),
        None,
        None,
        None,
        None,
        move |executor, binding, target, payload| {
            let Some(mut send) = executor.begin_dns_send(binding, target, payload)? else {
                return Ok(None);
            };
            if let Some((blocked, gate)) = hook.take() {
                // Exercise the same actor boundary for a session-invalidating
                // error. Actual partial stream IO is covered by shared_io tests.
                if matches!(action, Action::SessionError) {
                    send.reset_on_cancel = true;
                }
                let future = send.future;
                send.future = Box::pin(async move {
                    let _ = blocked.send(());
                    let _ = gate.await;
                    let mut done = future.await;
                    if matches!(
                        action,
                        Action::LocalError | Action::IdleError | Action::SessionError
                    ) {
                        done.result = Err("injected send failure".to_owned());
                        done.reset_session = matches!(action, Action::SessionError);
                    }
                    done
                });
            }
            Ok(Some(send))
        },
    );
    let handle = registration.handle.clone();
    let first = tokio::spawn(async move {
        handle
            .exchange_once(
                &dns_query(1, "first.test"),
                ProxyDnsRequestContext::from_timeout(if matches!(action, Action::ExpireA) {
                    Duration::from_millis(150)
                } else {
                    Duration::from_secs(5)
                }),
            )
            .await
    });
    time::timeout(Duration::from_secs(1), receive_gate)
        .await
        .unwrap()
        .unwrap();
    let handle = registration.handle.clone();
    let mut second = tokio::spawn(async move {
        handle
            .exchange_once(
                &dns_query(2, "second.test"),
                ProxyDnsRequestContext::from_timeout(if matches!(action, Action::ExpireB) {
                    Duration::from_millis(150)
                } else {
                    Duration::from_secs(5)
                }),
            )
            .await
    });
    time::timeout(Duration::from_secs(1), block_gate)
        .await
        .unwrap()
        .unwrap();
    match action {
        Action::CancelA => {
            first.abort();
            let _ = first.await;
        }
        Action::ExpireA => {
            assert!(
                time::timeout(Duration::from_secs(1), first)
                    .await
                    .unwrap()
                    .unwrap()
                    .is_err()
            );
        }
        Action::CancelB => {
            second.abort();
            let _ = (&mut second).await;
            release_a.send(()).unwrap();
            assert!(
                time::timeout(Duration::from_secs(1), first)
                    .await
                    .unwrap()
                    .unwrap()
                    .is_ok()
            );
        }
        Action::ExpireB => {
            assert!(
                time::timeout(Duration::from_secs(1), &mut second)
                    .await
                    .unwrap()
                    .unwrap()
                    .is_err()
            );
            release_a.send(()).unwrap();
            assert!(
                time::timeout(Duration::from_secs(1), first)
                    .await
                    .unwrap()
                    .unwrap()
                    .is_ok()
            );
        }
        Action::IdleError => {
            release_a.send(()).unwrap();
            assert!(
                time::timeout(Duration::from_secs(1), first)
                    .await
                    .unwrap()
                    .unwrap()
                    .is_ok()
            );
            release_b.send(()).unwrap();
            assert!(
                time::timeout(Duration::from_secs(1), &mut second)
                    .await
                    .unwrap()
                    .unwrap()
                    .is_err()
            );
        }
        Action::LocalError | Action::SessionError => {
            release_b.send(()).unwrap();
            assert!(
                time::timeout(Duration::from_secs(1), &mut second)
                    .await
                    .unwrap()
                    .unwrap()
                    .is_err()
            );
            if matches!(action, Action::SessionError) {
                assert!(
                    time::timeout(Duration::from_secs(1), first)
                        .await
                        .unwrap()
                        .unwrap()
                        .is_err()
                );
            } else {
                release_a.send(()).unwrap();
                assert!(
                    time::timeout(Duration::from_secs(1), first)
                        .await
                        .unwrap()
                        .unwrap()
                        .is_ok()
                );
            }
        }
        Action::Stop => {
            registration.handle.close();
            assert!(
                time::timeout(Duration::from_secs(1), first)
                    .await
                    .unwrap()
                    .unwrap()
                    .is_err()
            );
            assert!(
                time::timeout(Duration::from_secs(1), &mut second)
                    .await
                    .unwrap()
                    .unwrap()
                    .is_err()
            );
        }
    }
    if matches!(action, Action::CancelA | Action::ExpireA) {
        time::timeout(Duration::from_secs(1), async {
            while metrics.snapshot()["proxyDnsUdpPendingCurrent"] != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(
            admission.current() > 0,
            "B's live send must retain its payload budget"
        );
        second.abort();
        let _ = (&mut second).await;
    }
    if matches!(
        action,
        Action::CancelB | Action::ExpireB | Action::LocalError | Action::IdleError
    ) {
        let answer = registration
            .handle
            .exchange_once(
                &dns_query(3, "third.test"),
                ProxyDnsRequestContext::from_timeout(Duration::from_secs(1)),
            )
            .await
            .unwrap();
        assert_eq!(&answer[..2], &3_u16.to_be_bytes());
        assert_eq!(
            metrics.snapshot()["proxyDnsUdpExecutorsOpened"],
            1 + usize::from(matches!(action, Action::IdleError))
        );
    }
    registration.handle.close();
    assert!(
        !time::timeout(Duration::from_secs(1), registration.task)
            .await
            .unwrap()
            .unwrap()
    );
    server.abort();
    let _ = server.await;
    let snapshot = metrics.snapshot();
    assert_eq!(
        snapshot["proxyDnsUdpExecutorsReset"],
        usize::from(matches!(action, Action::SessionError | Action::IdleError))
    );
    for metric in [
        "proxyDnsUdpQueuedCurrent",
        "proxyDnsUdpQueuedBytesCurrent",
        "proxyDnsUdpPendingCurrent",
        "proxyDnsUdpPendingBytesCurrent",
        "proxyDnsUdpPendingMetadataBytesCurrent",
        "proxyDnsUdpResponseBytesCurrent",
    ] {
        assert_eq!(snapshot[metric], 0, "{metric}");
    }
    assert_eq!(admission.current(), 0);
}

#[tokio::test]
async fn cancelling_a_pending_request_progresses_during_send_backpressure() {
    check_backpressure(Action::CancelA).await;
}
#[tokio::test]
async fn pending_deadline_progresses_during_send_backpressure() {
    check_backpressure(Action::ExpireA).await;
}
#[tokio::test]
async fn cancelling_a_datagram_send_preserves_other_pending_and_socket() {
    check_backpressure(Action::CancelB).await;
}
#[tokio::test]
async fn datagram_send_deadline_preserves_other_pending_and_socket() {
    check_backpressure(Action::ExpireB).await;
}
#[tokio::test]
async fn local_datagram_send_error_preserves_other_pending_and_socket() {
    check_backpressure(Action::LocalError).await;
}
#[tokio::test]
async fn failed_datagram_sender_reopens_after_older_pending_drains() {
    check_backpressure(Action::IdleError).await;
}
#[tokio::test]
async fn shared_session_send_failure_resets_other_pending() {
    check_backpressure(Action::SessionError).await;
}
#[tokio::test]
async fn shutdown_interrupts_send_backpressure_and_releases_all_budgets() {
    check_backpressure(Action::Stop).await;
}

#[tokio::test]
async fn shutdown_interrupts_first_connection_handshake() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut proxy = proxy_plan(listener.local_addr().unwrap());
    proxy.protocol = "socks5";
    proxy.handler = ResidentProxyProtocolPlan::Socks5Tcp {
        username: String::new(),
        password: String::new(),
    };
    proxy.materialize_execution();
    let binding = ResidentProxyBinding::configuration(Arc::new(proxy)).unwrap();
    let metrics = Arc::new(ResidentDataplaneMetrics::default());
    let runtime = ResidentDnsUdpRuntimeConfig::standalone();
    let admission = runtime.payload_admission.clone();
    let registration = super::super::actor::start_proxy_dns_udp_actor(
        binding,
        "127.0.0.1:53".parse().unwrap(),
        runtime,
        Arc::clone(&metrics),
        None,
        None,
        None,
        None,
    );
    let handle = registration.handle.clone();
    let request = tokio::spawn(async move {
        handle
            .exchange_once(
                &dns_query(1, "connect.test"),
                ProxyDnsRequestContext::from_timeout(Duration::from_secs(5)),
            )
            .await
    });
    let (_connection, _) = time::timeout(Duration::from_secs(1), listener.accept())
        .await
        .unwrap()
        .unwrap();
    registration.handle.close();
    assert!(
        time::timeout(Duration::from_secs(1), request)
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
    assert!(
        !time::timeout(Duration::from_secs(1), registration.task)
            .await
            .unwrap()
            .unwrap()
    );
    assert_eq!(metrics.snapshot()["proxyDnsUdpPendingCurrent"], 0);
    assert_eq!(admission.current(), 0);
}
