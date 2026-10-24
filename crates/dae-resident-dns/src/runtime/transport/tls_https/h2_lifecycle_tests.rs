use super::tests::{h2_test_upstream, send_h2_doh_response};
use super::*;
use std::time::Duration;

fn context() -> ProxyDnsRequestContext {
    ProxyDnsRequestContext::from_timeout(Duration::from_secs(2))
}

fn forwarder() -> Arc<ResidentDnsHttpsForwarder> {
    ResidentDnsForwarderCache::default()
        .https_forwarder(
            &h2_test_upstream(),
            "127.0.0.1:443".parse().unwrap(),
            0,
            &ResidentDnsUpstreamSelection::Direct { mark: 0 },
        )
        .unwrap()
}

async fn install(
    forwarder: &ResidentDnsHttpsForwarder,
) -> (Arc<ResidentDnsH2Forwarder>, tokio::io::DuplexStream) {
    let (client, server) = tokio::io::duplex(65536);
    let (sender, driver) = h2::client::handshake(client).await.unwrap();
    (
        forwarder
            .install_h2(sender, driver, context())
            .await
            .unwrap(),
        server,
    )
}

#[tokio::test]
async fn stale_h2_failure_preserves_replacement_and_cooldown_without_open_lock() {
    let forwarder = forwarder();
    let (old, old_server) = install(&forwarder).await;
    let (replacement, server) = install(&forwarder).await;
    let _opening = forwarder.h2_open_lock.lock().await;
    time::timeout(
        Duration::from_millis(100),
        forwarder.invalidate_h2(&old, context()),
    )
    .await
    .unwrap();
    assert!(forwarder.h2_retry_ready());
    assert!(Arc::ptr_eq(
        forwarder.h2.lock().await.current.as_ref().unwrap(),
        &replacement
    ));
    drop(old);
    drop(old_server);
    let query = build_dns_query_packet(0x1234, "replacement.example", DNS_QTYPE_A).unwrap();
    let answer_query = query.clone();
    let peer = tokio::spawn(async move {
        let mut server = h2::server::handshake(server).await.unwrap();
        let (_, response) = server.accept().await.unwrap().unwrap();
        send_h2_doh_response(response, &answer_query, [192, 0, 2, 3]);
        let _ = server.accept().await;
    });
    assert_eq!(
        &forwarder.exchange_h2(&query, context()).await.unwrap()[..2],
        &[0x12, 0x34]
    );
    peer.abort();
    let _ = peer.await;
}

#[tokio::test]
async fn h2_stream_failures_preserve_connection_and_sibling() {
    // Exercise the production pool path, including its invalidation decision.
    for failure in ["status", "content-type", "reset", "deadline"] {
        let forwarder = forwarder();
        let (connection, server) = install(&forwarder).await;
        let query = build_dns_query_packet(0x1234, "sibling.example", DNS_QTYPE_A).unwrap();
        let answer_query = query.clone();
        let (first_accepted, first_accepted_rx) = tokio::sync::oneshot::channel();
        let (accepted, accepted_rx) = tokio::sync::oneshot::channel();
        let (release, release_rx) = tokio::sync::oneshot::channel();
        let peer = tokio::spawn(async move {
            let mut server = h2::server::handshake(server).await.unwrap();
            let first = server.accept().await.unwrap().unwrap();
            first_accepted.send(()).unwrap();
            let mut second = server.accept().await.unwrap().unwrap();
            accepted.send(()).unwrap();
            match failure {
                "reset" => second.1.send_reset(h2::Reason::CANCEL),
                "deadline" => {}
                _ => {
                    let response = http::Response::builder()
                        .status(if failure == "status" { 500 } else { 200 })
                        .header(
                            "content-type",
                            if failure == "status" {
                                DOH_MEDIA_TYPE
                            } else {
                                "text/plain"
                            },
                        )
                        .body(())
                        .unwrap();
                    second.1.send_response(response, true).unwrap();
                }
            }
            tokio::select! {
                _ = release_rx => {},
                _ = server.accept() => panic!("connection unexpectedly closed"),
            }
            send_h2_doh_response(first.1, &answer_query, [192, 0, 2, 4]);
            let _ = server.accept().await;
        });
        let sibling = {
            let forwarder = Arc::clone(&forwarder);
            let query = query.clone();
            tokio::spawn(async move { forwarder.exchange_h2(&query, context()).await })
        };
        time::timeout(Duration::from_secs(1), first_accepted_rx)
            .await
            .unwrap()
            .unwrap();
        let failed = {
            let forwarder = Arc::clone(&forwarder);
            let query = query.clone();
            tokio::spawn(async move {
                let deadline = if failure == "deadline" {
                    Duration::from_millis(100)
                } else {
                    Duration::from_secs(2)
                };
                forwarder
                    .exchange_h2(&query, ProxyDnsRequestContext::from_timeout(deadline))
                    .await
            })
        };
        time::timeout(Duration::from_secs(1), accepted_rx)
            .await
            .unwrap()
            .unwrap();
        assert!(failed.await.unwrap().is_err(), "{failure}");
        assert!(forwarder.h2_retry_ready(), "{failure}");
        assert!(Arc::ptr_eq(
            forwarder.h2.lock().await.current.as_ref().unwrap(),
            &connection
        ));
        release.send(()).unwrap();
        assert!(sibling.await.unwrap().is_ok(), "{failure}");
        peer.abort();
        let _ = peer.await;
    }
}

#[tokio::test]
async fn retired_h2_driver_lives_until_last_stream_lease_then_is_joined() {
    let forwarder = forwarder();
    let (connection, _server) = install(&forwarder).await;
    let abort = connection.driver_abort.clone();
    forwarder.invalidate_h2(&connection, context()).await;
    assert!(!forwarder.h2_retry_ready());
    assert!(!abort.is_finished());
    drop(connection);
    let report = super::super::cache::shutdown_dns_https_forwarder(
        Arc::clone(&forwarder),
        time::Instant::now() + Duration::from_secs(1),
    )
    .await;
    assert_eq!(report["status"], "pass", "{report}");
    assert!(forwarder.h2.lock().await.drivers.is_empty());
    assert!(abort.is_finished());
}

#[tokio::test]
async fn closed_https_pool_rejects_late_h2_install() {
    let forwarder = forwarder();
    let (client, _server) = tokio::io::duplex(65536);
    let (sender, driver) = h2::client::handshake(client).await.unwrap();
    let report = super::super::cache::shutdown_dns_https_forwarder(
        Arc::clone(&forwarder),
        time::Instant::now() + Duration::from_secs(1),
    )
    .await;
    assert_eq!(report["status"], "pass");
    assert!(
        forwarder
            .install_h2(sender, driver, context())
            .await
            .is_err()
    );
    let state = forwarder.h2.lock().await;
    assert!(state.current.is_none());
    assert!(state.drivers.is_empty());
}

#[tokio::test]
async fn goaway_retirement_preserves_an_already_accepted_stream() {
    let forwarder = forwarder();
    let (connection, server) = install(&forwarder).await;
    let query = build_dns_query_packet(42, "goaway.example", DNS_QTYPE_A).unwrap();
    let server_query = query.clone();
    let (accepted, accepted_rx) = tokio::sync::oneshot::channel();
    let (release, release_rx) = tokio::sync::oneshot::channel();
    let peer = tokio::spawn(async move {
        let mut server = h2::server::handshake(server).await.unwrap();
        let (_, response) = server.accept().await.unwrap().unwrap();
        server.graceful_shutdown();
        accepted.send(()).unwrap();
        tokio::select! {
            _ = release_rx => {},
            request = server.accept() => panic!("unexpected request during GOAWAY: {request:?}"),
        }
        send_h2_doh_response(response, &server_query, [192, 0, 2, 5]);
        let _ = server.accept().await;
    });
    let sibling = {
        let forwarder = Arc::clone(&forwarder);
        tokio::spawn(async move { forwarder.exchange_h2(&query, context()).await })
    };
    accepted_rx.await.unwrap();
    let failure = time::timeout(Duration::from_secs(1), async {
        loop {
            match connection.sender.clone().ready().await {
                Err(error) => break error,
                Ok(_) => tokio::task::yield_now().await,
            }
        }
    })
    .await
    .unwrap();
    assert!(DnsH2ExchangeError::transport("GOAWAY", failure).is_connection());
    forwarder.invalidate_h2(&connection, context()).await;
    drop(connection);
    release.send(()).unwrap();
    assert!(sibling.await.unwrap().is_ok());
    peer.await.unwrap();
}

#[tokio::test]
async fn closed_stream_pool_does_not_recycle_an_inflight_success() {
    let pool = AsyncMutex::new(vec![1_u8]);
    let permits = Semaphore::new(1);
    let mut idle = pool.lock().await;
    let recycle = return_dns_stream_to_pool(&pool, &permits, 2_u8);
    tokio::pin!(recycle);
    assert!(futures_util::poll!(&mut recycle).is_pending());
    permits.close();
    idle.clear();
    drop(idle);
    recycle.await;
    assert!(pool.lock().await.is_empty());
}
