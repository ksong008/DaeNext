use super::*;
use std::sync::atomic::Ordering;
use std::time::Duration;

fn context() -> ProxyDnsRequestContext {
    ProxyDnsRequestContext::from_timeout(Duration::from_secs(1))
}

fn forwarder(target: SocketAddr) -> Arc<ResidentDnsTcpForwarder> {
    let mut upstream = super::super::tls_https::tests::h2_test_upstream();
    upstream.scheme = ResidentDnsUpstreamScheme::Tcp;
    ResidentDnsForwarderCache::default()
        .tcp_forwarder(
            &upstream,
            target,
            0,
            &ResidentDnsUpstreamSelection::Direct { mark: 0 },
        )
        .unwrap()
}

#[tokio::test]
async fn shutdown_rejects_a_tcp_connection_opened_before_close() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let forwarder = forwarder(listener.local_addr().unwrap());
    let (handle, actor) = forwarder.open_connection(context()).await.unwrap();
    let (mut peer, _) = listener.accept().await.unwrap();
    let report = super::super::cache::shutdown_dns_tcp_forwarder(
        Arc::clone(&forwarder),
        time::Instant::now() + Duration::from_secs(1),
    )
    .await;
    assert_eq!(report["status"], "pass");
    assert!(
        forwarder
            .install_connection(handle.clone(), actor, context())
            .await
            .is_err()
    );
    assert!(handle.is_closed());
    assert!(forwarder.connections.lock().await.is_empty());
    let mut byte = [0];
    assert_eq!(
        time::timeout(Duration::from_secs(1), peer.read(&mut byte))
            .await
            .unwrap()
            .unwrap(),
        0
    );
}

#[tokio::test]
async fn cancelling_tcp_reap_keeps_handle_until_join_and_records_panic() {
    let forwarder = forwarder("127.0.0.1:53".parse().unwrap());
    let (handle, _registration) = ResidentDnsTcpMultiplexHandle::new(1);
    handle.close();
    let (release, released) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(async {
        let _ = released.await;
        panic!("actor failure");
    });
    forwarder
        .connections
        .lock()
        .await
        .push(ResidentDnsTcpMultiplexConnection { handle, task });
    {
        let reap = forwarder.reap_closed_connections(context());
        tokio::pin!(reap);
        assert!(futures_util::poll!(&mut reap).is_pending());
    }
    assert_eq!(forwarder.connections.lock().await.len(), 1);
    release.send(()).unwrap();
    forwarder.reap_closed_connections(context()).await.unwrap();
    assert!(forwarder.connections.lock().await.is_empty());
    assert_eq!(forwarder.task_failures.load(Ordering::Relaxed), 1);
}
