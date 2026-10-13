use super::*;
use quinn::AsyncUdpSocket;

#[tokio::test]
async fn poisoned_hop_freezes_paths_but_keeps_the_owned_socket_usable() {
    let remote = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let destination = remote.local_addr().unwrap();
    let runtime = quinn::default_runtime().unwrap();
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let bind = socket.local_addr().unwrap();
    let metrics = Arc::new(Hysteria2PortHoppingMetrics::default());
    metrics.socket_opened();
    let state = Arc::new(Hysteria2PortHoppingState {
        runtime: Arc::clone(&runtime),
        addresses: Arc::new(vec![destination.ip()]),
        ports: Arc::new(vec![destination.port()]),
        interval: Duration::from_secs(1),
        mark: 0,
        transition_socket_limit: 3,
        bind,
        logical_remote: destination,
        metrics: Arc::clone(&metrics),
        paths: std::sync::RwLock::new(Hysteria2PortHoppingPaths {
            current: runtime.wrap_udp_socket(socket).unwrap(),
            previous: None,
            destination,
            generation: 1,
        }),
    });
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = state.paths.write().unwrap();
        panic!("injected hop poison");
    }));
    state.hop();
    let socket = Arc::new(Hysteria2PortHoppingUdpSocket {
        state: Arc::clone(&state),
        poll_previous_first: AtomicBool::new(false),
    });
    assert_eq!(socket.local_addr().unwrap(), bind);
    let mut poller = Arc::clone(&socket).create_io_poller();
    poll_fn(|cx| poller.as_mut().poll_writable(cx))
        .await
        .unwrap();
    socket
        .try_send(&udp::Transmit {
            destination,
            ecn: None,
            contents: b"test",
            segment_size: None,
            src_ip: None,
        })
        .unwrap();
    let mut bytes = [0; 4];
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), remote.recv(&mut bytes))
            .await
            .unwrap()
            .unwrap(),
        4
    );
    assert_eq!(&bytes, b"test");
    assert_eq!(state.paths.read().err().unwrap().into_inner().generation, 1);
    drop(poller);
    drop(socket);
    drop(state);
    assert_eq!(metrics.active_sockets.load(Ordering::Acquire), 0);
}
