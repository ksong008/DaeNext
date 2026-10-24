#[tokio::test]
async fn tcp_dns_leader_rst_does_not_cancel_live_udp_follower() {
    let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let input = format!("global {{}} routing {{}} dns {{ upstream {{ primary: 'tcp://{upstream_addr}' }} routing {{ request {{ fallback: primary }} }} }}");
    let config = dae_config::schema::build_config(&dae_config::parser::parse_config(&input).unwrap()).unwrap();
    let geodata = ResidentGeodataStore::new(Vec::<PathBuf>::new());
    let dns = Arc::new(build_resident_dns_plan_with_refresh_interval(&config, &geodata, Duration::from_secs(60)).unwrap());
    let (leader_sent, leader_seen) = tokio::sync::oneshot::channel();
    let (answer, answer_ready) = tokio::sync::oneshot::channel();
    let upstream_server = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await.unwrap();
        let mut reader = DnsTcpFrameReader::default();
        let _first = reader.read_frame(&mut stream).await.unwrap().unwrap();
        leader_sent.send(()).unwrap();
        let replacement = reader.read_frame(&mut stream).await.unwrap().unwrap();
        answer_ready.await.unwrap();
        let response = dns_a_response_for_test(&replacement, [192, 0, 2, 80]);
        write_dns_tcp_payload_async(&mut stream, &response).await.unwrap();
        let mut byte = [0];
        let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut byte).await;
    });
    let tcp = TokioTcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_addr = tcp.local_addr().unwrap();
    let mut client = TokioTcpStream::connect(local_addr).await.unwrap();
    let (stream, peer) = tcp.accept().await.unwrap();
    let stop = ResidentStopSignal::shared();
    let metrics = Arc::new(ResidentDataplaneMetrics::default());
    let events = std::env::temp_dir().join(format!("daed-dns-flight-{}.jsonl", std::process::id()));
    let event_lock = Arc::new(Mutex::new(()));
    let handler = tokio::spawn(handle_resident_dns_tcp_bind_connection_async(
        stream, peer, local_addr, Arc::clone(&dns), Arc::clone(&metrics), Arc::clone(&stop),
        Arc::new(Semaphore::new(16)), events.clone(), Arc::clone(&event_lock),
        ResidentDnsResourceProfile::from_runtime_profile(ResidentRuntimeProfile::LowMemory),
        Arc::new(Semaphore::new(1)).acquire_owned().await.unwrap(),
    ));
    write_dns_tcp_payload_async(&mut client, &dns_query_for_test(0x1111, "flight.example")).await.unwrap();
    time::timeout(Duration::from_secs(1), leader_seen).await.unwrap().unwrap();
    let udp = Arc::new(TokioUdpSocket::bind("127.0.0.1:0").await.unwrap());
    let udp_client = TokioUdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut dispatcher = ResidentDnsUdpBindDispatcher::start(
        Arc::clone(&udp), local_addr, events.clone(), event_lock, 1, 4,
    );
    udp_client.send_to(&dns_query_for_test(0x2222, "flight.example"), udp.local_addr().unwrap()).await.unwrap();
    let mut buf = [0; 512];
    let (length, peer) = udp.recv_from(&mut buf).await.unwrap();
    assert!(dispatcher.try_dispatch(ResidentDnsUdpBindJob {
        peer, dns: Arc::clone(&dns), metrics, request: buf[..length].to_vec(),
        flow_stop: Arc::clone(&stop), permit: Arc::new(Semaphore::new(1)).acquire_owned().await.unwrap(),
    }).is_ok());
    time::timeout(Duration::from_secs(1), async {
        while dns.cache.flight_follower_count() != 1 { tokio::task::yield_now().await; }
    }).await.expect("UDP never became a follower of the TCP leader");
    // Force an actual RST only after proving the single-flight relationship.
    let socket = client.into_std().unwrap();
    let linger = libc::linger { l_onoff: 1, l_linger: 0 };
    // SAFETY: socket is owned here; linger has the expected ABI and lifetime.
    assert_eq!(unsafe { libc::setsockopt(socket.as_raw_fd(), libc::SOL_SOCKET, libc::SO_LINGER,
        (&linger as *const libc::linger).cast(), std::mem::size_of_val(&linger) as _) }, 0);
    drop(socket);
    time::timeout(Duration::from_secs(1), handler).await.unwrap().unwrap();
    answer.send(()).unwrap();
    let length = time::timeout(Duration::from_secs(2), udp_client.recv(&mut buf)).await.unwrap().unwrap();
    assert_eq!(dns_packet_id_for_test(&buf[..length]), 0x2222);
    assert_eq!(&buf[length - 4..length], &[192, 0, 2, 80]);
    assert_eq!(dns.cache.inflight_len(), 0);
    assert_eq!(dns.cache.flight_retained_bytes(), 0);
    dispatcher.shutdown(Duration::from_secs(1)).await;
    assert_eq!(dns.shutdown_forwarders(time::Instant::now() + Duration::from_secs(1)).await["status"], "pass");
    upstream_server.await.unwrap();
    let _ = std::fs::remove_file(events);
}

#[tokio::test]
async fn aborting_tcp_dns_handler_drops_its_writer_socket_and_connection_budget() {
    use tokio::io::AsyncReadExt;
    let listener = TokioTcpListener::bind("127.0.0.1:0").await.unwrap();
    let local = listener.local_addr().unwrap();
    let mut client = TokioTcpStream::connect(local).await.unwrap();
    let (stream, peer) = listener.accept().await.unwrap();
    let permits = Arc::new(Semaphore::new(1));
    let metrics = Arc::new(ResidentDataplaneMetrics::default());
    let handler = tokio::spawn(handle_resident_dns_tcp_bind_connection_async(
        stream, peer, local, Arc::new(ResidentDnsPlan::asis(0)), Arc::clone(&metrics),
        ResidentStopSignal::shared(), Arc::new(Semaphore::new(1)),
        std::env::temp_dir().join("unused-dns-abort-test.jsonl"), Arc::new(Mutex::new(())),
        ResidentDnsResourceProfile::from_runtime_profile(ResidentRuntimeProfile::LowMemory),
        Arc::clone(&permits).acquire_owned().await.unwrap(),
    ));
    time::timeout(Duration::from_secs(1), async {
        while metrics.snapshot()["activeTcpConnections"] != 1 {
            tokio::task::yield_now().await;
        }
    }).await.unwrap();
    handler.abort();
    assert!(handler.await.unwrap_err().is_cancelled());
    let mut byte = [0];
    assert_eq!(time::timeout(Duration::from_secs(1), client.read(&mut byte)).await.unwrap().unwrap(), 0);
    assert_eq!(permits.available_permits(), 1);
    assert_eq!(metrics.snapshot()["activeTcpConnections"], 0);
}
