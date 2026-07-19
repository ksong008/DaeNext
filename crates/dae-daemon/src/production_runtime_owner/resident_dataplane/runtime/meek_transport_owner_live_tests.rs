use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use dae_outbound::shared_transport::MeekRoundTripOptions;
use rcgen::generate_simple_self_signed;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::time;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls;
use tokio_rustls::rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

use super::*;

static NEXT_MEEK_TEST_GENERATION: AtomicU64 = AtomicU64::new(90_000);

enum MeekTestReply {
    Echo,
    Close,
    LyingLength,
    Gated(Arc<Semaphore>),
}

struct MeekTestServer {
    address: SocketAddr,
    tcp_connections: Arc<AtomicUsize>,
    tls_handshakes: Arc<AtomicUsize>,
    requests: Arc<AtomicUsize>,
    session_ids: Arc<Mutex<Vec<String>>>,
    bodies: Arc<Mutex<Vec<Vec<u8>>>>,
    stop: SharedResidentStopSignal,
    task: tokio::task::JoinHandle<()>,
}

impl MeekTestServer {
    async fn start(replies: Vec<MeekTestReply>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let tcp_connections = Arc::new(AtomicUsize::new(0));
        let tls_handshakes = Arc::new(AtomicUsize::new(0));
        let requests = Arc::new(AtomicUsize::new(0));
        let session_ids = Arc::new(Mutex::new(Vec::new()));
        let bodies = Arc::new(Mutex::new(Vec::new()));
        let replies = Arc::new(Mutex::new(VecDeque::from(replies)));
        let stop = ResidentStopSignal::shared();
        let task_stop = Arc::clone(&stop);
        let task_tcp_connections = Arc::clone(&tcp_connections);
        let task_tls_handshakes = Arc::clone(&tls_handshakes);
        let task_requests = Arc::clone(&requests);
        let task_session_ids = Arc::clone(&session_ids);
        let task_bodies = Arc::clone(&bodies);
        let task_replies = Arc::clone(&replies);
        let acceptor = meek_test_tls_acceptor();
        let task = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            let mut stop_listener = task_stop.listener();
            loop {
                tokio::select! {
                    _ = stop_listener.cancelled() => break,
                    accepted = listener.accept() => {
                        let Ok((stream, _)) = accepted else {
                            break;
                        };
                        task_tcp_connections.fetch_add(1, Ordering::Relaxed);
                        let connection_acceptor = acceptor.clone();
                        let connection_handshakes = Arc::clone(&task_tls_handshakes);
                        let connection_requests = Arc::clone(&task_requests);
                        let connection_session_ids = Arc::clone(&task_session_ids);
                        let connection_bodies = Arc::clone(&task_bodies);
                        let connection_replies = Arc::clone(&task_replies);
                        connections.spawn(async move {
                            let Ok(stream) = connection_acceptor.accept(stream).await else {
                                return;
                            };
                            connection_handshakes.fetch_add(1, Ordering::Relaxed);
                            serve_meek_test_connection(
                                stream,
                                connection_requests,
                                connection_session_ids,
                                connection_bodies,
                                connection_replies,
                            )
                            .await;
                        });
                    }
                    completion = connections.join_next(), if !connections.is_empty() => {
                        let _ = completion;
                    }
                }
            }
            connections.abort_all();
            while connections.join_next().await.is_some() {}
        });
        Self {
            address,
            tcp_connections,
            tls_handshakes,
            requests,
            session_ids,
            bodies,
            stop,
            task,
        }
    }

    async fn wait_for_requests(&self, expected: usize) {
        time::timeout(Duration::from_secs(2), async {
            while self.requests.load(Ordering::Relaxed) < expected {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    async fn stop(self) {
        self.stop.store(true, Ordering::Release);
        self.task.await.unwrap();
    }
}

async fn serve_meek_test_connection(
    mut stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    requests: Arc<AtomicUsize>,
    session_ids: Arc<Mutex<Vec<String>>>,
    bodies: Arc<Mutex<Vec<Vec<u8>>>>,
    replies: Arc<Mutex<VecDeque<MeekTestReply>>>,
) {
    let mut buffered = Vec::new();
    loop {
        let Some((session_id, body)) = read_meek_test_request(&mut stream, &mut buffered).await
        else {
            return;
        };
        requests.fetch_add(1, Ordering::Relaxed);
        session_ids.lock().unwrap().push(session_id);
        bodies.lock().unwrap().push(body.clone());
        let reply = replies
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(MeekTestReply::Echo);
        match reply {
            MeekTestReply::Echo => {
                if write_meek_test_response(&mut stream, &body, false)
                    .await
                    .is_err()
                {
                    return;
                }
            }
            MeekTestReply::Close => {
                let _ = write_meek_test_response(&mut stream, &body, true).await;
                let _ = stream.shutdown().await;
                return;
            }
            MeekTestReply::LyingLength => {
                let _ = stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nab")
                    .await;
                let _ = stream.flush().await;
                return;
            }
            MeekTestReply::Gated(gate) => {
                let Ok(permit) = gate.acquire().await else {
                    return;
                };
                permit.forget();
                if write_meek_test_response(&mut stream, &body, false)
                    .await
                    .is_err()
                {
                    return;
                }
            }
        }
    }
}

async fn read_meek_test_request(
    stream: &mut tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    buffered: &mut Vec<u8>,
) -> Option<(String, Vec<u8>)> {
    let head_end = loop {
        if let Some(index) = buffered.windows(4).position(|window| window == b"\r\n\r\n") {
            break index + 4;
        }
        let mut chunk = [0_u8; 1024];
        let read = stream.read(&mut chunk).await.ok()?;
        if read == 0 {
            return None;
        }
        buffered.extend_from_slice(&chunk[..read]);
    };
    let head = std::str::from_utf8(&buffered[..head_end]).ok()?;
    let content_length =
        test_header_value(head, "content-length").and_then(|value| value.parse::<usize>().ok())?;
    let session_id = test_header_value(head, "x-session-id")?.to_owned();
    while buffered.len() < head_end.saturating_add(content_length) {
        let mut chunk = [0_u8; 1024];
        let read = stream.read(&mut chunk).await.ok()?;
        if read == 0 {
            return None;
        }
        buffered.extend_from_slice(&chunk[..read]);
    }
    let body = buffered[head_end..head_end + content_length].to_vec();
    buffered.drain(..head_end + content_length);
    Some((session_id, body))
}

fn test_header_value<'a>(head: &'a str, wanted: &str) -> Option<&'a str> {
    head.split("\r\n").skip(1).find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case(wanted).then(|| value.trim())
    })
}

async fn write_meek_test_response(
    stream: &mut tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    body: &[u8],
    close: bool,
) -> std::io::Result<()> {
    let connection = if close { "Connection: close\r\n" } else { "" };
    let head = format!(
        "HTTP/1.1 200 OK\r\n{connection}Content-Length: {}\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.flush().await
}

fn meek_test_tls_acceptor() -> TlsAcceptor {
    let certified = generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let certificate = certified.cert.der().clone();
    let private_key =
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der()));
    let mut config =
        rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_no_client_auth()
            .with_single_cert(vec![certificate], private_key)
            .unwrap();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    TlsAcceptor::from(Arc::new(config))
}

fn meek_test_proxy(
    address: SocketAddr,
    generation: u64,
    graph_link_hash: &str,
) -> Arc<plan::ResidentProxyPlan> {
    let mut proxy = plan::ResidentProxyPlan {
        graph_id: format!("resident-graph:{graph_link_hash}"),
        graph_link_hash: graph_link_hash.to_owned(),
        redacted_link_source: "vless://<redacted>".to_owned(),
        protocol: "vless",
        group_name: "meek-owner-test".to_owned(),
        group_policy: "fixed".to_owned(),
        node_tag: "meek-owner-node".to_owned(),
        server_host: address.ip().to_string(),
        server_port: address.port(),
        server_name: "localhost".to_owned(),
        alpn: vec!["http/1.1".to_owned()],
        flow: String::new(),
        net: "meek".to_owned(),
        stream_host: "localhost".to_owned(),
        stream_path: "/owner-test".to_owned(),
        xhttp_download: None,
        xhttp_mode: plan::ResidentXhttpMode::PacketUp,
        xhttp_settings: plan::ResidentXhttpSettingsPlan::default(),
        xhttp_xmux: None,
        tls: "tls".to_owned(),
        allow_insecure: true,
        tls_fragment: None,
        utls_fingerprint: None,
        reality: None,
        handler: plan::ResidentProxyProtocolPlan::VlessVisionTcpTls { key: [9; 16] },
        execution: None,
        chain_parent: None,
        mark: 0,
        mptcp: false,
    };
    proxy.apply_runtime_generation(generation);
    Arc::new(proxy)
}

fn meek_test_options(session: &[u8]) -> MeekRoundTripOptions {
    MeekRoundTripOptions {
        url: "https://localhost/owner-test".to_owned(),
        host: "localhost".to_owned(),
        path: "/owner-test".to_owned(),
        session_tag: session.to_vec(),
    }
}

fn meek_owner_deadline(duration: Duration) -> dae_runtime_control::AbsoluteDeadline {
    dae_runtime_control::AbsoluteDeadline::from_now(Instant::now(), duration)
}

async fn meek_round_trip_from_fresh_runtime(
    proxy: Arc<plan::ResidentProxyPlan>,
    options: MeekRoundTripOptions,
    body: Vec<u8>,
) -> Result<Vec<u8>, String> {
    tokio::task::spawn_blocking(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .unwrap()
            .block_on(tcp::meek_round_trip_async(&proxy, &options, &body))
    })
    .await
    .unwrap()
}

async fn stop_meek_owner(stop: SharedResidentStopSignal, thread: std::thread::JoinHandle<()>) {
    stop.store(true, Ordering::Release);
    tokio::task::spawn_blocking(move || thread.join().unwrap())
        .await
        .unwrap();
}

fn assert_meek_owner_released(owner: &MeekTransportGenerationOwnerHandle) {
    let metrics = owner.metrics_snapshot();
    assert_eq!(metrics["registeredKeys"], 0);
    assert_eq!(metrics["registeredBuildTasks"], 0);
    assert_eq!(metrics["reservedPhysicalConnections"], 0);
    assert_eq!(metrics["activePhysicalConnections"], 0);
    assert_eq!(metrics["activeLeases"], 0);
    assert_eq!(metrics["idlePhysicalConnections"], 0);
    assert_eq!(metrics["activeBuilds"], 0);
    assert_eq!(metrics["ownerStateBytesLowerBound"], 0);
    assert_eq!(metrics["shutdownTimedOut"], false);
}

#[test]
fn meek_transport_reuses_one_physical_across_caller_runtimes_and_sessions() {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_io()
        .enable_time()
        .build()
        .unwrap()
        .block_on(async {
            let server =
                MeekTestServer::start(vec![MeekTestReply::Echo, MeekTestReply::Echo]).await;
            let generation = NEXT_MEEK_TEST_GENERATION.fetch_add(1, Ordering::Relaxed);
            let proxy = meek_test_proxy(server.address, generation, "sha256:meek-reuse");
            let stop = ResidentStopSignal::shared();
            let (owner, owner_thread) = start_meek_transport_generation_owner(
                generation,
                Arc::clone(&stop),
                RESIDENT_TCP_FLOW_STACK_BYTES_DEFAULT,
                2,
            )
            .unwrap();

            let first = meek_round_trip_from_fresh_runtime(
                Arc::clone(&proxy),
                meek_test_options(b"session-a"),
                b"first".to_vec(),
            )
            .await
            .unwrap();
            let second = meek_round_trip_from_fresh_runtime(
                Arc::clone(&proxy),
                meek_test_options(b"session-b"),
                b"second".to_vec(),
            )
            .await
            .unwrap();
            assert_eq!(first, b"first");
            assert_eq!(second, b"second");
            assert_eq!(server.tcp_connections.load(Ordering::Relaxed), 1);
            assert_eq!(server.tls_handshakes.load(Ordering::Relaxed), 1);
            assert_eq!(
                server.bodies.lock().unwrap().as_slice(),
                [b"first".to_vec(), b"second".to_vec()]
            );
            {
                let sessions = server.session_ids.lock().unwrap();
                assert_eq!(sessions.len(), 2);
                assert_ne!(sessions[0], sessions[1]);
            }
            let metrics = owner.metrics_snapshot();
            assert_eq!(metrics["executor"], "multi-thread");
            assert_eq!(metrics["runtimeWorkerThreads"], 2);
            assert_eq!(metrics["cumulativeBuilds"], 1);
            assert_eq!(metrics["cumulativeReuses"], 1);
            assert_eq!(metrics["idlePhysicalConnections"], 1);

            stop_meek_owner(stop, owner_thread).await;
            assert_meek_owner_released(&owner);
            server.stop().await;
        });
}

#[test]
fn meek_transport_retires_close_and_lying_framing_without_replay() {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_io()
        .enable_time()
        .build()
        .unwrap()
        .block_on(async {
            let server = MeekTestServer::start(vec![
                MeekTestReply::Close,
                MeekTestReply::LyingLength,
                MeekTestReply::Echo,
            ])
            .await;
            let generation = NEXT_MEEK_TEST_GENERATION.fetch_add(1, Ordering::Relaxed);
            let proxy = meek_test_proxy(server.address, generation, "sha256:meek-retire");
            let stop = ResidentStopSignal::shared();
            let (owner, owner_thread) = start_meek_transport_generation_owner(
                generation,
                Arc::clone(&stop),
                RESIDENT_TCP_FLOW_STACK_BYTES_DEFAULT,
                1,
            )
            .unwrap();

            assert_eq!(
                tcp::meek_round_trip_async(&proxy, &meek_test_options(b"close"), b"a")
                    .await
                    .unwrap(),
                b"a"
            );
            let lying = tcp::meek_round_trip_async(&proxy, &meek_test_options(b"lying"), b"b")
                .await
                .unwrap_err();
            assert!(lying.contains("beyond Content-Length"), "{lying}");
            assert_eq!(
                tcp::meek_round_trip_async(&proxy, &meek_test_options(b"rebuild"), b"c")
                    .await
                    .unwrap(),
                b"c"
            );
            assert_eq!(server.requests.load(Ordering::Relaxed), 3);
            assert_eq!(server.tcp_connections.load(Ordering::Relaxed), 3);
            assert_eq!(
                server.bodies.lock().unwrap().as_slice(),
                [b"a".to_vec(), b"b".to_vec(), b"c".to_vec()]
            );
            let metrics = owner.metrics_snapshot();
            assert_eq!(metrics["cumulativeBuilds"], 3);
            assert_eq!(metrics["cumulativeReuses"], 0);
            assert_eq!(metrics["idlePhysicalConnections"], 1);

            stop_meek_owner(stop, owner_thread).await;
            assert_meek_owner_released(&owner);
            server.stop().await;
        });
}

#[test]
fn cancelled_meek_poll_retires_uncertain_physical_and_generations_drain() {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_io()
        .enable_time()
        .build()
        .unwrap()
        .block_on(async {
            let gate = Arc::new(Semaphore::new(0));
            let server = MeekTestServer::start(vec![
                MeekTestReply::Gated(Arc::clone(&gate)),
                MeekTestReply::Echo,
            ])
            .await;
            let generation = NEXT_MEEK_TEST_GENERATION.fetch_add(1, Ordering::Relaxed);
            let proxy = meek_test_proxy(server.address, generation, "sha256:meek-cancel");
            let stop = ResidentStopSignal::shared();
            let (owner, owner_thread) = start_meek_transport_generation_owner(
                generation,
                Arc::clone(&stop),
                RESIDENT_TCP_FLOW_STACK_BYTES_DEFAULT,
                2,
            )
            .unwrap();
            let cancelled_proxy = Arc::clone(&proxy);
            let cancelled = tokio::spawn(async move {
                tcp::meek_round_trip_async(
                    &cancelled_proxy,
                    &meek_test_options(b"cancelled"),
                    b"uncertain",
                )
                .await
            });
            server.wait_for_requests(1).await;
            cancelled.abort();
            assert!(cancelled.await.unwrap_err().is_cancelled());
            gate.add_permits(1);

            assert_eq!(
                tcp::meek_round_trip_async(&proxy, &meek_test_options(b"survivor"), b"safe")
                    .await
                    .unwrap(),
                b"safe"
            );
            assert_eq!(server.requests.load(Ordering::Relaxed), 2);
            assert_eq!(server.tcp_connections.load(Ordering::Relaxed), 2);
            assert_eq!(
                server.bodies.lock().unwrap().as_slice(),
                [b"uncertain".to_vec(), b"safe".to_vec()]
            );

            stop_meek_owner(stop, owner_thread).await;
            assert_meek_owner_released(&owner);
            server.stop().await;

            for cycle in 0..5_u64 {
                let generation = NEXT_MEEK_TEST_GENERATION.fetch_add(1, Ordering::Relaxed);
                let server = MeekTestServer::start(vec![MeekTestReply::Echo]).await;
                let proxy = meek_test_proxy(
                    server.address,
                    generation,
                    &format!("sha256:meek-cycle-{cycle}"),
                );
                let stop = ResidentStopSignal::shared();
                let (owner, owner_thread) = start_meek_transport_generation_owner(
                    generation,
                    Arc::clone(&stop),
                    RESIDENT_TCP_FLOW_STACK_BYTES_DEFAULT,
                    1,
                )
                .unwrap();
                assert_eq!(
                    tcp::meek_round_trip_async(&proxy, &meek_test_options(b"cycle"), b"payload")
                        .await
                        .unwrap(),
                    b"payload"
                );
                stop_meek_owner(stop, owner_thread).await;
                assert_meek_owner_released(&owner);
                server.stop().await;
            }
        });
}

#[test]
fn meek_transport_partitions_keys_and_expires_idle_physicals() {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_io()
        .enable_time()
        .build()
        .unwrap()
        .block_on(async {
            let server = MeekTestServer::start(vec![
                MeekTestReply::Echo,
                MeekTestReply::Echo,
                MeekTestReply::Echo,
                MeekTestReply::Echo,
            ])
            .await;
            let generation = NEXT_MEEK_TEST_GENERATION.fetch_add(1, Ordering::Relaxed);
            let first_proxy = meek_test_proxy(server.address, generation, "sha256:meek-key-a");
            let second_proxy = meek_test_proxy(server.address, generation, "sha256:meek-key-b");
            let resources = MeekTransportResourceProfile::from_runtime_profile(
                ResidentRuntimeProfile::LowMemory,
            )
            .with_transport_limits_for_test(2, 2, 1, Duration::from_millis(500));
            let stop = ResidentStopSignal::shared();
            let (owner, owner_thread) = start_meek_transport_generation_owner_for_test(
                generation,
                Arc::clone(&stop),
                RESIDENT_TCP_FLOW_STACK_BYTES_DEFAULT,
                1,
                resources,
            )
            .unwrap();

            assert_eq!(
                tcp::meek_round_trip_async(&first_proxy, &meek_test_options(b"key-a-1"), b"a1")
                    .await
                    .unwrap(),
                b"a1"
            );
            assert_eq!(
                tcp::meek_round_trip_async(&second_proxy, &meek_test_options(b"key-b"), b"b")
                    .await
                    .unwrap(),
                b"b"
            );
            assert_eq!(
                tcp::meek_round_trip_async(&first_proxy, &meek_test_options(b"key-a-2"), b"a2")
                    .await
                    .unwrap(),
                b"a2"
            );
            assert_eq!(server.tcp_connections.load(Ordering::Relaxed), 2);
            assert_eq!(owner.metrics_snapshot()["cumulativeReuses"], 1);

            time::timeout(Duration::from_secs(2), async {
                loop {
                    let metrics = owner.metrics_snapshot();
                    if metrics["idlePhysicalConnections"] == 0
                        && metrics["activePhysicalConnections"] == 0
                        && metrics["reservedPhysicalConnections"] == 0
                        && metrics["cumulativeIdleExpirations"] == 2
                    {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            let expired = owner.metrics_snapshot();
            assert_eq!(expired["activePhysicalConnections"], 0);
            assert_eq!(expired["reservedPhysicalConnections"], 0);
            assert_eq!(expired["cumulativeIdleExpirations"], 2);

            assert_eq!(
                tcp::meek_round_trip_async(&first_proxy, &meek_test_options(b"key-a-3"), b"a3")
                    .await
                    .unwrap(),
                b"a3"
            );
            assert_eq!(server.tcp_connections.load(Ordering::Relaxed), 3);

            stop_meek_owner(stop, owner_thread).await;
            assert_meek_owner_released(&owner);
            server.stop().await;
        });
}

#[test]
fn meek_transport_enforces_owner_and_physical_capacity() {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_io()
        .enable_time()
        .build()
        .unwrap()
        .block_on(async {
            let server = MeekTestServer::start(Vec::new()).await;
            let generation = NEXT_MEEK_TEST_GENERATION.fetch_add(1, Ordering::Relaxed);
            let first_proxy = meek_test_proxy(server.address, generation, "sha256:meek-limit-a");
            let second_proxy = meek_test_proxy(server.address, generation, "sha256:meek-limit-b");
            let resources = MeekTransportResourceProfile::from_runtime_profile(
                ResidentRuntimeProfile::LowMemory,
            )
            .with_transport_limits_for_test(1, 1, 1, Duration::from_secs(1));
            let missing_owner = acquire_meek_transport(
                Arc::clone(&first_proxy),
                meek_owner_deadline(Duration::from_millis(40)),
            )
            .await
            .err()
            .expect("Meek acquisition without a generation owner must fail");
            assert!(missing_owner.contains("is unavailable"), "{missing_owner}");
            assert_eq!(server.tcp_connections.load(Ordering::Relaxed), 0);
            let stop = ResidentStopSignal::shared();
            let (owner, owner_thread) = start_meek_transport_generation_owner_for_test(
                generation,
                Arc::clone(&stop),
                RESIDENT_TCP_FLOW_STACK_BYTES_DEFAULT,
                1,
                resources,
            )
            .unwrap();

            let first = acquire_meek_transport(
                Arc::clone(&first_proxy),
                meek_owner_deadline(Duration::from_secs(1)),
            )
            .await
            .unwrap();
            let capacity = acquire_meek_transport(
                Arc::clone(&first_proxy),
                meek_owner_deadline(Duration::from_millis(40)),
            )
            .await
            .err()
            .expect("second physical acquisition must reach the capacity deadline");
            assert!(capacity.contains("capacity deadline"), "{capacity}");
            let owner_limit =
                acquire_meek_transport(second_proxy, meek_owner_deadline(Duration::from_secs(1)))
                    .await
                    .err()
                    .expect("a second transport key must exceed the owner budget");
            assert!(owner_limit.contains("owner budget"), "{owner_limit}");

            first.recycle();
            let reused =
                acquire_meek_transport(first_proxy, meek_owner_deadline(Duration::from_secs(1)))
                    .await
                    .unwrap();
            reused.recycle();
            let metrics = owner.metrics_snapshot();
            assert_eq!(metrics["registeredKeys"], 1);
            assert_eq!(metrics["reservedPhysicalConnections"], 1);
            assert_eq!(metrics["idlePhysicalConnections"], 1);
            assert_eq!(metrics["cumulativeBuilds"], 1);
            assert_eq!(metrics["cumulativeReuses"], 1);
            assert_eq!(metrics["ownerLimitRejections"], 1);
            assert!(metrics["capacityWaits"].as_u64().unwrap() >= 1);

            stop_meek_owner(stop, owner_thread).await;
            assert_meek_owner_released(&owner);
            server.stop().await;
        });
}
