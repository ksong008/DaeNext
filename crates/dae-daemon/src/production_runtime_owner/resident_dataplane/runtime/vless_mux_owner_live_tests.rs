use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use dae_outbound::shared_transport::mux::{
    MuxFrameDecoder, MuxFrameOptions, SESSION_STATUS_END, SESSION_STATUS_KEEP, SESSION_STATUS_NEW,
    mux_data_frame, mux_new_frame,
};
use rcgen::generate_simple_self_signed;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls;
use tokio_rustls::rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

use super::vless_mux_owner::VlessMuxLogicalStream;
use super::*;

static NEXT_VLESS_MUX_TEST_GENERATION: AtomicU64 = AtomicU64::new(110_000);

#[derive(Clone, Copy)]
enum VlessMuxTestInjection {
    UnknownSid,
    ServerNew,
}

struct VlessMuxTestServer {
    address: SocketAddr,
    tcp_connections: Arc<AtomicUsize>,
    new_sids: Arc<Mutex<Vec<u16>>>,
    payloads: Arc<Mutex<Vec<(u16, Vec<u8>)>>>,
    unknown_ends: Arc<AtomicUsize>,
    close_connections: Arc<tokio::sync::Notify>,
    stop: SharedResidentStopSignal,
    task: tokio::task::JoinHandle<()>,
}

impl VlessMuxTestServer {
    async fn start() -> Self {
        Self::start_with_injection(None).await
    }

    async fn start_with_injection(injection: Option<VlessMuxTestInjection>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let tcp_connections = Arc::new(AtomicUsize::new(0));
        let new_sids = Arc::new(Mutex::new(Vec::new()));
        let payloads = Arc::new(Mutex::new(Vec::new()));
        let unknown_ends = Arc::new(AtomicUsize::new(0));
        let injection = Arc::new(Mutex::new(injection));
        let close_connections = Arc::new(tokio::sync::Notify::new());
        let stop = ResidentStopSignal::shared();
        let task_stop = Arc::clone(&stop);
        let task_connections = Arc::clone(&tcp_connections);
        let task_new_sids = Arc::clone(&new_sids);
        let task_payloads = Arc::clone(&payloads);
        let task_unknown_ends = Arc::clone(&unknown_ends);
        let task_injection = Arc::clone(&injection);
        let task_close_connections = Arc::clone(&close_connections);
        let acceptor = vless_mux_test_tls_acceptor();
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
                        task_connections.fetch_add(1, Ordering::Relaxed);
                        let connection_acceptor = acceptor.clone();
                        let connection_new_sids = Arc::clone(&task_new_sids);
                        let connection_payloads = Arc::clone(&task_payloads);
                        let connection_unknown_ends = Arc::clone(&task_unknown_ends);
                        let connection_injection = Arc::clone(&task_injection);
                        let connection_close = Arc::clone(&task_close_connections);
                        connections.spawn(async move {
                            let Ok(stream) = connection_acceptor.accept(stream).await else {
                                return;
                            };
                            serve_vless_mux_test_connection(
                                stream,
                                connection_new_sids,
                                connection_payloads,
                                connection_unknown_ends,
                                connection_injection,
                                connection_close,
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
            new_sids,
            payloads,
            unknown_ends,
            close_connections,
            stop,
            task,
        }
    }

    fn close_all_connections(&self) {
        self.close_connections.notify_waiters();
    }

    async fn stop(self) {
        self.stop.store(true, Ordering::Release);
        self.task.await.unwrap();
    }
}

async fn serve_vless_mux_test_connection(
    mut stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    new_sids: Arc<Mutex<Vec<u16>>>,
    payloads: Arc<Mutex<Vec<(u16, Vec<u8>)>>>,
    unknown_ends: Arc<AtomicUsize>,
    injection: Arc<Mutex<Option<VlessMuxTestInjection>>>,
    close_connections: Arc<tokio::sync::Notify>,
) {
    let mut header = [0_u8; 19];
    if stream.read_exact(&mut header).await.is_err()
        || header[0] != 0
        || header[17] != 0
        || header[18] != 0x03
    {
        return;
    }
    if stream.write_all(&[0, 0]).await.is_err() || stream.flush().await.is_err() {
        return;
    }
    let mut decoder = MuxFrameDecoder::default();
    let mut active = HashSet::<u16>::new();
    let mut buffer = [0_u8; 4096];
    loop {
        let read = tokio::select! {
            _ = close_connections.notified() => {
                let _ = stream.shutdown().await;
                return;
            }
            read = stream.read(&mut buffer) => read,
        };
        let Ok(read) = read else {
            return;
        };
        if read == 0 {
            return;
        }
        let Ok(frames) = decoder.push(&buffer[..read]) else {
            return;
        };
        for frame in frames {
            let sid = u16::from_be_bytes(frame.id);
            match frame.status {
                SESSION_STATUS_NEW => {
                    active.insert(sid);
                    new_sids.lock().unwrap().push(sid);
                    let injected = injection.lock().unwrap().take();
                    let injected_frame = match injected {
                        Some(VlessMuxTestInjection::UnknownSid) => {
                            mux_data_frame(u16::MAX.to_be_bytes(), b"unknown").ok()
                        }
                        Some(VlessMuxTestInjection::ServerNew) => mux_new_frame(
                            &MuxFrameOptions::new(u16::MAX.to_be_bytes(), "127.0.0.1", 80, "tcp"),
                        )
                        .ok(),
                        None => None,
                    };
                    if let Some(injected_frame) = injected_frame
                        && (stream.write_all(&injected_frame).await.is_err()
                            || stream.flush().await.is_err())
                    {
                        return;
                    }
                }
                SESSION_STATUS_KEEP if active.contains(&sid) => {
                    payloads.lock().unwrap().push((sid, frame.payload.clone()));
                    let Ok(response) = mux_data_frame(frame.id, &frame.payload) else {
                        return;
                    };
                    if stream.write_all(&response).await.is_err() || stream.flush().await.is_err() {
                        return;
                    }
                }
                SESSION_STATUS_END => {
                    if sid == u16::MAX {
                        unknown_ends.fetch_add(1, Ordering::Relaxed);
                    }
                    active.remove(&sid);
                }
                _ => {}
            }
        }
    }
}

fn vless_mux_test_tls_acceptor() -> TlsAcceptor {
    let certified = generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let certificate = certified.cert.der().clone();
    let private_key =
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der()));
    let config = rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_no_client_auth()
        .with_single_cert(vec![certificate], private_key)
        .unwrap();
    TlsAcceptor::from(Arc::new(config))
}

fn vless_mux_test_proxy(
    address: SocketAddr,
    generation: u64,
    graph_link_hash: &str,
) -> Arc<plan::ResidentProxyPlan> {
    let mut proxy = plan::ResidentProxyPlan {
        graph_id: format!("resident-graph:{graph_link_hash}"),
        graph_link_hash: graph_link_hash.to_owned(),
        redacted_link_source: "vless://<redacted>".to_owned(),
        protocol: "vless",
        group_name: "mux-owner-test".to_owned(),
        group_policy: "fixed".to_owned(),
        node_tag: "mux-owner-node".to_owned(),
        server_host: address.ip().to_string(),
        server_port: address.port(),
        server_name: "localhost".to_owned(),
        alpn: Vec::new(),
        flow: String::new(),
        net: "mux".to_owned(),
        stream_host: String::new(),
        stream_path: String::new(),
        xhttp_download: None,
        xhttp_mode: plan::ResidentXhttpMode::PacketUp,
        xhttp_settings: plan::ResidentXhttpSettingsPlan::default(),
        xhttp_xmux: None,
        tls: "tls".to_owned(),
        allow_insecure: true,
        tls_fragment: None,
        utls_fingerprint: None,
        reality: None,
        handler: plan::ResidentProxyProtocolPlan::VlessMuxTcpTls { key: [11; 16] },
        execution: None,
        chain_parent: None,
        mark: 0,
        mptcp: false,
    };
    proxy.apply_runtime_generation(generation);
    Arc::new(proxy)
}

fn vless_mux_test_deadline(duration: Duration) -> dae_runtime_control::AbsoluteDeadline {
    dae_runtime_control::AbsoluteDeadline::from_now(Instant::now(), duration)
}

async fn stop_vless_mux_owner(stop: SharedResidentStopSignal, thread: std::thread::JoinHandle<()>) {
    stop.store(true, Ordering::Release);
    tokio::task::spawn_blocking(move || thread.join().unwrap())
        .await
        .unwrap();
}

fn assert_vless_mux_owner_released(owner: &VlessMuxGenerationOwnerHandle) {
    let metrics = owner.metrics_snapshot();
    assert_eq!(metrics["registeredKeys"], 0);
    assert_eq!(metrics["registeredPhysicalConnections"], 0);
    assert_eq!(metrics["registeredBuildTasks"], 0);
    assert_eq!(metrics["reservedPhysicalConnections"], 0);
    assert_eq!(metrics["activePhysicalConnections"], 0);
    assert_eq!(metrics["activeLogicalStreams"], 0);
    assert_eq!(metrics["currentLogicalBufferBytes"], 0);
    assert_eq!(metrics["idlePhysicalConnections"], 0);
    assert_eq!(metrics["activeBuilds"], 0);
    assert_eq!(metrics["ownerStateBytesLowerBound"], 0);
    assert_eq!(metrics["shutdownTimedOut"], false);
}

async fn write_and_read_echo(stream: &mut VlessMuxLogicalStream, payload: &[u8]) {
    stream.write_all(payload).await.unwrap();
    stream.flush().await.unwrap();
    let mut response = vec![0_u8; payload.len()];
    time::timeout(Duration::from_secs(2), stream.read_exact(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response, payload);
}

async fn acquire_vless_mux_from_fresh_runtime(
    proxy: Arc<plan::ResidentProxyPlan>,
    target: &str,
) -> Result<VlessMuxLogicalStream, String> {
    let target = target.to_owned();
    tokio::task::spawn_blocking(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .unwrap()
            .block_on(acquire_vless_mux_logical_stream(
                proxy,
                target,
                vless_mux_test_deadline(Duration::from_secs(2)),
            ))
    })
    .await
    .unwrap()
}

#[test]
fn vless_mux_owner_demultiplexes_concurrent_streams_and_isolates_close_and_failure() {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_io()
        .enable_time()
        .build()
        .unwrap()
        .block_on(async {
            let server = VlessMuxTestServer::start().await;
            let generation = NEXT_VLESS_MUX_TEST_GENERATION.fetch_add(1, Ordering::Relaxed);
            let proxy = vless_mux_test_proxy(server.address, generation, "sha256:mux-concurrent");
            let resources = VlessMuxOwnerResourceProfile::from_runtime_profile(
                ResidentRuntimeProfile::LowMemory,
            )
            .with_limits_for_test(2, 2, 4, 16, Duration::from_secs(2));
            let stop = ResidentStopSignal::shared();
            let (owner, owner_thread) = start_vless_mux_generation_owner_for_test(
                generation,
                Arc::clone(&stop),
                RESIDENT_TCP_FLOW_STACK_BYTES_DEFAULT,
                2,
                resources,
            )
            .unwrap();

            let mut first =
                acquire_vless_mux_from_fresh_runtime(Arc::clone(&proxy), "127.0.0.1:443")
                    .await
                    .unwrap();
            let mut second =
                acquire_vless_mux_from_fresh_runtime(Arc::clone(&proxy), "127.0.0.1:443")
                    .await
                    .unwrap();
            assert_eq!(first.physical_instance_id(), second.physical_instance_id());
            assert_ne!(first.sid(), second.sid());
            write_and_read_echo(&mut first, b"logical-a").await;
            write_and_read_echo(&mut second, b"logical-b").await;
            drop(first);
            time::timeout(Duration::from_secs(2), async {
                while owner.metrics_snapshot()["activeLogicalStreams"] != 1 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            write_and_read_echo(&mut second, b"logical-b-survives").await;

            let mut third = acquire_vless_mux_logical_stream(
                Arc::clone(&proxy),
                "127.0.0.1:443".to_owned(),
                vless_mux_test_deadline(Duration::from_secs(2)),
            )
            .await
            .unwrap();
            assert_eq!(second.physical_instance_id(), third.physical_instance_id());
            assert_ne!(second.sid(), third.sid());
            write_and_read_echo(&mut third, b"logical-c").await;
            assert_eq!(server.tcp_connections.load(Ordering::Relaxed), 1);

            server.close_all_connections();
            let mut byte = [0_u8; 1];
            let second_failure = time::timeout(Duration::from_secs(2), second.read(&mut byte))
                .await
                .unwrap();
            let third_failure = time::timeout(Duration::from_secs(2), third.read(&mut byte))
                .await
                .unwrap();
            assert!(second_failure.is_err());
            assert!(third_failure.is_err());
            let sids = server.new_sids.lock().unwrap().clone();
            assert_eq!(sids.len(), 3);
            assert_eq!(sids.iter().copied().collect::<HashSet<_>>().len(), 3);
            {
                let payloads = server.payloads.lock().unwrap();
                assert!(payloads.iter().any(|(_, payload)| payload == b"logical-a"));
                assert!(
                    payloads
                        .iter()
                        .any(|(_, payload)| payload == b"logical-b-survives")
                );
            }

            stop_vless_mux_owner(stop, owner_thread).await;
            assert_vless_mux_owner_released(&owner);
            server.stop().await;
        });
}

#[test]
fn vless_mux_owner_rejects_unknown_sessions_and_server_new_frames() {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_io()
        .enable_time()
        .build()
        .unwrap()
        .block_on(async {
            let server =
                VlessMuxTestServer::start_with_injection(Some(VlessMuxTestInjection::UnknownSid))
                    .await;
            let generation = NEXT_VLESS_MUX_TEST_GENERATION.fetch_add(1, Ordering::Relaxed);
            let proxy = vless_mux_test_proxy(server.address, generation, "sha256:mux-unknown");
            let stop = ResidentStopSignal::shared();
            let (owner, owner_thread) = start_vless_mux_generation_owner(
                generation,
                Arc::clone(&stop),
                RESIDENT_TCP_FLOW_STACK_BYTES_DEFAULT,
                1,
            )
            .unwrap();
            let mut logical = acquire_vless_mux_logical_stream(
                proxy,
                "127.0.0.1:443".to_owned(),
                vless_mux_test_deadline(Duration::from_secs(2)),
            )
            .await
            .unwrap();
            write_and_read_echo(&mut logical, b"survivor").await;
            time::timeout(Duration::from_secs(2), async {
                while server.unknown_ends.load(Ordering::Relaxed) == 0 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            assert_eq!(owner.metrics_snapshot()["cumulativeUnknownSidFrames"], 1);
            drop(logical);
            stop_vless_mux_owner(stop, owner_thread).await;
            assert_vless_mux_owner_released(&owner);
            server.stop().await;

            let server =
                VlessMuxTestServer::start_with_injection(Some(VlessMuxTestInjection::ServerNew))
                    .await;
            let generation = NEXT_VLESS_MUX_TEST_GENERATION.fetch_add(1, Ordering::Relaxed);
            let proxy = vless_mux_test_proxy(server.address, generation, "sha256:mux-server-new");
            let stop = ResidentStopSignal::shared();
            let (owner, owner_thread) = start_vless_mux_generation_owner(
                generation,
                Arc::clone(&stop),
                RESIDENT_TCP_FLOW_STACK_BYTES_DEFAULT,
                1,
            )
            .unwrap();
            let mut logical = acquire_vless_mux_logical_stream(
                proxy,
                "127.0.0.1:443".to_owned(),
                vless_mux_test_deadline(Duration::from_secs(2)),
            )
            .await
            .unwrap();
            let mut byte = [0_u8; 1];
            let failure = time::timeout(Duration::from_secs(2), logical.read(&mut byte))
                .await
                .unwrap();
            assert!(failure.is_err());
            assert_eq!(owner.metrics_snapshot()["cumulativeServerNewRejections"], 1);
            stop_vless_mux_owner(stop, owner_thread).await;
            assert_vless_mux_owner_released(&owner);
            server.stop().await;
        });
}

#[test]
fn vless_mux_owner_enforces_capacity_key_partition_idle_expiry_and_generation_cleanup() {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_io()
        .enable_time()
        .build()
        .unwrap()
        .block_on(async {
            let missing_server = VlessMuxTestServer::start().await;
            let missing_generation = NEXT_VLESS_MUX_TEST_GENERATION.fetch_add(1, Ordering::Relaxed);
            let missing_proxy = vless_mux_test_proxy(
                missing_server.address,
                missing_generation,
                "sha256:mux-missing",
            );
            let missing = acquire_vless_mux_logical_stream(
                missing_proxy,
                "127.0.0.1:443".to_owned(),
                vless_mux_test_deadline(Duration::from_millis(50)),
            )
            .await
            .err()
            .expect("VLESS mux acquisition without a generation owner must fail");
            assert!(missing.contains("is unavailable"), "{missing}");
            assert_eq!(missing_server.tcp_connections.load(Ordering::Relaxed), 0);
            missing_server.stop().await;

            for cycle in 0..5_u64 {
                let server = VlessMuxTestServer::start().await;
                let generation = NEXT_VLESS_MUX_TEST_GENERATION.fetch_add(1, Ordering::Relaxed);
                let first_proxy = vless_mux_test_proxy(
                    server.address,
                    generation,
                    &format!("sha256:mux-cycle-{cycle}-a"),
                );
                let second_proxy = vless_mux_test_proxy(
                    server.address,
                    generation,
                    &format!("sha256:mux-cycle-{cycle}-b"),
                );
                let resources = VlessMuxOwnerResourceProfile::from_runtime_profile(
                    ResidentRuntimeProfile::LowMemory,
                )
                .with_limits_for_test(2, 2, 1, 8, Duration::from_millis(100));
                let stop = ResidentStopSignal::shared();
                let (owner, owner_thread) = start_vless_mux_generation_owner_for_test(
                    generation,
                    Arc::clone(&stop),
                    RESIDENT_TCP_FLOW_STACK_BYTES_DEFAULT,
                    1,
                    resources,
                )
                .unwrap();
                let mut first = acquire_vless_mux_logical_stream(
                    Arc::clone(&first_proxy),
                    "127.0.0.1:443".to_owned(),
                    vless_mux_test_deadline(Duration::from_secs(2)),
                )
                .await
                .unwrap();
                let mut second = acquire_vless_mux_logical_stream(
                    Arc::clone(&first_proxy),
                    "127.0.0.1:443".to_owned(),
                    vless_mux_test_deadline(Duration::from_secs(2)),
                )
                .await
                .unwrap();
                assert_ne!(first.physical_instance_id(), second.physical_instance_id());
                let mut partitioned = acquire_vless_mux_logical_stream(
                    second_proxy,
                    "127.0.0.1:443".to_owned(),
                    vless_mux_test_deadline(Duration::from_secs(2)),
                )
                .await
                .unwrap();
                assert_ne!(
                    first.physical_instance_id(),
                    partitioned.physical_instance_id()
                );
                write_and_read_echo(&mut first, b"first").await;
                write_and_read_echo(&mut second, b"second").await;
                write_and_read_echo(&mut partitioned, b"partitioned").await;
                drop(first);
                drop(second);
                drop(partitioned);
                time::timeout(Duration::from_secs(3), async {
                    loop {
                        let metrics = owner.metrics_snapshot();
                        if metrics["activeLogicalStreams"] == 0
                            && metrics["activePhysicalConnections"] == 0
                            && metrics["reservedPhysicalConnections"] == 0
                            && metrics["cumulativeIdleExpirations"].as_u64().unwrap_or(0) >= 3
                        {
                            break;
                        }
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .unwrap();

                stop_vless_mux_owner(stop, owner_thread).await;
                assert_vless_mux_owner_released(&owner);
                server.stop().await;
            }
        });
}
