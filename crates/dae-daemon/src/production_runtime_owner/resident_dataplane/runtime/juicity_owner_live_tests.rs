use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use dae_outbound::juicity::{
    JUICITY_AUTHENTICATE_HEADER_LEN, seal_stream_packet_frame, write_juicity_tcp_request,
};
use quinn::crypto::rustls::QuicServerConfig;
use rcgen::generate_simple_self_signed;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::sync::oneshot;
use tokio::time;

use super::tcp::{QuicEndpointCallerClass, quic_endpoint_metrics_snapshot};
use super::udp::exercise_juicity_udp_stream_session;
use super::*;

const TEST_UUID: &str = "01234567-89ab-cdef-0123-456789abcdef";
const TEST_PASSWORD: &str = "juicity-owner-test-secret";
const TEST_TCP_TARGET: &str = "192.0.2.10:80";
const TEST_UDP_TARGET: &str = "192.0.2.20:5353";

#[derive(Default)]
struct JuicityServerObservation {
    connections: AtomicUsize,
    authentications: AtomicUsize,
    tcp_streams: AtomicUsize,
    udp_streams: AtomicUsize,
    udp_packets: AtomicUsize,
    last_connection_id: AtomicU64,
    current_connection: Mutex<Option<quinn::Connection>>,
}

struct JuicityTestServer {
    addr: SocketAddr,
    observation: Arc<JuicityServerObservation>,
    shutdown: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<()>,
}

impl JuicityTestServer {
    async fn start() -> Self {
        Self::start_with_auth_rejection(false).await
    }

    async fn start_rejecting_auth() -> Self {
        Self::start_with_auth_rejection(true).await
    }

    async fn start_with_auth_rejection(reject_auth: bool) -> Self {
        let endpoint = quinn::Endpoint::server(
            juicity_server_config(),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        )
        .unwrap();
        let addr = endpoint.local_addr().unwrap();
        let observation = Arc::new(JuicityServerObservation::default());
        let task_observation = Arc::clone(&observation);
        let (shutdown, mut shutdown_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => break,
                    incoming = endpoint.accept() => {
                        let Some(incoming) = incoming else {
                            break;
                        };
                        let observation = Arc::clone(&task_observation);
                        tokio::spawn(async move {
                            if let Ok(connection) = incoming.await {
                                observation.connections.fetch_add(1, Ordering::Relaxed);
                                observation.last_connection_id.store(
                                    connection.stable_id() as u64,
                                    Ordering::Relaxed,
                                );
                                *observation.current_connection.lock().unwrap() =
                                    Some(connection.clone());
                                run_juicity_server_connection(
                                    connection,
                                    observation,
                                    reject_auth,
                                )
                                .await;
                            }
                        });
                    }
                }
            }
            endpoint.close(0_u32.into(), b"juicity test server stopped");
            endpoint.wait_idle().await;
        });
        Self {
            addr,
            observation,
            shutdown: Some(shutdown),
            task,
        }
    }

    fn close_current(&self) {
        if let Some(connection) = self.observation.current_connection.lock().unwrap().as_ref() {
            connection.close(0_u32.into(), b"juicity test remote close");
        }
    }

    async fn stop(mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        time::timeout(Duration::from_secs(2), &mut self.task)
            .await
            .unwrap()
            .unwrap();
    }
}

async fn run_juicity_server_connection(
    connection: quinn::Connection,
    observation: Arc<JuicityServerObservation>,
    reject_auth: bool,
) {
    let mut stream_tasks = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            stream = connection.accept_uni() => match stream {
                Ok(mut stream) => {
                    let observation = Arc::clone(&observation);
                    let connection = connection.clone();
                    stream_tasks.spawn(async move {
                        let mut auth = [0_u8; JUICITY_AUTHENTICATE_HEADER_LEN];
                        if stream.read_exact(&mut auth).await.is_ok()
                            && auth[..2] == [0x00, 0x00]
                        {
                            observation.authentications.fetch_add(1, Ordering::Relaxed);
                            if reject_auth {
                                connection.close(0x100_u32.into(), b"juicity auth rejected");
                            } else {
                                std::future::pending::<()>().await;
                            }
                        }
                    });
                }
                Err(_) => break,
            },
            stream = connection.accept_bi() => match stream {
                Ok((send, recv)) => {
                    let observation = Arc::clone(&observation);
                    stream_tasks.spawn(async move {
                        handle_juicity_bidirectional_stream(send, recv, observation).await;
                    });
                }
                Err(_) => break,
            },
            _ = connection.closed() => break,
            completed = stream_tasks.join_next(), if !stream_tasks.is_empty() => {
                if completed.is_none() {
                    break;
                }
            }
        }
    }
    stream_tasks.abort_all();
    while stream_tasks.join_next().await.is_some() {}
}

async fn handle_juicity_bidirectional_stream(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    observation: Arc<JuicityServerObservation>,
) {
    let Ok(network) = recv.read_u8().await else {
        return;
    };
    match network {
        1 => {
            if read_juicity_address(&mut recv).await.is_err() {
                return;
            }
            let mut payload = [0_u8; 4];
            if recv.read_exact(&mut payload).await.is_err() {
                return;
            }
            observation.tcp_streams.fetch_add(1, Ordering::Relaxed);
            if send.write_all(&payload).await.is_ok() {
                let _ = send.finish();
            }
        }
        3 => {
            if read_juicity_address(&mut recv).await.is_err() {
                return;
            }
            observation.udp_streams.fetch_add(1, Ordering::Relaxed);
            loop {
                let Ok(metadata) = read_juicity_address(&mut recv).await else {
                    break;
                };
                let Ok(payload_len) = recv.read_u16().await else {
                    break;
                };
                let mut payload = vec![0_u8; payload_len as usize];
                if recv.read_exact(&mut payload).await.is_err() {
                    break;
                }
                observation.udp_packets.fetch_add(1, Ordering::Relaxed);
                if send.write_all(&metadata).await.is_err()
                    || send.write_all(&payload_len.to_be_bytes()).await.is_err()
                    || send.write_all(&payload).await.is_err()
                    || send.flush().await.is_err()
                {
                    break;
                }
            }
        }
        _ => {}
    }
}

async fn read_juicity_address(reader: &mut (impl AsyncRead + Unpin)) -> std::io::Result<Vec<u8>> {
    let atyp = reader.read_u8().await?;
    let mut encoded = vec![atyp];
    let remaining = match atyp {
        1 => 4 + 2,
        4 => 16 + 2,
        3 => {
            let domain_len = reader.read_u8().await?;
            encoded.push(domain_len);
            domain_len as usize + 2
        }
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid Juicity address type",
            ));
        }
    };
    let start = encoded.len();
    encoded.resize(start + remaining, 0);
    reader.read_exact(&mut encoded[start..]).await?;
    Ok(encoded)
}

fn juicity_server_config() -> quinn::ServerConfig {
    let certified = generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let cert_der = certified.cert.der().clone();
    let key_der =
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der()));
    let mut crypto =
        rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .unwrap();
    crypto.alpn_protocols = vec![b"h3".to_vec()];
    quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(crypto).unwrap()))
}

fn juicity_proxy(addr: SocketAddr, generation: u64) -> Arc<plan::ResidentProxyPlan> {
    let config = dae_config::Config {
        global: dae_config::Global::default(),
        subscription: Vec::new(),
        node: Vec::new(),
        group: Vec::new(),
        routing: dae_config::Routing::default(),
        dns: dae_config::Dns::default(),
    };
    let mut proxy = plan::build_resident_proxy_plan_for_node(
        &config,
        "juicity-owner-test".to_owned(),
        "juicity-owner-node".to_owned(),
        format!(
            "juicity://{TEST_UUID}:{TEST_PASSWORD}@{}:{}?allow_insecure=1&sni=localhost#owner-test",
            addr.ip(),
            addr.port(),
        ),
    )
    .unwrap();
    proxy.apply_runtime_generation(generation);
    Arc::new(proxy)
}

fn juicity_owner_deadline() -> dae_runtime_control::AbsoluteDeadline {
    dae_runtime_control::AbsoluteDeadline::from_now(Instant::now(), Duration::from_secs(2))
}

async fn open_juicity_echo_stream(lease: &JuicityTransportLease, payload: [u8; 4]) -> [u8; 4] {
    let (mut send, mut recv) = lease.open_stream(juicity_owner_deadline()).await.unwrap();
    write_juicity_tcp_request(&mut send, TEST_TCP_TARGET, &payload)
        .await
        .unwrap();
    let mut echoed = [0_u8; 4];
    recv.read_exact(&mut echoed).await.unwrap();
    echoed
}

async fn wait_until(mut predicate: impl FnMut() -> bool) {
    time::timeout(Duration::from_secs(3), async {
        while !predicate() {
            time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("Juicity owner integration state reached before timeout");
}

async fn stop_juicity_owner_registry(
    stop: SharedResidentStopSignal,
    owner_thread: std::thread::JoinHandle<()>,
) -> Duration {
    let started = Instant::now();
    stop.store(true, Ordering::Release);
    tokio::task::spawn_blocking(move || owner_thread.join().unwrap())
        .await
        .unwrap();
    started.elapsed()
}

fn assert_juicity_owner_resources_released(registry: &JuicityOwnerRegistryHandle, generation: u64) {
    let owner = registry.metrics_snapshot();
    assert_eq!(owner["activePools"], 0);
    assert_eq!(owner["activePhysicalOwners"], 0);
    assert_eq!(owner["activeBuilds"], 0);
    assert_eq!(owner["activeLogicalLeases"], 0);
    assert_eq!(owner["activeWaiters"], 0);
    assert_eq!(owner["shutdownTimedOut"], false);
    let endpoint = quic_endpoint_metrics_snapshot(generation);
    assert_eq!(endpoint["liveStates"]["total"], 0);
    assert_eq!(endpoint["endpointDriverTasks"]["live"], 0);
    assert_eq!(endpoint["chargedBytes"]["total"], 0);
}

#[test]
fn juicity_owner_reuses_auth_and_persistent_udp_streams_across_runtimes() {
    tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .unwrap()
        .block_on(async {
            let server = JuicityTestServer::start().await;
            let generation = 8_101;
            let proxy = juicity_proxy(server.addr, generation);
            let stop = ResidentStopSignal::shared();
            let (registry, owner_thread) = start_juicity_owner_registry(
                generation,
                Arc::clone(&stop),
                RESIDENT_TCP_FLOW_STACK_BYTES_DEFAULT,
            )
            .unwrap();

            let acquire_from_runtime = |caller| {
                let registry = registry.clone();
                let proxy = Arc::clone(&proxy);
                tokio::task::spawn_blocking(move || {
                    tokio::runtime::Builder::new_current_thread()
                        .enable_io()
                        .enable_time()
                        .build()
                        .unwrap()
                        .block_on(registry.acquire(proxy, caller, juicity_owner_deadline()))
                })
            };
            let tcp_a = acquire_from_runtime(QuicEndpointCallerClass::TcpData)
                .await
                .unwrap()
                .unwrap();
            let tcp_b = acquire_from_runtime(QuicEndpointCallerClass::BackgroundHealth)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(tcp_a.physical_owner_id(), tcp_b.physical_owner_id());
            assert!(tcp_a.auth_token_nonzero());
            let (echo_a, echo_b) = tokio::join!(
                open_juicity_echo_stream(&tcp_a, *b"tcp1"),
                open_juicity_echo_stream(&tcp_b, *b"tcp2"),
            );
            assert_eq!(echo_a, *b"tcp1");
            assert_eq!(echo_b, *b"tcp2");

            let target: SocketAddr = TEST_UDP_TARGET.parse().unwrap();
            let (udp_a_owner, udp_a) = exercise_juicity_udp_stream_session(
                Arc::clone(&proxy),
                registry.clone(),
                target,
                &[b"udp-a1", b"udp-a2"],
            )
            .await
            .unwrap();
            assert_eq!(udp_a_owner, tcp_a.physical_owner_id());
            assert_eq!(udp_a, [b"udp-a1".to_vec(), b"udp-a2".to_vec()]);
            let (udp_b_owner, udp_b) = exercise_juicity_udp_stream_session(
                Arc::clone(&proxy),
                registry.clone(),
                target,
                &[b"udp-b1"],
            )
            .await
            .unwrap();
            assert_eq!(udp_b_owner, udp_a_owner);
            assert_eq!(udp_b, [b"udp-b1".to_vec()]);

            wait_until(|| server.observation.authentications.load(Ordering::Relaxed) == 1).await;
            assert_eq!(server.observation.connections.load(Ordering::Relaxed), 1);
            assert_eq!(server.observation.tcp_streams.load(Ordering::Relaxed), 2);
            assert_eq!(server.observation.udp_streams.load(Ordering::Relaxed), 2);
            assert_eq!(server.observation.udp_packets.load(Ordering::Relaxed), 3);
            assert_eq!(registry.metrics_snapshot()["cumulativeBuilds"], 1);

            drop(tcp_a);
            drop(tcp_b);
            assert!(
                stop_juicity_owner_registry(stop, owner_thread).await
                    < RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE
            );
            assert_juicity_owner_resources_released(&registry, generation);
            server.stop().await;
        });
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn juicity_owner_expands_a_bounded_pool_only_after_stream_capacity_is_used() {
    let server = JuicityTestServer::start().await;
    let generation = 8_102;
    let resources =
        JuicityOwnerResourceProfile::from_runtime_profile(ResidentRuntimeProfile::LowMemory)
            .with_owner_limit(2)
            .with_pool_shape(2, 2, 1);
    let stop = ResidentStopSignal::shared();
    let (registry, owner_thread) =
        super::juicity_owner::start_juicity_owner_registry_with_resources(
            generation,
            Arc::clone(&stop),
            RESIDENT_TCP_FLOW_STACK_BYTES_DEFAULT,
            resources,
        )
        .unwrap();
    let proxy = juicity_proxy(server.addr, generation);

    let first = registry
        .acquire(
            Arc::clone(&proxy),
            QuicEndpointCallerClass::TcpData,
            juicity_owner_deadline(),
        )
        .await
        .unwrap();
    let second = registry
        .acquire(
            Arc::clone(&proxy),
            QuicEndpointCallerClass::UdpData,
            juicity_owner_deadline(),
        )
        .await
        .unwrap();
    assert_ne!(first.connection_stable_id(), second.connection_stable_id());
    assert_eq!(registry.metrics_snapshot()["activePhysicalOwners"], 2);
    assert_eq!(registry.metrics_snapshot()["cumulativeBuilds"], 2);
    let capacity_error = match registry
        .acquire(
            proxy,
            QuicEndpointCallerClass::ManagedDns,
            juicity_owner_deadline(),
        )
        .await
    {
        Ok(_) => panic!("the bounded Juicity connection pool must reject excess leases"),
        Err(error) => error,
    };
    assert!(capacity_error.contains("bounded capacity"));
    assert_eq!(open_juicity_echo_stream(&first, *b"one1").await, *b"one1");
    assert_eq!(open_juicity_echo_stream(&second, *b"two2").await, *b"two2");

    drop(first);
    drop(second);
    assert!(
        stop_juicity_owner_registry(stop, owner_thread).await
            < RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE
    );
    assert_juicity_owner_resources_released(&registry, generation);
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn juicity_owner_rebuilds_once_after_remote_close() {
    let server = JuicityTestServer::start().await;
    let generation = 8_103;
    let proxy = juicity_proxy(server.addr, generation);
    let stop = ResidentStopSignal::shared();
    let (registry, owner_thread) = start_juicity_owner_registry(
        generation,
        Arc::clone(&stop),
        RESIDENT_TCP_FLOW_STACK_BYTES_DEFAULT,
    )
    .unwrap();
    let old = registry
        .acquire(
            Arc::clone(&proxy),
            QuicEndpointCallerClass::TcpData,
            juicity_owner_deadline(),
        )
        .await
        .unwrap();
    let old_id = old.physical_owner_id();
    assert_eq!(open_juicity_echo_stream(&old, *b"old1").await, *b"old1");
    server.close_current();
    wait_until(|| registry.metrics_snapshot()["remoteCloses"] == 1).await;
    assert!(old.open_stream(juicity_owner_deadline()).await.is_err());

    let replacement = registry
        .acquire(
            proxy,
            QuicEndpointCallerClass::BackgroundHealth,
            juicity_owner_deadline(),
        )
        .await
        .unwrap();
    assert_ne!(replacement.physical_owner_id(), old_id);
    assert_eq!(
        open_juicity_echo_stream(&replacement, *b"new2").await,
        *b"new2"
    );
    wait_until(|| server.observation.authentications.load(Ordering::Relaxed) == 2).await;
    assert_eq!(registry.metrics_snapshot()["cumulativeBuilds"], 2);

    drop(old);
    drop(replacement);
    assert!(
        stop_juicity_owner_registry(stop, owner_thread).await
            < RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE
    );
    assert_juicity_owner_resources_released(&registry, generation);
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn juicity_auth_write_is_not_reported_as_server_acceptance() {
    let server = JuicityTestServer::start_rejecting_auth().await;
    let generation = 8_104;
    let stop = ResidentStopSignal::shared();
    let (registry, owner_thread) = start_juicity_owner_registry(
        generation,
        Arc::clone(&stop),
        RESIDENT_TCP_FLOW_STACK_BYTES_DEFAULT,
    )
    .unwrap();
    let acquired = registry
        .acquire(
            juicity_proxy(server.addr, generation),
            QuicEndpointCallerClass::TcpData,
            juicity_owner_deadline(),
        )
        .await;
    wait_until(|| server.observation.authentications.load(Ordering::Relaxed) == 1).await;
    if let Ok(lease) = acquired {
        wait_until(|| registry.metrics_snapshot()["remoteCloses"] == 1).await;
        assert!(lease.open_stream(juicity_owner_deadline()).await.is_err());
        drop(lease);
    }
    assert_eq!(registry.metrics_snapshot()["cumulativeBuilds"], 1);

    assert!(
        stop_juicity_owner_registry(stop, owner_thread).await
            < RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE
    );
    assert_juicity_owner_resources_released(&registry, generation);
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn overlapping_juicity_generations_and_five_reload_cycles_drain_independently() {
    let server = JuicityTestServer::start().await;
    let first_generation = 8_110;
    let second_generation = 8_111;
    let first_stop = ResidentStopSignal::shared();
    let second_stop = ResidentStopSignal::shared();
    let (first_registry, first_thread) = start_juicity_owner_registry(
        first_generation,
        Arc::clone(&first_stop),
        RESIDENT_TCP_FLOW_STACK_BYTES_DEFAULT,
    )
    .unwrap();
    let (second_registry, second_thread) = start_juicity_owner_registry(
        second_generation,
        Arc::clone(&second_stop),
        RESIDENT_TCP_FLOW_STACK_BYTES_DEFAULT,
    )
    .unwrap();
    let first = first_registry
        .acquire(
            juicity_proxy(server.addr, first_generation),
            QuicEndpointCallerClass::TcpData,
            juicity_owner_deadline(),
        )
        .await
        .unwrap();
    let second = second_registry
        .acquire(
            juicity_proxy(server.addr, second_generation),
            QuicEndpointCallerClass::TcpData,
            juicity_owner_deadline(),
        )
        .await
        .unwrap();
    assert_ne!(first.connection_stable_id(), second.connection_stable_id());
    drop(first);
    assert!(
        stop_juicity_owner_registry(first_stop, first_thread).await
            < RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE
    );
    assert_juicity_owner_resources_released(&first_registry, first_generation);
    assert_eq!(open_juicity_echo_stream(&second, *b"live").await, *b"live");
    drop(second);
    assert!(
        stop_juicity_owner_registry(second_stop, second_thread).await
            < RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE
    );
    assert_juicity_owner_resources_released(&second_registry, second_generation);

    for offset in 0..5 {
        let generation = 8_120 + offset;
        let stop = ResidentStopSignal::shared();
        let (registry, owner_thread) = start_juicity_owner_registry(
            generation,
            Arc::clone(&stop),
            RESIDENT_TCP_FLOW_STACK_BYTES_DEFAULT,
        )
        .unwrap();
        let lease = registry
            .acquire(
                juicity_proxy(server.addr, generation),
                QuicEndpointCallerClass::BackgroundHealth,
                juicity_owner_deadline(),
            )
            .await
            .unwrap();
        assert_eq!(open_juicity_echo_stream(&lease, *b"pass").await, *b"pass");
        drop(lease);
        assert!(
            stop_juicity_owner_registry(stop, owner_thread).await
                < RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE
        );
        assert_juicity_owner_resources_released(&registry, generation);
    }
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_and_simultaneous_juicity_waiters_share_one_no_response_attempt() {
    let blackhole = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let generation = 8_130;
    let proxy = juicity_proxy(blackhole.local_addr().unwrap(), generation);
    let stop = ResidentStopSignal::shared();
    let (registry, owner_thread) = start_juicity_owner_registry(
        generation,
        Arc::clone(&stop),
        RESIDENT_TCP_FLOW_STACK_BYTES_DEFAULT,
    )
    .unwrap();

    let elected_registry = registry.clone();
    let elected_proxy = Arc::clone(&proxy);
    let elected = tokio::spawn(async move {
        elected_registry
            .acquire(
                elected_proxy,
                QuicEndpointCallerClass::BackgroundHealth,
                dae_runtime_control::AbsoluteDeadline::from_now(
                    Instant::now(),
                    Duration::from_millis(400),
                ),
            )
            .await
    });
    wait_until(|| registry.metrics_snapshot()["cumulativeBuilds"] == 1).await;

    let barrier = Arc::new(tokio::sync::Barrier::new(8));
    let mut observers = Vec::new();
    for _ in 0..7 {
        let registry = registry.clone();
        let proxy = Arc::clone(&proxy);
        let barrier = Arc::clone(&barrier);
        observers.push(tokio::spawn(async move {
            barrier.wait().await;
            registry
                .acquire(
                    proxy,
                    QuicEndpointCallerClass::ManagedDns,
                    dae_runtime_control::AbsoluteDeadline::from_now(
                        Instant::now(),
                        Duration::from_secs(1),
                    ),
                )
                .await
        }));
    }
    barrier.wait().await;
    elected.abort();
    match elected.await {
        Err(error) => assert!(error.is_cancelled()),
        Ok(_) => panic!("the elected Juicity waiter must be cancelled"),
    }
    for observer in observers {
        assert!(observer.await.unwrap().is_err());
    }
    assert_eq!(registry.metrics_snapshot()["cumulativeBuilds"], 1);
    wait_until(|| registry.metrics_snapshot()["cumulativeBuildFailures"] == 1).await;
    assert_eq!(registry.metrics_snapshot()["activeWaiters"], 0);

    assert!(
        stop_juicity_owner_registry(stop, owner_thread).await
            < RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE
    );
    assert_juicity_owner_resources_released(&registry, generation);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn low_memory_juicity_owner_budget_rejects_excess_nodes_before_endpoint_creation() {
    let resources =
        JuicityOwnerResourceProfile::from_runtime_profile(ResidentRuntimeProfile::LowMemory)
            .with_owner_limit(1);
    let owner_limit = resources.owner_limit();
    let node_count = owner_limit + 2;
    let generation = 8_131;
    let stop = ResidentStopSignal::shared();
    let (registry, owner_thread) =
        super::juicity_owner::start_juicity_owner_registry_with_resources(
            generation,
            Arc::clone(&stop),
            RESIDENT_TCP_FLOW_STACK_BYTES_DEFAULT,
            resources,
        )
        .unwrap();
    let mut blackholes = Vec::with_capacity(node_count);
    let mut proxies = Vec::with_capacity(node_count);
    for _ in 0..node_count {
        let socket = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        proxies.push(juicity_proxy(socket.local_addr().unwrap(), generation));
        blackholes.push(socket);
    }
    let barrier = Arc::new(tokio::sync::Barrier::new(node_count + 1));
    let mut attempts = Vec::with_capacity(node_count);
    for proxy in proxies {
        let registry = registry.clone();
        let barrier = Arc::clone(&barrier);
        attempts.push(tokio::spawn(async move {
            barrier.wait().await;
            registry
                .acquire(
                    proxy,
                    QuicEndpointCallerClass::BackgroundHealth,
                    dae_runtime_control::AbsoluteDeadline::from_now(
                        Instant::now(),
                        Duration::from_millis(350),
                    ),
                )
                .await
        }));
    }
    barrier.wait().await;
    let mut budget_rejections = 0;
    for attempt in attempts {
        let error = match attempt.await.unwrap() {
            Ok(_) => panic!("no-response and owner-budget attempts must fail"),
            Err(error) => error,
        };
        if error.contains("owner budget is full") {
            budget_rejections += 1;
        }
    }
    assert_eq!(budget_rejections, node_count - owner_limit);
    assert_eq!(
        registry.metrics_snapshot()["ownerLimitRejections"],
        (node_count - owner_limit) as u64
    );
    assert_eq!(
        quic_endpoint_metrics_snapshot(generation)["cumulativeCreations"],
        owner_limit as u64
    );
    drop(blackholes);

    assert!(
        stop_juicity_owner_registry(stop, owner_thread).await
            < RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE
    );
    assert_juicity_owner_resources_released(&registry, generation);
}

#[test]
fn juicity_stream_packet_wire_fixture_has_one_initial_header_and_per_packet_metadata() {
    let first = seal_stream_packet_frame(TEST_UDP_TARGET, b"first").unwrap();
    let second = seal_stream_packet_frame(TEST_UDP_TARGET, b"second").unwrap();
    let initial =
        super::udp::build_juicity_stream_packet_request(TEST_UDP_TARGET, &first.encoded).unwrap();
    assert_eq!(initial[0], 3);
    assert!(initial.ends_with(&first.encoded));
    assert!(!second.encoded.starts_with(&[3, 1]));
}
