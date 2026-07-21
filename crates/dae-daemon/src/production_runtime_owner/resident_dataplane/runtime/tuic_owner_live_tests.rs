use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use dae_outbound::tuic::{
    TuicUdpPacket, decode_tuic_udp_packet, encode_tuic_udp_packet, write_tuic_connect_request,
};
use quinn::crypto::rustls::QuicServerConfig;
use rcgen::generate_simple_self_signed;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::AsyncWriteExt;
use tokio::sync::oneshot;
use tokio::time;

use super::tcp::{QuicEndpointCallerClass, quic_endpoint_metrics_snapshot};
use super::*;

const TEST_UUID: &str = "01234567-89ab-cdef-0123-456789abcdef";
const TEST_PASSWORD: &str = "tuic-owner-test-secret";
const TEST_TCP_TARGET: &str = "192.0.2.10:80";
const TEST_UDP_TARGET: &str = "192.0.2.20:5353";

#[derive(Default)]
struct TuicServerObservation {
    connections: AtomicUsize,
    authentications: AtomicUsize,
    tcp_streams: AtomicUsize,
    udp_packets: AtomicUsize,
    dissociations: AtomicUsize,
    heartbeats: AtomicUsize,
    last_connection_id: AtomicU64,
    current_connection: Mutex<Option<quinn::Connection>>,
}

struct TuicTestServer {
    addr: SocketAddr,
    observation: Arc<TuicServerObservation>,
    shutdown: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<()>,
}

impl TuicTestServer {
    async fn start() -> Self {
        let endpoint = quinn::Endpoint::server(
            tuic_server_config(),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        )
        .unwrap();
        let addr = endpoint.local_addr().unwrap();
        let observation = Arc::new(TuicServerObservation::default());
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
                                run_tuic_server_connection(connection, observation).await;
                            }
                        });
                    }
                }
            }
            endpoint.close(0_u32.into(), b"tuic test server stopped");
            endpoint.wait_idle().await;
        });
        Self {
            addr,
            observation,
            shutdown: Some(shutdown),
            task,
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

    fn close_current(&self) {
        if let Some(connection) = self.observation.current_connection.lock().unwrap().as_ref() {
            connection.close(0_u32.into(), b"tuic test remote close");
        }
    }
}

async fn run_tuic_server_connection(
    connection: quinn::Connection,
    observation: Arc<TuicServerObservation>,
) {
    let mut stream_tasks = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            stream = connection.accept_uni() => match stream {
                Ok(mut stream) => {
                    let observation = Arc::clone(&observation);
                    stream_tasks.spawn(async move {
                        if let Ok(frame) = stream.read_to_end(64).await {
                            match frame.as_slice() {
                                [0x05, 0x00, ..] if frame.len() == 50 => {
                                    observation.authentications.fetch_add(1, Ordering::Relaxed);
                                }
                                [0x05, 0x03, _, _] => {
                                    observation.dissociations.fetch_add(1, Ordering::Relaxed);
                                }
                                _ => {}
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
                        handle_tuic_tcp_stream(send, recv, observation).await;
                    });
                }
                Err(_) => break,
            },
            datagram = connection.read_datagram() => match datagram {
                Ok(datagram) if datagram.as_ref() == [0x05, 0x04] => {
                    observation.heartbeats.fetch_add(1, Ordering::Relaxed);
                }
                Ok(datagram) => {
                    if let Ok(packet) = decode_tuic_udp_packet(&datagram) {
                        observation.udp_packets.fetch_add(1, Ordering::Relaxed);
                        if let Some(target) = packet.target()
                            && let Ok(response) = TuicUdpPacket::new(
                                packet.association_id(),
                                packet.packet_id(),
                                target,
                                packet.payload(),
                            )
                            && let Ok(response) = encode_tuic_udp_packet(&response)
                        {
                            let _ = connection.send_datagram(response.into());
                        }
                    }
                }
                Err(_) => break,
            },
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

async fn handle_tuic_tcp_stream(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    observation: Arc<TuicServerObservation>,
) {
    let mut request = [0_u8; 9];
    if recv.read_exact(&mut request).await.is_err()
        || request[..2] != [0x05, 0x01]
        || request[2] != 0x01
    {
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

fn tuic_server_config() -> quinn::ServerConfig {
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
    let mut config =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(crypto).unwrap()));
    let mut transport = quinn::TransportConfig::default();
    transport.datagram_receive_buffer_size(Some(64 * 1024));
    transport.datagram_send_buffer_size(64 * 1024);
    config.transport_config(Arc::new(transport));
    config
}

fn tuic_proxy(addr: SocketAddr, generation: u64) -> Arc<plan::ResidentProxyPlan> {
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
        "tuic-owner-test".to_owned(),
        "tuic-owner-node".to_owned(),
        format!(
            "tuic://{TEST_UUID}:{TEST_PASSWORD}@{}:{}?allow_insecure=1&alpn=h3&congestion_control=bbr#owner-test",
            addr.ip(),
            addr.port(),
        ),
    )
    .unwrap();
    proxy.apply_runtime_generation(generation);
    Arc::new(proxy)
}

async fn open_tuic_echo_stream(lease: &TuicTransportLease, payload: [u8; 4]) -> [u8; 4] {
    let (mut send, mut recv) = lease.connection().open_bi().await.unwrap();
    write_tuic_connect_request(&mut send, TEST_TCP_TARGET)
        .await
        .unwrap();
    send.write_all(&payload).await.unwrap();
    send.flush().await.unwrap();
    let mut echoed = [0_u8; 4];
    recv.read_exact(&mut echoed).await.unwrap();
    echoed
}

async fn exchange_tuic_udp(
    association: &mut TuicUdpAssociationLease,
    packet_id: u16,
    payload: &[u8],
) -> Vec<u8> {
    let packet = TuicUdpPacket::new(
        association.association_id(),
        packet_id,
        TEST_UDP_TARGET,
        payload,
    )
    .unwrap();
    association
        .connection()
        .send_datagram(encode_tuic_udp_packet(&packet).unwrap().into())
        .unwrap();
    association
        .receive_until(Some(Instant::now() + Duration::from_secs(1)))
        .await
        .unwrap()
        .unwrap()
        .into_payload()
}

fn tuic_owner_deadline() -> dae_runtime_control::AbsoluteDeadline {
    dae_runtime_control::AbsoluteDeadline::from_now(Instant::now(), Duration::from_secs(2))
}

async fn wait_until(mut predicate: impl FnMut() -> bool) {
    time::timeout(Duration::from_secs(3), async {
        while !predicate() {
            time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("TUIC owner integration state reached before timeout");
}

async fn stop_tuic_owner_registry(
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

fn assert_tuic_owner_resources_released(registry: &TuicOwnerRegistryHandle, generation: u64) {
    let owner = registry.metrics_snapshot();
    assert_eq!(owner["registeredKeys"], 0);
    assert_eq!(owner["activeOwners"], 0);
    assert_eq!(owner["activeLogicalLeases"], 0);
    assert_eq!(owner["activeUdpAssociations"], 0);
    assert_eq!(owner["currentUdpQueuedBytes"], 0);
    assert_eq!(owner["activeAssociationQuarantine"], 0);
    assert_eq!(owner["registryOwnershipReleased"], true);
    assert_eq!(
        owner["endpointDrain"]["completed"],
        owner["endpointDrain"]["requested"]
    );
    assert_eq!(owner["endpointDrain"]["timedOut"], 0);
    assert_eq!(owner["shutdownTimedOut"], false);
    let endpoint = quic_endpoint_metrics_snapshot(generation);
    assert_eq!(endpoint["liveStates"]["total"], 0);
    assert_eq!(endpoint["endpointDriverTasks"]["live"], 0);
    assert_eq!(endpoint["chargedBytes"]["total"], 0);
}

#[test]
fn tuic_owner_reuses_auth_and_isolates_associations_across_runtimes() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .unwrap();
    runtime.block_on(async {
        let server = TuicTestServer::start().await;
        let generation = 71;
        let proxy = tuic_proxy(server.addr, generation);
        let stop = ResidentStopSignal::shared();
        let (registry, owner_thread) =
            start_tuic_owner_registry(generation, Arc::clone(&stop), 2 * 1024 * 1024).unwrap();
        let deadline = || {
            dae_runtime_control::AbsoluteDeadline::from_now(Instant::now(), Duration::from_secs(2))
        };

        let tcp_a = {
            let registry = registry.clone();
            let proxy = Arc::clone(&proxy);
            tokio::task::spawn_blocking(move || {
                tokio::runtime::Builder::new_current_thread()
                    .enable_io()
                    .enable_time()
                    .build()
                    .unwrap()
                    .block_on(registry.acquire(
                        proxy,
                        QuicEndpointCallerClass::TcpData,
                        dae_runtime_control::AbsoluteDeadline::from_now(
                            Instant::now(),
                            Duration::from_secs(2),
                        ),
                    ))
            })
            .await
            .unwrap()
            .unwrap()
        };
        let tcp_b = {
            let registry = registry.clone();
            let proxy = Arc::clone(&proxy);
            tokio::task::spawn_blocking(move || {
                tokio::runtime::Builder::new_current_thread()
                    .enable_io()
                    .enable_time()
                    .build()
                    .unwrap()
                    .block_on(registry.acquire(
                        proxy,
                        QuicEndpointCallerClass::BackgroundHealth,
                        dae_runtime_control::AbsoluteDeadline::from_now(
                            Instant::now(),
                            Duration::from_secs(2),
                        ),
                    ))
            })
            .await
            .unwrap()
            .unwrap()
        };
        assert_eq!(
            tcp_a.connection().stable_id(),
            tcp_b.connection().stable_id()
        );
        assert_eq!(open_tuic_echo_stream(&tcp_a, *b"tcpA").await, *b"tcpA");
        assert_eq!(open_tuic_echo_stream(&tcp_b, *b"tcpB").await, *b"tcpB");

        let mut udp_a = registry
            .acquire(
                Arc::clone(&proxy),
                QuicEndpointCallerClass::UdpData,
                deadline(),
            )
            .await
            .unwrap()
            .open_udp_association()
            .unwrap();
        let mut udp_b = registry
            .acquire(
                Arc::clone(&proxy),
                QuicEndpointCallerClass::ManagedDns,
                deadline(),
            )
            .await
            .unwrap()
            .open_udp_association()
            .unwrap();
        assert_ne!(udp_a.association_id(), udp_b.association_id());
        assert_eq!(exchange_tuic_udp(&mut udp_a, 1, b"udp-a").await, b"udp-a");
        assert_eq!(exchange_tuic_udp(&mut udp_b, 2, b"udp-b").await, b"udp-b");
        drop(udp_a);
        time::sleep(Duration::from_secs(
            dae_outbound::tuic::DEFAULT_TUIC_KEEPALIVE_SECS + 1,
        ))
        .await;
        assert!(server.observation.heartbeats.load(Ordering::Relaxed) >= 1);
        assert_eq!(exchange_tuic_udp(&mut udp_b, 3, b"udp-b2").await, b"udp-b2");

        time::sleep(Duration::from_millis(50)).await;
        assert_eq!(server.observation.connections.load(Ordering::Relaxed), 1);
        assert_eq!(
            server.observation.authentications.load(Ordering::Relaxed),
            1
        );
        assert_eq!(server.observation.tcp_streams.load(Ordering::Relaxed), 2);
        assert_eq!(server.observation.udp_packets.load(Ordering::Relaxed), 3);
        assert_eq!(server.observation.dissociations.load(Ordering::Relaxed), 1);

        drop(udp_b);
        drop(tcp_a);
        drop(tcp_b);
        stop.store(true, Ordering::Release);
        let joined = tokio::task::spawn_blocking(move || owner_thread.join())
            .await
            .unwrap();
        assert!(joined.is_ok());
        let metrics = registry.metrics_snapshot();
        assert_eq!(metrics["activeOwners"], 0);
        assert_eq!(metrics["activeLogicalLeases"], 0);
        assert_eq!(metrics["activeUdpAssociations"], 0);
        assert_eq!(metrics["currentUdpQueuedBytes"], 0);
        assert_eq!(metrics["shutdownTimedOut"], false);
        server.stop().await;
    });
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tuic_owner_rebuilds_once_after_remote_close_and_invalidates_old_associations() {
    let server = TuicTestServer::start().await;
    let generation = 7_102;
    let proxy = tuic_proxy(server.addr, generation);
    let stop = ResidentStopSignal::shared();
    let (registry, owner_thread) = start_tuic_owner_registry(
        generation,
        Arc::clone(&stop),
        RESIDENT_TCP_FLOW_STACK_BYTES_DEFAULT,
    )
    .unwrap();

    let first = registry
        .acquire(
            Arc::clone(&proxy),
            QuicEndpointCallerClass::TcpData,
            tuic_owner_deadline(),
        )
        .await
        .unwrap();
    let first_connection_id = first.connection().stable_id();
    let mut old_association = registry
        .acquire(
            Arc::clone(&proxy),
            QuicEndpointCallerClass::UdpData,
            tuic_owner_deadline(),
        )
        .await
        .unwrap()
        .open_udp_association()
        .unwrap();
    let old_association_id = old_association.association_id();
    assert_eq!(
        exchange_tuic_udp(&mut old_association, 11, b"before-close").await,
        b"before-close"
    );
    wait_until(|| server.observation.authentications.load(Ordering::Relaxed) == 1).await;

    server.close_current();
    wait_until(|| registry.metrics_snapshot()["activeOwners"] == 0).await;
    assert!(
        old_association
            .receive_until(Some(Instant::now() + Duration::from_millis(100)))
            .await
            .is_err()
    );
    drop(old_association);
    drop(first);

    let replacement = registry
        .acquire(
            Arc::clone(&proxy),
            QuicEndpointCallerClass::BackgroundHealth,
            tuic_owner_deadline(),
        )
        .await
        .unwrap();
    assert_ne!(replacement.connection().stable_id(), first_connection_id);
    let mut replacement_association = registry
        .acquire(
            proxy,
            QuicEndpointCallerClass::ManagedDns,
            tuic_owner_deadline(),
        )
        .await
        .unwrap()
        .open_udp_association()
        .unwrap();
    assert_ne!(replacement_association.association_id(), 0);
    assert_eq!(
        exchange_tuic_udp(&mut replacement_association, 12, b"after-close").await,
        b"after-close"
    );
    wait_until(|| server.observation.authentications.load(Ordering::Relaxed) == 2).await;
    assert_eq!(server.observation.connections.load(Ordering::Relaxed), 2);
    assert_eq!(registry.metrics_snapshot()["cumulativeBuilds"], 2);
    assert_ne!(old_association_id, 0);

    drop(replacement_association);
    drop(replacement);
    assert!(
        stop_tuic_owner_registry(stop, owner_thread).await < RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE
    );
    assert_tuic_owner_resources_released(&registry, generation);
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn overlapping_tuic_generations_drain_independently() {
    let server = TuicTestServer::start().await;
    let first_generation = 7_103;
    let second_generation = 7_104;
    let first_stop = ResidentStopSignal::shared();
    let second_stop = ResidentStopSignal::shared();
    let (first_registry, first_thread) = start_tuic_owner_registry(
        first_generation,
        Arc::clone(&first_stop),
        RESIDENT_TCP_FLOW_STACK_BYTES_DEFAULT,
    )
    .unwrap();
    let (second_registry, second_thread) = start_tuic_owner_registry(
        second_generation,
        Arc::clone(&second_stop),
        RESIDENT_TCP_FLOW_STACK_BYTES_DEFAULT,
    )
    .unwrap();
    let first = first_registry
        .acquire(
            tuic_proxy(server.addr, first_generation),
            QuicEndpointCallerClass::TcpData,
            tuic_owner_deadline(),
        )
        .await
        .unwrap();
    let second = second_registry
        .acquire(
            tuic_proxy(server.addr, second_generation),
            QuicEndpointCallerClass::TcpData,
            tuic_owner_deadline(),
        )
        .await
        .unwrap();
    assert_ne!(
        first.connection().stable_id(),
        second.connection().stable_id()
    );
    drop(first);
    assert!(
        stop_tuic_owner_registry(first_stop, first_thread).await
            < RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE
    );
    assert_tuic_owner_resources_released(&first_registry, first_generation);
    assert_eq!(second_registry.metrics_snapshot()["activeOwners"], 1);
    assert_eq!(open_tuic_echo_stream(&second, *b"live").await, *b"live");
    drop(second);
    assert!(
        stop_tuic_owner_registry(second_stop, second_thread).await
            < RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE
    );
    assert_tuic_owner_resources_released(&second_registry, second_generation);
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn five_tuic_owner_reload_cycles_return_all_resources_to_zero() {
    let server = TuicTestServer::start().await;
    let first_generation = 7_105;

    for offset in 0..5 {
        let generation = first_generation + offset;
        let stop = ResidentStopSignal::shared();
        let (registry, owner_thread) = start_tuic_owner_registry(
            generation,
            Arc::clone(&stop),
            RESIDENT_TCP_FLOW_STACK_BYTES_DEFAULT,
        )
        .unwrap();
        let lease = registry
            .acquire(
                tuic_proxy(server.addr, generation),
                QuicEndpointCallerClass::BackgroundHealth,
                tuic_owner_deadline(),
            )
            .await
            .unwrap();
        assert_eq!(open_tuic_echo_stream(&lease, *b"pass").await, *b"pass");
        drop(lease);
        assert!(
            stop_tuic_owner_registry(stop, owner_thread).await
                < RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE
        );
        assert_tuic_owner_resources_released(&registry, generation);
    }
    assert_eq!(
        server.observation.authentications.load(Ordering::Relaxed),
        5
    );
    assert_eq!(server.observation.connections.load(Ordering::Relaxed), 5);
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_tuic_waiter_does_not_cancel_a_shared_no_response_build() {
    let blackhole = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let generation = 7_110;
    let proxy = tuic_proxy(blackhole.local_addr().unwrap(), generation);
    let stop = ResidentStopSignal::shared();
    let (registry, owner_thread) = start_tuic_owner_registry(
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

    let observer_registry = registry.clone();
    let observer = tokio::spawn(async move {
        observer_registry
            .acquire(
                proxy,
                QuicEndpointCallerClass::ManagedDns,
                dae_runtime_control::AbsoluteDeadline::from_now(
                    Instant::now(),
                    Duration::from_secs(1),
                ),
            )
            .await
    });
    time::sleep(Duration::from_millis(20)).await;
    elected.abort();
    match elected.await {
        Err(error) => assert!(error.is_cancelled()),
        Ok(_) => panic!("the elected TUIC acquisition waiter must be cancelled"),
    }
    let observer_error = observer
        .await
        .unwrap()
        .err()
        .expect("the no-response transport must fail by the elected absolute deadline");
    assert!(
        observer_error.contains("construction failed")
            || observer_error.contains("deadline")
            || observer_error.contains("cancel")
    );
    assert_eq!(registry.metrics_snapshot()["cumulativeBuilds"], 1);
    wait_until(|| registry.metrics_snapshot()["cumulativeBuildFailures"] == 1).await;
    assert_eq!(registry.metrics_snapshot()["cumulativeBuildFailures"], 1);
    assert!(
        stop_tuic_owner_registry(stop, owner_thread).await < RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE
    );
    assert_tuic_owner_resources_released(&registry, generation);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn simultaneous_tuic_no_response_waiters_share_one_physical_attempt() {
    let blackhole = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let generation = 7_111;
    let proxy = tuic_proxy(blackhole.local_addr().unwrap(), generation);
    let stop = ResidentStopSignal::shared();
    let (registry, owner_thread) = start_tuic_owner_registry(
        generation,
        Arc::clone(&stop),
        RESIDENT_TCP_FLOW_STACK_BYTES_DEFAULT,
    )
    .unwrap();
    let waiter_count = 8;
    let barrier = Arc::new(tokio::sync::Barrier::new(waiter_count + 1));
    let mut waiters = Vec::with_capacity(waiter_count);
    for _ in 0..waiter_count {
        let registry = registry.clone();
        let proxy = Arc::clone(&proxy);
        let barrier = Arc::clone(&barrier);
        waiters.push(tokio::spawn(async move {
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
    for waiter in waiters {
        assert!(waiter.await.unwrap().is_err());
    }
    assert_eq!(registry.metrics_snapshot()["cumulativeBuilds"], 1);
    wait_until(|| registry.metrics_snapshot()["cumulativeBuildFailures"] == 1).await;
    assert_eq!(registry.metrics_snapshot()["cumulativeBuildFailures"], 1);

    assert!(
        stop_tuic_owner_registry(stop, owner_thread).await < RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE
    );
    assert_tuic_owner_resources_released(&registry, generation);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn low_memory_tuic_owner_budget_rejects_excess_nodes_before_endpoint_creation() {
    let resources =
        TuicOwnerResourceProfile::from_runtime_profile(ResidentRuntimeProfile::LowMemory)
            .with_owner_limit(1);
    let owner_limit = resources.owner_limit();
    let node_count = owner_limit + 2;
    let generation = 7_112;
    let stop = ResidentStopSignal::shared();
    let (registry, owner_thread) = super::tuic_owner::start_tuic_owner_registry_with_resources(
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
        proxies.push(tuic_proxy(socket.local_addr().unwrap(), generation));
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
        let error = attempt
            .await
            .unwrap()
            .err()
            .expect("no-response and owner-budget attempts must fail");
        if error.contains("owner budget is full") {
            budget_rejections += 1;
        }
    }
    assert_eq!(budget_rejections, node_count - owner_limit);
    let owner = registry.metrics_snapshot();
    assert_eq!(
        owner["ownerLimitRejections"],
        (node_count - owner_limit) as u64
    );
    let endpoint = quic_endpoint_metrics_snapshot(generation);
    assert_eq!(endpoint["cumulativeCreations"], owner_limit as u64);
    drop(blackholes);

    assert!(
        stop_tuic_owner_registry(stop, owner_thread).await < RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE
    );
    assert_tuic_owner_resources_released(&registry, generation);
}
