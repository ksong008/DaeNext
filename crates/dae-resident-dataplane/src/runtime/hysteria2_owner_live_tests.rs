use super::*;

use std::net::SocketAddr;
use std::sync::atomic::AtomicUsize;
use std::time::Duration;

use bytes::Bytes;
use dae_outbound::shared_transport::test_support::{
    boring_quic_server_config, self_signed_tls_identity,
};
use h3::server;
use http::{Response, StatusCode};
use tokio::sync::{Barrier, Notify, oneshot};

use crate::plan::build_resident_proxy_plan_for_node;
use crate::quic_endpoint_metrics_snapshot;
use dae_resident_plan::ResidentProxyBinding;
use dae_resident_transport::QuicEndpointCallerClass;
use dae_runtime_control::AbsoluteDeadline;

const SERVER_NAME: &str = "localhost";
const AUTH_HEADER: &str = "Hysteria-Auth";
const UDP_ENABLED_HEADER: &str = "Hysteria-UDP";
const BANDWIDTH_HEADER: &str = "Hysteria-CC-RX";
const AUTH_PATH: &str = "/auth";

#[derive(Clone, Copy)]
enum Hysteria2OwnerAuthBehavior {
    UdpEnabled,
    TcpOnly,
    Reject,
    WaitForRelease,
}

struct Hysteria2OwnerTestServer {
    address: SocketAddr,
    auth_count: Arc<AtomicUsize>,
    connection_count: Arc<AtomicUsize>,
    current_connection: Arc<Mutex<Option<quinn::Connection>>>,
    auth_release: Arc<Notify>,
    task: tokio::task::JoinHandle<()>,
}

impl Hysteria2OwnerTestServer {
    async fn start() -> Self {
        Self::start_with_auth(Hysteria2OwnerAuthBehavior::UdpEnabled).await
    }

    async fn start_on(ip: std::net::IpAddr) -> Self {
        Self::start_with_auth_on(Hysteria2OwnerAuthBehavior::UdpEnabled, ip).await
    }

    async fn start_with_auth(auth_behavior: Hysteria2OwnerAuthBehavior) -> Self {
        Self::start_with_auth_on(
            auth_behavior,
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        )
        .await
    }

    async fn start_with_auth_on(
        auth_behavior: Hysteria2OwnerAuthBehavior,
        ip: std::net::IpAddr,
    ) -> Self {
        let identity = self_signed_tls_identity(&[SERVER_NAME]).unwrap();
        let server_config = boring_quic_server_config(
            &identity,
            &[b"h3".to_vec()],
            Arc::new(quinn::TransportConfig::default()),
        )
        .unwrap();
        let endpoint = dae_outbound::shared_transport::test_support::boring_quic_server_endpoint(
            server_config,
            SocketAddr::new(ip, 0),
        )
        .unwrap();
        let address = endpoint.local_addr().unwrap();
        let auth_count = Arc::new(AtomicUsize::new(0));
        let connection_count = Arc::new(AtomicUsize::new(0));
        let current_connection = Arc::new(Mutex::new(None));
        let auth_release = Arc::new(Notify::new());
        let task_auth_count = Arc::clone(&auth_count);
        let task_connection_count = Arc::clone(&connection_count);
        let task_current_connection = Arc::clone(&current_connection);
        let task_auth_release = Arc::clone(&auth_release);
        let task = tokio::spawn(async move {
            while let Some(connecting) = endpoint.accept().await {
                let task_auth_count = Arc::clone(&task_auth_count);
                let task_connection_count = Arc::clone(&task_connection_count);
                let task_current_connection = Arc::clone(&task_current_connection);
                let task_auth_release = Arc::clone(&task_auth_release);
                tokio::spawn(async move {
                    let Ok(connection) = connecting.await else {
                        return;
                    };
                    task_connection_count.fetch_add(1, Ordering::Relaxed);
                    *task_current_connection
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner()) =
                        Some(connection.clone());
                    serve_hysteria2_owner_connection(
                        connection,
                        task_auth_count,
                        auth_behavior,
                        task_auth_release,
                    )
                    .await;
                });
            }
        });
        Self {
            address,
            auth_count,
            connection_count,
            current_connection,
            auth_release,
            task,
        }
    }

    fn close_current(&self) {
        if let Some(connection) = self
            .current_connection
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
        {
            connection.close(0_u32.into(), b"owner rebuild test");
        }
    }

    fn release_auth(&self) {
        self.auth_release.notify_one();
    }
}

impl Drop for Hysteria2OwnerTestServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn serve_hysteria2_owner_connection(
    connection: quinn::Connection,
    auth_count: Arc<AtomicUsize>,
    auth_behavior: Hysteria2OwnerAuthBehavior,
    auth_release: Arc<Notify>,
) {
    let h3_connection = h3_quinn::Connection::new(connection.clone());
    let Ok(mut incoming): Result<server::Connection<h3_quinn::Connection, Bytes>, _> =
        server::Connection::new(h3_connection).await
    else {
        return;
    };
    let Some(Some(request)) = incoming.accept().await.ok() else {
        return;
    };
    let Ok((request, mut stream)) = request.resolve_request().await else {
        return;
    };
    assert_eq!(request.uri().path(), AUTH_PATH);
    assert!(request.headers().contains_key(AUTH_HEADER));
    while stream.recv_data().await.unwrap().is_some() {}
    auth_count.fetch_add(1, Ordering::Relaxed);
    if matches!(auth_behavior, Hysteria2OwnerAuthBehavior::WaitForRelease) {
        auth_release.notified().await;
    }
    let status = match auth_behavior {
        Hysteria2OwnerAuthBehavior::Reject => StatusCode::UNAUTHORIZED,
        Hysteria2OwnerAuthBehavior::UdpEnabled
        | Hysteria2OwnerAuthBehavior::TcpOnly
        | Hysteria2OwnerAuthBehavior::WaitForRelease => StatusCode::from_u16(233).unwrap(),
    };
    let udp_enabled = !matches!(
        auth_behavior,
        Hysteria2OwnerAuthBehavior::TcpOnly | Hysteria2OwnerAuthBehavior::Reject
    );
    let response = Response::builder()
        .status(status)
        .header(
            UDP_ENABLED_HEADER,
            if udp_enabled { "true" } else { "false" },
        )
        .header(BANDWIDTH_HEADER, "0")
        .body(())
        .unwrap();
    if stream.send_response(response).await.is_err() {
        return;
    }
    if stream.finish().await.is_err() {
        return;
    }

    let stream_connection = connection.clone();
    let stream_task = tokio::spawn(async move {
        loop {
            let Ok((mut send, mut recv)) = stream_connection.accept_bi().await else {
                return;
            };
            tokio::spawn(async move {
                let frame_type = read_test_varint(&mut recv).await;
                assert_eq!(
                    frame_type,
                    dae_outbound::hysteria2::HYSTERIA2_FRAME_TYPE_TCP_REQUEST
                );
                let target_len = read_test_varint(&mut recv).await as usize;
                let mut target = vec![0_u8; target_len];
                recv.read_exact(&mut target).await.unwrap();
                assert!(!target.is_empty());
                let padding_len = read_test_varint(&mut recv).await as usize;
                let mut padding = vec![0_u8; padding_len];
                recv.read_exact(&mut padding).await.unwrap();
                send.write_all(&[0, 0, 0]).await.unwrap();
                send.finish().unwrap();
                let _ = send.stopped().await;
            });
        }
    });
    let datagram_connection = connection.clone();
    let datagram_task = tokio::spawn(async move {
        loop {
            let Ok(encoded) = datagram_connection.read_datagram().await else {
                return;
            };
            let request = dae_outbound::hysteria2::decode_hysteria2_udp_message(&encoded).unwrap();
            let response = dae_outbound::hysteria2::Hysteria2UdpMessage::new(
                request.session_id(),
                request.target(),
                request.payload(),
            )
            .unwrap();
            datagram_connection
                .send_datagram(Bytes::from(
                    dae_outbound::hysteria2::encode_hysteria2_udp_message(&response).unwrap(),
                ))
                .unwrap();
        }
    });

    let _ = connection.closed().await;
    stream_task.abort();
    datagram_task.abort();
    drop(incoming);
}

async fn read_test_varint(recv: &mut quinn::RecvStream) -> u64 {
    let mut first = [0_u8; 1];
    recv.read_exact(&mut first).await.unwrap();
    let length = 1_usize << (first[0] >> 6);
    let mut value = u64::from(first[0] & 0x3f);
    if length > 1 {
        let mut rest = vec![0_u8; length - 1];
        recv.read_exact(&mut rest).await.unwrap();
        for byte in rest {
            value = (value << 8) | u64::from(byte);
        }
    }
    value
}

fn owner_test_proxy(address: SocketAddr, generation: u64) -> ResidentProxyBinding {
    owner_test_proxy_for_authority(&address.to_string(), generation, "owner-test-auth")
}

fn owner_test_proxy_for_authority(
    authority: &str,
    generation: u64,
    auth: &str,
) -> ResidentProxyBinding {
    let sections = dae_config::parser::parse_config(
        r#"
        global {
        allow_insecure: false
        }
        routing {
        fallback: direct
        }
        "#,
    )
    .unwrap();
    let config = dae_config::schema::build_config(&sections).unwrap();
    let link = format!("hysteria2://{auth}@{authority}?insecure=1&sni={SERVER_NAME}#owner-test",);
    let mut proxy = build_resident_proxy_plan_for_node(
        &config,
        "owner-test".to_owned(),
        "owner-test-node".to_owned(),
        link,
    )
    .unwrap();
    proxy.materialize_execution();
    ResidentProxyBinding::resident(
        Arc::new(proxy),
        dae_runtime_control::OwnerGeneration::new(generation),
    )
    .expect("materialized Hysteria2 owner test binding")
}

fn owner_deadline() -> AbsoluteDeadline {
    AbsoluteDeadline::from_now(Instant::now(), Duration::from_secs(3))
}

async fn exchange_tcp(connection: &quinn::Connection, target: &str) {
    let (mut send, mut recv) = connection.open_bi().await.unwrap();
    dae_outbound::hysteria2::write_hysteria2_tcp_request(&mut send, target)
        .await
        .unwrap();
    let response = dae_outbound::hysteria2::read_hysteria2_tcp_response(&mut recv)
        .await
        .unwrap();
    assert!(response.ok);
}

async fn exchange_udp(session: &mut Hysteria2UdpSessionLease, target: &str, payload: &[u8]) {
    let message =
        dae_outbound::hysteria2::Hysteria2UdpMessage::new(session.session_id(), target, payload)
            .unwrap();
    session
        .connection()
        .send_datagram(Bytes::from(
            dae_outbound::hysteria2::encode_hysteria2_udp_message(&message).unwrap(),
        ))
        .unwrap();
    let response = session
        .receive_until(Some(Instant::now() + Duration::from_secs(2)))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.session_id(), session.session_id());
    assert_eq!(response.target(), target);
    assert_eq!(response.payload(), payload);
}

async fn wait_until(mut predicate: impl FnMut() -> bool) {
    tokio::time::timeout(Duration::from_secs(2), async {
        while !predicate() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("owner integration state reached before timeout");
}

async fn stop_owner_registry(
    stop: SharedResidentStopSignal,
    owner_thread: JoinHandle<()>,
) -> Duration {
    let started = Instant::now();
    stop.store(true, Ordering::Release);
    tokio::task::spawn_blocking(move || owner_thread.join().unwrap())
        .await
        .unwrap();
    started.elapsed()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn generation_owner_reuses_auth_across_runtimes_and_rebuilds_after_remote_close() {
    let server = Hysteria2OwnerTestServer::start().await;
    let generation = 9_902;
    let proxy = owner_test_proxy(server.address, generation);
    let stop = ResidentStopSignal::shared();
    let (registry, owner_thread) = start_hysteria2_owner_registry(
        generation,
        Arc::clone(&stop),
        RESIDENT_TCP_FLOW_STACK_BYTES_DEFAULT,
    )
    .unwrap();

    let primary = registry
        .acquire(
            proxy.clone(),
            QuicEndpointCallerClass::TcpData,
            owner_deadline(),
        )
        .await
        .unwrap();
    let first_connection_id = primary.connection().stable_id();
    wait_until(|| server.auth_count.load(Ordering::Relaxed) == 1).await;

    let mut caller_threads = Vec::new();
    let mut caller_results = Vec::new();
    for caller in [
        QuicEndpointCallerClass::UdpData,
        QuicEndpointCallerClass::ConfiguredDns,
        QuicEndpointCallerClass::ManagedDns,
        QuicEndpointCallerClass::BackgroundHealth,
    ] {
        let registry = registry.clone();
        let proxy = proxy.clone();
        let (sender, receiver) = oneshot::channel();
        caller_threads.push(std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .enable_time()
                .build()
                .unwrap();
            let result = runtime.block_on(async move {
                registry
                    .acquire(proxy, caller, owner_deadline())
                    .await
                    .map(|lease| lease.connection().stable_id())
            });
            let _ = sender.send(result);
        }));
        caller_results.push(receiver);
    }
    for result in caller_results {
        assert_eq!(result.await.unwrap().unwrap(), first_connection_id);
    }
    for thread in caller_threads {
        thread.join().unwrap();
    }
    assert_eq!(server.auth_count.load(Ordering::Relaxed), 1);

    tokio::join!(
        exchange_tcp(primary.connection(), "tcp-a.invalid:443"),
        exchange_tcp(primary.connection(), "tcp-b.invalid:443")
    );
    let mut udp_a = registry
        .acquire(
            proxy.clone(),
            QuicEndpointCallerClass::UdpData,
            owner_deadline(),
        )
        .await
        .unwrap()
        .open_udp_session()
        .unwrap();
    let mut udp_b = registry
        .acquire(
            proxy.clone(),
            QuicEndpointCallerClass::ManagedDns,
            owner_deadline(),
        )
        .await
        .unwrap()
        .open_udp_session()
        .unwrap();
    assert_ne!(udp_a.session_id(), udp_b.session_id());
    exchange_udp(&mut udp_a, "udp-a.invalid:53", b"a-one").await;
    exchange_udp(&mut udp_b, "udp-b.invalid:53", b"b-one").await;
    drop(udp_a);
    exchange_udp(&mut udp_b, "udp-b.invalid:53", b"b-two").await;

    server.close_current();
    wait_until(|| registry.metrics_snapshot()["activeOwners"] == 0).await;
    assert!(
        udp_b
            .receive_until(Some(Instant::now() + Duration::from_millis(100)))
            .await
            .is_err()
    );
    drop(udp_b);
    drop(primary);

    let replacement = registry
        .acquire(
            proxy.clone(),
            QuicEndpointCallerClass::BackgroundHealth,
            owner_deadline(),
        )
        .await
        .unwrap();
    assert_ne!(replacement.connection().stable_id(), first_connection_id);
    wait_until(|| server.auth_count.load(Ordering::Relaxed) == 2).await;
    assert_eq!(server.connection_count.load(Ordering::Relaxed), 2);
    exchange_tcp(replacement.connection(), "tcp-rebuilt.invalid:443").await;
    drop(replacement);

    assert!(stop_owner_registry(stop, owner_thread).await < Duration::from_secs(2));
    let owner_snapshot = registry.metrics_snapshot();
    assert_eq!(owner_snapshot["activeOwners"], 0);
    assert_eq!(owner_snapshot["activeLogicalLeases"], 0);
    assert_eq!(owner_snapshot["activeUdpSessions"], 0);
    assert_eq!(owner_snapshot["activeUdpSessionQuarantine"], 0);
    let endpoint_snapshot = quic_endpoint_metrics_snapshot(generation);
    assert_eq!(endpoint_snapshot["liveStates"]["total"], 0);
    assert_eq!(endpoint_snapshot["endpointDriverTasks"]["live"], 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ipv6_owner_carries_tcp_and_udp_and_releases_endpoint_resources() {
    let server =
        Hysteria2OwnerTestServer::start_on(std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST))
            .await;
    let generation = 9_915;
    let proxy = owner_test_proxy(server.address, generation);
    let stop = ResidentStopSignal::shared();
    let (registry, owner_thread) = start_hysteria2_owner_registry(
        generation,
        Arc::clone(&stop),
        RESIDENT_TCP_FLOW_STACK_BYTES_DEFAULT,
    )
    .unwrap();

    let tcp = registry
        .acquire(
            proxy.clone(),
            QuicEndpointCallerClass::TcpData,
            owner_deadline(),
        )
        .await
        .unwrap();
    assert!(tcp.connection().remote_address().is_ipv6());
    exchange_tcp(tcp.connection(), "ipv6-tcp.invalid:443").await;

    let mut udp = registry
        .acquire(proxy, QuicEndpointCallerClass::UdpData, owner_deadline())
        .await
        .unwrap()
        .open_udp_session()
        .unwrap();
    assert_eq!(udp.connection().stable_id(), tcp.connection().stable_id());
    exchange_udp(&mut udp, "[2001:db8::53]:53", b"ipv6-udp").await;
    drop(udp);
    drop(tcp);

    assert!(stop_owner_registry(stop, owner_thread).await < Duration::from_secs(2));
    let owner_snapshot = registry.metrics_snapshot();
    assert_eq!(owner_snapshot["activeOwners"], 0);
    assert_eq!(owner_snapshot["activeLogicalLeases"], 0);
    assert_eq!(owner_snapshot["activeUdpSessions"], 0);
    let endpoint_snapshot = quic_endpoint_metrics_snapshot(generation);
    assert_eq!(endpoint_snapshot["liveStates"]["total"], 0);
    assert_eq!(endpoint_snapshot["endpointDriverTasks"]["live"], 0);
    assert_eq!(endpoint_snapshot["chargedBytes"]["total"], 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_auth_waiter_does_not_cancel_the_generation_owner_build() {
    let server =
        Hysteria2OwnerTestServer::start_with_auth(Hysteria2OwnerAuthBehavior::WaitForRelease).await;
    let generation = 9_903;
    let proxy = owner_test_proxy(server.address, generation);
    let stop = ResidentStopSignal::shared();
    let (registry, owner_thread) = start_hysteria2_owner_registry(
        generation,
        Arc::clone(&stop),
        RESIDENT_TCP_FLOW_STACK_BYTES_DEFAULT,
    )
    .unwrap();

    let first_registry = registry.clone();
    let first_proxy = proxy.clone();
    let first = tokio::spawn(async move {
        first_registry
            .acquire(
                first_proxy,
                QuicEndpointCallerClass::TcpData,
                owner_deadline(),
            )
            .await
    });
    wait_until(|| server.auth_count.load(Ordering::Relaxed) == 1).await;

    let observer_registry = registry.clone();
    let observer_proxy = proxy.clone();
    let observer = tokio::spawn(async move {
        observer_registry
            .acquire(
                observer_proxy,
                QuicEndpointCallerClass::ManagedDns,
                owner_deadline(),
            )
            .await
    });
    tokio::time::sleep(Duration::from_millis(20)).await;
    first.abort();
    match first.await {
        Err(error) => assert!(error.is_cancelled()),
        Ok(_) => panic!("the first acquisition waiter must be cancelled"),
    }
    server.release_auth();

    let lease = observer.await.unwrap().unwrap();
    exchange_tcp(lease.connection(), "cancelled-waiter.invalid:443").await;
    assert_eq!(server.auth_count.load(Ordering::Relaxed), 1);
    assert_eq!(server.connection_count.load(Ordering::Relaxed), 1);
    assert_eq!(registry.metrics_snapshot()["cumulativeBuilds"], 1);
    drop(lease);

    assert!(stop_owner_registry(stop, owner_thread).await < RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE);
    let endpoint_snapshot = quic_endpoint_metrics_snapshot(generation);
    assert_eq!(endpoint_snapshot["liveStates"]["total"], 0);
    assert_eq!(endpoint_snapshot["endpointDriverTasks"]["live"], 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn simultaneous_auth_failure_waiters_share_one_connection_attempt() {
    let server =
        Hysteria2OwnerTestServer::start_with_auth(Hysteria2OwnerAuthBehavior::Reject).await;
    let generation = 9_904;
    let proxy = owner_test_proxy(server.address, generation);
    let stop = ResidentStopSignal::shared();
    let (registry, owner_thread) = start_hysteria2_owner_registry(
        generation,
        Arc::clone(&stop),
        RESIDENT_TCP_FLOW_STACK_BYTES_DEFAULT,
    )
    .unwrap();
    let waiter_count = 8;
    let barrier = Arc::new(Barrier::new(waiter_count + 1));
    let mut waiters = Vec::with_capacity(waiter_count);
    for _ in 0..waiter_count {
        let registry = registry.clone();
        let proxy = proxy.clone();
        let barrier = Arc::clone(&barrier);
        waiters.push(tokio::spawn(async move {
            barrier.wait().await;
            registry
                .acquire(
                    proxy,
                    QuicEndpointCallerClass::BackgroundHealth,
                    owner_deadline(),
                )
                .await
                .err()
                .expect("rejected authentication must fail acquisition")
        }));
    }
    barrier.wait().await;

    for waiter in waiters {
        let error = waiter.await.unwrap();
        assert!(
            error.contains("authentication rejected")
                || error.contains("operation=hysteria2-owner-auth")
                || error.contains("authenticate Hysteria2 owner"),
            "unexpected shared authentication failure: {error}"
        );
    }
    assert_eq!(server.auth_count.load(Ordering::Relaxed), 1);
    assert_eq!(server.connection_count.load(Ordering::Relaxed), 1);
    let owner_snapshot = registry.metrics_snapshot();
    assert_eq!(owner_snapshot["cumulativeBuilds"], 1);
    assert_eq!(owner_snapshot["cumulativeBuildFailures"], 1);

    assert!(stop_owner_registry(stop, owner_thread).await < RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE);
    let endpoint_snapshot = quic_endpoint_metrics_snapshot(generation);
    assert_eq!(endpoint_snapshot["liveStates"]["total"], 0);
    assert_eq!(endpoint_snapshot["endpointDriverTasks"]["live"], 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tcp_only_auth_rejects_udp_without_reauthenticating() {
    let server =
        Hysteria2OwnerTestServer::start_with_auth(Hysteria2OwnerAuthBehavior::TcpOnly).await;
    let generation = 9_905;
    let proxy = owner_test_proxy(server.address, generation);
    let stop = ResidentStopSignal::shared();
    let (registry, owner_thread) = start_hysteria2_owner_registry(
        generation,
        Arc::clone(&stop),
        RESIDENT_TCP_FLOW_STACK_BYTES_DEFAULT,
    )
    .unwrap();

    let tcp = registry
        .acquire(
            proxy.clone(),
            QuicEndpointCallerClass::TcpData,
            owner_deadline(),
        )
        .await
        .unwrap();
    let connection_id = tcp.connection().stable_id();
    exchange_tcp(tcp.connection(), "tcp-only.invalid:443").await;
    let udp_transport = registry
        .acquire(
            proxy.clone(),
            QuicEndpointCallerClass::UdpData,
            owner_deadline(),
        )
        .await
        .unwrap();
    assert_eq!(udp_transport.connection().stable_id(), connection_id);
    let error = match udp_transport.open_udp_session() {
        Ok(_) => panic!("TCP-only Hysteria2 auth must reject a UDP session"),
        Err(error) => error,
    };
    assert!(error.contains("did not negotiate UDP support"));
    assert_eq!(server.auth_count.load(Ordering::Relaxed), 1);
    assert_eq!(server.connection_count.load(Ordering::Relaxed), 1);
    drop(tcp);

    assert!(stop_owner_registry(stop, owner_thread).await < RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE);
    let endpoint_snapshot = quic_endpoint_metrics_snapshot(generation);
    assert_eq!(endpoint_snapshot["liveStates"]["total"], 0);
    assert_eq!(endpoint_snapshot["endpointDriverTasks"]["live"], 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn overlapping_generations_drain_independently_across_reloads() {
    let server = Hysteria2OwnerTestServer::start().await;
    let first_generation = 9_906;
    let second_generation = 9_907;
    let first_proxy = owner_test_proxy(server.address, first_generation);
    let second_proxy = owner_test_proxy(server.address, second_generation);
    let first_stop = ResidentStopSignal::shared();
    let second_stop = ResidentStopSignal::shared();
    let (first_registry, first_thread) = start_hysteria2_owner_registry(
        first_generation,
        Arc::clone(&first_stop),
        RESIDENT_TCP_FLOW_STACK_BYTES_DEFAULT,
    )
    .unwrap();
    let (second_registry, second_thread) = start_hysteria2_owner_registry(
        second_generation,
        Arc::clone(&second_stop),
        RESIDENT_TCP_FLOW_STACK_BYTES_DEFAULT,
    )
    .unwrap();

    let first = first_registry
        .acquire(
            first_proxy,
            QuicEndpointCallerClass::TcpData,
            owner_deadline(),
        )
        .await
        .unwrap();
    let second = second_registry
        .acquire(
            second_proxy,
            QuicEndpointCallerClass::TcpData,
            owner_deadline(),
        )
        .await
        .unwrap();
    assert_ne!(
        first.connection().stable_id(),
        second.connection().stable_id()
    );
    wait_until(|| server.auth_count.load(Ordering::Relaxed) == 2).await;
    drop(first);

    assert!(
        stop_owner_registry(first_stop, first_thread).await < RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE
    );
    let first_endpoint_snapshot = quic_endpoint_metrics_snapshot(first_generation);
    assert_eq!(first_endpoint_snapshot["liveStates"]["total"], 0);
    assert_eq!(first_endpoint_snapshot["endpointDriverTasks"]["live"], 0);
    assert_eq!(second_registry.metrics_snapshot()["activeOwners"], 1);
    exchange_tcp(second.connection(), "overlap-survivor.invalid:443").await;
    drop(second);

    assert!(
        stop_owner_registry(second_stop, second_thread).await
            < RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE
    );
    let second_endpoint_snapshot = quic_endpoint_metrics_snapshot(second_generation);
    assert_eq!(second_endpoint_snapshot["liveStates"]["total"], 0);
    assert_eq!(second_endpoint_snapshot["endpointDriverTasks"]["live"], 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn five_owner_reload_cycles_return_endpoint_resources_to_zero() {
    let server = Hysteria2OwnerTestServer::start().await;
    let first_generation = 9_908;

    for offset in 0..5 {
        let generation = first_generation + offset;
        let proxy = owner_test_proxy(server.address, generation);
        let stop = ResidentStopSignal::shared();
        let (registry, owner_thread) = start_hysteria2_owner_registry(
            generation,
            Arc::clone(&stop),
            RESIDENT_TCP_FLOW_STACK_BYTES_DEFAULT,
        )
        .unwrap();
        let lease = registry
            .acquire(
                proxy,
                QuicEndpointCallerClass::BackgroundHealth,
                owner_deadline(),
            )
            .await
            .unwrap();
        exchange_tcp(lease.connection(), "reload-cycle.invalid:443").await;
        drop(lease);
        assert!(
            stop_owner_registry(stop, owner_thread).await < RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE
        );
        let owner_snapshot = registry.metrics_snapshot();
        assert_eq!(owner_snapshot["registeredKeys"], 0);
        assert_eq!(owner_snapshot["activeOwners"], 0);
        assert_eq!(owner_snapshot["activeLogicalLeases"], 0);
        assert_eq!(owner_snapshot["activeUdpSessions"], 0);
        let endpoint_snapshot = quic_endpoint_metrics_snapshot(generation);
        assert_eq!(endpoint_snapshot["liveStates"]["total"], 0);
        assert_eq!(endpoint_snapshot["endpointDriverTasks"]["live"], 0);
    }
    assert_eq!(server.auth_count.load(Ordering::Relaxed), 5);
    assert_eq!(server.connection_count.load(Ordering::Relaxed), 5);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn multi_owner_shutdown_drains_endpoints_concurrently_and_reconciles_ownership() {
    let server = Hysteria2OwnerTestServer::start().await;
    let generation = 9_914;
    let stop = ResidentStopSignal::shared();
    let (registry, owner_thread) = start_hysteria2_owner_registry(
        generation,
        Arc::clone(&stop),
        RESIDENT_TCP_FLOW_STACK_BYTES_DEFAULT,
    )
    .unwrap();
    let mut leases = Vec::new();
    let first_proxy = owner_test_proxy_for_authority(
        &server.address.to_string(),
        generation,
        "owner-test-auth-0",
    );
    leases.push(
        registry
            .acquire(
                first_proxy,
                QuicEndpointCallerClass::BackgroundHealth,
                owner_deadline(),
            )
            .await
            .unwrap(),
    );
    let endpoint = quic_endpoint_metrics_snapshot(generation);
    let endpoint_admission_charge = endpoint["endpoints"][0]["admissionChargedBytes"]
        .as_u64()
        .unwrap() as usize;
    let admission_owner_limit = endpoint["admission"]["budget"]["maxActiveOwners"]
        .as_u64()
        .unwrap() as usize;
    let admission_byte_limit = endpoint["admission"]["budget"]["maxChargedBytes"]
        .as_u64()
        .unwrap() as usize;
    let endpoint_capacity = registry
        .resource_profile_for_test()
        .owner_limit()
        .min(admission_owner_limit)
        .min(admission_byte_limit / endpoint_admission_charge);
    let owner_count = endpoint_capacity.div_ceil(2);
    assert!(owner_count > 1);
    leases.reserve(owner_count.saturating_sub(1));
    for index in 1..owner_count {
        let proxy = owner_test_proxy_for_authority(
            &server.address.to_string(),
            generation,
            &format!("owner-test-auth-{index}"),
        );
        leases.push(
            registry
                .acquire(
                    proxy,
                    QuicEndpointCallerClass::BackgroundHealth,
                    owner_deadline(),
                )
                .await
                .unwrap(),
        );
    }
    wait_until(|| registry.metrics_snapshot()["activeOwners"] == owner_count).await;
    drop(leases);

    assert!(stop_owner_registry(stop, owner_thread).await < Duration::from_secs(2));
    let owner = registry.metrics_snapshot();
    assert_eq!(owner["registeredKeys"], 0);
    assert_eq!(owner["activeOwners"], 0);
    assert_eq!(owner["activeLogicalLeases"], 0);
    assert_eq!(owner["registryOwnershipReleased"], true);
    assert_eq!(owner["endpointDrain"]["requested"], owner_count);
    assert_eq!(owner["endpointDrain"]["completed"], owner_count);
    assert_eq!(owner["endpointDrain"]["timedOut"], 0);
    assert_eq!(owner["shutdownTimedOut"], false);
    let endpoints = quic_endpoint_metrics_snapshot(generation);
    assert_eq!(endpoints["liveStates"]["total"], 0);
    assert_eq!(endpoints["endpointDriverTasks"]["live"], 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ten_no_response_nodes_release_all_endpoint_resources() {
    let blackhole = std::net::UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, 0)).unwrap();
    let authority = format!("localhost:{}", blackhole.local_addr().unwrap().port());
    let generation = 9_916;
    let stop = ResidentStopSignal::shared();
    let (registry, owner_thread) = start_hysteria2_owner_registry(
        generation,
        Arc::clone(&stop),
        RESIDENT_TCP_FLOW_STACK_BYTES_DEFAULT,
    )
    .unwrap();
    let node_count = 10;
    let owner_limit = registry.metrics_snapshot()["budget"]["owners"]
        .as_u64()
        .unwrap() as usize;
    let admitted_node_count = node_count.min(owner_limit);
    let barrier = Arc::new(Barrier::new(node_count + 1));
    let mut attempts = Vec::with_capacity(node_count);
    for node in 0..node_count {
        let registry = registry.clone();
        let proxy = owner_test_proxy_for_authority(
            &authority,
            generation,
            &format!("no-response-auth-{node}"),
        );
        let barrier = Arc::clone(&barrier);
        attempts.push(tokio::spawn(async move {
            barrier.wait().await;
            registry
                .acquire(
                    proxy,
                    QuicEndpointCallerClass::BackgroundHealth,
                    AbsoluteDeadline::from_now(Instant::now(), Duration::from_millis(300)),
                )
                .await
        }));
    }
    barrier.wait().await;
    for attempt in attempts {
        let result = attempt.await.unwrap();
        assert!(
            result.is_err(),
            "a no-response node must not acquire an owner"
        );
    }
    tokio::time::sleep(Duration::from_secs(2)).await;
    let owner_snapshot = registry.metrics_snapshot();
    assert_eq!(
        owner_snapshot["cumulativeBuilds"], admitted_node_count,
        "unexpected no-response owner snapshot: {owner_snapshot}"
    );
    assert_eq!(
        owner_snapshot["cumulativeBuildFailures"],
        admitted_node_count
    );
    assert_eq!(
        owner_snapshot["ownerLimitRejections"],
        node_count - admitted_node_count
    );
    assert_eq!(owner_snapshot["activeOwners"], 0);
    assert_eq!(owner_snapshot["activeLogicalLeases"], 0);
    wait_until(|| {
        let snapshot = quic_endpoint_metrics_snapshot(generation);
        snapshot["liveStates"]["total"] == 0 && snapshot["endpointDriverTasks"]["live"] == 0
    })
    .await;
    let settled_endpoint_snapshot = quic_endpoint_metrics_snapshot(generation);
    assert_eq!(settled_endpoint_snapshot["liveStates"]["total"], 0);
    assert_eq!(settled_endpoint_snapshot["endpointDriverTasks"]["live"], 0);
    assert_eq!(settled_endpoint_snapshot["chargedBytes"]["total"], 0);

    assert!(stop_owner_registry(stop, owner_thread).await < RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE);
    let endpoint_snapshot = quic_endpoint_metrics_snapshot(generation);
    assert!(
        endpoint_snapshot["cumulativeCreations"].as_u64().unwrap() >= admitted_node_count as u64,
        "unexpected no-response endpoint snapshot: {endpoint_snapshot}"
    );
    assert_eq!(endpoint_snapshot["liveStates"]["total"], 0);
    assert_eq!(endpoint_snapshot["endpointDriverTasks"]["live"], 0);
    assert_eq!(endpoint_snapshot["chargedBytes"]["total"], 0);
    assert_eq!(endpoint_snapshot["chargedBytes"]["udpSocketCount"], 0);
    drop(blackhole);
}
