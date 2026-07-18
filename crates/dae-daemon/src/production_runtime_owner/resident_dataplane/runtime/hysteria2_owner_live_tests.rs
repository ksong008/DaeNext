use super::*;

use std::sync::atomic::AtomicUsize;
use std::time::Duration;

use bytes::Bytes;
use h3::server;
use http::{Response, StatusCode};
use quinn::crypto::rustls::QuicServerConfig;
use rcgen::generate_simple_self_signed;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::sync::oneshot;

use crate::production_runtime_owner::resident_dataplane::plan::build_resident_proxy_plan_for_node;
use crate::production_runtime_owner::resident_dataplane::tcp::quic_endpoint_metrics_snapshot;

const SERVER_NAME: &str = "localhost";
const AUTH_HEADER: &str = "Hysteria-Auth";
const UDP_ENABLED_HEADER: &str = "Hysteria-UDP";
const BANDWIDTH_HEADER: &str = "Hysteria-CC-RX";
const AUTH_PATH: &str = "/auth";

struct Hysteria2OwnerTestServer {
    address: SocketAddr,
    auth_count: Arc<AtomicUsize>,
    connection_count: Arc<AtomicUsize>,
    current_connection: Arc<Mutex<Option<quinn::Connection>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Hysteria2OwnerTestServer {
    async fn start() -> Self {
        let certified = generate_simple_self_signed(vec![SERVER_NAME.to_owned()]).unwrap();
        let certificate = certified.cert.der().clone();
        let private_key =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der()));
        let mut crypto =
            rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_no_client_auth()
                .with_single_cert(vec![certificate], private_key)
                .unwrap();
        crypto.alpn_protocols = vec![b"h3".to_vec()];
        let server_config =
            quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(crypto).unwrap()));
        let endpoint = quinn::Endpoint::server(
            server_config,
            SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 0),
        )
        .unwrap();
        let address = endpoint.local_addr().unwrap();
        let auth_count = Arc::new(AtomicUsize::new(0));
        let connection_count = Arc::new(AtomicUsize::new(0));
        let current_connection = Arc::new(Mutex::new(None));
        let task_auth_count = Arc::clone(&auth_count);
        let task_connection_count = Arc::clone(&connection_count);
        let task_current_connection = Arc::clone(&current_connection);
        let task = tokio::spawn(async move {
            while let Some(connecting) = endpoint.accept().await {
                let task_auth_count = Arc::clone(&task_auth_count);
                let task_connection_count = Arc::clone(&task_connection_count);
                let task_current_connection = Arc::clone(&task_current_connection);
                tokio::spawn(async move {
                    let Ok(connection) = connecting.await else {
                        return;
                    };
                    task_connection_count.fetch_add(1, Ordering::Relaxed);
                    *task_current_connection.lock().unwrap() = Some(connection.clone());
                    serve_hysteria2_owner_connection(connection, task_auth_count).await;
                });
            }
        });
        Self {
            address,
            auth_count,
            connection_count,
            current_connection,
            task,
        }
    }

    fn close_current(&self) {
        if let Some(connection) = self.current_connection.lock().unwrap().as_ref() {
            connection.close(0_u32.into(), b"owner rebuild test");
        }
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
    stream
        .send_response(
            Response::builder()
                .status(StatusCode::from_u16(233).unwrap())
                .header(UDP_ENABLED_HEADER, "true")
                .header(BANDWIDTH_HEADER, "0")
                .body(())
                .unwrap(),
        )
        .await
        .unwrap();
    stream.finish().await.unwrap();
    auth_count.fetch_add(1, Ordering::Relaxed);

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

fn owner_test_proxy(address: SocketAddr, generation: u64) -> Arc<ResidentProxyPlan> {
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
    let link = format!(
        "hysteria2://owner-test-auth@{}?insecure=1&sni={SERVER_NAME}#owner-test",
        address
    );
    let mut proxy = build_resident_proxy_plan_for_node(
        &config,
        "owner-test".to_owned(),
        "owner-test-node".to_owned(),
        link,
    )
    .unwrap();
    proxy.apply_runtime_generation(generation);
    Arc::new(proxy)
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
            Arc::clone(&proxy),
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
        let proxy = Arc::clone(&proxy);
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
            Arc::clone(&proxy),
            QuicEndpointCallerClass::UdpData,
            owner_deadline(),
        )
        .await
        .unwrap()
        .open_udp_session()
        .unwrap();
    let mut udp_b = registry
        .acquire(
            Arc::clone(&proxy),
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
            Arc::clone(&proxy),
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

    let shutdown_started = Instant::now();
    stop.store(true, Ordering::Release);
    tokio::task::spawn_blocking(move || owner_thread.join().unwrap())
        .await
        .unwrap();
    assert!(shutdown_started.elapsed() < Duration::from_secs(2));
    let owner_snapshot = registry.metrics_snapshot();
    assert_eq!(owner_snapshot["activeOwners"], 0);
    assert_eq!(owner_snapshot["activeLogicalLeases"], 0);
    assert_eq!(owner_snapshot["activeUdpSessions"], 0);
    assert_eq!(owner_snapshot["activeUdpSessionQuarantine"], 0);
    let endpoint_snapshot = quic_endpoint_metrics_snapshot(generation);
    assert_eq!(endpoint_snapshot["liveStates"]["total"], 0);
    assert_eq!(endpoint_snapshot["endpointDriverTasks"]["live"], 0);
}
