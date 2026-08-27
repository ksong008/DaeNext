use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use boring::ssl::SslAcceptor;
use bytes::Bytes;
use dae_outbound::shared_transport::test_support::{self_signed_tls_identity, tls13_acceptor};
use dae_resident_core::{
    RESIDENT_TCP_FLOW_STACK_BYTES_DEFAULT, ResidentStopSignal, SharedResidentStopSignal,
};
use dae_resident_plan as plan;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::time;

use super::h2_carrier_owner::start_h2_carrier_generation_owner;
use super::*;

static NEXT_H2_TEST_GENERATION: AtomicU64 = AtomicU64::new(80_000);

struct H2TestServer {
    address: SocketAddr,
    tcp_connections: Arc<AtomicUsize>,
    tls_handshakes: Arc<AtomicUsize>,
    accepted_requests: Arc<AtomicUsize>,
    handshake_gate: Option<Arc<Semaphore>>,
    response_gate: Option<Arc<Semaphore>>,
    stop: SharedResidentStopSignal,
    task: tokio::task::JoinHandle<()>,
}

impl H2TestServer {
    async fn start(max_concurrent_streams: Option<u32>, gate_handshake: bool) -> Self {
        Self::start_with_options(b"h2", max_concurrent_streams, gate_handshake, false).await
    }

    async fn start_with_goaway() -> Self {
        Self::start_with_options(b"h2", None, false, true).await
    }

    async fn start_with_alpn(
        alpn: &[u8],
        max_concurrent_streams: Option<u32>,
        gate_handshake: bool,
    ) -> Self {
        Self::start_with_options(alpn, max_concurrent_streams, gate_handshake, false).await
    }

    async fn start_with_options(
        alpn: &[u8],
        max_concurrent_streams: Option<u32>,
        gate_handshake: bool,
        goaway_after_first_request: bool,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let tcp_connections = Arc::new(AtomicUsize::new(0));
        let tls_handshakes = Arc::new(AtomicUsize::new(0));
        let accepted_requests = Arc::new(AtomicUsize::new(0));
        let handshake_gate = gate_handshake.then(|| Arc::new(Semaphore::new(0)));
        let response_gate = max_concurrent_streams.map(|_| Arc::new(Semaphore::new(0)));
        let stop = ResidentStopSignal::shared();
        let task_tcp_connections = Arc::clone(&tcp_connections);
        let task_tls_handshakes = Arc::clone(&tls_handshakes);
        let task_accepted_requests = Arc::clone(&accepted_requests);
        let task_gate = handshake_gate.clone();
        let task_response_gate = response_gate.clone();
        let task_stop = Arc::clone(&stop);
        let acceptor = h2_test_tls_acceptor(alpn);
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
                        let connection_accepted_requests = Arc::clone(&task_accepted_requests);
                        let connection_gate = task_gate.clone();
                        let connection_response_gate = task_response_gate.clone();
                        connections.spawn(async move {
                            if let Some(gate) = connection_gate {
                                let Ok(permit) = gate.acquire().await else {
                                    return;
                                };
                                permit.forget();
                            }
                            let Ok(stream) = tokio_boring::accept(&connection_acceptor, stream).await else {
                                return;
                            };
                            connection_handshakes.fetch_add(1, Ordering::Relaxed);
                            serve_h2_connection(
                                stream,
                                max_concurrent_streams,
                                connection_response_gate,
                                goaway_after_first_request,
                                connection_accepted_requests,
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
            accepted_requests,
            handshake_gate,
            response_gate,
            stop,
            task,
        }
    }

    fn release_handshake(&self) {
        self.handshake_gate
            .as_ref()
            .expect("test server handshake is not gated")
            .add_permits(1);
    }

    fn release_response(&self) {
        self.response_gate
            .as_ref()
            .expect("test server responses are not gated")
            .add_permits(1);
    }

    async fn stop(self) {
        self.stop.store(true, Ordering::Release);
        self.task.await.unwrap();
    }
}

async fn serve_h2_connection<T>(
    stream: T,
    max_concurrent_streams: Option<u32>,
    response_gate: Option<Arc<Semaphore>>,
    goaway_after_first_request: bool,
    accepted_requests: Arc<AtomicUsize>,
) where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let handshake = if let Some(limit) = max_concurrent_streams {
        let mut builder = h2::server::Builder::new();
        builder.max_concurrent_streams(limit);
        builder.handshake(stream).await
    } else {
        h2::server::handshake(stream).await
    };
    let Ok(mut connection) = handshake else {
        return;
    };
    let mut responses = tokio::task::JoinSet::new();
    let mut accepted_requests_on_connection = 0_u64;
    while let Some(accepted) = connection.accept().await {
        let Ok((request, mut respond)) = accepted else {
            break;
        };
        let response_gate = response_gate.clone();
        accepted_requests.fetch_add(1, Ordering::Relaxed);
        accepted_requests_on_connection = accepted_requests_on_connection.saturating_add(1);
        if goaway_after_first_request && accepted_requests_on_connection == 1 {
            connection.graceful_shutdown();
        }
        responses.spawn(async move {
            let mut body = request.into_body();
            let response = http::Response::builder().status(200).body(()).unwrap();
            let Ok(mut response_stream) = respond.send_response(response, false) else {
                return;
            };
            if let Some(gate) = response_gate {
                let Ok(permit) = gate.acquire().await else {
                    return;
                };
                permit.forget();
            }
            while let Some(Ok(data)) = body.data().await {
                let length = data.len();
                let _ = body.flow_control().release_capacity(length);
            }
            let _ = response_stream.send_data(Bytes::from_static(b"ok"), true);
        });
    }
    while responses.join_next().await.is_some() {}
}

fn h2_test_tls_acceptor(alpn: &[u8]) -> SslAcceptor {
    let identity = self_signed_tls_identity(&["localhost"]).unwrap();
    tls13_acceptor(&identity, &[alpn.to_vec()]).unwrap()
}

fn h2_test_proxy(
    address: SocketAddr,
    generation: u64,
    graph_link_hash: &str,
) -> plan::ResidentProxyBinding {
    let mut proxy = plan::ResidentProxyPlan {
        graph_id: format!("resident-graph:{graph_link_hash}"),
        graph_link_hash: graph_link_hash.to_owned(),
        redacted_link_source: "vless://<redacted>".to_owned(),
        protocol: "vless",
        group_name: "h2-owner-test".to_owned(),
        group_policy: "fixed".to_owned(),
        node_tag: "h2-owner-node".to_owned(),
        server_host: address.ip().to_string(),
        server_port: address.port(),
        server_name: "localhost".to_owned(),
        alpn: vec!["h2".to_owned()],
        flow: String::new(),
        net: "grpc".to_owned(),
        stream_host: "localhost".to_owned(),
        stream_path: "OwnerTest".to_owned(),
        grpc_mode: dae_outbound::shared_transport::GrpcMode::Gun,
        xhttp_download: None,
        xhttp_mode: plan::ResidentXhttpMode::PacketUp,
        xhttp_settings: plan::ResidentXhttpSettingsPlan::default(),
        xhttp_xmux: None,
        tls: "tls".to_owned(),
        allow_insecure: true,
        tls_fragment: None,
        utls_fingerprint: None,
        ech: None,
        reality: None,
        handler: plan::ResidentProxyProtocolPlan::VlessVisionTcpTls {
            key: [7; 16],
            encryption: None,
        },
        execution: None,
        chain_parent: None,
        mark: 0,
        mptcp: false,
    };
    proxy.materialize_execution();
    plan::ResidentProxyBinding::resident(
        Arc::new(proxy),
        dae_runtime_control::OwnerGeneration::new(generation),
    )
    .unwrap()
}

fn h2_owner_deadline() -> dae_runtime_control::AbsoluteDeadline {
    dae_runtime_control::AbsoluteDeadline::from_now(Instant::now(), Duration::from_secs(3))
}

async fn exchange_h2_request(
    lease: &H2CarrierLease,
    end_request: bool,
) -> (h2::SendStream<Bytes>, h2::RecvStream) {
    let request = http::Request::builder()
        .method(http::Method::POST)
        .version(http::Version::HTTP_2)
        .uri("https://localhost/owner-test")
        .body(())
        .unwrap();
    let (response, send_stream) = lease
        .open_request(request, end_request, h2_owner_deadline(), "owner test")
        .await
        .unwrap();
    let response = time::timeout(Duration::from_secs(2), response)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.status(), http::StatusCode::OK);
    (send_stream, response.into_body())
}

async fn acquire_h2_from_fresh_runtime(
    binding: plan::ResidentProxyBinding,
) -> (u64, Result<http::StatusCode, String>) {
    tokio::task::spawn_blocking(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .unwrap()
            .block_on(async move {
                let lease = acquire_h2_carrier(binding, h2_owner_deadline()).await?;
                let instance_id = lease.physical_instance_id();
                let request = http::Request::builder()
                    .method(http::Method::POST)
                    .version(http::Version::HTTP_2)
                    .uri("https://localhost/fresh-runtime")
                    .body(())
                    .map_err(|error| error.to_string())?;
                let (response, _) = lease
                    .open_request(request, true, h2_owner_deadline(), "fresh-runtime test")
                    .await?;
                let status = response.await.map_err(|error| error.to_string())?.status();
                Ok::<_, String>((instance_id, Ok(status)))
            })
    })
    .await
    .unwrap()
    .unwrap()
}

async fn stop_h2_owner(stop: SharedResidentStopSignal, thread: std::thread::JoinHandle<()>) {
    stop.store(true, Ordering::Release);
    tokio::task::spawn_blocking(move || thread.join().unwrap())
        .await
        .unwrap();
}

fn assert_h2_owner_released(owner: &H2CarrierGenerationOwnerHandle) {
    let metrics = owner.metrics_snapshot();
    assert_eq!(metrics["registeredKeys"], 0);
    assert_eq!(metrics["registeredBuildTasks"], 0);
    assert_eq!(metrics["registeredDriverTasks"], 0);
    assert_eq!(metrics["reservedPhysicalConnections"], 0);
    assert_eq!(metrics["activePhysicalConnections"], 0);
    assert_eq!(metrics["activeLogicalStreams"], 0);
    assert_eq!(metrics["activeBuilds"], 0);
    assert_eq!(metrics["ownerStateBytesLowerBound"], 0);
    assert_eq!(metrics["shutdownTimedOut"], false);
}

#[test]
fn h2_carrier_reuses_one_physical_connection_across_caller_runtimes() {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_io()
        .enable_time()
        .build()
        .unwrap()
        .block_on(async {
            let server = H2TestServer::start(None, false).await;
            let generation = NEXT_H2_TEST_GENERATION.fetch_add(1, Ordering::Relaxed);
            let proxy = h2_test_proxy(server.address, generation, "sha256:h2-cross-runtime");
            let stop = ResidentStopSignal::shared();
            let (owner, owner_thread) = start_h2_carrier_generation_owner(
                generation,
                Arc::clone(&stop),
                RESIDENT_TCP_FLOW_STACK_BYTES_DEFAULT,
                2,
            )
            .unwrap();

            let first = acquire_h2_from_fresh_runtime(proxy.clone()).await;
            let second = acquire_h2_from_fresh_runtime(proxy.clone()).await;
            assert_eq!(first.0, second.0);
            assert_eq!(first.1.unwrap(), http::StatusCode::OK);
            assert_eq!(second.1.unwrap(), http::StatusCode::OK);
            assert_eq!(server.tcp_connections.load(Ordering::Relaxed), 1);
            assert_eq!(server.tls_handshakes.load(Ordering::Relaxed), 1);
            let metrics = owner.metrics_snapshot();
            assert_eq!(metrics["executor"], "multi-thread");
            assert_eq!(metrics["runtimeWorkerThreads"], 2);
            assert_eq!(metrics["cumulativeBuilds"], 1);
            assert_eq!(metrics["cumulativeReuses"], 1);

            stop_h2_owner(stop, owner_thread).await;
            assert_h2_owner_released(&owner);
            server.stop().await;
        });
}

#[test]
fn cancelled_h2_acquirer_does_not_cancel_the_generation_build() {
    tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .unwrap()
        .block_on(async {
            let server = H2TestServer::start(None, true).await;
            let generation = NEXT_H2_TEST_GENERATION.fetch_add(1, Ordering::Relaxed);
            let proxy = h2_test_proxy(server.address, generation, "sha256:h2-cancelled-acquirer");
            let stop = ResidentStopSignal::shared();
            let (owner, owner_thread) = start_h2_carrier_generation_owner(
                generation,
                Arc::clone(&stop),
                RESIDENT_TCP_FLOW_STACK_BYTES_DEFAULT,
                1,
            )
            .unwrap();

            let first_proxy = proxy.clone();
            let first =
                tokio::spawn(
                    async move { acquire_h2_carrier(first_proxy, h2_owner_deadline()).await },
                );
            time::timeout(Duration::from_secs(2), async {
                while server.tcp_connections.load(Ordering::Relaxed) != 1 {
                    time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .unwrap();
            first.abort();
            let _ = first.await;

            let second_proxy = proxy.clone();
            let second =
                tokio::spawn(
                    async move { acquire_h2_carrier(second_proxy, h2_owner_deadline()).await },
                );
            server.release_handshake();
            let lease = second.await.unwrap().unwrap();
            let _ = exchange_h2_request(&lease, true).await;
            assert_eq!(server.tcp_connections.load(Ordering::Relaxed), 1);
            assert_eq!(server.tls_handshakes.load(Ordering::Relaxed), 1);
            assert_eq!(owner.metrics_snapshot()["cumulativeBuilds"], 1);
            drop(lease);

            stop_h2_owner(stop, owner_thread).await;
            assert_h2_owner_released(&owner);
            server.stop().await;
        });
}

#[test]
fn concurrent_h2_acquirers_receive_one_shared_alpn_failure() {
    tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .unwrap()
        .block_on(async {
            let server = H2TestServer::start_with_alpn(b"http/1.1", None, true).await;
            let generation = NEXT_H2_TEST_GENERATION.fetch_add(1, Ordering::Relaxed);
            let mut proxy = h2_test_proxy(server.address, generation, "sha256:h2-shared-failure")
                .plan()
                .clone();
            proxy.alpn = vec!["h2".to_owned(), "http/1.1".to_owned()];
            proxy.materialize_execution();
            let proxy = plan::ResidentProxyBinding::resident(
                Arc::new(proxy),
                dae_runtime_control::OwnerGeneration::new(generation),
            )
            .unwrap();
            let stop = ResidentStopSignal::shared();
            let (owner, owner_thread) = start_h2_carrier_generation_owner(
                generation,
                Arc::clone(&stop),
                RESIDENT_TCP_FLOW_STACK_BYTES_DEFAULT,
                1,
            )
            .unwrap();

            let first_proxy = proxy.clone();
            let first =
                tokio::spawn(
                    async move { acquire_h2_carrier(first_proxy, h2_owner_deadline()).await },
                );
            let second_proxy = proxy.clone();
            let second =
                tokio::spawn(
                    async move { acquire_h2_carrier(second_proxy, h2_owner_deadline()).await },
                );
            time::timeout(Duration::from_secs(2), async {
                while server.tcp_connections.load(Ordering::Relaxed) != 1 {
                    time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .unwrap();
            time::sleep(Duration::from_millis(20)).await;
            server.release_handshake();

            let first_error = first.await.unwrap().err().unwrap();
            let second_error = second.await.unwrap().err().unwrap();
            assert_eq!(first_error, second_error);
            assert!(
                first_error.contains("unsupported ALPN http/1.1"),
                "{first_error}"
            );
            assert_eq!(server.tcp_connections.load(Ordering::Relaxed), 1);
            assert_eq!(server.tls_handshakes.load(Ordering::Relaxed), 1);
            time::timeout(Duration::from_secs(2), async {
                loop {
                    let metrics = owner.metrics_snapshot();
                    if metrics["activeBuilds"] == 0 && metrics["reservedPhysicalConnections"] == 0 {
                        break;
                    }
                    time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .unwrap();
            let metrics = owner.metrics_snapshot();
            assert_eq!(metrics["cumulativeBuilds"], 1);
            assert_eq!(metrics["cumulativeBuildFailures"], 1);
            assert_eq!(metrics["activeBuilds"], 0);
            assert_eq!(metrics["reservedPhysicalConnections"], 0);

            stop_h2_owner(stop, owner_thread).await;
            assert_h2_owner_released(&owner);
            server.stop().await;
        });
}

#[test]
fn h2_owner_shutdown_aborts_a_stalled_physical_build() {
    tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .unwrap()
        .block_on(async {
            let server = H2TestServer::start(None, true).await;
            let generation = NEXT_H2_TEST_GENERATION.fetch_add(1, Ordering::Relaxed);
            let proxy = h2_test_proxy(server.address, generation, "sha256:h2-stalled-build");
            let stop = ResidentStopSignal::shared();
            let (owner, owner_thread) = start_h2_carrier_generation_owner(
                generation,
                Arc::clone(&stop),
                RESIDENT_TCP_FLOW_STACK_BYTES_DEFAULT,
                1,
            )
            .unwrap();

            let acquisition =
                tokio::spawn(async move { acquire_h2_carrier(proxy, h2_owner_deadline()).await });
            time::timeout(Duration::from_secs(2), async {
                while server.tcp_connections.load(Ordering::Relaxed) != 1 {
                    time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .unwrap();
            assert_eq!(owner.metrics_snapshot()["activeBuilds"], 1);

            stop_h2_owner(stop, owner_thread).await;
            let error = acquisition.await.unwrap().err().unwrap();
            assert!(error.contains("closing"), "{error}");
            assert_h2_owner_released(&owner);
            server.stop().await;
        });
}

#[test]
fn h2_carrier_partitions_distinct_transport_graphs() {
    tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .unwrap()
        .block_on(async {
            let server = H2TestServer::start(None, false).await;
            let generation = NEXT_H2_TEST_GENERATION.fetch_add(1, Ordering::Relaxed);
            let first_proxy = h2_test_proxy(server.address, generation, "sha256:h2-graph-a");
            let second_proxy = h2_test_proxy(server.address, generation, "sha256:h2-graph-b");
            let stop = ResidentStopSignal::shared();
            let (owner, owner_thread) = start_h2_carrier_generation_owner(
                generation,
                Arc::clone(&stop),
                RESIDENT_TCP_FLOW_STACK_BYTES_DEFAULT,
                1,
            )
            .unwrap();

            let first = acquire_h2_carrier(first_proxy, h2_owner_deadline())
                .await
                .unwrap();
            let second = acquire_h2_carrier(second_proxy, h2_owner_deadline())
                .await
                .unwrap();
            assert_ne!(first.physical_instance_id(), second.physical_instance_id());
            let _ = exchange_h2_request(&first, true).await;
            let _ = exchange_h2_request(&second, true).await;
            assert_eq!(server.tcp_connections.load(Ordering::Relaxed), 2);
            assert_eq!(server.tls_handshakes.load(Ordering::Relaxed), 2);
            assert_eq!(owner.metrics_snapshot()["registeredKeys"], 2);
            drop(first);
            drop(second);

            stop_h2_owner(stop, owner_thread).await;
            assert_h2_owner_released(&owner);
            server.stop().await;
        });
}

#[test]
fn h2_goaway_drains_the_old_physical_before_the_next_acquisition_rebuilds() {
    tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .unwrap()
        .block_on(async {
            let server = H2TestServer::start_with_goaway().await;
            let generation = NEXT_H2_TEST_GENERATION.fetch_add(1, Ordering::Relaxed);
            let proxy = h2_test_proxy(server.address, generation, "sha256:h2-goaway");
            let stop = ResidentStopSignal::shared();
            let (owner, owner_thread) = start_h2_carrier_generation_owner(
                generation,
                Arc::clone(&stop),
                RESIDENT_TCP_FLOW_STACK_BYTES_DEFAULT,
                1,
            )
            .unwrap();

            let first = acquire_h2_carrier(proxy.clone(), h2_owner_deadline())
                .await
                .unwrap();
            let first_instance = first.physical_instance_id();
            let (first_send, mut first_response) = exchange_h2_request(&first, true).await;
            drop(first_send);
            while first_response.data().await.is_some() {}
            drop(first_response);
            drop(first);
            time::timeout(Duration::from_secs(2), async {
                while owner.metrics_snapshot()["activePhysicalConnections"] != 0 {
                    time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .expect("GOAWAY physical did not finish draining");

            let second = acquire_h2_carrier(proxy.clone(), h2_owner_deadline())
                .await
                .unwrap();
            assert_ne!(first_instance, second.physical_instance_id());
            time::timeout(Duration::from_secs(2), async {
                while server.tls_handshakes.load(Ordering::Relaxed) != 2 {
                    time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .expect("rebuilt H2 physical did not finish the server-side TLS handshake");
            assert_eq!(server.tcp_connections.load(Ordering::Relaxed), 2);
            assert_eq!(server.tls_handshakes.load(Ordering::Relaxed), 2);
            assert_eq!(owner.metrics_snapshot()["cumulativeBuilds"], 2);
            drop(second);

            stop_h2_owner(stop, owner_thread).await;
            assert_h2_owner_released(&owner);
            server.stop().await;
        });
}

#[test]
fn h2_peer_stream_capacity_does_not_require_request_gate_serialization() {
    tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .unwrap()
        .block_on(async {
            let server = H2TestServer::start(Some(1), false).await;
            let generation = NEXT_H2_TEST_GENERATION.fetch_add(1, Ordering::Relaxed);
            let proxy = h2_test_proxy(server.address, generation, "sha256:h2-peer-capacity");
            let stop = ResidentStopSignal::shared();
            let (owner, owner_thread) = start_h2_carrier_generation_owner(
                generation,
                Arc::clone(&stop),
                RESIDENT_TCP_FLOW_STACK_BYTES_DEFAULT,
                1,
            )
            .unwrap();
            let first = acquire_h2_carrier(proxy.clone(), h2_owner_deadline())
                .await
                .unwrap();
            let second = acquire_h2_carrier(proxy.clone(), h2_owner_deadline())
                .await
                .unwrap();
            let third = acquire_h2_carrier(proxy.clone(), h2_owner_deadline())
                .await
                .unwrap();
            assert_eq!(first.physical_instance_id(), second.physical_instance_id());
            assert_eq!(first.physical_instance_id(), third.physical_instance_id());
            time::timeout(Duration::from_secs(2), async {
                while first.current_max_send_streams().await != 1 {
                    time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .expect("client did not apply peer SETTINGS_MAX_CONCURRENT_STREAMS");

            let (mut first_stream, _first_response) = exchange_h2_request(&first, false).await;
            first_stream
                .send_data(Bytes::from_static(b"hold-open"), false)
                .unwrap();
            let second_request = http::Request::builder()
                .method(http::Method::POST)
                .uri("https://localhost/second")
                .body(())
                .unwrap();
            let (second_response, _) = time::timeout(
                Duration::from_millis(100),
                second.open_request(
                    second_request,
                    true,
                    h2_owner_deadline(),
                    "second owner test",
                ),
            )
            .await
            .expect("second logical open waited for response headers")
            .unwrap();
            let third_request = http::Request::builder()
                .method(http::Method::POST)
                .uri("https://localhost/third")
                .body(())
                .unwrap();
            let (third_response, _) = time::timeout(
                Duration::from_millis(100),
                third.open_request(third_request, true, h2_owner_deadline(), "third owner test"),
            )
            .await
            .expect("third logical open waited for response headers")
            .unwrap();
            assert_eq!(owner.metrics_snapshot()["activePendingOpens"], 2);
            time::sleep(Duration::from_millis(25)).await;
            assert_eq!(server.accepted_requests.load(Ordering::Relaxed), 1);
            first_stream.send_data(Bytes::new(), true).unwrap();
            server.release_response();
            let second_response = time::timeout(Duration::from_secs(2), second_response)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(second_response.status(), http::StatusCode::OK);
            assert_eq!(owner.metrics_snapshot()["activePendingOpens"], 1);
            let mut second_body = second_response.into_body();
            server.release_response();
            while second_body.data().await.transpose().unwrap().is_some() {}
            let third_response = time::timeout(Duration::from_secs(2), third_response)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(third_response.status(), http::StatusCode::OK);
            assert_eq!(owner.metrics_snapshot()["activePendingOpens"], 0);
            let mut third_body = third_response.into_body();
            server.release_response();
            while third_body.data().await.transpose().unwrap().is_some() {}
            assert_eq!(server.accepted_requests.load(Ordering::Relaxed), 3);
            assert_eq!(server.tcp_connections.load(Ordering::Relaxed), 1);
            assert_eq!(owner.metrics_snapshot()["highWaterPhysicalConnections"], 1);
            drop(first);
            drop(second);
            drop(third);

            stop_h2_owner(stop, owner_thread).await;
            assert_h2_owner_released(&owner);
            server.stop().await;
        });
}
