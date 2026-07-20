use dae_runtime_control::OwnerGeneration;

use super::charge::QuicEndpointCharge;
use super::metrics::quic_endpoint_metrics_snapshot;
use super::*;

mod source_gate;

fn open_test_quic_endpoint(
    mark: u32,
    runtime: Option<Arc<dyn quinn::Runtime>>,
    remote: SocketAddr,
    bind: SocketAddr,
    underlay: QuicEndpointUnderlay,
    context: QuicEndpointOpenContext,
) -> Result<ObservedQuicEndpoint, String> {
    let cancellation = OwnerCancellationSignal::new();
    open_observed_quic_endpoint(
        mark,
        runtime,
        remote,
        bind,
        underlay,
        context,
        QuicEndpointAdmissionContext::new(
            AbsoluteDeadline::from_now(
                std::time::Instant::now(),
                std::time::Duration::from_secs(1),
            ),
            &cancellation,
        ),
    )
}

#[test]
fn receive_slab_charge_uses_quinn_runtime_dimensions() {
    let config = quinn::EndpointConfig::default();
    let ordinary = QuicEndpointCharge::for_socket(&config, 64, true).unwrap();
    let salamander = QuicEndpointCharge::for_socket(&config, 1, true).unwrap();

    assert_eq!(
        ordinary.receive_slab_bytes,
        config.get_max_udp_payload_size().min(64 * 1024) * 64 * quinn::udp::BATCH_SIZE as u64
    );
    assert_eq!(
        salamander.receive_slab_bytes,
        config.get_max_udp_payload_size().min(64 * 1024) * quinn::udp::BATCH_SIZE as u64
    );
    assert!(ordinary.quic_transport_bytes > 0);
    assert!(ordinary.http3_bytes > 0);
    assert!(ordinary.tls_bytes > 0);
    assert!(ordinary.queue_bytes > 0);
    assert!(ordinary.underlay_socket_bytes > 0);
    assert_eq!(
        ordinary.total_bytes,
        ordinary.receive_slab_bytes
            + ordinary.quic_transport_bytes
            + ordinary.http3_bytes
            + ordinary.tls_bytes
            + ordinary.queue_bytes
            + ordinary.underlay_socket_bytes
    );
}

#[test]
fn pure_quic_omits_only_the_http3_component() {
    let config = quinn::EndpointConfig::default();
    let charge = QuicEndpointCharge::for_socket(&config, 1, false).unwrap();
    assert_eq!(charge.http3_bytes, 0);
    assert!(charge.quic_transport_bytes > 0);
    assert!(charge.tls_bytes > 0);
    assert!(charge.queue_bytes > 0);
}

#[test]
fn context_debug_never_exposes_identity_material() {
    let context = QuicEndpointOpenContext::from_identity_parts(
        QuicEndpointProtocol::DnsOverQuic,
        QuicEndpointCallerClass::ConfiguredDns,
        OwnerGeneration::new(8_001),
        QuicEndpointIdentityRole::ConfiguredDns,
        &[b"private-key-material"],
    );
    let debug = format!("{context:?}");
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains("private-key-material"));
}

#[tokio::test]
async fn task_scoped_caller_and_generation_do_not_cross_requests() {
    async fn scoped_context(
        caller: QuicEndpointCallerClass,
        generation: OwnerGeneration,
    ) -> QuicEndpointOpenContext {
        scope_quic_endpoint_observation(caller, Some(generation), async move {
            tokio::task::yield_now().await;
            QuicEndpointOpenContext::from_identity_parts(
                QuicEndpointProtocol::DnsOverQuic,
                QuicEndpointCallerClass::ConfiguredDns,
                OwnerGeneration::new(9_999),
                QuicEndpointIdentityRole::ConfiguredDns,
                &[b"scoped-observation"],
            )
        })
        .await
    }

    let manual_generation = OwnerGeneration::new(8_101);
    let health_generation = OwnerGeneration::new(8_102);
    let (manual, health) = tokio::join!(
        scoped_context(QuicEndpointCallerClass::ManualProbe, manual_generation),
        scoped_context(QuicEndpointCallerClass::BackgroundHealth, health_generation,),
    );
    let charge =
        QuicEndpointCharge::for_socket(&quinn::EndpointConfig::default(), 1, false).unwrap();
    let remote = "127.0.0.1:443".parse().unwrap();
    let bind = "0.0.0.0:0".parse().unwrap();
    let manual = manual.finalize(
        remote,
        bind,
        0,
        QuicEndpointUnderlay::Ordinary,
        charge,
        charge,
    );
    let health = health.finalize(
        remote,
        bind,
        0,
        QuicEndpointUnderlay::Ordinary,
        charge,
        charge,
    );
    assert_eq!(manual.caller, QuicEndpointCallerClass::ManualProbe);
    assert_eq!(manual.generation, Some(manual_generation));
    assert_eq!(health.caller, QuicEndpointCallerClass::BackgroundHealth);
    assert_eq!(health.generation, Some(health_generation));

    let default = QuicEndpointOpenContext::from_identity_parts(
        QuicEndpointProtocol::DnsOverQuic,
        QuicEndpointCallerClass::ConfiguredDns,
        OwnerGeneration::new(8_103),
        QuicEndpointIdentityRole::ConfiguredDns,
        &[b"default-observation"],
    )
    .finalize(
        remote,
        bind,
        0,
        QuicEndpointUnderlay::Ordinary,
        charge,
        charge,
    );
    assert_eq!(default.caller, QuicEndpointCallerClass::ConfiguredDns);
    assert_eq!(default.generation, Some(OwnerGeneration::new(8_103)));
}

#[tokio::test]
async fn inherited_task_observation_survives_spawn() {
    let generation = OwnerGeneration::new(8_105);
    let context = scope_quic_endpoint_observation(
        QuicEndpointCallerClass::ManagedDns,
        Some(generation),
        async move {
            tokio::spawn(inherit_quic_endpoint_observation(async move {
                QuicEndpointOpenContext::from_identity_parts(
                    QuicEndpointProtocol::DnsOverHttp3,
                    QuicEndpointCallerClass::ConfiguredDns,
                    OwnerGeneration::new(9_999),
                    QuicEndpointIdentityRole::ConfiguredDns,
                    &[b"spawned-observation"],
                )
            }))
            .await
            .unwrap()
        },
    )
    .await;
    let charge =
        QuicEndpointCharge::for_socket(&quinn::EndpointConfig::default(), 1, true).unwrap();
    let provenance = context.finalize(
        "127.0.0.1:443".parse().unwrap(),
        "0.0.0.0:0".parse().unwrap(),
        0,
        QuicEndpointUnderlay::Ordinary,
        charge,
        charge,
    );
    assert_eq!(provenance.caller, QuicEndpointCallerClass::ManagedDns);
    assert_eq!(provenance.generation, Some(generation));
}

#[test]
fn redacted_key_partitions_socket_mark_and_bind_policy() {
    let context = QuicEndpointOpenContext::isolated_test(
        QuicEndpointProtocol::Tuic,
        QuicEndpointCallerClass::TcpData,
        Some(OwnerGeneration::new(8_104)),
        b"socket-policy-partition",
    );
    let charge =
        QuicEndpointCharge::for_socket(&quinn::EndpointConfig::default(), 1, false).unwrap();
    let remote = "192.0.2.10:443".parse().unwrap();
    let wildcard_bind = "0.0.0.0:0".parse().unwrap();
    let explicit_bind = "192.0.2.20:0".parse().unwrap();
    let base = context.clone().finalize(
        remote,
        wildcard_bind,
        100,
        QuicEndpointUnderlay::Ordinary,
        charge,
        charge,
    );
    let different_mark = context.clone().finalize(
        remote,
        wildcard_bind,
        101,
        QuicEndpointUnderlay::Ordinary,
        charge,
        charge,
    );
    let different_bind = context.finalize(
        remote,
        explicit_bind,
        100,
        QuicEndpointUnderlay::Ordinary,
        charge,
        charge,
    );
    assert_ne!(base.redacted_identity, different_mark.redacted_identity);
    assert_ne!(base.redacted_identity, different_bind.redacted_identity);
}

#[tokio::test]
async fn endpoint_driver_fd_charge_and_states_balance_after_drop() {
    let generation = OwnerGeneration::new(8_002);
    let context = QuicEndpointOpenContext::from_identity_parts(
        QuicEndpointProtocol::DnsOverQuic,
        QuicEndpointCallerClass::ConfiguredDns,
        generation,
        QuicEndpointIdentityRole::ConfiguredDns,
        &[b"driver-lifetime-test"],
    );
    let endpoint = open_test_quic_endpoint(
        0,
        quinn::default_runtime(),
        "127.0.0.1:443".parse().unwrap(),
        "0.0.0.0:0".parse().unwrap(),
        QuicEndpointUnderlay::Ordinary,
        context,
    )
    .unwrap();
    endpoint.mark_ready();
    let endpoint_clone = endpoint.clone();
    drop(endpoint);
    let live = quic_endpoint_metrics_snapshot(generation.get());
    assert_eq!(live["cumulativeCreations"], 1);
    assert_eq!(live["liveStates"]["ready"], 1);
    assert_eq!(live["udpFds"]["ipv4"], 1);
    assert_eq!(live["endpointDriverTasks"]["live"], 1);
    assert!(live["chargedBytes"]["receiveSlab"].as_u64().unwrap() > 0);

    endpoint_clone.close(0_u32.into(), b"lifetime test complete");
    let draining = quic_endpoint_metrics_snapshot(generation.get());
    assert_eq!(draining["liveStates"]["draining"], 1);
    assert_eq!(draining["closeEvidence"]["explicitCloseRequests"], 1);
    endpoint_clone.wait_idle().await;
    let closed = quic_endpoint_metrics_snapshot(generation.get());
    assert_eq!(closed["liveStates"]["closed"], 1);
    assert_eq!(closed["closeEvidence"]["waitIdleCompletions"], 1);
    assert!(closed["chargedBytes"]["total"].as_u64().unwrap() > 0);
    assert_eq!(closed["udpFds"]["ipv4"], 1);
    drop(endpoint_clone);

    for _ in 0..32 {
        let snapshot = quic_endpoint_metrics_snapshot(generation.get());
        if snapshot["liveStates"]["total"] == 0
            && snapshot["endpointDriverTasks"]["live"] == 0
            && snapshot["udpFds"]["ipv4"] == 0
        {
            assert_eq!(snapshot["chargedBytes"]["total"], 0);
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!("QUIC endpoint driver, UDP FD, or charge did not balance after endpoint drop");
}

#[tokio::test]
async fn implicit_endpoint_drop_records_handle_and_driver_completion() {
    let generation = OwnerGeneration::new(8_206);
    let endpoint = open_test_quic_endpoint(
        0,
        quinn::default_runtime(),
        "127.0.0.1:443".parse().unwrap(),
        "0.0.0.0:0".parse().unwrap(),
        QuicEndpointUnderlay::Ordinary,
        QuicEndpointOpenContext::isolated_test(
            QuicEndpointProtocol::DnsOverQuic,
            QuicEndpointCallerClass::ConfiguredDns,
            Some(generation),
            b"implicit-drop-test",
        ),
    )
    .unwrap();
    drop(endpoint);

    for _ in 0..32 {
        let snapshot = quic_endpoint_metrics_snapshot(generation.get());
        if snapshot["liveStates"]["total"] == 0 && snapshot["endpointDriverTasks"]["live"] == 0 {
            assert_eq!(snapshot["closeEvidence"]["implicitHandleReleases"], 1);
            assert_eq!(snapshot["closeEvidence"]["endpointDriverCompletions"], 1);
            assert_eq!(snapshot["admission"]["enforced"], true);
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!("implicit QUIC Endpoint drop did not complete its driver");
}

#[tokio::test]
async fn runtime_snapshot_keeps_unassigned_and_other_live_generations_visible() {
    let current_generation = OwnerGeneration::new(8_201);
    let retiring_generation = OwnerGeneration::new(8_202);
    let current = open_test_quic_endpoint(
        0,
        quinn::default_runtime(),
        "127.0.0.1:443".parse().unwrap(),
        "0.0.0.0:0".parse().unwrap(),
        QuicEndpointUnderlay::Ordinary,
        QuicEndpointOpenContext::isolated_test(
            QuicEndpointProtocol::Tuic,
            QuicEndpointCallerClass::TcpData,
            Some(current_generation),
            b"current-generation",
        ),
    )
    .unwrap();
    current.mark_ready();
    let retiring = open_test_quic_endpoint(
        0,
        quinn::default_runtime(),
        "127.0.0.1:443".parse().unwrap(),
        "0.0.0.0:0".parse().unwrap(),
        QuicEndpointUnderlay::Ordinary,
        QuicEndpointOpenContext::isolated_test(
            QuicEndpointProtocol::Hysteria2,
            QuicEndpointCallerClass::BackgroundHealth,
            Some(retiring_generation),
            b"retiring-generation",
        ),
    )
    .unwrap();
    retiring.mark_ready();
    retiring.close(0_u32.into(), b"retiring generation");
    let unassigned = open_test_quic_endpoint(
        0,
        quinn::default_runtime(),
        "127.0.0.1:443".parse().unwrap(),
        "0.0.0.0:0".parse().unwrap(),
        QuicEndpointUnderlay::Ordinary,
        QuicEndpointOpenContext::isolated_test(
            QuicEndpointProtocol::Juicity,
            QuicEndpointCallerClass::ManualProbe,
            None,
            b"unassigned-generation",
        ),
    )
    .unwrap();
    unassigned.mark_ready();

    let snapshot = quic_endpoint_metrics_snapshot(current_generation.get());
    assert_eq!(snapshot["liveStates"]["ready"], 1);
    assert_eq!(snapshot["unassigned"]["liveStates"]["ready"], 1);
    assert!(snapshot["allLive"]["total"].as_u64().unwrap() >= 3);
    assert!(snapshot["allLive"]["endpointDriverTasks"].as_u64().unwrap() >= 3);
    assert!(
        snapshot["otherLiveGenerations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| {
                value["generation"] == retiring_generation.get()
                    && value["liveStates"]["draining"] == 1
            })
    );

    current.close(0_u32.into(), b"snapshot test complete");
    retiring.wait_idle().await;
    unassigned.close(0_u32.into(), b"snapshot test complete");
    current.wait_idle().await;
    unassigned.wait_idle().await;
    drop((current, retiring, unassigned));
}

#[tokio::test]
async fn bind_failure_creates_no_endpoint_driver_fd_or_charge_record() {
    let occupied = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let bind = occupied.local_addr().unwrap();
    let generation = OwnerGeneration::new(8_203);
    let result = open_test_quic_endpoint(
        0,
        quinn::default_runtime(),
        "127.0.0.1:443".parse().unwrap(),
        bind,
        QuicEndpointUnderlay::Ordinary,
        QuicEndpointOpenContext::isolated_test(
            QuicEndpointProtocol::Tuic,
            QuicEndpointCallerClass::TcpData,
            Some(generation),
            b"bind-failure",
        ),
    );
    assert!(result.is_err());
    let snapshot = quic_endpoint_metrics_snapshot(generation.get());
    assert_eq!(snapshot["cumulativeCreations"], 0);
    assert_eq!(snapshot["liveStates"]["total"], 0);
    assert_eq!(snapshot["endpointDriverTasks"]["live"], 0);
    assert_eq!(snapshot["udpFds"]["ipv4"], 0);
    assert_eq!(snapshot["chargedBytes"]["total"], 0);
}

#[tokio::test]
async fn abstract_socket_constructor_failure_records_failure_without_leaking_resources() {
    let generation = OwnerGeneration::new(8_205);
    let result = open_test_quic_endpoint(
        0,
        Some(std::sync::Arc::new(LocalAddressFailureRuntime)),
        "127.0.0.1:443".parse().unwrap(),
        "127.0.0.1:0".parse().unwrap(),
        QuicEndpointUnderlay::Ordinary,
        QuicEndpointOpenContext::isolated_test(
            QuicEndpointProtocol::Tuic,
            QuicEndpointCallerClass::TcpData,
            Some(generation),
            b"abstract-socket-failure",
        ),
    );
    assert!(result.is_err());
    let snapshot = quic_endpoint_metrics_snapshot(generation.get());
    assert_eq!(snapshot["cumulativeCreations"], 0);
    assert_eq!(snapshot["stateTransitions"]["failed"], 1);
    assert_eq!(snapshot["liveStates"]["total"], 0);
    assert_eq!(snapshot["endpointDriverTasks"]["live"], 0);
    assert_eq!(snapshot["udpFds"]["ipv4"], 0);
    assert_eq!(snapshot["chargedBytes"]["total"], 0);
}

#[derive(Debug)]
struct LocalAddressFailureRuntime;

impl quinn::Runtime for LocalAddressFailureRuntime {
    fn new_timer(&self, _: std::time::Instant) -> std::pin::Pin<Box<dyn quinn::AsyncTimer>> {
        panic!("timer creation is unreachable for Endpoint local-address failure")
    }

    fn spawn(&self, _: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>) {
        panic!("driver spawn is unreachable for Endpoint local-address failure")
    }

    fn wrap_udp_socket(
        &self,
        _: std::net::UdpSocket,
    ) -> std::io::Result<std::sync::Arc<dyn quinn::AsyncUdpSocket>> {
        Ok(std::sync::Arc::new(LocalAddressFailureSocket))
    }

    fn now(&self) -> std::time::Instant {
        std::time::Instant::now()
    }
}

#[derive(Debug)]
struct LocalAddressFailureSocket;

impl quinn::AsyncUdpSocket for LocalAddressFailureSocket {
    fn create_io_poller(self: std::sync::Arc<Self>) -> std::pin::Pin<Box<dyn quinn::UdpPoller>> {
        panic!("poller creation is unreachable for Endpoint local-address failure")
    }

    fn try_send(&self, _: &quinn::udp::Transmit<'_>) -> std::io::Result<()> {
        Err(std::io::Error::other("test socket cannot send"))
    }

    fn poll_recv(
        &self,
        _: &mut std::task::Context<'_>,
        _: &mut [std::io::IoSliceMut<'_>],
        _: &mut [quinn::udp::RecvMeta],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::task::Poll::Ready(Err(std::io::Error::other("test socket cannot receive")))
    }

    fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        Err(std::io::Error::other("injected local-address failure"))
    }

    fn may_fragment(&self) -> bool {
        false
    }
}
