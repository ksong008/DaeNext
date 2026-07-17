use super::*;

use std::future::poll_fn;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use dae_runtime_control::OwnerGeneration;
use quinn::crypto::rustls::QuicClientConfig;
use rustls::{ClientConfig, RootCertStore};

use super::h3_server::H3TestServer;
use crate::production_runtime_owner::resident_dataplane::RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE;
use crate::production_runtime_owner::resident_dataplane::plan::build_resident_proxy_plan_for_node;
use crate::production_runtime_owner::resident_dataplane::tcp::quic_endpoint_metrics_snapshot;
use crate::production_runtime_owner::resident_dataplane::udp::{
    ResidentProxyUdpBridgeTestObservation,
    open_resident_proxy_udp_bridge_with_test_observation_async,
};

const PROXIED_DOH3_PRODUCTION_RESOURCE_TEST_GENERATION: u64 = 7_307;

struct H3DriverTestObservation {
    live: AtomicUsize,
}

impl H3DriverTestObservation {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            live: AtomicUsize::new(0),
        })
    }

    fn live(&self) -> usize {
        self.live.load(Ordering::Acquire)
    }
}

struct H3DriverTestGuard(Arc<H3DriverTestObservation>);

impl H3DriverTestGuard {
    fn new(observation: Arc<H3DriverTestObservation>) -> Self {
        observation.live.fetch_add(1, Ordering::AcqRel);
        Self(observation)
    }
}

impl Drop for H3DriverTestGuard {
    fn drop(&mut self) {
        let previous = self.0.live.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous > 0, "proxied DoH3 test driver counter underflow");
    }
}

struct ProductionResourceTarget {
    resources: ProxiedDoh3Resources,
    metrics: Arc<ResidentDataplaneMetrics>,
}

impl ProxiedDoh3ExchangeTarget for ProductionResourceTarget {
    async fn exchange(&mut self) -> Result<Vec<u8>, ProxyDnsRequestError> {
        Err(ProxyDnsRequestError::new(
            ProxyDnsRequestStage::Read,
            ProxyDnsRequestFailure::Network,
            "injected failure after production resources opened",
        ))
    }

    fn discard_client(&mut self) -> bool {
        self.resources.discard_client()
    }

    fn close_connection(&mut self) -> bool {
        self.resources.close_connection()
    }

    async fn close_endpoint_and_wait_idle(
        &mut self,
        deadline: ProxiedDoh3CleanupDeadline,
    ) -> Result<Option<ProxiedDoh3EndpointCompletion>, String> {
        Ok(self.resources.close_endpoint_and_wait_idle(deadline).await)
    }

    async fn finish_driver(
        &mut self,
        deadline: ProxiedDoh3CleanupDeadline,
    ) -> Result<Option<ProxiedDoh3DriverCompletion>, String> {
        self.resources.finish_driver(deadline).await
    }

    async fn shutdown_bridge(
        &mut self,
        deadline: ProxiedDoh3CleanupDeadline,
    ) -> Result<Option<ResidentProxyUdpBridgeShutdownCompletion>, String> {
        self.resources.shutdown_bridge(deadline).await
    }

    fn observe_cleanup(&self, outcome: &ProxiedDoh3CleanupOutcome) {
        outcome.record_metrics(&self.metrics);
    }
}

fn trusted_h3_client_config(server: &H3TestServer) -> quinn::ClientConfig {
    let mut roots = RootCertStore::empty();
    roots.add(server.certificate()).unwrap();
    let mut crypto = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_root_certificates(roots)
        .with_no_client_auth();
    crypto.alpn_protocols = vec![DNS_DOH3_ALPN.as_bytes().to_vec()];
    quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(crypto).unwrap()))
}

fn bridge_test_proxy() -> Arc<ResidentProxyPlan> {
    let sections = dae_config::parser::parse_config(
        r#"
        global {
            lan_interface: daerust0
            allow_insecure: false
            so_mark_from_dae: 0
            mptcp: false
            udp_check_dns: '192.0.2.53:53'
        }
        routing {
            fallback: direct
        }
        "#,
    )
    .unwrap();
    let config = dae_config::schema::build_config(&sections).unwrap();
    Arc::new(
        build_resident_proxy_plan_for_node(
            &config,
            "bridge-resource-fixture".to_owned(),
            "socks-node".to_owned(),
            "socks5://192.0.2.1:1080".to_owned(),
        )
        .unwrap(),
    )
}

fn assert_generation_resources_live(snapshot: &serde_json::Value) {
    assert_eq!(snapshot["liveStates"]["ready"], 1);
    assert_eq!(snapshot["udpFds"]["ipv4"], 1);
    assert_eq!(snapshot["udpFds"]["ipv6"], 0);
    assert_eq!(snapshot["endpointDriverTasks"]["live"], 1);
    assert!(snapshot["chargedBytes"]["total"].as_u64().unwrap() > 0);
}

fn assert_generation_resources_closed(snapshot: &serde_json::Value) {
    assert_eq!(snapshot["liveStates"]["total"], 0);
    assert_eq!(snapshot["udpFds"]["ipv4"], 0);
    assert_eq!(snapshot["udpFds"]["ipv6"], 0);
    assert_eq!(snapshot["endpointDriverTasks"]["live"], 0);
    assert_eq!(snapshot["chargedBytes"]["total"], 0);
}

#[tokio::test]
async fn production_resource_graph_closes_endpoint_h3_driver_and_stalled_bridge() {
    let server = H3TestServer::start().await;
    let generation = OwnerGeneration::new(PROXIED_DOH3_PRODUCTION_RESOURCE_TEST_GENERATION);
    let endpoint_context = QuicEndpointOpenContext::from_identity_parts(
        QuicEndpointProtocol::DnsOverHttp3,
        QuicEndpointCallerClass::ManagedDns,
        generation,
        QuicEndpointIdentityRole::ManagedDnsOuter,
        &[b"proxied-doh3-production-resource-test"],
    );
    let cancellation = dae_runtime_control::OwnerCancellationSignal::new();
    let mut endpoint = open_marked_quic_endpoint_for_remote(
        0,
        server.address(),
        endpoint_context,
        dae_runtime_control::AbsoluteDeadline::from_now(
            std::time::Instant::now(),
            std::time::Duration::from_secs(1),
        ),
        &cancellation,
    )
    .unwrap();
    endpoint.set_default_client_config(trusted_h3_client_config(&server));
    let connection = time::timeout(
        RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE,
        endpoint
            .connect(server.address(), server.server_name())
            .unwrap(),
    )
    .await
    .unwrap()
    .unwrap();
    let h3_connection = h3_quinn::Connection::new(connection.clone());
    let (mut driver, client) = time::timeout(
        RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE,
        h3::client::new(h3_connection),
    )
    .await
    .unwrap()
    .unwrap();
    endpoint.mark_ready();
    let driver_observation = H3DriverTestObservation::new();
    let driver_guard = H3DriverTestGuard::new(Arc::clone(&driver_observation));
    let driver_task = tokio::spawn(async move {
        let _guard = driver_guard;
        let _ = poll_fn(|cx| driver.poll_close(cx)).await;
    });

    let bridge_observation = ResidentProxyUdpBridgeTestObservation::stalled_execution();
    let bridge = open_resident_proxy_udp_bridge_with_test_observation_async(
        bridge_test_proxy(),
        server.address(),
        Arc::clone(&bridge_observation),
    )
    .await
    .unwrap();
    let bridge_peer = bridge.local_addr();
    let trigger = tokio::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    trigger
        .send_to(b"hold executor future", bridge_peer)
        .await
        .unwrap();
    assert!(
        bridge_observation
            .wait_execution_started(time::Instant::now() + RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE)
            .await
    );
    drop(trigger);

    let server_connection_observed = time::timeout(RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE, async {
        while server.connection_count() == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await;
    assert!(server_connection_observed.is_ok());
    assert_eq!(server.connection_count(), 1);
    assert_eq!(driver_observation.live(), 1);
    assert_generation_resources_live(&quic_endpoint_metrics_snapshot(generation.get()));
    let bridge_live = bridge_observation.snapshot();
    assert_eq!(bridge_live.socket_live, 1);
    assert_eq!(bridge_live.task_live, 1);
    assert_eq!(bridge_live.execution_future_live, 1);

    let metrics = Arc::new(ResidentDataplaneMetrics::default());
    let target = ProductionResourceTarget {
        resources: ProxiedDoh3Resources::from_parts(
            bridge,
            endpoint,
            connection,
            client,
            driver_task,
        ),
        metrics: Arc::clone(&metrics),
    };
    let (_keep_open, cancelled) = tokio::sync::oneshot::channel();
    let (result, cleanup) =
        lifecycle::run_owned_proxied_doh3_exchange_observed(target, cancelled).await;

    assert!(result.unwrap_err().to_string().contains("injected failure"));
    assert!(cleanup.client_discarded);
    assert!(cleanup.connection_closed);
    assert!(cleanup.endpoint.is_some());
    assert!(cleanup.driver.is_some());
    assert_eq!(
        cleanup.bridge,
        Some(ResidentProxyUdpBridgeShutdownCompletion::Aborted)
    );
    assert_generation_resources_closed(&quic_endpoint_metrics_snapshot(generation.get()));
    assert_eq!(driver_observation.live(), 0);
    let bridge_closed = bridge_observation.snapshot();
    assert_eq!(bridge_closed.socket_live, 0);
    assert_eq!(bridge_closed.task_live, 0);
    assert_eq!(bridge_closed.execution_future_live, 0);
    assert_eq!(bridge_closed.execution_future_cancelled, 1);
    let cleanup_metrics = metrics.proxied_doh3_cleanup_snapshot();
    assert_eq!(cleanup_metrics["completionClasses"]["forced"], 1);
    assert_eq!(cleanup_metrics["forcedComponents"]["bridgeAbort"], 1);
}
