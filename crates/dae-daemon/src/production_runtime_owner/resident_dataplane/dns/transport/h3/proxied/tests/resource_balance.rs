use super::*;

use std::net::{SocketAddr, SocketAddrV4};

use dae_runtime_control::OwnerGeneration;

use crate::production_runtime_owner::resident_dataplane::tcp::quic_endpoint_metrics_snapshot;

const REPEATED_RESOURCE_FAILURE_ATTEMPTS: u8 = 6;
const PROXIED_DOH3_FAILURE_RESOURCE_TEST_GENERATION: u64 = 7_306;

struct ObservedEndpointFailure {
    resources: ProxiedDoh3Resources,
}

impl ProxiedDoh3ExchangeTarget for ObservedEndpointFailure {
    async fn exchange(&mut self) -> Result<Vec<u8>, ProxyDnsRequestError> {
        Err(ProxyDnsRequestError::new(
            ProxyDnsRequestStage::Connect,
            ProxyDnsRequestFailure::Network,
            "injected proxied DoH3 failure",
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

    fn observe_cleanup(&self, _outcome: &ProxiedDoh3CleanupOutcome) {}
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct QuicLiveResourceGauges {
    endpoints: u64,
    udp4_fds: u64,
    udp6_fds: u64,
    driver_tasks: u64,
    charged_bytes: u64,
}

impl QuicLiveResourceGauges {
    fn current(snapshot: &serde_json::Value) -> Self {
        Self {
            endpoints: snapshot["liveStates"]["total"].as_u64().unwrap(),
            udp4_fds: snapshot["udpFds"]["ipv4"].as_u64().unwrap(),
            udp6_fds: snapshot["udpFds"]["ipv6"].as_u64().unwrap(),
            driver_tasks: snapshot["endpointDriverTasks"]["live"].as_u64().unwrap(),
            charged_bytes: snapshot["chargedBytes"]["total"].as_u64().unwrap(),
        }
    }

    fn all_live(snapshot: &serde_json::Value) -> Self {
        Self {
            endpoints: snapshot["allLive"]["total"].as_u64().unwrap(),
            udp4_fds: snapshot["allLive"]["udpFds"]["ipv4"].as_u64().unwrap(),
            udp6_fds: snapshot["allLive"]["udpFds"]["ipv6"].as_u64().unwrap(),
            driver_tasks: snapshot["allLive"]["endpointDriverTasks"].as_u64().unwrap(),
            charged_bytes: snapshot["allLive"]["chargedBytes"].as_u64().unwrap(),
        }
    }

    fn is_empty(self) -> bool {
        self == Self {
            endpoints: 0,
            udp4_fds: 0,
            udp6_fds: 0,
            driver_tasks: 0,
            charged_bytes: 0,
        }
    }
}

#[tokio::test]
async fn repeated_failures_restore_observed_endpoint_resources_by_cleanup_deadline() {
    let generation = OwnerGeneration::new(PROXIED_DOH3_FAILURE_RESOURCE_TEST_GENERATION);
    let remote = SocketAddr::V4(SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, 443));

    for attempt in 0..REPEATED_RESOURCE_FAILURE_ATTEMPTS {
        let before = quic_endpoint_metrics_snapshot(generation.get());
        let all_live_baseline = QuicLiveResourceGauges::all_live(&before);
        assert!(QuicLiveResourceGauges::current(&before).is_empty());

        let attempt_identity = [attempt];
        let identity_parts: [&[u8]; 2] = [b"proxied-doh3-cleanup-failure", &attempt_identity];
        let cancellation = dae_runtime_control::OwnerCancellationSignal::new();
        let endpoint = open_marked_quic_endpoint_for_remote(
            0,
            remote,
            QuicEndpointOpenContext::from_identity_parts(
                QuicEndpointProtocol::DnsOverHttp3,
                QuicEndpointCallerClass::ManagedDns,
                generation,
                QuicEndpointIdentityRole::ManagedDnsOuter,
                &identity_parts,
            ),
            dae_runtime_control::AbsoluteDeadline::from_now(
                std::time::Instant::now(),
                std::time::Duration::from_secs(1),
            ),
            &cancellation,
        )
        .unwrap();
        endpoint.mark_failed();
        let live = quic_endpoint_metrics_snapshot(generation.get());
        assert_eq!(QuicLiveResourceGauges::current(&live).endpoints, 1);
        assert_eq!(QuicLiveResourceGauges::current(&live).udp4_fds, 1);
        assert_eq!(QuicLiveResourceGauges::current(&live).driver_tasks, 1);
        assert!(QuicLiveResourceGauges::current(&live).charged_bytes > 0);

        let target = ObservedEndpointFailure {
            resources: ProxiedDoh3Resources {
                endpoint: Some(endpoint),
                ..ProxiedDoh3Resources::default()
            },
        };
        let (_keep_open, cancelled) = tokio::sync::oneshot::channel();
        let (result, cleanup) =
            lifecycle::run_owned_proxied_doh3_exchange_observed(target, cancelled).await;
        assert!(result.unwrap_err().to_string().contains("injected"));

        let after_cleanup = quic_endpoint_metrics_snapshot(generation.get());
        let balanced = if QuicLiveResourceGauges::current(&after_cleanup).is_empty() {
            Ok(())
        } else {
            time::timeout_at(cleanup.deadline.instant(), async {
                loop {
                    let snapshot = quic_endpoint_metrics_snapshot(generation.get());
                    if QuicLiveResourceGauges::current(&snapshot).is_empty() {
                        return;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
        };
        let snapshot = quic_endpoint_metrics_snapshot(generation.get());
        assert!(
            balanced.is_ok(),
            "proxied DoH3 endpoint resources exceeded the cleanup deadline: generation={snapshot}; all_live_baseline={all_live_baseline:?}; all_live_now={:?}",
            QuicLiveResourceGauges::all_live(&snapshot),
        );
        assert!(QuicLiveResourceGauges::current(&snapshot).is_empty());
    }
}
