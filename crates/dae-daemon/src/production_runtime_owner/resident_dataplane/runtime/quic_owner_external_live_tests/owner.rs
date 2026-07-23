use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use serde_json::Value;
use tokio::time;

use super::super::tcp::QuicEndpointCallerClass;
use super::super::tcp::quic_endpoint_metrics_snapshot;
use super::super::{
    Hysteria2OwnerRegistryHandle, Hysteria2TransportLease, JuicityOwnerRegistryHandle,
    ResidentStopSignal, ResidentTransportOwnerRegistries, SharedResidentStopSignal,
    TuicOwnerRegistryHandle, start_hysteria2_owner_registry_on, start_juicity_owner_registry_on,
    start_tuic_owner_registry_on,
};
use super::config::QuicOwnerProtocol;

enum OwnerRegistry {
    Hysteria2(Hysteria2OwnerRegistryHandle),
    Tuic(TuicOwnerRegistryHandle),
    Juicity(JuicityOwnerRegistryHandle),
}

pub(super) struct ExternalLiveOwner {
    generation: u64,
    protocol: QuicOwnerProtocol,
    registry: OwnerRegistry,
    registries: ResidentTransportOwnerRegistries,
    stop: SharedResidentStopSignal,
    task: tokio::task::JoinHandle<()>,
}

impl ExternalLiveOwner {
    pub(super) fn start(protocol: QuicOwnerProtocol, generation: u64) -> Self {
        let stop = ResidentStopSignal::shared();
        let runtime = tokio::runtime::Handle::current();
        let (registry, registries, task) = match protocol {
            QuicOwnerProtocol::Hysteria2 => {
                let (registry, task) =
                    start_hysteria2_owner_registry_on(&runtime, generation, Arc::clone(&stop));
                (
                    OwnerRegistry::Hysteria2(registry.clone()),
                    ResidentTransportOwnerRegistries::new(Some(registry), None, None),
                    task,
                )
            }
            QuicOwnerProtocol::Tuic => {
                let (registry, task) =
                    start_tuic_owner_registry_on(&runtime, generation, Arc::clone(&stop));
                (
                    OwnerRegistry::Tuic(registry.clone()),
                    ResidentTransportOwnerRegistries::new(None, Some(registry), None),
                    task,
                )
            }
            QuicOwnerProtocol::Juicity => {
                let (registry, task) =
                    start_juicity_owner_registry_on(&runtime, generation, Arc::clone(&stop));
                (
                    OwnerRegistry::Juicity(registry.clone()),
                    ResidentTransportOwnerRegistries::new(None, None, Some(registry)),
                    task,
                )
            }
        };
        Self {
            generation,
            protocol,
            registry,
            registries,
            stop,
            task,
        }
    }

    pub(super) fn registries(&self) -> ResidentTransportOwnerRegistries {
        self.registries.clone()
    }

    pub(super) fn snapshot(&self) -> Value {
        owner_registry_snapshot(&self.registry)
    }

    pub(super) fn endpoint_snapshot(&self) -> Value {
        quic_endpoint_metrics_snapshot(self.generation)
    }

    pub(super) fn cumulative_builds(&self) -> u64 {
        self.snapshot()["cumulativeBuilds"]
            .as_u64()
            .expect("external owner metrics expose cumulativeBuilds")
    }

    pub(super) async fn acquire_hysteria2(
        &self,
        binding: super::super::plan::ResidentProxyBinding,
        timeout: Duration,
    ) -> Result<Hysteria2TransportLease, String> {
        let OwnerRegistry::Hysteria2(registry) = &self.registry else {
            return Err("external owner is not Hysteria2".to_owned());
        };
        registry
            .acquire(
                binding,
                QuicEndpointCallerClass::TcpData,
                dae_runtime_control::AbsoluteDeadline::from_now(Instant::now(), timeout),
            )
            .await
    }

    pub(super) fn assert_pressure(&self, session_count: usize) {
        let snapshot = self.snapshot();
        let sessions = session_count as u64;
        match self.protocol {
            QuicOwnerProtocol::Hysteria2 => {
                assert_eq!(snapshot["activeOwners"], 1);
                assert_eq!(snapshot["activeLogicalLeases"], sessions);
                assert_eq!(snapshot["activeUdpSessions"], sessions);
                assert!(snapshot["highWaterUdpSessions"].as_u64().unwrap() >= sessions);
            }
            QuicOwnerProtocol::Tuic => {
                assert_eq!(snapshot["activeOwners"], 1);
                assert_eq!(snapshot["activeLogicalLeases"], sessions);
                assert_eq!(snapshot["activeUdpAssociations"], sessions);
                assert!(snapshot["highWaterUdpAssociations"].as_u64().unwrap() >= sessions);
            }
            QuicOwnerProtocol::Juicity => {
                let usable = snapshot["budget"]["usableStreamsPerConnection"]
                    .as_u64()
                    .expect("Juicity metrics expose usable stream capacity");
                assert!(
                    sessions <= usable,
                    "configured sessions exceed one owner capacity"
                );
                assert_eq!(snapshot["activePhysicalOwners"], 1);
                assert_eq!(snapshot["activeLogicalLeases"], sessions);
                assert!(snapshot["highWaterLogicalLeases"].as_u64().unwrap() >= sessions);
            }
        }
        assert_eq!(self.cumulative_builds(), 1);
        let endpoint = self.endpoint_snapshot();
        assert_eq!(endpoint["liveStates"]["total"], 1);
        assert_eq!(endpoint["endpointDriverTasks"]["live"], 1);
    }

    pub(super) async fn wait_until_transport_closed(
        &self,
        timeout: Duration,
    ) -> Result<(), String> {
        let deadline = Instant::now() + timeout;
        loop {
            let snapshot = self.snapshot();
            let active = match self.protocol {
                QuicOwnerProtocol::Hysteria2 | QuicOwnerProtocol::Tuic => {
                    snapshot["activeOwners"].as_u64()
                }
                QuicOwnerProtocol::Juicity => snapshot["activePhysicalOwners"].as_u64(),
            }
            .ok_or_else(|| "external owner metrics omitted active owner count".to_owned())?;
            if active == 0 {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(
                    "external owner did not observe the remote close before timeout".to_owned(),
                );
            }
            time::sleep(Duration::from_millis(25)).await;
        }
    }

    pub(super) async fn stop(self, timeout: Duration) -> Result<(Value, Value), String> {
        let Self {
            generation,
            protocol,
            registry,
            registries: _,
            stop,
            task,
        } = self;
        stop.store(true, Ordering::Release);
        time::timeout(timeout, task)
            .await
            .map_err(|_| "external owner shutdown timed out".to_owned())?
            .map_err(|err| format!("external owner task join failed: {err}"))?;
        let owner = owner_registry_snapshot(&registry);
        match protocol {
            QuicOwnerProtocol::Hysteria2 => {
                assert_eq!(owner["activeOwners"], 0);
                assert_eq!(owner["activeLogicalLeases"], 0);
                assert_eq!(owner["activeUdpSessions"], 0);
            }
            QuicOwnerProtocol::Tuic => {
                assert_eq!(owner["activeOwners"], 0);
                assert_eq!(owner["activeLogicalLeases"], 0);
                assert_eq!(owner["activeUdpAssociations"], 0);
            }
            QuicOwnerProtocol::Juicity => {
                assert_eq!(owner["activePools"], 0);
                assert_eq!(owner["activePhysicalOwners"], 0);
                assert_eq!(owner["activeLogicalLeases"], 0);
                assert_eq!(owner["activeWaiters"], 0);
            }
        }
        assert_eq!(owner["registryOwnershipReleased"], true);
        assert_eq!(
            owner["endpointDrain"]["requested"],
            owner["endpointDrain"]["completed"]
        );
        assert_eq!(owner["endpointDrain"]["timedOut"], 0);
        assert_eq!(owner["shutdownTimedOut"], false);
        let endpoint = quic_endpoint_metrics_snapshot(generation);
        assert_eq!(endpoint["liveStates"]["total"], 0);
        assert_eq!(endpoint["endpointDriverTasks"]["live"], 0);
        assert_eq!(endpoint["chargedBytes"]["total"], 0);
        Ok((owner, endpoint))
    }
}

fn owner_registry_snapshot(registry: &OwnerRegistry) -> Value {
    match registry {
        OwnerRegistry::Hysteria2(registry) => registry.metrics_snapshot(),
        OwnerRegistry::Tuic(registry) => registry.metrics_snapshot(),
        OwnerRegistry::Juicity(registry) => registry.metrics_snapshot(),
    }
}
