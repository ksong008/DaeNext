use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, OnceLock};

use dae_runtime_control::{OwnerGeneration, PhysicalOwnerState};
use serde_json::{Value, json};

use super::charge::charge_model_json;
use super::model::{
    QuicEndpointAddressFamily, QuicEndpointCallerClass, QuicEndpointProtocol,
    QuicEndpointProvenance, QuicEndpointUnderlay,
};

const QUIC_ENDPOINT_METRICS_SCHEMA: &str = "quinn-endpoint-resources";
const QUIC_ENDPOINT_METRICS_SCHEMA_VERSION: u64 = 1;
const QUIC_ENDPOINT_OBSERVABILITY_MODEL: &str = "bounded-generation-quinn-inventory";
const QUIC_ENDPOINT_OBSERVABILITY_MODEL_VERSION: u64 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct QuicEndpointObservabilityProfile {
    retained_inactive_generations: usize,
}

impl QuicEndpointObservabilityProfile {
    const CURRENT: Self = Self {
        retained_inactive_generations: 2,
    };
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct QuicEndpointMetricDimensions {
    protocol: QuicEndpointProtocol,
    caller: QuicEndpointCallerClass,
    family: QuicEndpointAddressFamily,
    underlay: QuicEndpointUnderlay,
}

impl From<&QuicEndpointProvenance> for QuicEndpointMetricDimensions {
    fn from(value: &QuicEndpointProvenance) -> Self {
        Self {
            protocol: value.protocol,
            caller: value.caller,
            family: value.family,
            underlay: value.underlay,
        }
    }
}

#[derive(Clone, Debug)]
struct QuicEndpointLiveRecord {
    provenance: QuicEndpointProvenance,
    state: PhysicalOwnerState,
    udp_fd_live: bool,
    endpoint_driver_task_live: bool,
    endpoint_charge_live: bool,
}

#[derive(Default)]
struct QuicEndpointGenerationMetrics {
    creations: BTreeMap<QuicEndpointMetricDimensions, u64>,
    failed_transitions: u64,
    draining_transitions: u64,
    closed_transitions: u64,
}

#[derive(Default)]
struct QuicEndpointMetricsRegistry {
    // Evidence only: records contain no Endpoint, Connection, socket, task, or protocol state.
    // Physical ownership remains with each protocol caller until a protocol registry is migrated.
    next_id: u64,
    live: BTreeMap<u64, QuicEndpointLiveRecord>,
    generations: BTreeMap<Option<OwnerGeneration>, QuicEndpointGenerationMetrics>,
}

impl QuicEndpointMetricsRegistry {
    fn register(&mut self, provenance: QuicEndpointProvenance) -> u64 {
        self.next_id = self.next_id.wrapping_add(1).max(1);
        let id = self.next_id;
        self.generations.entry(provenance.generation).or_default();
        self.live.insert(
            id,
            QuicEndpointLiveRecord {
                provenance,
                state: PhysicalOwnerState::Connecting,
                udp_fd_live: false,
                endpoint_driver_task_live: false,
                endpoint_charge_live: false,
            },
        );
        self.prune_inactive_generations();
        id
    }

    fn endpoint_created(&mut self, id: u64) {
        let Some(record) = self.live.get(&id) else {
            return;
        };
        let generation = record.provenance.generation;
        let dimensions = QuicEndpointMetricDimensions::from(&record.provenance);
        *self
            .generations
            .entry(generation)
            .or_default()
            .creations
            .entry(dimensions)
            .or_default() += 1;
    }

    fn transition(&mut self, id: u64, next: PhysicalOwnerState) {
        let Some(record) = self.live.get_mut(&id) else {
            return;
        };
        if record.state == next || !state_transition_allowed(record.state, next) {
            return;
        }
        record.state = next;
        let generation = record.provenance.generation;
        let generation = self.generations.entry(generation).or_default();
        match next {
            PhysicalOwnerState::Failed => generation.failed_transitions += 1,
            PhysicalOwnerState::Draining => generation.draining_transitions += 1,
            PhysicalOwnerState::Closed => generation.closed_transitions += 1,
            PhysicalOwnerState::Connecting | PhysicalOwnerState::Ready => {}
        }
    }

    fn mark_closed_if_draining(&mut self, id: u64) {
        if self
            .live
            .get(&id)
            .is_some_and(|record| record.state == PhysicalOwnerState::Draining)
        {
            self.transition(id, PhysicalOwnerState::Closed);
        }
    }

    fn set_udp_fd_live(&mut self, id: u64, live: bool) {
        if let Some(record) = self.live.get_mut(&id) {
            record.udp_fd_live = live;
            // Quinn's receive slab and Endpoint state share the EndpointInner that owns this
            // abstract socket. The socket lifetime therefore remains charged even if the
            // EndpointDriver future exits early while an Endpoint/Connection handle is retained.
            record.endpoint_charge_live = live;
        }
    }

    fn set_endpoint_driver_live(&mut self, id: u64, live: bool) {
        if let Some(record) = self.live.get_mut(&id) {
            record.endpoint_driver_task_live = live;
        }
    }

    fn endpoint_driver_finished(&mut self, id: u64) {
        self.set_endpoint_driver_live(id, false);
        if self.live.get(&id).is_some_and(|record| {
            matches!(
                record.state,
                PhysicalOwnerState::Connecting | PhysicalOwnerState::Ready
            )
        }) {
            self.transition(id, PhysicalOwnerState::Failed);
        }
    }

    fn release(&mut self, id: u64) {
        if !self.live.contains_key(&id) {
            return;
        }
        self.transition(id, PhysicalOwnerState::Closed);
        self.live.remove(&id);
        self.prune_inactive_generations();
    }

    fn prune_inactive_generations(&mut self) {
        let live_generations = self
            .live
            .values()
            .map(|record| record.provenance.generation)
            .collect::<std::collections::BTreeSet<_>>();
        let inactive = self
            .generations
            .keys()
            .copied()
            .filter(|generation| !live_generations.contains(generation))
            .collect::<Vec<_>>();
        let remove = inactive.len().saturating_sub(
            QuicEndpointObservabilityProfile::CURRENT.retained_inactive_generations,
        );
        for generation in inactive.into_iter().take(remove) {
            self.generations.remove(&generation);
        }
    }

    fn snapshot(&self, generation: Option<OwnerGeneration>) -> Value {
        let generation_metrics = self.generations.get(&generation);
        let records = self
            .live
            .values()
            .filter(|record| record.provenance.generation == generation)
            .collect::<Vec<_>>();
        let mut connecting = 0_u64;
        let mut ready = 0_u64;
        let mut failed = 0_u64;
        let mut draining = 0_u64;
        let mut closed = 0_u64;
        let mut udp4_fds = 0_u64;
        let mut udp6_fds = 0_u64;
        let mut endpoint_driver_tasks = 0_u64;
        let mut receive_slab_bytes = 0_u64;
        let mut quic_transport_bytes = 0_u64;
        let mut http3_bytes = 0_u64;
        let mut tls_bytes = 0_u64;
        let mut queue_bytes = 0_u64;
        let mut total_bytes = 0_u64;
        for record in &records {
            match record.state {
                PhysicalOwnerState::Connecting => connecting += 1,
                PhysicalOwnerState::Ready => ready += 1,
                PhysicalOwnerState::Failed => failed += 1,
                PhysicalOwnerState::Draining => draining += 1,
                PhysicalOwnerState::Closed => closed += 1,
            }
            if record.udp_fd_live {
                match record.provenance.family {
                    QuicEndpointAddressFamily::Ipv4 => udp4_fds += 1,
                    QuicEndpointAddressFamily::Ipv6 => udp6_fds += 1,
                }
            }
            if record.endpoint_driver_task_live {
                endpoint_driver_tasks += 1;
            }
            if record.endpoint_charge_live {
                let charge = record.provenance.charge;
                receive_slab_bytes += charge.receive_slab_bytes;
                quic_transport_bytes += charge.quic_transport_bytes;
                http3_bytes += charge.http3_bytes;
                tls_bytes += charge.tls_bytes;
                queue_bytes += charge.queue_bytes;
                total_bytes += charge.total_bytes;
            }
        }
        let creations_total = generation_metrics
            .map(|metrics| metrics.creations.values().copied().sum::<u64>())
            .unwrap_or_default();
        let creations = generation_metrics
            .map(|metrics| {
                metrics
                    .creations
                    .iter()
                    .map(|(dimensions, count)| {
                        json!({
                            "protocol": dimensions.protocol.as_str(),
                            "callerClass": dimensions.caller.as_str(),
                            "addressFamily": dimensions.family.as_str(),
                            "underlay": dimensions.underlay.as_str(),
                            "count": count,
                        })
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let endpoints = records
            .iter()
            .map(|record| {
                let charge = record.provenance.charge;
                json!({
                    "protocol": record.provenance.protocol.as_str(),
                    "callerClass": record.provenance.caller.as_str(),
                    "generation": record.provenance.generation.map(OwnerGeneration::get),
                    "redactedKey": record.provenance.redacted_identity.report_value(),
                    "addressFamily": record.provenance.family.as_str(),
                    "underlay": record.provenance.underlay.as_str(),
                    "state": state_name(record.state),
                    "udpFdLive": record.udp_fd_live,
                    "endpointDriverTaskLive": record.endpoint_driver_task_live,
                    "chargedBytes": {
                        "live": record.endpoint_charge_live,
                        "receiveSlab": charge.receive_slab_bytes,
                        "quicTransport": charge.quic_transport_bytes,
                        "http3": charge.http3_bytes,
                        "tls": charge.tls_bytes,
                        "queue": charge.queue_bytes,
                        "total": charge.total_bytes,
                        "maxUdpPayload": charge.max_udp_payload_bytes,
                        "receiveSegments": charge.receive_segments,
                        "batchSize": charge.batch_size,
                    },
                })
            })
            .collect::<Vec<_>>();
        let (failed_transitions, draining_transitions, closed_transitions) = generation_metrics
            .map(|metrics| {
                (
                    metrics.failed_transitions,
                    metrics.draining_transitions,
                    metrics.closed_transitions,
                )
            })
            .unwrap_or_default();
        json!({
            "schema": QUIC_ENDPOINT_METRICS_SCHEMA,
            "schemaVersion": QUIC_ENDPOINT_METRICS_SCHEMA_VERSION,
            "generation": generation.map(OwnerGeneration::get),
            "cumulativeCreations": creations_total,
            "creationsByDimensions": creations,
            "liveStates": {
                "connecting": connecting,
                "ready": ready,
                "failed": failed,
                "draining": draining,
                "closed": closed,
                "total": records.len(),
            },
            "stateTransitions": {
                "failed": failed_transitions,
                "draining": draining_transitions,
                "closed": closed_transitions,
            },
            "udpFds": { "ipv4": udp4_fds, "ipv6": udp6_fds },
            "endpointDriverTasks": {
                "live": endpoint_driver_tasks,
                "measurement": "quinn-endpoint-driver-future",
            },
            "chargedBytes": {
                "receiveSlab": receive_slab_bytes,
                "quicTransport": quic_transport_bytes,
                "http3": http3_bytes,
                "tls": tls_bytes,
                "queue": queue_bytes,
                "total": total_bytes,
            },
            "chargeModel": charge_model_json(),
            "endpoints": endpoints,
            "closeJoinEvidenceComplete": false,
            "admissionEnforced": false,
        })
    }

    fn runtime_snapshot(&self, current_generation: OwnerGeneration) -> Value {
        let mut current = self.snapshot(Some(current_generation));
        let live_generations = self
            .live
            .values()
            .map(|record| record.provenance.generation)
            .collect::<std::collections::BTreeSet<_>>();
        let other_live_generations = self
            .generations
            .keys()
            .filter_map(|generation| *generation)
            .filter(|generation| *generation != current_generation)
            .filter(|generation| live_generations.contains(&Some(*generation)))
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .map(|generation| self.snapshot(Some(generation)))
            .collect::<Vec<_>>();
        let inactive_generation_history = self
            .generations
            .keys()
            .filter_map(|generation| *generation)
            .filter(|generation| *generation != current_generation)
            .filter(|generation| !live_generations.contains(&Some(*generation)))
            .map(|generation| self.snapshot(Some(generation)))
            .collect::<Vec<_>>();
        current["inventoryScope"] = json!("current-plus-unassigned-and-other-live");
        current["unassigned"] = self.snapshot(None);
        current["otherLiveGenerations"] = json!(other_live_generations);
        current["allLive"] = self.all_live_summary();
        current["inactiveGenerationHistory"] = json!(inactive_generation_history);
        current["observabilityProfile"] = json!({
            "model": QUIC_ENDPOINT_OBSERVABILITY_MODEL,
            "modelVersion": QUIC_ENDPOINT_OBSERVABILITY_MODEL_VERSION,
            "retainedInactiveGenerations": QuicEndpointObservabilityProfile::CURRENT
                .retained_inactive_generations,
            "liveGenerationsAlwaysRetained": true,
            "inactiveRetentionOrder": "highest-generation-id",
            "cumulativeCreationRetention": "current-and-bounded-inactive-generations",
        });
        current
    }

    fn all_live_summary(&self) -> Value {
        let mut states = [0_u64; 5];
        let mut udp4_fds = 0_u64;
        let mut udp6_fds = 0_u64;
        let mut endpoint_driver_tasks = 0_u64;
        let mut charged_bytes = 0_u64;
        for record in self.live.values() {
            let state_index = match record.state {
                PhysicalOwnerState::Connecting => 0,
                PhysicalOwnerState::Ready => 1,
                PhysicalOwnerState::Failed => 2,
                PhysicalOwnerState::Draining => 3,
                PhysicalOwnerState::Closed => 4,
            };
            states[state_index] += 1;
            if record.udp_fd_live {
                match record.provenance.family {
                    QuicEndpointAddressFamily::Ipv4 => udp4_fds += 1,
                    QuicEndpointAddressFamily::Ipv6 => udp6_fds += 1,
                }
            }
            if record.endpoint_driver_task_live {
                endpoint_driver_tasks += 1;
            }
            if record.endpoint_charge_live {
                charged_bytes += record.provenance.charge.total_bytes;
            }
        }
        json!({
            "total": self.live.len(),
            "states": {
                "connecting": states[0],
                "ready": states[1],
                "failed": states[2],
                "draining": states[3],
                "closed": states[4],
            },
            "udpFds": { "ipv4": udp4_fds, "ipv6": udp6_fds },
            "endpointDriverTasks": endpoint_driver_tasks,
            "chargedBytes": charged_bytes,
        })
    }
}

fn state_transition_allowed(from: PhysicalOwnerState, to: PhysicalOwnerState) -> bool {
    use PhysicalOwnerState as State;
    matches!(
        (from, to),
        (State::Connecting, State::Ready)
            | (State::Connecting, State::Failed)
            | (State::Connecting, State::Draining)
            | (State::Connecting, State::Closed)
            | (State::Ready, State::Failed)
            | (State::Ready, State::Draining)
            | (State::Ready, State::Closed)
            | (State::Failed, State::Draining)
            | (State::Failed, State::Closed)
            | (State::Draining, State::Closed)
    )
}

fn state_name(state: PhysicalOwnerState) -> &'static str {
    match state {
        PhysicalOwnerState::Connecting => "connecting",
        PhysicalOwnerState::Ready => "ready",
        PhysicalOwnerState::Failed => "failed",
        PhysicalOwnerState::Draining => "draining",
        PhysicalOwnerState::Closed => "closed",
    }
}

fn registry() -> &'static Mutex<QuicEndpointMetricsRegistry> {
    static REGISTRY: OnceLock<Mutex<QuicEndpointMetricsRegistry>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(QuicEndpointMetricsRegistry::default()))
}

pub(super) struct QuicEndpointObservation {
    id: u64,
    provenance: QuicEndpointProvenance,
}

impl QuicEndpointObservation {
    pub(super) fn register(provenance: QuicEndpointProvenance) -> Arc<Self> {
        let id = registry().lock().unwrap().register(provenance.clone());
        Arc::new(Self { id, provenance })
    }

    pub(super) const fn provenance(&self) -> &QuicEndpointProvenance {
        &self.provenance
    }

    pub(super) fn endpoint_created(&self) {
        registry().lock().unwrap().endpoint_created(self.id);
    }

    pub(super) fn mark_ready(&self) {
        registry()
            .lock()
            .unwrap()
            .transition(self.id, PhysicalOwnerState::Ready);
    }

    pub(super) fn mark_failed(&self) {
        registry()
            .lock()
            .unwrap()
            .transition(self.id, PhysicalOwnerState::Failed);
    }

    pub(super) fn begin_draining(&self) {
        registry()
            .lock()
            .unwrap()
            .transition(self.id, PhysicalOwnerState::Draining);
    }

    pub(super) fn mark_closed_if_draining(&self) {
        registry().lock().unwrap().mark_closed_if_draining(self.id);
    }

    pub(super) fn udp_fd_opened(&self) {
        registry().lock().unwrap().set_udp_fd_live(self.id, true);
    }

    pub(super) fn udp_fd_closed(&self) {
        registry().lock().unwrap().set_udp_fd_live(self.id, false);
    }

    pub(super) fn endpoint_driver_started(&self) {
        registry()
            .lock()
            .unwrap()
            .set_endpoint_driver_live(self.id, true);
    }

    pub(super) fn endpoint_driver_finished(&self) {
        registry().lock().unwrap().endpoint_driver_finished(self.id);
    }
}

impl Drop for QuicEndpointObservation {
    fn drop(&mut self) {
        registry().lock().unwrap().release(self.id);
    }
}

pub(crate) fn quic_endpoint_metrics_snapshot(generation: u64) -> Value {
    registry()
        .lock()
        .unwrap()
        .runtime_snapshot(OwnerGeneration::new(generation))
}
