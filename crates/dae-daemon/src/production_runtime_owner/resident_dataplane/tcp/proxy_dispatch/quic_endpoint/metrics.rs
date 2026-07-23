use std::sync::{
    Arc, Mutex, OnceLock,
    atomic::{AtomicBool, Ordering},
};

use dae_runtime_control::{OwnerGeneration, OwnerReservation, PhysicalOwnerState};
use serde_json::{Value, json};
use tokio::sync::Notify;

use super::admission::admission_snapshot;
use super::charge::charge_model_json;
use super::model::{
    QuicEndpointAddressFamily, QuicEndpointCallerClass, QuicEndpointProtocol,
    QuicEndpointProvenance, QuicEndpointUnderlay,
};

const QUIC_ENDPOINT_METRICS_SCHEMA: &str = "quinn-endpoint-resources";
const QUIC_ENDPOINT_METRICS_SCHEMA_VERSION: u64 = 3;
const QUIC_ENDPOINT_OBSERVABILITY_MODEL: &str = "bounded-generation-quinn-inventory";
const QUIC_ENDPOINT_OBSERVABILITY_MODEL_VERSION: u64 = 2;

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
    explicit_close_requested: bool,
    endpoint_handles_released: bool,
    wait_idle_completed: bool,
    endpoint_driver_finished: bool,
}

#[derive(Default)]
struct QuicEndpointGenerationMetrics {
    creations: Vec<(QuicEndpointMetricDimensions, u64)>,
    failed_transitions: u64,
    draining_transitions: u64,
    closed_transitions: u64,
    explicit_close_requests: u64,
    implicit_handle_releases: u64,
    wait_idle_completions: u64,
    endpoint_driver_completions: u64,
}

struct QuicEndpointGenerationEntry {
    generation: Option<OwnerGeneration>,
    metrics: QuicEndpointGenerationMetrics,
}

struct QuicEndpointLiveEntry {
    id: u64,
    record: QuicEndpointLiveRecord,
}

struct QuicEndpointMetricsRegistry {
    // Evidence only: records contain no Endpoint, Connection, socket, task, or protocol state.
    // Physical ownership remains with each protocol caller until a protocol registry is migrated.
    next_id: u64,
    live: Vec<QuicEndpointLiveEntry>,
    generations: Vec<QuicEndpointGenerationEntry>,
    inactive_generation_retention: usize,
}

impl Default for QuicEndpointMetricsRegistry {
    fn default() -> Self {
        Self {
            next_id: 0,
            live: Vec::new(),
            generations: Vec::new(),
            inactive_generation_retention: QuicEndpointObservabilityProfile::CURRENT
                .retained_inactive_generations,
        }
    }
}

#[cfg(test)]
impl QuicEndpointMetricsRegistry {
    fn for_parallel_process_tests() -> Self {
        // Parallel endpoint tests use distinct generations and inspect their just-completed
        // evidence. Keep that bounded evidence from being evicted by an unrelated test before
        // its assertion; local registry tests and production retain the low-cardinality profile.
        Self {
            inactive_generation_retention: 128,
            ..Self::default()
        }
    }
}

impl QuicEndpointMetricsRegistry {
    fn generation_metrics(
        &self,
        generation: Option<OwnerGeneration>,
    ) -> Option<&QuicEndpointGenerationMetrics> {
        self.generations
            .binary_search_by_key(&generation, |entry| entry.generation)
            .ok()
            .map(|index| &self.generations[index].metrics)
    }

    fn generation_metrics_mut(
        &mut self,
        generation: Option<OwnerGeneration>,
    ) -> &mut QuicEndpointGenerationMetrics {
        let index = match self
            .generations
            .binary_search_by_key(&generation, |entry| entry.generation)
        {
            Ok(index) => index,
            Err(index) => {
                self.generations.insert(
                    index,
                    QuicEndpointGenerationEntry {
                        generation,
                        metrics: QuicEndpointGenerationMetrics::default(),
                    },
                );
                index
            }
        };
        &mut self.generations[index].metrics
    }

    fn live_record(&self, id: u64) -> Option<&QuicEndpointLiveRecord> {
        self.live
            .binary_search_by_key(&id, |entry| entry.id)
            .ok()
            .map(|index| &self.live[index].record)
    }

    fn live_record_mut(&mut self, id: u64) -> Option<&mut QuicEndpointLiveRecord> {
        self.live
            .binary_search_by_key(&id, |entry| entry.id)
            .ok()
            .map(|index| &mut self.live[index].record)
    }

    fn generation_has_live_endpoint(&self, generation: Option<OwnerGeneration>) -> bool {
        self.live
            .iter()
            .any(|entry| entry.record.provenance.generation == generation)
    }

    fn register(&mut self, provenance: QuicEndpointProvenance) -> u64 {
        let mut id = self.next_id.wrapping_add(1).max(1);
        while self.live_record(id).is_some() {
            id = id.wrapping_add(1).max(1);
        }
        self.next_id = id;
        self.generation_metrics_mut(provenance.generation);
        let index = self
            .live
            .binary_search_by_key(&id, |entry| entry.id)
            .expect_err("unused QUIC endpoint observation id");
        self.live.insert(
            index,
            QuicEndpointLiveEntry {
                id,
                record: QuicEndpointLiveRecord {
                    provenance,
                    state: PhysicalOwnerState::Connecting,
                    udp_fd_live: false,
                    endpoint_driver_task_live: false,
                    endpoint_charge_live: false,
                    explicit_close_requested: false,
                    endpoint_handles_released: false,
                    wait_idle_completed: false,
                    endpoint_driver_finished: false,
                },
            },
        );
        self.prune_inactive_generations();
        id
    }

    fn endpoint_created(&mut self, id: u64) {
        let Some(record) = self.live_record(id) else {
            return;
        };
        let generation = record.provenance.generation;
        let dimensions = QuicEndpointMetricDimensions::from(&record.provenance);
        let creations = &mut self.generation_metrics_mut(generation).creations;
        match creations.binary_search_by_key(&dimensions, |(dimensions, _)| *dimensions) {
            Ok(index) => creations[index].1 += 1,
            Err(index) => creations.insert(index, (dimensions, 1)),
        }
    }

    fn transition(&mut self, id: u64, next: PhysicalOwnerState) {
        let Some(record) = self.live_record_mut(id) else {
            return;
        };
        if record.state == next || !state_transition_allowed(record.state, next) {
            return;
        }
        record.state = next;
        let generation = record.provenance.generation;
        let generation = self.generation_metrics_mut(generation);
        match next {
            PhysicalOwnerState::Failed => generation.failed_transitions += 1,
            PhysicalOwnerState::Draining => generation.draining_transitions += 1,
            PhysicalOwnerState::Closed => generation.closed_transitions += 1,
            PhysicalOwnerState::Connecting | PhysicalOwnerState::Ready => {}
        }
    }

    fn mark_closed_if_draining(&mut self, id: u64) {
        if self
            .live_record(id)
            .is_some_and(|record| record.state == PhysicalOwnerState::Draining)
        {
            self.transition(id, PhysicalOwnerState::Closed);
        }
    }

    fn set_udp_fd_live(&mut self, id: u64, live: bool) {
        if let Some(record) = self.live_record_mut(id) {
            record.udp_fd_live = live;
            // Quinn's receive slab and Endpoint state share the EndpointInner that owns this
            // abstract socket. The socket lifetime therefore remains charged even if the
            // EndpointDriver future exits early while an Endpoint/Connection handle is retained.
            record.endpoint_charge_live = live;
        }
    }

    fn set_endpoint_driver_live(&mut self, id: u64, live: bool) {
        if let Some(record) = self.live_record_mut(id) {
            record.endpoint_driver_task_live = live;
        }
    }

    fn endpoint_driver_finished(&mut self, id: u64) {
        let generation = self
            .live_record(id)
            .map(|record| record.provenance.generation);
        if let Some(record) = self.live_record_mut(id)
            && !record.endpoint_driver_finished
        {
            record.endpoint_driver_finished = true;
            if let Some(generation) = generation {
                self.generation_metrics_mut(generation)
                    .endpoint_driver_completions += 1;
            }
        }
        self.set_endpoint_driver_live(id, false);
        if self.live_record(id).is_some_and(|record| {
            matches!(
                record.state,
                PhysicalOwnerState::Connecting | PhysicalOwnerState::Ready
            )
        }) {
            self.transition(id, PhysicalOwnerState::Failed);
        }
    }

    fn explicit_close_requested(&mut self, id: u64) {
        let generation = self
            .live_record(id)
            .map(|record| record.provenance.generation);
        if let Some(record) = self.live_record_mut(id)
            && !record.explicit_close_requested
        {
            record.explicit_close_requested = true;
            if let Some(generation) = generation {
                self.generation_metrics_mut(generation)
                    .explicit_close_requests += 1;
            }
        }
        self.transition(id, PhysicalOwnerState::Draining);
    }

    fn endpoint_handles_released(&mut self, id: u64) {
        let generation = self
            .live_record(id)
            .map(|record| record.provenance.generation);
        let mut implicit = false;
        if let Some(record) = self.live_record_mut(id)
            && !record.endpoint_handles_released
        {
            record.endpoint_handles_released = true;
            implicit = !record.explicit_close_requested;
            if implicit && let Some(generation) = generation {
                self.generation_metrics_mut(generation)
                    .implicit_handle_releases += 1;
            }
        }
        if implicit {
            self.transition(id, PhysicalOwnerState::Draining);
        }
    }

    fn wait_idle_completed(&mut self, id: u64) {
        let generation = self
            .live_record(id)
            .map(|record| record.provenance.generation);
        if let Some(record) = self.live_record_mut(id)
            && !record.wait_idle_completed
        {
            record.wait_idle_completed = true;
            if let Some(generation) = generation {
                self.generation_metrics_mut(generation)
                    .wait_idle_completions += 1;
            }
        }
        self.mark_closed_if_draining(id);
    }

    fn release(&mut self, id: u64) {
        let Ok(index) = self.live.binary_search_by_key(&id, |entry| entry.id) else {
            return;
        };
        self.transition(id, PhysicalOwnerState::Closed);
        self.live.remove(index);
        self.prune_inactive_generations();
    }

    fn prune_inactive_generations(&mut self) {
        let inactive = self
            .generations
            .iter()
            .map(|entry| entry.generation)
            .filter(|generation| !self.generation_has_live_endpoint(*generation))
            .collect::<Vec<_>>();
        let remove = inactive
            .len()
            .saturating_sub(self.inactive_generation_retention);
        for generation in inactive.into_iter().take(remove) {
            if let Ok(index) = self
                .generations
                .binary_search_by_key(&generation, |entry| entry.generation)
            {
                self.generations.remove(index);
            }
        }
    }

    fn snapshot(&self, generation: Option<OwnerGeneration>) -> Value {
        let generation_metrics = self.generation_metrics(generation);
        let records = self
            .live
            .iter()
            .map(|entry| &entry.record)
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
        let mut underlay_socket_bytes = 0_u64;
        let mut total_bytes = 0_u64;
        let mut udp_socket_charge_count = 0_u64;
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
                underlay_socket_bytes += charge.underlay_socket_bytes;
                total_bytes += charge.total_bytes;
                udp_socket_charge_count += charge.udp_socket_count;
            }
        }
        let creations_total = generation_metrics
            .map(|metrics| {
                metrics
                    .creations
                    .iter()
                    .map(|(_, count)| *count)
                    .sum::<u64>()
            })
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
                    "closeEvidence": {
                        "explicitCloseRequested": record.explicit_close_requested,
                        "endpointHandlesReleased": record.endpoint_handles_released,
                        "waitIdleCompleted": record.wait_idle_completed,
                        "endpointDriverFinished": record.endpoint_driver_finished,
                    },
                    "chargedBytes": {
                        "live": record.endpoint_charge_live,
                        "receiveSlab": charge.receive_slab_bytes,
                        "quicTransport": charge.quic_transport_bytes,
                        "http3": charge.http3_bytes,
                        "tls": charge.tls_bytes,
                        "queue": charge.queue_bytes,
                        "underlaySockets": charge.underlay_socket_bytes,
                        "total": charge.total_bytes,
                        "maxUdpPayload": charge.max_udp_payload_bytes,
                        "receiveSegments": charge.receive_segments,
                        "batchSize": charge.batch_size,
                        "udpSocketCount": charge.udp_socket_count,
                    },
                    "admissionChargedBytes": record.provenance.admission_charge.total_bytes,
                })
            })
            .collect::<Vec<_>>();
        let (
            failed_transitions,
            draining_transitions,
            closed_transitions,
            explicit_close_requests,
            implicit_handle_releases,
            wait_idle_completions,
            endpoint_driver_completions,
        ) = generation_metrics
            .map(|metrics| {
                (
                    metrics.failed_transitions,
                    metrics.draining_transitions,
                    metrics.closed_transitions,
                    metrics.explicit_close_requests,
                    metrics.implicit_handle_releases,
                    metrics.wait_idle_completions,
                    metrics.endpoint_driver_completions,
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
            "closeEvidence": {
                "explicitCloseRequests": explicit_close_requests,
                "implicitHandleReleases": implicit_handle_releases,
                "waitIdleCompletions": wait_idle_completions,
                "endpointDriverCompletions": endpoint_driver_completions,
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
                "underlaySockets": underlay_socket_bytes,
                "total": total_bytes,
                "udpSocketCount": udp_socket_charge_count,
            },
            "chargeModel": charge_model_json(),
            "admission": admission_snapshot(),
            "endpoints": endpoints,
            "closeJoinEvidenceComplete": true,
            "admissionEnforced": true,
        })
    }

    fn runtime_snapshot(&self, current_generation: OwnerGeneration) -> Value {
        let mut current = self.snapshot(Some(current_generation));
        let other_live_generations = self
            .generations
            .iter()
            .filter_map(|entry| entry.generation)
            .filter(|generation| *generation != current_generation)
            .filter(|generation| self.generation_has_live_endpoint(Some(*generation)))
            .map(|generation| self.snapshot(Some(generation)))
            .collect::<Vec<_>>();
        let inactive_generation_history = self
            .generations
            .iter()
            .filter_map(|entry| entry.generation)
            .filter(|generation| *generation != current_generation)
            .filter(|generation| !self.generation_has_live_endpoint(Some(*generation)))
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
            "retainedInactiveGenerations": self.inactive_generation_retention,
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
        for entry in &self.live {
            let record = &entry.record;
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
    REGISTRY.get_or_init(|| {
        #[cfg(test)]
        let registry = QuicEndpointMetricsRegistry::for_parallel_process_tests();
        #[cfg(not(test))]
        let registry = QuicEndpointMetricsRegistry::default();
        Mutex::new(registry)
    })
}

pub(super) struct QuicEndpointObservation {
    id: u64,
    provenance: QuicEndpointProvenance,
    release: Arc<QuicEndpointReleaseSignal>,
    reservation: Option<OwnerReservation>,
}

#[derive(Default)]
pub(super) struct QuicEndpointReleaseSignal {
    released: AtomicBool,
    notify: Notify,
}

impl QuicEndpointReleaseSignal {
    fn complete(&self) {
        if !self.released.swap(true, Ordering::AcqRel) {
            self.notify.notify_waiters();
        }
    }

    pub(super) async fn wait(&self) {
        loop {
            if self.released.load(Ordering::Acquire) {
                return;
            }
            let notified = self.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.released.load(Ordering::Acquire) {
                return;
            }
            notified.await;
        }
    }
}

impl QuicEndpointObservation {
    pub(super) fn register(
        provenance: QuicEndpointProvenance,
        reservation: OwnerReservation,
    ) -> Arc<Self> {
        let id = registry().lock().unwrap().register(provenance.clone());
        Arc::new(Self {
            id,
            provenance,
            release: Arc::new(QuicEndpointReleaseSignal::default()),
            reservation: Some(reservation),
        })
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

    pub(super) fn explicit_close_requested(&self) {
        registry().lock().unwrap().explicit_close_requested(self.id);
    }

    pub(super) fn endpoint_handles_released(&self) {
        registry()
            .lock()
            .unwrap()
            .endpoint_handles_released(self.id);
    }

    pub(super) fn wait_idle_completed(&self) {
        registry().lock().unwrap().wait_idle_completed(self.id);
    }

    pub(super) fn release_signal(&self) -> Arc<QuicEndpointReleaseSignal> {
        Arc::clone(&self.release)
    }
}

impl Drop for QuicEndpointObservation {
    fn drop(&mut self) {
        drop(self.reservation.take());
        registry().lock().unwrap().release(self.id);
        self.release.complete();
    }
}

pub(crate) fn quic_endpoint_metrics_snapshot(generation: u64) -> Value {
    registry()
        .lock()
        .unwrap()
        .runtime_snapshot(OwnerGeneration::new(generation))
}

#[cfg(test)]
mod registry_tests {
    use super::*;
    use crate::production_runtime_owner::resident_dataplane::tcp::proxy_dispatch::quic_endpoint::{
        charge::QuicEndpointCharge, model::QuicEndpointOpenContext,
    };

    fn provenance(
        protocol: QuicEndpointProtocol,
        caller: QuicEndpointCallerClass,
        generation: Option<OwnerGeneration>,
        ipv6: bool,
    ) -> QuicEndpointProvenance {
        let endpoint_config = quinn::EndpointConfig::default();
        let charge =
            QuicEndpointCharge::for_socket(&endpoint_config, 1, protocol.uses_http3()).unwrap();
        let (remote, bind) = if ipv6 {
            ("[::1]:443".parse().unwrap(), "[::]:0".parse().unwrap())
        } else {
            (
                "127.0.0.1:443".parse().unwrap(),
                "0.0.0.0:0".parse().unwrap(),
            )
        };
        QuicEndpointOpenContext::isolated_test(
            protocol,
            caller,
            generation,
            b"metrics-registry-test",
        )
        .finalize(
            remote,
            bind,
            0,
            QuicEndpointUnderlay::Ordinary,
            charge,
            charge,
        )
    }

    #[test]
    fn creations_and_live_records_remain_sorted_by_typed_keys() {
        let generation = Some(OwnerGeneration::new(71));
        let mut registry = QuicEndpointMetricsRegistry {
            next_id: 9,
            ..Default::default()
        };
        let high_id = registry.register(provenance(
            QuicEndpointProtocol::DnsOverHttp3,
            QuicEndpointCallerClass::ManualProbe,
            generation,
            true,
        ));
        registry.next_id = 1;
        let low_id = registry.register(provenance(
            QuicEndpointProtocol::Hysteria2,
            QuicEndpointCallerClass::TcpData,
            generation,
            false,
        ));
        registry.endpoint_created(high_id);
        registry.endpoint_created(low_id);
        registry.endpoint_created(low_id);

        assert_eq!(
            registry
                .live
                .iter()
                .map(|entry| entry.id)
                .collect::<Vec<_>>(),
            vec![low_id, high_id]
        );
        let creations = &registry.generation_metrics(generation).unwrap().creations;
        assert!(creations.windows(2).all(|pair| pair[0].0 < pair[1].0));
        assert_eq!(creations.iter().map(|(_, count)| *count).sum::<u64>(), 3);

        let snapshot = registry.snapshot(generation);
        assert_eq!(snapshot["schema"], QUIC_ENDPOINT_METRICS_SCHEMA);
        assert_eq!(
            snapshot["schemaVersion"],
            QUIC_ENDPOINT_METRICS_SCHEMA_VERSION
        );
        assert_eq!(snapshot["cumulativeCreations"], 3);
        assert_eq!(
            snapshot["creationsByDimensions"][0]["protocol"],
            "hysteria2"
        );
        assert_eq!(snapshot["creationsByDimensions"][0]["count"], 2);
        assert_eq!(snapshot["creationsByDimensions"][1]["protocol"], "doh3");
        assert_eq!(snapshot["creationsByDimensions"][1]["count"], 1);
    }

    #[test]
    fn live_generations_are_retained_and_inactive_history_keeps_highest_ids() {
        let current_generation = OwnerGeneration::new(130);
        let mut registry = QuicEndpointMetricsRegistry::default();
        let unassigned = registry.register(provenance(
            QuicEndpointProtocol::Juicity,
            QuicEndpointCallerClass::ManagedDns,
            None,
            false,
        ));
        let current = registry.register(provenance(
            QuicEndpointProtocol::Tuic,
            QuicEndpointCallerClass::TcpData,
            Some(current_generation),
            false,
        ));
        let other_live_high = registry.register(provenance(
            QuicEndpointProtocol::DnsOverQuic,
            QuicEndpointCallerClass::ConfiguredDns,
            Some(OwnerGeneration::new(120)),
            false,
        ));
        let other_live_low = registry.register(provenance(
            QuicEndpointProtocol::Hysteria2,
            QuicEndpointCallerClass::BackgroundHealth,
            Some(OwnerGeneration::new(110)),
            false,
        ));

        for generation in [140, 150, 160] {
            let id = registry.register(provenance(
                QuicEndpointProtocol::XhttpHttp3,
                QuicEndpointCallerClass::ManualProbe,
                Some(OwnerGeneration::new(generation)),
                true,
            ));
            registry.release(id);
        }

        let snapshot = registry.runtime_snapshot(current_generation);
        assert_eq!(snapshot["unassigned"]["liveStates"]["total"], 1);
        assert_eq!(
            snapshot["otherLiveGenerations"]
                .as_array()
                .unwrap()
                .iter()
                .map(|value| value["generation"].as_u64().unwrap())
                .collect::<Vec<_>>(),
            vec![110, 120]
        );
        assert_eq!(
            snapshot["inactiveGenerationHistory"]
                .as_array()
                .unwrap()
                .iter()
                .map(|value| value["generation"].as_u64().unwrap())
                .collect::<Vec<_>>(),
            vec![150, 160]
        );

        for id in [unassigned, current, other_live_high, other_live_low] {
            registry.release(id);
        }
    }

    #[test]
    fn release_records_closed_before_removing_the_live_record() {
        let generation = Some(OwnerGeneration::new(170));
        let mut registry = QuicEndpointMetricsRegistry::default();
        let id = registry.register(provenance(
            QuicEndpointProtocol::Tuic,
            QuicEndpointCallerClass::UdpData,
            generation,
            false,
        ));
        registry.endpoint_created(id);
        registry.transition(id, PhysicalOwnerState::Ready);
        registry.transition(id, PhysicalOwnerState::Failed);
        registry.transition(id, PhysicalOwnerState::Ready);
        registry.transition(id, PhysicalOwnerState::Draining);
        registry.release(id);

        assert!(registry.live_record(id).is_none());
        let snapshot = registry.snapshot(generation);
        assert_eq!(snapshot["cumulativeCreations"], 1);
        assert_eq!(snapshot["stateTransitions"]["failed"], 1);
        assert_eq!(snapshot["stateTransitions"]["draining"], 1);
        assert_eq!(snapshot["stateTransitions"]["closed"], 1);
        assert_eq!(snapshot["liveStates"]["total"], 0);
    }

    #[test]
    fn wrapped_ids_skip_existing_live_records() {
        let mut registry = QuicEndpointMetricsRegistry {
            next_id: u64::MAX,
            ..Default::default()
        };
        let first = registry.register(provenance(
            QuicEndpointProtocol::Tuic,
            QuicEndpointCallerClass::TcpData,
            Some(OwnerGeneration::new(180)),
            false,
        ));
        registry.next_id = u64::MAX;
        let second = registry.register(provenance(
            QuicEndpointProtocol::Tuic,
            QuicEndpointCallerClass::UdpData,
            Some(OwnerGeneration::new(180)),
            false,
        ));

        assert_eq!((first, second), (1, 2));
        assert_eq!(registry.live.len(), 2);
        assert_eq!(registry.live[0].id, 1);
        assert_eq!(registry.live[1].id, 2);
    }
}
