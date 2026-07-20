use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Instant;

use dae_outbound::hysteria2::{
    Hysteria2AuthReport, Hysteria2AuthenticatedSession, Hysteria2BbrProfile,
    Hysteria2CongestionNegotiation, Hysteria2CongestionRuntime,
    Hysteria2EffectiveCongestionController, Hysteria2ServerBandwidthResponse, Hysteria2UdpMessage,
    authenticate_hysteria2_connection, decode_hysteria2_udp_message,
    hysteria2_padding_metrics_snapshot,
};
use dae_runtime_control::{
    AbsoluteDeadline, OwnerCancellationSignal, OwnerDrainReason, OwnerFailureClass,
    OwnerGeneration, PhysicalOwnerFailure, RedactedOwnerIdentity, SingleFlightBuilder,
    SingleFlightDecision, SingleFlightError, SingleFlightPhysicalOwner,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinSet;
use tokio::time;

use crate::production_runtime_owner::udp_payload_admission::{
    ResidentUdpPayloadAdmission, ResidentUdpPayloadPermit,
};

use super::*;
use crate::production_runtime_owner::resident_dataplane::plan::{
    ResidentProxyPlan, ResidentProxyProtocolPlan,
};
use crate::production_runtime_owner::resident_dataplane::tcp::{
    Hysteria2PortHoppingMetrics, Hysteria2QuicConnectionRequest, ObservedQuicEndpoint,
    QuicEndpointCallerClass, ResidentConnectedQuicEndpoint,
    open_hysteria2_quic_connection_candidates_async, wait_quic_endpoint_idle_after_close,
};

const HYSTERIA2_OWNER_IDENTITY_DOMAIN: &[u8] = b"dae/hysteria2-owner/v1";
const HYSTERIA2_OWNER_IDENTITY_NAMESPACE: &str = "hysteria2-transport";

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
struct Hysteria2OwnerKey {
    generation: OwnerGeneration,
    digest: [u8; 32],
}

impl std::fmt::Debug for Hysteria2OwnerKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Hysteria2OwnerKey")
            .field("generation", &self.generation)
            .field("digest", &"<redacted>")
            .finish()
    }
}

impl Hysteria2OwnerKey {
    fn for_proxy(proxy: &ResidentProxyPlan) -> Self {
        let generation = proxy.execution_plan().runtime_generation();
        let mut digest = Sha256::new();
        digest.update(HYSTERIA2_OWNER_IDENTITY_DOMAIN);
        update_identity_part(&mut digest, proxy.graph_link_hash.as_bytes());
        update_identity_part(&mut digest, &proxy.mark.to_be_bytes());
        Self {
            generation,
            digest: digest.finalize().into(),
        }
    }

    fn redacted_identity(self) -> RedactedOwnerIdentity {
        RedactedOwnerIdentity::new(HYSTERIA2_OWNER_IDENTITY_NAMESPACE, self.digest)
            .expect("static Hysteria2 owner identity namespace is valid")
    }

    #[cfg(test)]
    fn fixture(generation: u64, identity: &[u8]) -> Self {
        let mut digest = Sha256::new();
        digest.update(HYSTERIA2_OWNER_IDENTITY_DOMAIN);
        update_identity_part(&mut digest, identity);
        Self {
            generation: OwnerGeneration::new(generation),
            digest: digest.finalize().into(),
        }
    }
}

fn update_identity_part(digest: &mut Sha256, value: &[u8]) {
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value);
}

type Hysteria2OwnerCell = SingleFlightPhysicalOwner<Hysteria2SharedTransport>;

struct Hysteria2OwnerIndex {
    cells: HashMap<Hysteria2OwnerKey, Arc<Hysteria2OwnerCell>>,
    draining: bool,
}

impl Hysteria2OwnerIndex {
    fn new() -> Self {
        Self {
            cells: HashMap::new(),
            draining: false,
        }
    }
}

#[derive(Default)]
struct Hysteria2OwnerRegistryMetrics {
    port_hopping: Arc<Hysteria2PortHoppingMetrics>,
    active_owners: AtomicUsize,
    high_water_owners: AtomicUsize,
    active_leases: AtomicUsize,
    high_water_leases: AtomicUsize,
    cumulative_builds: AtomicU64,
    cumulative_build_failures: AtomicU64,
    cumulative_reuses: AtomicU64,
    owner_limit_rejections: AtomicU64,
    command_queue_rejections: AtomicU64,
    logical_lease_rejections: AtomicU64,
    active_udp_sessions: AtomicUsize,
    high_water_udp_sessions: AtomicUsize,
    cumulative_udp_datagrams: AtomicU64,
    malformed_udp_datagrams: AtomicU64,
    unknown_udp_sessions: AtomicU64,
    late_udp_sessions: AtomicU64,
    udp_session_queue_drops: AtomicU64,
    udp_session_queue_byte_drops: AtomicU64,
    udp_session_rejections: AtomicU64,
    current_udp_queued_bytes: AtomicUsize,
    high_water_udp_queued_bytes: AtomicUsize,
    active_udp_session_quarantine: AtomicUsize,
    high_water_udp_session_quarantine: AtomicUsize,
    next_transport_instance: AtomicU64,
    shutdown_timed_out: AtomicBool,
    active_brutal_controllers: AtomicUsize,
    active_bbr_controllers: AtomicUsize,
    active_reno_controllers: AtomicUsize,
    high_water_brutal_controllers: AtomicUsize,
    high_water_bbr_controllers: AtomicUsize,
    high_water_reno_controllers: AtomicUsize,
    cumulative_bandwidth_auto: AtomicU64,
    cumulative_bandwidth_zero: AtomicU64,
    cumulative_bandwidth_known: AtomicU64,
    last_max_tx: AtomicU64,
    last_max_rx: AtomicU64,
    last_server_rx: AtomicU64,
    last_effective_tx: AtomicU64,
    last_controller: AtomicU8,
    last_bbr_profile: AtomicU8,
    last_loss_compensation: AtomicBool,
}

impl Hysteria2OwnerRegistryMetrics {
    fn owner_opened(&self) {
        let active = self.active_owners.fetch_add(1, Ordering::AcqRel) + 1;
        update_high_water(&self.high_water_owners, active);
    }

    fn owner_closed(&self) {
        subtract_active(&self.active_owners);
    }

    fn lease_opened(&self) {
        let active = self.active_leases.fetch_add(1, Ordering::AcqRel) + 1;
        update_high_water(&self.high_water_leases, active);
    }

    fn lease_closed(&self) {
        subtract_active(&self.active_leases);
    }

    fn udp_session_opened(&self) {
        let active = self.active_udp_sessions.fetch_add(1, Ordering::AcqRel) + 1;
        update_high_water(&self.high_water_udp_sessions, active);
    }

    fn udp_session_closed(&self) {
        subtract_active(&self.active_udp_sessions);
    }

    fn next_transport_instance(&self) -> u64 {
        let instance = self.next_transport_instance.fetch_add(1, Ordering::Relaxed);
        instance.wrapping_add(1).max(1)
    }

    fn udp_payload_queued(&self, bytes: usize) {
        let current = self
            .current_udp_queued_bytes
            .fetch_add(bytes, Ordering::AcqRel)
            + bytes;
        update_high_water(&self.high_water_udp_queued_bytes, current);
    }

    fn udp_payload_released(&self, bytes: usize) {
        subtract_count(&self.current_udp_queued_bytes, bytes);
    }

    fn udp_session_quarantined(&self) {
        let active = self
            .active_udp_session_quarantine
            .fetch_add(1, Ordering::AcqRel)
            + 1;
        update_high_water(&self.high_water_udp_session_quarantine, active);
    }

    fn udp_session_quarantine_released(&self, count: usize) {
        subtract_count(&self.active_udp_session_quarantine, count);
    }

    fn congestion_negotiated(
        self: &Arc<Self>,
        negotiation: Hysteria2CongestionNegotiation,
    ) -> Hysteria2CongestionObservation {
        let (active, high_water, controller_code) = match negotiation.controller {
            Hysteria2EffectiveCongestionController::Brutal => (
                &self.active_brutal_controllers,
                &self.high_water_brutal_controllers,
                1,
            ),
            Hysteria2EffectiveCongestionController::Bbr => (
                &self.active_bbr_controllers,
                &self.high_water_bbr_controllers,
                2,
            ),
            Hysteria2EffectiveCongestionController::Reno => (
                &self.active_reno_controllers,
                &self.high_water_reno_controllers,
                3,
            ),
        };
        let current = active.fetch_add(1, Ordering::AcqRel) + 1;
        update_high_water(high_water, current);
        match negotiation.server_response {
            Hysteria2ServerBandwidthResponse::Auto => {
                self.cumulative_bandwidth_auto
                    .fetch_add(1, Ordering::Relaxed);
            }
            Hysteria2ServerBandwidthResponse::Unlimited => {
                self.cumulative_bandwidth_zero
                    .fetch_add(1, Ordering::Relaxed);
            }
            Hysteria2ServerBandwidthResponse::Known => {
                self.cumulative_bandwidth_known
                    .fetch_add(1, Ordering::Relaxed);
            }
            Hysteria2ServerBandwidthResponse::Pending => {}
        }
        self.last_max_tx
            .store(negotiation.max_tx, Ordering::Relaxed);
        self.last_max_rx
            .store(negotiation.max_rx, Ordering::Relaxed);
        self.last_server_rx
            .store(negotiation.server_rx, Ordering::Relaxed);
        self.last_effective_tx
            .store(negotiation.effective_tx, Ordering::Relaxed);
        self.last_controller
            .store(controller_code, Ordering::Relaxed);
        self.last_bbr_profile.store(
            match negotiation.profile {
                Hysteria2BbrProfile::Standard => 1,
                Hysteria2BbrProfile::Conservative => 2,
                Hysteria2BbrProfile::Aggressive => 3,
            },
            Ordering::Relaxed,
        );
        self.last_loss_compensation
            .store(negotiation.loss_compensation, Ordering::Relaxed);
        Hysteria2CongestionObservation {
            metrics: Arc::clone(self),
            controller: negotiation.controller,
        }
    }
}

struct Hysteria2CongestionObservation {
    metrics: Arc<Hysteria2OwnerRegistryMetrics>,
    controller: Hysteria2EffectiveCongestionController,
}

impl Drop for Hysteria2CongestionObservation {
    fn drop(&mut self) {
        let active = match self.controller {
            Hysteria2EffectiveCongestionController::Brutal => {
                &self.metrics.active_brutal_controllers
            }
            Hysteria2EffectiveCongestionController::Bbr => &self.metrics.active_bbr_controllers,
            Hysteria2EffectiveCongestionController::Reno => &self.metrics.active_reno_controllers,
        };
        subtract_active(active);
    }
}

fn update_high_water(high_water: &AtomicUsize, value: usize) {
    let mut current = high_water.load(Ordering::Relaxed);
    while value > current {
        match high_water.compare_exchange_weak(current, value, Ordering::Relaxed, Ordering::Relaxed)
        {
            Ok(_) => break,
            Err(observed) => current = observed,
        }
    }
}

fn subtract_active(active: &AtomicUsize) {
    let _ = active.fetch_update(Ordering::AcqRel, Ordering::Relaxed, |value| {
        Some(value.saturating_sub(1))
    });
}

fn subtract_count(active: &AtomicUsize, count: usize) {
    let _ = active.fetch_update(Ordering::AcqRel, Ordering::Relaxed, |value| {
        Some(value.saturating_sub(count))
    });
}

struct Hysteria2LogicalLeaseAdmission {
    limit: usize,
    active: AtomicUsize,
    high_water: AtomicUsize,
    registry_metrics: Arc<Hysteria2OwnerRegistryMetrics>,
}

impl Hysteria2LogicalLeaseAdmission {
    fn new(limit: usize, registry_metrics: Arc<Hysteria2OwnerRegistryMetrics>) -> Arc<Self> {
        Arc::new(Self {
            limit: limit.max(1),
            active: AtomicUsize::new(0),
            high_water: AtomicUsize::new(0),
            registry_metrics,
        })
    }

    fn reserve(self: &Arc<Self>) -> Result<Hysteria2LogicalLeaseReservation, String> {
        let mut active = self.active.load(Ordering::Acquire);
        loop {
            if active >= self.limit {
                self.registry_metrics
                    .logical_lease_rejections
                    .fetch_add(1, Ordering::Relaxed);
                return Err(format!(
                    "Hysteria2 logical lease budget is full ({})",
                    self.limit
                ));
            }
            match self.active.compare_exchange_weak(
                active,
                active + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(observed) => active = observed,
            }
        }
        update_high_water(&self.high_water, active + 1);
        self.registry_metrics.lease_opened();
        Ok(Hysteria2LogicalLeaseReservation {
            admission: Some(Arc::clone(self)),
        })
    }
}

struct Hysteria2LogicalLeaseReservation {
    admission: Option<Arc<Hysteria2LogicalLeaseAdmission>>,
}

impl Drop for Hysteria2LogicalLeaseReservation {
    fn drop(&mut self) {
        if let Some(admission) = self.admission.take() {
            subtract_active(&admission.active);
            admission.registry_metrics.lease_closed();
        }
    }
}

struct Hysteria2UdpSessionManagerState {
    closed: bool,
    next_session_id: u32,
    sessions: HashMap<u32, Hysteria2UdpSessionQueue>,
    quarantine: HashMap<u32, Instant>,
}

struct Hysteria2UdpSessionQueue {
    sender: mpsc::Sender<Hysteria2QueuedUdpMessage>,
    payload_admission: ResidentUdpPayloadAdmission,
}

struct Hysteria2QueuedUdpMessage {
    message: Option<Hysteria2UdpMessage>,
    _owner_payload: ResidentUdpPayloadPermit,
    _session_payload: ResidentUdpPayloadPermit,
    metrics: Arc<Hysteria2OwnerRegistryMetrics>,
    charged_bytes: usize,
}

impl Drop for Hysteria2QueuedUdpMessage {
    fn drop(&mut self) {
        self.metrics.udp_payload_released(self.charged_bytes);
    }
}

impl Hysteria2QueuedUdpMessage {
    fn into_message(mut self) -> Hysteria2UdpMessage {
        self.message
            .take()
            .expect("queued Hysteria2 UDP message is present until delivery")
    }
}

struct Hysteria2UdpSessionManager {
    generation: OwnerGeneration,
    limit: usize,
    queue_depth: usize,
    session_queue_bytes: usize,
    quarantine_limit: usize,
    quarantine_ttl: std::time::Duration,
    owner_payload_admission: ResidentUdpPayloadAdmission,
    state: Mutex<Hysteria2UdpSessionManagerState>,
    metrics: Arc<Hysteria2OwnerRegistryMetrics>,
}

impl Hysteria2UdpSessionManager {
    fn new(
        generation: OwnerGeneration,
        resources: Hysteria2OwnerResourceProfile,
        metrics: Arc<Hysteria2OwnerRegistryMetrics>,
    ) -> Arc<Self> {
        Arc::new(Self {
            generation,
            limit: resources.udp_session_limit().max(1),
            queue_depth: resources.udp_session_queue_depth().max(1),
            session_queue_bytes: resources.udp_session_queue_bytes().max(1),
            quarantine_limit: resources.udp_session_quarantine_limit().max(1),
            quarantine_ttl: resources.udp_session_quarantine_ttl(),
            owner_payload_admission: ResidentUdpPayloadAdmission::new(
                generation.get(),
                resources.udp_owner_queue_bytes(),
            ),
            state: Mutex::new(Hysteria2UdpSessionManagerState {
                closed: false,
                next_session_id: fastrand::u32(1..=u32::MAX),
                sessions: HashMap::new(),
                quarantine: HashMap::new(),
            }),
            metrics,
        })
    }

    fn register(
        self: &Arc<Self>,
    ) -> Result<
        (
            u32,
            mpsc::Receiver<Hysteria2QueuedUdpMessage>,
            Hysteria2UdpSessionRegistration,
        ),
        String,
    > {
        let mut state = self.state.lock().unwrap();
        if state.closed {
            return Err("Hysteria2 UDP session manager is closed".to_owned());
        }
        self.expire_quarantine(&mut state, Instant::now());
        if state.sessions.len() >= self.limit {
            self.metrics
                .udp_session_rejections
                .fetch_add(1, Ordering::Relaxed);
            return Err(format!(
                "Hysteria2 UDP session budget is full ({})",
                self.limit
            ));
        }
        let mut session_id = state.next_session_id;
        let search_limit = self.limit.saturating_add(1);
        for _ in 0..search_limit {
            session_id = session_id.wrapping_add(1).max(1);
            if !state.sessions.contains_key(&session_id)
                && !state.quarantine.contains_key(&session_id)
            {
                break;
            }
        }
        if state.sessions.contains_key(&session_id) || state.quarantine.contains_key(&session_id) {
            return Err("Hysteria2 UDP SessionID allocation is unavailable".to_owned());
        }
        state.next_session_id = session_id;
        let (sender, receiver) = mpsc::channel(self.queue_depth);
        state.sessions.insert(
            session_id,
            Hysteria2UdpSessionQueue {
                sender,
                payload_admission: ResidentUdpPayloadAdmission::new(
                    self.generation.get(),
                    self.session_queue_bytes,
                ),
            },
        );
        drop(state);
        self.metrics.udp_session_opened();
        Ok((
            session_id,
            receiver,
            Hysteria2UdpSessionRegistration {
                manager: Some(Arc::clone(self)),
                session_id,
            },
        ))
    }

    fn dispatch(&self, message: Hysteria2UdpMessage) {
        let session_id = message.session_id();
        let (sender, session_payload_admission) = {
            let mut state = self.state.lock().unwrap();
            self.expire_quarantine(&mut state, Instant::now());
            let Some(queue) = state.sessions.get(&session_id) else {
                if state.quarantine.contains_key(&session_id) {
                    self.metrics
                        .late_udp_sessions
                        .fetch_add(1, Ordering::Relaxed);
                } else {
                    self.metrics
                        .unknown_udp_sessions
                        .fetch_add(1, Ordering::Relaxed);
                }
                return;
            };
            (queue.sender.clone(), queue.payload_admission.clone())
        };
        let bytes = message.encoded_len();
        let owner_payload = match self.owner_payload_admission.try_acquire(bytes) {
            Ok(permit) => permit,
            Err(_) => {
                self.metrics
                    .udp_session_queue_byte_drops
                    .fetch_add(1, Ordering::Relaxed);
                return;
            }
        };
        let session_payload = match session_payload_admission.try_acquire(bytes) {
            Ok(permit) => permit,
            Err(_) => {
                self.metrics
                    .udp_session_queue_byte_drops
                    .fetch_add(1, Ordering::Relaxed);
                return;
            }
        };
        let queued = Hysteria2QueuedUdpMessage {
            message: Some(message),
            _owner_payload: owner_payload,
            _session_payload: session_payload,
            metrics: Arc::clone(&self.metrics),
            charged_bytes: bytes,
        };
        self.metrics.udp_payload_queued(bytes);
        match sender.try_send(queued) {
            Ok(()) => {
                self.metrics
                    .cumulative_udp_datagrams
                    .fetch_add(1, Ordering::Relaxed);
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.metrics
                    .udp_session_queue_drops
                    .fetch_add(1, Ordering::Relaxed);
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                self.unregister(session_id);
            }
        }
    }

    fn expire_quarantine(&self, state: &mut Hysteria2UdpSessionManagerState, now: Instant) {
        let before = state.quarantine.len();
        state.quarantine.retain(|_, expiration| *expiration > now);
        self.metrics
            .udp_session_quarantine_released(before.saturating_sub(state.quarantine.len()));
    }

    fn insert_quarantine(&self, state: &mut Hysteria2UdpSessionManagerState, session_id: u32) {
        let now = Instant::now();
        self.expire_quarantine(state, now);
        if state.quarantine.len() >= self.quarantine_limit
            && let Some(oldest) = state
                .quarantine
                .iter()
                .min_by_key(|(_, expiration)| **expiration)
                .map(|(session_id, _)| *session_id)
        {
            state.quarantine.remove(&oldest);
            self.metrics.udp_session_quarantine_released(1);
        }
        let expiration = now.checked_add(self.quarantine_ttl).unwrap_or(now);
        state.quarantine.insert(session_id, expiration);
        self.metrics.udp_session_quarantined();
    }

    fn unregister(&self, session_id: u32) {
        let removed = {
            let mut state = self.state.lock().unwrap();
            let removed = state.sessions.remove(&session_id).is_some();
            if removed && !state.closed {
                self.insert_quarantine(&mut state, session_id);
            }
            removed
        };
        if removed {
            self.metrics.udp_session_closed();
        }
    }

    fn is_closed(&self) -> bool {
        self.state.lock().unwrap().closed
    }

    #[cfg(test)]
    fn queued_payload_snapshot(&self) -> Value {
        self.owner_payload_admission.snapshot()
    }

    #[cfg(test)]
    fn quarantine_len(&self) -> usize {
        let mut state = self.state.lock().unwrap();
        self.expire_quarantine(&mut state, Instant::now());
        state.quarantine.len()
    }

    /*
     * Session removal is synchronous so a dropped logical lease cannot leave a
     * stale SessionID occupying the bounded registry while the transport is idle.
     */
    fn remove_session(&self, session_id: u32) {
        self.unregister(session_id);
    }

    fn close(&self) {
        let (removed, quarantined) = {
            let mut state = self.state.lock().unwrap();
            state.closed = true;
            let removed = state.sessions.len();
            let quarantined = state.quarantine.len();
            state.sessions.clear();
            state.quarantine.clear();
            (removed, quarantined)
        };
        for _ in 0..removed {
            self.metrics.udp_session_closed();
        }
        self.metrics.udp_session_quarantine_released(quarantined);
    }
}

struct Hysteria2UdpSessionRegistration {
    manager: Option<Arc<Hysteria2UdpSessionManager>>,
    session_id: u32,
}

impl Drop for Hysteria2UdpSessionRegistration {
    fn drop(&mut self) {
        if let Some(manager) = self.manager.take() {
            manager.remove_session(self.session_id);
        }
    }
}

pub(crate) struct Hysteria2SharedTransport {
    instance_id: u64,
    _identity: RedactedOwnerIdentity,
    remote: SocketAddr,
    endpoint: ObservedQuicEndpoint,
    connection: quinn::Connection,
    auth_report: Hysteria2AuthReport,
    _congestion_observation: Hysteria2CongestionObservation,
    leases: Arc<Hysteria2LogicalLeaseAdmission>,
    udp_sessions: Arc<Hysteria2UdpSessionManager>,
}

impl Hysteria2SharedTransport {
    fn try_lease(self: &Arc<Self>) -> Result<Hysteria2TransportLease, String> {
        if self.connection.close_reason().is_some() {
            return Err("Hysteria2 shared transport is closed".to_owned());
        }
        let reservation = self.leases.reserve()?;
        Ok(Hysteria2TransportLease {
            transport: Arc::clone(self),
            _reservation: reservation,
        })
    }

    pub(crate) fn connection(&self) -> &quinn::Connection {
        &self.connection
    }

    pub(crate) const fn remote(&self) -> SocketAddr {
        self.remote
    }

    pub(crate) fn auth_report(&self) -> &Hysteria2AuthReport {
        &self.auth_report
    }

    async fn close(&self) {
        self.udp_sessions.close();
        self.connection
            .close(0_u32.into(), b"resident hysteria2 owner draining");
        self.endpoint
            .close(0_u32.into(), b"resident hysteria2 owner draining");
        wait_quic_endpoint_idle_after_close(&self.endpoint).await;
    }
}

impl Drop for Hysteria2SharedTransport {
    fn drop(&mut self) {
        self.udp_sessions.close();
        self.connection
            .close(0_u32.into(), b"resident hysteria2 owner released");
        self.endpoint
            .close(0_u32.into(), b"resident hysteria2 owner released");
    }
}

pub(crate) struct Hysteria2TransportLease {
    transport: Arc<Hysteria2SharedTransport>,
    _reservation: Hysteria2LogicalLeaseReservation,
}

impl Hysteria2TransportLease {
    pub(crate) fn connection(&self) -> &quinn::Connection {
        self.transport.connection()
    }

    pub(crate) fn remote(&self) -> SocketAddr {
        self.transport.remote()
    }

    pub(crate) fn auth_report(&self) -> &Hysteria2AuthReport {
        self.transport.auth_report()
    }

    pub(crate) fn open_udp_session(self) -> Result<Hysteria2UdpSessionLease, String> {
        if !self.auth_report().udp_enabled {
            return Err("Hysteria2 shared transport did not negotiate UDP support".to_owned());
        }
        let manager = Arc::clone(&self.transport.udp_sessions);
        let (session_id, receiver, registration) = manager.register()?;
        Ok(Hysteria2UdpSessionLease {
            transport: self,
            session_id,
            receiver,
            manager,
            _registration: registration,
        })
    }
}

pub(crate) struct Hysteria2UdpSessionLease {
    transport: Hysteria2TransportLease,
    session_id: u32,
    receiver: mpsc::Receiver<Hysteria2QueuedUdpMessage>,
    manager: Arc<Hysteria2UdpSessionManager>,
    _registration: Hysteria2UdpSessionRegistration,
}

impl Hysteria2UdpSessionLease {
    pub(crate) fn session_id(&self) -> u32 {
        self.session_id
    }

    pub(crate) fn connection(&self) -> &quinn::Connection {
        self.transport.connection()
    }

    pub(crate) fn try_receive(&mut self) -> Result<Option<Hysteria2UdpMessage>, String> {
        if self.manager.is_closed() {
            return Err("Hysteria2 UDP transport owner is closed".to_owned());
        }
        match self.receiver.try_recv() {
            Ok(message) => Ok(Some(message.into_message())),
            Err(mpsc::error::TryRecvError::Empty) => Ok(None),
            Err(mpsc::error::TryRecvError::Disconnected) => {
                Err("Hysteria2 UDP transport owner is closed".to_owned())
            }
        }
    }

    pub(crate) async fn receive_until(
        &mut self,
        expiration: Option<Instant>,
    ) -> Result<Option<Hysteria2UdpMessage>, String> {
        if self.manager.is_closed() {
            return Err("Hysteria2 UDP transport owner is closed".to_owned());
        }
        let Some(expiration) = expiration else {
            return self
                .receiver
                .recv()
                .await
                .map(Hysteria2QueuedUdpMessage::into_message)
                .map(Some)
                .ok_or_else(|| "Hysteria2 UDP transport owner is closed".to_owned());
        };
        tokio::select! {
            message = self.receiver.recv() => message
                .map(Hysteria2QueuedUdpMessage::into_message)
                .map(Some)
                .ok_or_else(|| "Hysteria2 UDP transport owner is closed".to_owned()),
            _ = time::sleep_until(time::Instant::from_std(expiration)) => Ok(None),
        }
    }
}

struct Hysteria2OwnedTransport {
    shared: Arc<Hysteria2SharedTransport>,
    cell: Arc<Hysteria2OwnerCell>,
    _auth_session: Hysteria2AuthenticatedSession,
}

struct Hysteria2BuildCommand {
    key: Hysteria2OwnerKey,
    cell: Arc<Hysteria2OwnerCell>,
    builder: SingleFlightBuilder<Hysteria2SharedTransport>,
    proxy: Arc<ResidentProxyPlan>,
    caller: QuicEndpointCallerClass,
    deadline: AbsoluteDeadline,
    response: oneshot::Sender<Result<Arc<Hysteria2SharedTransport>, String>>,
}

enum Hysteria2OwnerCommand {
    Build(Hysteria2BuildCommand),
}

struct Hysteria2BuildCompletion {
    key: Hysteria2OwnerKey,
    owner: Option<Hysteria2OwnedTransport>,
}

enum Hysteria2TransportEvent {
    Datagram {
        key: Hysteria2OwnerKey,
        instance_id: u64,
        message: Result<Hysteria2UdpMessage, ()>,
    },
    Closed {
        key: Hysteria2OwnerKey,
        instance_id: u64,
    },
}

enum Hysteria2RegistryTaskCompletion {
    Build(Hysteria2BuildCompletion),
    Transport(Hysteria2TransportEvent),
}

#[derive(Clone)]
pub(crate) struct Hysteria2OwnerRegistryHandle {
    generation: OwnerGeneration,
    sender: mpsc::Sender<Hysteria2OwnerCommand>,
    index: Arc<Mutex<Hysteria2OwnerIndex>>,
    cancellation: OwnerCancellationSignal,
    resources: Hysteria2OwnerResourceProfile,
    metrics: Arc<Hysteria2OwnerRegistryMetrics>,
}

impl Hysteria2OwnerRegistryHandle {
    pub(crate) async fn acquire(
        &self,
        proxy: Arc<ResidentProxyPlan>,
        caller: QuicEndpointCallerClass,
        deadline: AbsoluteDeadline,
    ) -> Result<Hysteria2TransportLease, String> {
        let key = Hysteria2OwnerKey::for_proxy(&proxy);
        if key.generation != self.generation {
            return Err(format!(
                "Hysteria2 owner generation mismatch: requested={} active={}",
                key.generation.get(),
                self.generation.get()
            ));
        }
        let cell = {
            let mut index = self.index.lock().unwrap();
            if index.draining {
                return Err("Hysteria2 owner registry is draining".to_owned());
            }
            if let Some(cell) = index.cells.get(&key) {
                Arc::clone(cell)
            } else {
                if index.cells.len() >= self.resources.owner_limit() {
                    self.metrics
                        .owner_limit_rejections
                        .fetch_add(1, Ordering::Relaxed);
                    return Err(format!(
                        "Hysteria2 owner budget is full ({})",
                        self.resources.owner_limit()
                    ));
                }
                let cell = Arc::new(Hysteria2OwnerCell::new());
                index.cells.insert(key, Arc::clone(&cell));
                cell
            }
        };

        match cell
            .begin_or_observe(deadline, &self.cancellation)
            .map_err(single_flight_error)?
        {
            SingleFlightDecision::Ready(owner) => {
                self.metrics
                    .cumulative_reuses
                    .fetch_add(1, Ordering::Relaxed);
                owner.try_lease()
            }
            SingleFlightDecision::Observe(observer) => {
                let owner = observer.wait().await.map_err(single_flight_error)?;
                self.metrics
                    .cumulative_reuses
                    .fetch_add(1, Ordering::Relaxed);
                owner.try_lease()
            }
            SingleFlightDecision::Build(builder) => {
                let (response, receiver) = oneshot::channel();
                let command = Hysteria2OwnerCommand::Build(Hysteria2BuildCommand {
                    key,
                    cell: Arc::clone(&cell),
                    builder,
                    proxy,
                    caller,
                    deadline,
                    response,
                });
                if let Err(err) = self.sender.try_send(command) {
                    self.metrics
                        .command_queue_rejections
                        .fetch_add(1, Ordering::Relaxed);
                    let Hysteria2OwnerCommand::Build(command) = err.into_inner();
                    command.builder.publish_failed(PhysicalOwnerFailure::new(
                        OwnerFailureClass::Resource,
                        "hysteria2-owner-command-queue",
                    ));
                    let _ = cell.prepare_retry();
                    return Err("Hysteria2 owner command queue is unavailable".to_owned());
                }
                let remaining = deadline
                    .remaining_at(Instant::now())
                    .ok_or_else(|| "Hysteria2 owner acquisition deadline elapsed".to_owned())?;
                let owner = time::timeout(remaining, receiver)
                    .await
                    .map_err(|_| "Hysteria2 owner acquisition timeout".to_owned())?
                    .map_err(|_| {
                        "Hysteria2 owner runtime stopped during acquisition".to_owned()
                    })??;
                owner.try_lease()
            }
        }
    }

    pub(crate) fn metrics_snapshot(&self) -> Value {
        let index = self.index.lock().unwrap();
        let padding = hysteria2_padding_metrics_snapshot();
        let capabilities = dae_outbound::hysteria2::hysteria2_capability_ledger()
            .iter()
            .map(|entry| {
                json!({
                    "capability": entry.capability,
                    "disposition": entry.disposition.as_str(),
                    "reason": entry.reason,
                })
            })
            .collect::<Vec<_>>();
        json!({
            "schemaVersion": 1,
            "owner": "resident-hysteria2-owner-registry",
            "generation": self.generation.get(),
            "draining": index.draining,
            "registeredKeys": index.cells.len(),
            "activeOwners": self.metrics.active_owners.load(Ordering::Relaxed),
            "highWaterOwners": self.metrics.high_water_owners.load(Ordering::Relaxed),
            "activeLogicalLeases": self.metrics.active_leases.load(Ordering::Relaxed),
            "highWaterLogicalLeases": self.metrics.high_water_leases.load(Ordering::Relaxed),
            "activeUdpSessions": self.metrics.active_udp_sessions.load(Ordering::Relaxed),
            "highWaterUdpSessions": self.metrics.high_water_udp_sessions.load(Ordering::Relaxed),
            "cumulativeBuilds": self.metrics.cumulative_builds.load(Ordering::Relaxed),
            "cumulativeBuildFailures": self.metrics.cumulative_build_failures.load(Ordering::Relaxed),
            "cumulativeReuses": self.metrics.cumulative_reuses.load(Ordering::Relaxed),
            "cumulativeUdpDatagrams": self.metrics.cumulative_udp_datagrams.load(Ordering::Relaxed),
            "malformedUdpDatagrams": self.metrics.malformed_udp_datagrams.load(Ordering::Relaxed),
            "unknownUdpSessions": self.metrics.unknown_udp_sessions.load(Ordering::Relaxed),
            "lateUdpSessions": self.metrics.late_udp_sessions.load(Ordering::Relaxed),
            "udpSessionQueueDrops": self.metrics.udp_session_queue_drops.load(Ordering::Relaxed),
            "udpSessionQueueByteDrops": self.metrics.udp_session_queue_byte_drops.load(Ordering::Relaxed),
            "udpSessionRejections": self.metrics.udp_session_rejections.load(Ordering::Relaxed),
            "currentUdpQueuedBytes": self.metrics.current_udp_queued_bytes.load(Ordering::Relaxed),
            "highWaterUdpQueuedBytes": self.metrics.high_water_udp_queued_bytes.load(Ordering::Relaxed),
            "activeUdpSessionQuarantine": self.metrics.active_udp_session_quarantine.load(Ordering::Relaxed),
            "highWaterUdpSessionQuarantine": self.metrics.high_water_udp_session_quarantine.load(Ordering::Relaxed),
            "ownerLimitRejections": self.metrics.owner_limit_rejections.load(Ordering::Relaxed),
            "commandQueueRejections": self.metrics.command_queue_rejections.load(Ordering::Relaxed),
            "logicalLeaseRejections": self.metrics.logical_lease_rejections.load(Ordering::Relaxed),
            "shutdownTimedOut": self.metrics.shutdown_timed_out.load(Ordering::Relaxed),
            "portHopping": self.metrics.port_hopping.snapshot(),
            "capabilityLedger": {
                "bounded": true,
                "entries": capabilities,
            },
            "padding": {
                "scope": "process-wide Hysteria2 auth and TCP request generation",
                "contentRecorded": false,
                "auth": {
                    "range": {
                        "minimumInclusive": dae_outbound::hysteria2::HYSTERIA2_AUTH_PADDING_MIN,
                        "maximumExclusive": dae_outbound::hysteria2::HYSTERIA2_AUTH_PADDING_MAX_EXCLUSIVE,
                    },
                    "samples": padding.auth_samples,
                    "bytes": padding.auth_bytes,
                    "minimumObserved": padding.auth_min_observed,
                    "maximumObserved": padding.auth_max_observed,
                },
                "tcpRequest": {
                    "range": {
                        "minimumInclusive": dae_outbound::hysteria2::HYSTERIA2_TCP_REQUEST_PADDING_MIN,
                        "maximumExclusive": dae_outbound::hysteria2::HYSTERIA2_TCP_REQUEST_PADDING_MAX_EXCLUSIVE,
                    },
                    "samples": padding.tcp_request_samples,
                    "bytes": padding.tcp_request_bytes,
                    "minimumObserved": padding.tcp_request_min_observed,
                    "maximumObserved": padding.tcp_request_max_observed,
                },
            },
            "congestion": {
                "activeControllers": {
                    "brutal": self.metrics.active_brutal_controllers.load(Ordering::Relaxed),
                    "bbr": self.metrics.active_bbr_controllers.load(Ordering::Relaxed),
                    "reno": self.metrics.active_reno_controllers.load(Ordering::Relaxed),
                },
                "highWaterControllers": {
                    "brutal": self.metrics.high_water_brutal_controllers.load(Ordering::Relaxed),
                    "bbr": self.metrics.high_water_bbr_controllers.load(Ordering::Relaxed),
                    "reno": self.metrics.high_water_reno_controllers.load(Ordering::Relaxed),
                },
                "cumulativeServerResponses": {
                    "auto": self.metrics.cumulative_bandwidth_auto.load(Ordering::Relaxed),
                    "zero": self.metrics.cumulative_bandwidth_zero.load(Ordering::Relaxed),
                    "known": self.metrics.cumulative_bandwidth_known.load(Ordering::Relaxed),
                },
                "lastNegotiated": {
                    "maxTx": self.metrics.last_max_tx.load(Ordering::Relaxed),
                    "maxRx": self.metrics.last_max_rx.load(Ordering::Relaxed),
                    "serverRx": self.metrics.last_server_rx.load(Ordering::Relaxed),
                    "effectiveTx": self.metrics.last_effective_tx.load(Ordering::Relaxed),
                    "controller": match self.metrics.last_controller.load(Ordering::Relaxed) {
                        1 => "brutal",
                        2 => "bbr",
                        3 => "reno",
                        _ => "pending",
                    },
                    "bbrProfile": match self.metrics.last_bbr_profile.load(Ordering::Relaxed) {
                        1 => "standard",
                        2 => "conservative",
                        3 => "aggressive",
                        _ => "pending",
                    },
                    "lossCompensation": self.metrics.last_loss_compensation.load(Ordering::Relaxed),
                },
            },
            "budget": {
                "owners": self.resources.owner_limit(),
                "commandQueueDepth": self.resources.command_queue_depth(),
                "logicalLeasesPerOwner": self.resources.logical_lease_limit(),
                "udpSessionsPerOwner": self.resources.udp_session_limit(),
                "udpSessionQueueDepth": self.resources.udp_session_queue_depth(),
                "udpSessionQueueBytes": self.resources.udp_session_queue_bytes(),
                "udpOwnerQueueBytes": self.resources.udp_owner_queue_bytes(),
                "udpSessionQuarantineLimit": self.resources.udp_session_quarantine_limit(),
                "udpSessionQuarantineTtlMs": self.resources.udp_session_quarantine_ttl().as_millis(),
                "retryCooldownMs": self.resources.retry_cooldown().as_millis(),
                "initialConnectAttemptLimit": self.resources.initial_connect_attempt_limit(),
                "portHopTransitionSocketLimit": self.resources.port_hop_transition_socket_limit(),
            },
        })
    }
}

fn single_flight_error(error: SingleFlightError) -> String {
    match error {
        SingleFlightError::Cancelled(reason) => {
            format!("Hysteria2 owner acquisition cancelled: {reason:?}")
        }
        SingleFlightError::Failed(failure) => format!(
            "Hysteria2 owner construction failed: class={:?} operation={}",
            failure.class, failure.operation
        ),
        SingleFlightError::Draining(reason) => {
            format!("Hysteria2 owner registry is draining: {reason:?}")
        }
        SingleFlightError::Closed => "Hysteria2 owner registry is closed".to_owned(),
        SingleFlightError::Superseded => "Hysteria2 owner construction was superseded".to_owned(),
        SingleFlightError::RetryUnavailable(state) => {
            format!("Hysteria2 owner retry is unavailable from state {state:?}")
        }
    }
}

pub(crate) fn start_hysteria2_owner_registry(
    generation: u64,
    stop: SharedResidentStopSignal,
    stack_bytes: usize,
) -> Result<(Hysteria2OwnerRegistryHandle, JoinHandle<()>), String> {
    let generation = OwnerGeneration::new(generation);
    let resources = Hysteria2OwnerResourceProfile::selected();
    let (sender, receiver) = mpsc::channel(resources.command_queue_depth().max(1));
    let index = Arc::new(Mutex::new(Hysteria2OwnerIndex::new()));
    let cancellation = OwnerCancellationSignal::new();
    let metrics = Arc::new(Hysteria2OwnerRegistryMetrics::default());
    let handle = Hysteria2OwnerRegistryHandle {
        generation,
        sender,
        index: Arc::clone(&index),
        cancellation: cancellation.clone(),
        resources,
        metrics: Arc::clone(&metrics),
    };
    let (initialized, initialization) = std::sync::mpsc::sync_channel(1);
    let thread = std::thread::Builder::new()
        .name(format!("resident-hysteria2-owner-{}", generation.get()))
        .stack_size(stack_bytes)
        .spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .enable_time()
                .build();
            let runtime = match runtime {
                Ok(runtime) => {
                    let _ = initialized.send(Ok(()));
                    runtime
                }
                Err(err) => {
                    let _ = initialized
                        .send(Err(format!("build Hysteria2 owner Tokio runtime: {err}")));
                    return;
                }
            };
            runtime.block_on(run_hysteria2_owner_registry(
                generation,
                receiver,
                index,
                cancellation,
                resources,
                metrics,
                stop,
            ));
        })
        .map_err(|err| format!("spawn Hysteria2 owner runtime: {err}"))?;
    initialization
        .recv()
        .map_err(|_| "Hysteria2 owner runtime stopped during initialization".to_owned())??;
    Ok((handle, thread))
}

async fn run_hysteria2_owner_registry(
    _generation: OwnerGeneration,
    mut receiver: mpsc::Receiver<Hysteria2OwnerCommand>,
    index: Arc<Mutex<Hysteria2OwnerIndex>>,
    cancellation: OwnerCancellationSignal,
    resources: Hysteria2OwnerResourceProfile,
    metrics: Arc<Hysteria2OwnerRegistryMetrics>,
    stop: SharedResidentStopSignal,
) {
    let mut tasks = JoinSet::new();
    let mut owners = HashMap::<Hysteria2OwnerKey, Hysteria2OwnedTransport>::new();
    let mut stop_listener = stop.listener();
    loop {
        tokio::select! {
            _ = stop_listener.cancelled() => break,
            command = receiver.recv() => match command {
                Some(Hysteria2OwnerCommand::Build(command)) => {
                    let metrics = Arc::clone(&metrics);
                    let cancellation = cancellation.clone();
                    tasks.spawn(async move {
                        Hysteria2RegistryTaskCompletion::Build(
                            run_hysteria2_owner_build(
                                command,
                                resources,
                                metrics,
                                cancellation,
                            )
                            .await,
                        )
                    });
                }
                None => break,
            },
            completion = tasks.join_next(), if !tasks.is_empty() => {
                match completion {
                    Some(Ok(Hysteria2RegistryTaskCompletion::Build(completion))) => {
                        if let Some(owner) = completion.owner {
                            let connection = owner.shared.connection.clone();
                            let instance_id = owner.shared.instance_id;
                            if let Some(previous) = owners.insert(completion.key, owner) {
                                previous.cell.begin_drain(OwnerDrainReason::Fault);
                                previous.shared.close().await;
                                previous.cell.close();
                                metrics.owner_closed();
                            }
                            metrics.owner_opened();
                            tasks.spawn(async move {
                                Hysteria2RegistryTaskCompletion::Transport(
                                    wait_hysteria2_transport_event(
                                        completion.key,
                                        instance_id,
                                        connection,
                                    )
                                    .await,
                                )
                            });
                        }
                    }
                    Some(Ok(Hysteria2RegistryTaskCompletion::Transport(
                        Hysteria2TransportEvent::Datagram {
                            key,
                            instance_id,
                            message,
                        },
                    ))) => {
                        if let Some(owner) = owners.get(&key)
                            && owner.shared.instance_id == instance_id
                        {
                            match message {
                                Ok(message) => owner.shared.udp_sessions.dispatch(message),
                                Err(()) => {
                                    metrics
                                        .malformed_udp_datagrams
                                        .fetch_add(1, Ordering::Relaxed);
                                }
                            }
                            let connection = owner.shared.connection.clone();
                            tasks.spawn(async move {
                                Hysteria2RegistryTaskCompletion::Transport(
                                    wait_hysteria2_transport_event(key, instance_id, connection).await,
                                )
                            });
                        }
                    }
                    Some(Ok(Hysteria2RegistryTaskCompletion::Transport(
                        Hysteria2TransportEvent::Closed { key, instance_id },
                    ))) => {
                        let is_current = owners
                            .get(&key)
                            .is_some_and(|owner| owner.shared.instance_id == instance_id);
                        if is_current
                            && let Some(owner) = owners.remove(&key)
                        {
                            {
                                let mut index = index.lock().unwrap();
                                if index
                                    .cells
                                    .get(&key)
                                    .is_some_and(|cell| Arc::ptr_eq(cell, &owner.cell))
                                {
                                    index.cells.remove(&key);
                                }
                            }
                            owner.cell.begin_drain(OwnerDrainReason::Fault);
                            owner.shared.close().await;
                            owner.cell.close();
                            metrics.owner_closed();
                        }
                    }
                    Some(Err(_)) | None => {}
                }
            }
        }
    }

    cancellation.cancel(dae_runtime_control::OwnerCancellation::GenerationDraining);
    receiver.close();
    let cells = {
        let mut index = index.lock().unwrap();
        index.draining = true;
        index.cells.values().cloned().collect::<Vec<_>>()
    };
    for cell in &cells {
        cell.begin_drain(OwnerDrainReason::Shutdown);
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    let close_all = async {
        for (_, owner) in owners.drain() {
            owner.shared.close().await;
            metrics.owner_closed();
        }
    };
    if time::timeout(RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE, close_all)
        .await
        .is_err()
    {
        metrics.shutdown_timed_out.store(true, Ordering::Relaxed);
    }
    for cell in cells {
        cell.close();
    }
}

async fn wait_hysteria2_transport_event(
    key: Hysteria2OwnerKey,
    instance_id: u64,
    connection: quinn::Connection,
) -> Hysteria2TransportEvent {
    match connection.read_datagram().await {
        Ok(datagram) => Hysteria2TransportEvent::Datagram {
            key,
            instance_id,
            message: decode_hysteria2_udp_message(&datagram).map_err(|_| ()),
        },
        Err(_) => Hysteria2TransportEvent::Closed { key, instance_id },
    }
}

async fn run_hysteria2_owner_build(
    command: Hysteria2BuildCommand,
    resources: Hysteria2OwnerResourceProfile,
    metrics: Arc<Hysteria2OwnerRegistryMetrics>,
    cancellation: OwnerCancellationSignal,
) -> Hysteria2BuildCompletion {
    metrics.cumulative_builds.fetch_add(1, Ordering::Relaxed);
    let result = build_hysteria2_transport(
        command.key,
        command.proxy,
        command.caller,
        command.deadline,
        Arc::clone(&metrics),
        resources,
        cancellation,
    )
    .await;
    match result {
        Ok((transport, auth_session)) => {
            let owner = command.builder.publish_ready(transport);
            match owner {
                Ok(shared) => {
                    let _ = command.response.send(Ok(Arc::clone(&shared)));
                    Hysteria2BuildCompletion {
                        key: command.key,
                        owner: Some(Hysteria2OwnedTransport {
                            shared,
                            cell: Arc::clone(&command.cell),
                            _auth_session: auth_session,
                        }),
                    }
                }
                Err(err) => {
                    let _ = command.response.send(Err(single_flight_error(err)));
                    Hysteria2BuildCompletion {
                        key: command.key,
                        owner: None,
                    }
                }
            }
        }
        Err(error) => {
            metrics
                .cumulative_build_failures
                .fetch_add(1, Ordering::Relaxed);
            command
                .builder
                .publish_failed(PhysicalOwnerFailure::new(error.class, error.operation));
            let _ = command.response.send(Err(error.detail));
            time::sleep(resources.retry_cooldown()).await;
            let _ = command.cell.prepare_retry();
            Hysteria2BuildCompletion {
                key: command.key,
                owner: None,
            }
        }
    }
}

struct Hysteria2OwnerBuildError {
    class: OwnerFailureClass,
    operation: &'static str,
    detail: String,
}

async fn build_hysteria2_transport(
    key: Hysteria2OwnerKey,
    proxy: Arc<ResidentProxyPlan>,
    caller: QuicEndpointCallerClass,
    deadline: AbsoluteDeadline,
    metrics: Arc<Hysteria2OwnerRegistryMetrics>,
    resources: Hysteria2OwnerResourceProfile,
    cancellation: OwnerCancellationSignal,
) -> Result<(Hysteria2SharedTransport, Hysteria2AuthenticatedSession), Hysteria2OwnerBuildError> {
    let ResidentProxyProtocolPlan::Hysteria2QuicTcp {
        auth,
        tls_identity,
        max_tx,
        max_rx,
        congestion,
        obfs,
        port_hop_ports,
        port_hop_interval,
    } = &proxy.handler
    else {
        return Err(Hysteria2OwnerBuildError {
            class: OwnerFailureClass::Transport,
            operation: "hysteria2-owner-shape",
            detail: "Hysteria2 owner received a non-Hysteria2 proxy shape".to_owned(),
        });
    };
    let congestion_runtime = Arc::new(
        Hysteria2CongestionRuntime::new(*congestion, *max_tx, *max_rx).map_err(|err| {
            Hysteria2OwnerBuildError {
                class: OwnerFailureClass::Transport,
                operation: "hysteria2-owner-congestion",
                detail: err.to_string(),
            }
        })?,
    );
    let connected = open_hysteria2_quic_connection_candidates_async(
        Hysteria2QuicConnectionRequest {
            proxy: &proxy,
            mark: proxy.mark,
            obfs,
            port_hop_ports,
            port_hop_interval: *port_hop_interval,
            tls_identity,
            congestion: Arc::clone(&congestion_runtime),
            resources,
            port_hopping_metrics: Arc::clone(&metrics.port_hopping),
            caller,
            cancellation: &cancellation,
        },
        deadline,
    )
    .await
    .map_err(|failure| Hysteria2OwnerBuildError {
        class: failure.owner_failure_class(),
        operation: failure.operation(),
        detail: failure.to_string(),
    })?;
    let ResidentConnectedQuicEndpoint {
        remote,
        endpoint,
        connection,
    } = connected;
    let remaining = match deadline.remaining_at(Instant::now()) {
        Some(remaining) => remaining,
        None => {
            endpoint.mark_failed();
            endpoint.close(0_u32.into(), b"hysteria2 owner auth deadline elapsed");
            wait_quic_endpoint_idle_after_close(&endpoint).await;
            return Err(Hysteria2OwnerBuildError {
                class: OwnerFailureClass::Cancelled,
                operation: "hysteria2-owner-auth-deadline",
                detail: "Hysteria2 owner authentication deadline elapsed".to_owned(),
            });
        }
    };
    let auth_session = match time::timeout(
        remaining,
        authenticate_hysteria2_connection(
            connection.clone(),
            auth,
            congestion_runtime.requested_rx(),
        ),
    )
    .await
    {
        Ok(Ok(session)) if session.report().auth_ok => session,
        Ok(Ok(session)) => {
            endpoint.mark_failed();
            connection.close(0x101_u32.into(), b"hysteria2 owner auth rejected");
            wait_quic_endpoint_idle_after_close(&endpoint).await;
            return Err(Hysteria2OwnerBuildError {
                class: OwnerFailureClass::Authentication,
                operation: "hysteria2-owner-auth-status",
                detail: format!(
                    "Hysteria2 owner authentication rejected with status {}",
                    session.report().status
                ),
            });
        }
        Ok(Err(err)) => {
            endpoint.mark_failed();
            connection.close(0x101_u32.into(), b"hysteria2 owner auth failed");
            wait_quic_endpoint_idle_after_close(&endpoint).await;
            return Err(Hysteria2OwnerBuildError {
                class: OwnerFailureClass::Authentication,
                operation: "hysteria2-owner-auth",
                detail: format!("authenticate Hysteria2 owner: {err}"),
            });
        }
        Err(_) => {
            endpoint.mark_failed();
            connection.close(0x101_u32.into(), b"hysteria2 owner auth timeout");
            wait_quic_endpoint_idle_after_close(&endpoint).await;
            return Err(Hysteria2OwnerBuildError {
                class: OwnerFailureClass::Cancelled,
                operation: "hysteria2-owner-auth-timeout",
                detail: "Hysteria2 owner authentication timeout".to_owned(),
            });
        }
    };
    congestion_runtime
        .apply_server_response(auth_session.report().rx_auto, auth_session.report().rx);
    endpoint.mark_ready();
    let auth_report = auth_session.report().clone();
    let congestion = congestion_runtime.negotiation();
    let congestion_observation = metrics.congestion_negotiated(congestion);
    let identity = key.redacted_identity();
    let instance_id = metrics.next_transport_instance();
    Ok((
        Hysteria2SharedTransport {
            instance_id,
            _identity: identity,
            remote,
            endpoint,
            connection,
            auth_report,
            _congestion_observation: congestion_observation,
            leases: Hysteria2LogicalLeaseAdmission::new(
                resources.logical_lease_limit(),
                Arc::clone(&metrics),
            ),
            udp_sessions: Hysteria2UdpSessionManager::new(key.generation, resources, metrics),
        },
        auth_session,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn udp_test_resources(
        session_limit: usize,
        queue_depth: usize,
    ) -> Hysteria2OwnerResourceProfile {
        Hysteria2OwnerResourceProfile::with_udp_session_limits_for_test(session_limit, queue_depth)
    }

    #[test]
    fn owner_key_is_generation_and_normalized_identity_scoped() {
        let first = Hysteria2OwnerKey::fixture(7, b"node-a");
        let same = Hysteria2OwnerKey::fixture(7, b"node-a");
        let next_generation = Hysteria2OwnerKey::fixture(8, b"node-a");
        let other_node = Hysteria2OwnerKey::fixture(7, b"node-b");
        assert_eq!(first, same);
        assert_ne!(first, next_generation);
        assert_ne!(first, other_node);
        assert!(!format!("{first:?}").contains("node-a"));
    }

    #[test]
    fn logical_lease_admission_reconciles_after_drop() {
        let metrics = Arc::new(Hysteria2OwnerRegistryMetrics::default());
        let admission = Hysteria2LogicalLeaseAdmission::new(2, Arc::clone(&metrics));
        let first = admission.reserve().unwrap();
        let second = admission.reserve().unwrap();
        let Err(error) = admission.reserve() else {
            panic!("the third logical lease must exceed the configured budget");
        };
        assert!(error.contains("budget is full"));
        assert_eq!(admission.active.load(Ordering::Relaxed), 2);
        assert_eq!(admission.high_water.load(Ordering::Relaxed), 2);
        drop(first);
        assert_eq!(admission.active.load(Ordering::Relaxed), 1);
        drop(second);
        assert_eq!(admission.active.load(Ordering::Relaxed), 0);
        assert_eq!(metrics.active_leases.load(Ordering::Relaxed), 0);
        assert_eq!(metrics.logical_lease_rejections.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn udp_session_manager_demultiplexes_and_reconciles_session_ids() {
        let metrics = Arc::new(Hysteria2OwnerRegistryMetrics::default());
        let manager = Hysteria2UdpSessionManager::new(
            OwnerGeneration::new(7),
            udp_test_resources(2, 2),
            Arc::clone(&metrics),
        );
        let (first_id, mut first_rx, first_registration) = manager.register().unwrap();
        let (second_id, mut second_rx, second_registration) = manager.register().unwrap();
        assert_ne!(first_id, second_id);
        assert_eq!(metrics.active_udp_sessions.load(Ordering::Relaxed), 2);
        assert_eq!(metrics.high_water_udp_sessions.load(Ordering::Relaxed), 2);

        let first = Hysteria2UdpMessage::new(first_id, "192.0.2.1:53", b"first").unwrap();
        let second = Hysteria2UdpMessage::new(second_id, "[2001:db8::1]:53", b"second").unwrap();
        manager.dispatch(second.clone());
        manager.dispatch(first.clone());
        assert_eq!(first_rx.try_recv().unwrap().into_message(), first);
        assert_eq!(second_rx.try_recv().unwrap().into_message(), second);
        assert!(matches!(
            first_rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
        assert!(matches!(
            second_rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));

        drop(first_registration);
        drop(second_registration);
        assert_eq!(metrics.active_udp_sessions.load(Ordering::Relaxed), 0);
        assert!(manager.state.lock().unwrap().sessions.is_empty());
    }

    #[test]
    fn udp_session_manager_bounds_sessions_and_response_queues() {
        let metrics = Arc::new(Hysteria2OwnerRegistryMetrics::default());
        let manager = Hysteria2UdpSessionManager::new(
            OwnerGeneration::new(7),
            udp_test_resources(1, 1),
            Arc::clone(&metrics),
        );
        let (session_id, mut receiver, registration) = manager.register().unwrap();
        let Err(error) = manager.register() else {
            panic!("a second Hysteria2 UDP session must exceed the configured budget");
        };
        assert!(error.contains("budget is full"));
        let first = Hysteria2UdpMessage::new(session_id, "192.0.2.2:53", b"first").unwrap();
        let dropped = Hysteria2UdpMessage::new(session_id, "192.0.2.2:53", b"second").unwrap();
        manager.dispatch(first.clone());
        manager.dispatch(dropped);
        assert_eq!(receiver.try_recv().unwrap().into_message(), first);
        assert_eq!(metrics.udp_session_rejections.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.udp_session_queue_drops.load(Ordering::Relaxed), 1);
        manager.dispatch(
            Hysteria2UdpMessage::new(session_id, "192.0.2.2:53", vec![0_u8; 4_096]).unwrap(),
        );
        assert_eq!(
            metrics.udp_session_queue_byte_drops.load(Ordering::Relaxed),
            1
        );
        assert_eq!(manager.queued_payload_snapshot()["currentBytes"], 0);
        drop(registration);
        assert_eq!(metrics.active_udp_sessions.load(Ordering::Relaxed), 0);
        assert_eq!(manager.quarantine_len(), 1);
    }

    #[test]
    fn udp_session_manager_drops_unknown_ids_and_closes_receivers() {
        let metrics = Arc::new(Hysteria2OwnerRegistryMetrics::default());
        let manager = Hysteria2UdpSessionManager::new(
            OwnerGeneration::new(7),
            udp_test_resources(2, 1),
            Arc::clone(&metrics),
        );
        let (session_id, mut receiver, registration) = manager.register().unwrap();
        let unknown = session_id.wrapping_add(1).max(1);
        manager.dispatch(Hysteria2UdpMessage::new(unknown, "192.0.2.3:53", b"unknown").unwrap());
        assert_eq!(metrics.unknown_udp_sessions.load(Ordering::Relaxed), 1);
        manager.close();
        assert!(matches!(
            receiver.try_recv(),
            Err(mpsc::error::TryRecvError::Disconnected)
        ));
        assert_eq!(metrics.active_udp_sessions.load(Ordering::Relaxed), 0);
        drop(registration);
        assert_eq!(metrics.active_udp_sessions.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn udp_session_ids_skip_collisions_quarantine_and_wrap_without_zero() {
        let metrics = Arc::new(Hysteria2OwnerRegistryMetrics::default());
        let manager = Hysteria2UdpSessionManager::new(
            OwnerGeneration::new(7),
            udp_test_resources(3, 1),
            Arc::clone(&metrics),
        );
        manager.state.lock().unwrap().next_session_id = u32::MAX;
        let (wrapped_id, _wrapped_rx, wrapped_registration) = manager.register().unwrap();
        assert_eq!(wrapped_id, 1);
        manager.state.lock().unwrap().next_session_id = u32::MAX;
        let (collision_id, _collision_rx, collision_registration) = manager.register().unwrap();
        assert_eq!(collision_id, 2);
        drop(wrapped_registration);
        assert!(manager.state.lock().unwrap().quarantine.contains_key(&1));
        manager.state.lock().unwrap().next_session_id = u32::MAX;
        let (quarantine_id, _quarantine_rx, quarantine_registration) = manager.register().unwrap();
        assert_eq!(quarantine_id, 3);
        manager.dispatch(Hysteria2UdpMessage::new(1, "192.0.2.4:53", b"late").unwrap());
        assert_eq!(metrics.late_udp_sessions.load(Ordering::Relaxed), 1);
        drop(collision_registration);
        drop(quarantine_registration);
        assert_eq!(metrics.active_udp_sessions.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn empty_registry_runtime_is_owned_and_joinable() {
        let stop = ResidentStopSignal::shared();
        let (handle, thread) = start_hysteria2_owner_registry(
            9_901,
            Arc::clone(&stop),
            RESIDENT_TCP_FLOW_STACK_BYTES_DEFAULT,
        )
        .unwrap();
        let snapshot = handle.metrics_snapshot();
        assert_eq!(snapshot["generation"], 9_901);
        assert_eq!(snapshot["activeOwners"], 0);
        stop.store(true, Ordering::Relaxed);
        thread.join().unwrap();
        let snapshot = handle.metrics_snapshot();
        assert_eq!(snapshot["draining"], true);
        assert_eq!(snapshot["activeOwners"], 0);
        assert_eq!(snapshot["activeLogicalLeases"], 0);
    }

    #[test]
    fn daemon_hysteria2_consumers_receive_the_generation_owner_handle() {
        let consumers = [
            include_str!("../tcp/accept_loop.rs"),
            include_str!("../tcp/proxy_fetch.rs"),
            include_str!("../udp/session_actor.rs"),
            include_str!("../udp/proxy_dns_forwarder.rs"),
            include_str!("health_scheduler.rs"),
            include_str!("../probe/native_tcp/quic_stream.rs"),
            include_str!("../subscription_fetch.rs"),
        ];
        for source in consumers {
            assert!(
                source.contains("hysteria2_owner_registry"),
                "every production Hysteria2 consumer must receive an explicit owner registry"
            );
        }
        assert!(
            include_str!("../udp/session_executor/quic.rs").contains("Hysteria2UdpSessionLease")
        );
        assert!(
            include_str!("../tcp/proxy_dispatch/quic_handlers.rs")
                .contains("Hysteria2OwnerRegistryHandle")
        );
    }
}

#[cfg(test)]
#[path = "hysteria2_owner_live_tests.rs"]
mod live_tests;
