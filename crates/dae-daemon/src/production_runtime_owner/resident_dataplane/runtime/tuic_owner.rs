use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Instant;

use bytes::Bytes;
use dae_outbound::tuic::{
    TUIC_MAX_UDP_STREAM_FRAME_LEN, TuicAuthReport, TuicUdpPacket, TuicUdpRelayMode,
    authenticate_tuic_connection, build_tuic_dissociate_frame, build_tuic_heartbeat_frame,
    decode_tuic_udp_packet, decode_tuic_udp_stream_packet,
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

use super::*;
use crate::production_runtime_owner::resident_dataplane::plan::{
    ResidentProxyBinding, ResidentProxyProtocolPlan,
};
use crate::production_runtime_owner::resident_dataplane::tcp::{
    ObservedQuicEndpoint, QuicEndpointCallerClass, QuicEndpointDrainReport,
    ResidentConnectedQuicEndpoint, open_tuic_quic_connection_candidates_async,
    wait_quic_endpoint_idle_after_close, wait_quic_endpoints_idle_until,
};

const TUIC_OWNER_IDENTITY_DOMAIN: &[u8] = b"dae/tuic-owner/v1";
const TUIC_OWNER_IDENTITY_NAMESPACE: &str = "tuic-transport";
const TUIC_CONTROL_STREAM_ERROR_CODE: u32 = 0x104;
const TUIC_UDP_STREAM_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(8);

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
struct TuicOwnerKey {
    generation: OwnerGeneration,
    digest: [u8; 32],
}

impl std::fmt::Debug for TuicOwnerKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TuicOwnerKey")
            .field("generation", &self.generation)
            .field("digest", &"<redacted>")
            .finish()
    }
}

impl TuicOwnerKey {
    fn for_binding(binding: &ResidentProxyBinding) -> Self {
        let proxy = binding.plan();
        let generation = binding.runtime_generation();
        let ResidentProxyProtocolPlan::TuicQuicTcp {
            congestion,
            udp_relay_mode,
            ..
        } = &proxy.handler
        else {
            panic!("TUIC owner key received a non-TUIC proxy shape");
        };
        let mut digest = Sha256::new();
        digest.update(TUIC_OWNER_IDENTITY_DOMAIN);
        update_identity_part(&mut digest, proxy.graph_link_hash.as_bytes());
        update_identity_part(&mut digest, &binding.effective_socket_mark().to_be_bytes());
        update_identity_part(&mut digest, congestion.as_str().as_bytes());
        update_identity_part(&mut digest, udp_relay_mode.as_str().as_bytes());
        Self {
            generation,
            digest: digest.finalize().into(),
        }
    }

    fn redacted_identity(self) -> RedactedOwnerIdentity {
        RedactedOwnerIdentity::new(TUIC_OWNER_IDENTITY_NAMESPACE, self.digest)
            .expect("static TUIC owner identity namespace is valid")
    }
}

fn update_identity_part(digest: &mut Sha256, value: &[u8]) {
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value);
}

type TuicOwnerCell = SingleFlightPhysicalOwner<TuicSharedTransport>;

struct TuicOwnerIndex {
    cells: HashMap<TuicOwnerKey, Arc<TuicOwnerCell>>,
    draining: bool,
}

impl TuicOwnerIndex {
    fn new() -> Self {
        Self {
            cells: HashMap::new(),
            draining: false,
        }
    }
}

#[derive(Default)]
struct TuicOwnerRegistryMetrics {
    active_owners: AtomicUsize,
    high_water_owners: AtomicUsize,
    active_leases: AtomicUsize,
    high_water_leases: AtomicUsize,
    active_udp_associations: AtomicUsize,
    high_water_udp_associations: AtomicUsize,
    active_association_quarantine: AtomicUsize,
    high_water_association_quarantine: AtomicUsize,
    current_udp_queued_bytes: AtomicUsize,
    high_water_udp_queued_bytes: AtomicUsize,
    cumulative_builds: AtomicU64,
    cumulative_build_failures: AtomicU64,
    cumulative_reuses: AtomicU64,
    cumulative_udp_datagrams: AtomicU64,
    cumulative_udp_stream_packets: AtomicU64,
    malformed_udp_datagrams: AtomicU64,
    malformed_udp_streams: AtomicU64,
    unknown_udp_associations: AtomicU64,
    late_udp_associations: AtomicU64,
    association_limit_rejections: AtomicU64,
    association_queue_drops: AtomicU64,
    association_queue_byte_drops: AtomicU64,
    owner_limit_rejections: AtomicU64,
    command_queue_rejections: AtomicU64,
    logical_lease_rejections: AtomicU64,
    dissociate_commands: AtomicU64,
    dissociate_failures: AtomicU64,
    heartbeat_commands: AtomicU64,
    heartbeat_failures: AtomicU64,
    shutdown_timed_out: AtomicBool,
    endpoint_drain_requested: AtomicUsize,
    endpoint_drain_completed: AtomicUsize,
    endpoint_drain_timed_out: AtomicUsize,
}

impl TuicOwnerRegistryMetrics {
    fn owner_opened(&self) {
        let active = self.active_owners.fetch_add(1, Ordering::Relaxed) + 1;
        update_high_water(&self.high_water_owners, active);
    }

    fn owner_closed(&self) {
        subtract_active(&self.active_owners);
    }

    fn lease_opened(&self) {
        let active = self.active_leases.fetch_add(1, Ordering::Relaxed) + 1;
        update_high_water(&self.high_water_leases, active);
    }

    fn lease_closed(&self) {
        subtract_active(&self.active_leases);
    }

    fn association_opened(&self) {
        let active = self.active_udp_associations.fetch_add(1, Ordering::Relaxed) + 1;
        update_high_water(&self.high_water_udp_associations, active);
    }

    fn association_closed(&self) {
        subtract_active(&self.active_udp_associations);
    }

    fn quarantine_added(&self) {
        let active = self
            .active_association_quarantine
            .fetch_add(1, Ordering::Relaxed)
            + 1;
        update_high_water(&self.high_water_association_quarantine, active);
    }

    fn quarantine_released(&self, count: usize) {
        subtract_count(&self.active_association_quarantine, count);
    }

    fn queued_bytes_added(&self, bytes: usize) {
        let active = self
            .current_udp_queued_bytes
            .fetch_add(bytes, Ordering::Relaxed)
            .saturating_add(bytes);
        update_high_water(&self.high_water_udp_queued_bytes, active);
    }

    fn queued_bytes_released(&self, bytes: usize) {
        subtract_count(&self.current_udp_queued_bytes, bytes);
    }

    fn begin_endpoint_drain(&self, requested: usize) {
        self.endpoint_drain_requested
            .store(requested, Ordering::Release);
        self.endpoint_drain_completed.store(0, Ordering::Release);
        self.endpoint_drain_timed_out.store(0, Ordering::Release);
    }

    fn finish_endpoint_drain(&self, report: QuicEndpointDrainReport) {
        self.endpoint_drain_requested
            .store(report.requested(), Ordering::Release);
        self.endpoint_drain_completed
            .store(report.completed(), Ordering::Release);
        self.endpoint_drain_timed_out
            .store(report.timed_out(), Ordering::Release);
        if !report.is_complete() {
            self.shutdown_timed_out.store(true, Ordering::Release);
        }
    }
}

struct TuicRegistryOwnershipReconciler {
    metrics: Arc<TuicOwnerRegistryMetrics>,
    index: Arc<Mutex<TuicOwnerIndex>>,
    shutdown_finished: bool,
}

impl TuicRegistryOwnershipReconciler {
    fn new(metrics: Arc<TuicOwnerRegistryMetrics>, index: Arc<Mutex<TuicOwnerIndex>>) -> Self {
        Self {
            metrics,
            index,
            shutdown_finished: false,
        }
    }

    fn finish_shutdown(&mut self) {
        self.shutdown_finished = true;
    }
}

impl Drop for TuicRegistryOwnershipReconciler {
    fn drop(&mut self) {
        let cells = {
            let mut index = self
                .index
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            index.draining = true;
            index
                .cells
                .drain()
                .map(|(_, cell)| cell)
                .collect::<Vec<_>>()
        };
        for cell in cells {
            cell.begin_drain(OwnerDrainReason::Shutdown);
            cell.close();
        }
        self.metrics.active_owners.store(0, Ordering::Release);
        if !self.shutdown_finished {
            self.metrics
                .shutdown_timed_out
                .store(true, Ordering::Release);
        }
    }
}

struct TuicEndpointDrainGuard {
    metrics: Arc<TuicOwnerRegistryMetrics>,
    requested: usize,
    finished: bool,
}

impl TuicEndpointDrainGuard {
    fn new(metrics: Arc<TuicOwnerRegistryMetrics>, requested: usize) -> Self {
        metrics.begin_endpoint_drain(requested);
        Self {
            metrics,
            requested,
            finished: false,
        }
    }

    fn finish(mut self, report: QuicEndpointDrainReport) {
        self.metrics.finish_endpoint_drain(report);
        self.finished = true;
    }
}

impl Drop for TuicEndpointDrainGuard {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        self.metrics
            .endpoint_drain_timed_out
            .store(self.requested, Ordering::Release);
        self.metrics
            .shutdown_timed_out
            .store(true, Ordering::Release);
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
    let _ = active.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
        Some(value.saturating_sub(1))
    });
}

fn subtract_count(active: &AtomicUsize, count: usize) {
    let _ = active.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
        Some(value.saturating_sub(count))
    });
}

struct TuicLogicalLeaseAdmission {
    limit: usize,
    active: AtomicUsize,
    metrics: Arc<TuicOwnerRegistryMetrics>,
}

impl TuicLogicalLeaseAdmission {
    fn new(limit: usize, metrics: Arc<TuicOwnerRegistryMetrics>) -> Self {
        Self {
            limit,
            active: AtomicUsize::new(0),
            metrics,
        }
    }

    fn reserve(self: &Arc<Self>) -> Result<TuicLogicalLeaseReservation, String> {
        let mut current = self.active.load(Ordering::Acquire);
        loop {
            if current >= self.limit {
                self.metrics
                    .logical_lease_rejections
                    .fetch_add(1, Ordering::Relaxed);
                return Err(format!(
                    "TUIC logical lease budget is full ({})",
                    self.limit
                ));
            }
            match self.active.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    self.metrics.lease_opened();
                    return Ok(TuicLogicalLeaseReservation {
                        admission: Arc::clone(self),
                    });
                }
                Err(observed) => current = observed,
            }
        }
    }

    fn active(&self) -> usize {
        self.active.load(Ordering::Acquire)
    }
}

struct TuicLogicalLeaseReservation {
    admission: Arc<TuicLogicalLeaseAdmission>,
}

impl Drop for TuicLogicalLeaseReservation {
    fn drop(&mut self) {
        subtract_active(&self.admission.active);
        self.admission.metrics.lease_closed();
    }
}

struct TuicAssociationState {
    sessions: HashMap<u16, TuicAssociationQueue>,
    quarantine: HashMap<u16, Instant>,
    next_id: u16,
}

struct TuicAssociationQueue {
    sender: mpsc::Sender<TuicQueuedUdpPacket>,
    queued_bytes: Arc<AtomicUsize>,
}

struct TuicQueuedUdpPacket {
    packet: Option<TuicUdpPacket>,
    bytes: usize,
    session_queued_bytes: Arc<AtomicUsize>,
    metrics: Arc<TuicOwnerRegistryMetrics>,
}

impl TuicQueuedUdpPacket {
    fn into_packet(mut self) -> TuicUdpPacket {
        self.packet
            .take()
            .expect("queued TUIC UDP packet is present until consumed")
    }
}

impl Drop for TuicQueuedUdpPacket {
    fn drop(&mut self) {
        subtract_count(&self.session_queued_bytes, self.bytes);
        self.metrics.queued_bytes_released(self.bytes);
    }
}

struct TuicAssociationManager {
    state: Mutex<TuicAssociationState>,
    resources: TuicOwnerResourceProfile,
    metrics: Arc<TuicOwnerRegistryMetrics>,
    control_sender: mpsc::Sender<u16>,
    connection: quinn::Connection,
    closed: AtomicBool,
}

impl TuicAssociationManager {
    fn new(
        resources: TuicOwnerResourceProfile,
        metrics: Arc<TuicOwnerRegistryMetrics>,
        control_sender: mpsc::Sender<u16>,
        connection: quinn::Connection,
    ) -> Self {
        Self {
            state: Mutex::new(TuicAssociationState {
                sessions: HashMap::new(),
                quarantine: HashMap::new(),
                next_id: fastrand::u16(1..=u16::MAX),
            }),
            resources,
            metrics,
            control_sender,
            connection,
            closed: AtomicBool::new(false),
        }
    }

    fn register(
        self: &Arc<Self>,
    ) -> Result<
        (
            u16,
            mpsc::Receiver<TuicQueuedUdpPacket>,
            TuicAssociationRegistration,
        ),
        String,
    > {
        if self.closed.load(Ordering::Acquire) {
            return Err("TUIC association manager is closed".to_owned());
        }
        let now = Instant::now();
        let mut state = self.state.lock().unwrap();
        self.purge_quarantine(&mut state, now);
        if state.sessions.len() >= self.resources.udp_association_limit() {
            self.metrics
                .association_limit_rejections
                .fetch_add(1, Ordering::Relaxed);
            return Err(format!(
                "TUIC UDP association budget is full ({})",
                self.resources.udp_association_limit()
            ));
        }
        let association_id = allocate_association_id(&mut state)?;
        let (sender, receiver) = mpsc::channel(self.resources.udp_association_queue_depth().max(1));
        state.sessions.insert(
            association_id,
            TuicAssociationQueue {
                sender,
                queued_bytes: Arc::new(AtomicUsize::new(0)),
            },
        );
        drop(state);
        self.metrics.association_opened();
        Ok((
            association_id,
            receiver,
            TuicAssociationRegistration {
                manager: Some(Arc::clone(self)),
                association_id,
            },
        ))
    }

    fn dispatch(&self, packet: TuicUdpPacket, mode: TuicUdpRelayMode) {
        if self.closed.load(Ordering::Acquire) {
            return;
        }
        match mode {
            TuicUdpRelayMode::Native => &self.metrics.cumulative_udp_datagrams,
            TuicUdpRelayMode::Quic => &self.metrics.cumulative_udp_stream_packets,
        }
        .fetch_add(1, Ordering::Relaxed);
        let association_id = packet.association_id();
        let bytes = packet.payload().len();
        let now = Instant::now();
        let queue = {
            let mut state = self.state.lock().unwrap();
            self.purge_quarantine(&mut state, now);
            let Some(queue) = state.sessions.get(&association_id) else {
                if state.quarantine.contains_key(&association_id) {
                    self.metrics
                        .late_udp_associations
                        .fetch_add(1, Ordering::Relaxed);
                } else {
                    self.metrics
                        .unknown_udp_associations
                        .fetch_add(1, Ordering::Relaxed);
                }
                return;
            };
            TuicAssociationQueue {
                sender: queue.sender.clone(),
                queued_bytes: Arc::clone(&queue.queued_bytes),
            }
        };
        if !reserve_queued_bytes(
            &queue.queued_bytes,
            bytes,
            self.resources.udp_association_queue_bytes(),
        ) {
            self.metrics
                .association_queue_byte_drops
                .fetch_add(1, Ordering::Relaxed);
            return;
        }
        let owner_bytes = self
            .metrics
            .current_udp_queued_bytes
            .load(Ordering::Acquire);
        if owner_bytes
            .checked_add(bytes)
            .is_none_or(|next| next > self.resources.udp_owner_queue_bytes())
        {
            subtract_count(&queue.queued_bytes, bytes);
            self.metrics
                .association_queue_byte_drops
                .fetch_add(1, Ordering::Relaxed);
            return;
        }
        self.metrics.queued_bytes_added(bytes);
        let queued = TuicQueuedUdpPacket {
            packet: Some(packet),
            bytes,
            session_queued_bytes: Arc::clone(&queue.queued_bytes),
            metrics: Arc::clone(&self.metrics),
        };
        if queue.sender.try_send(queued).is_err() {
            self.metrics
                .association_queue_drops
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    fn remove_association(&self, association_id: u16) {
        let now = Instant::now();
        let removed = {
            let mut state = self.state.lock().unwrap();
            self.purge_quarantine(&mut state, now);
            let removed = state.sessions.remove(&association_id).is_some();
            if removed {
                self.insert_quarantine(&mut state, association_id, now);
            }
            removed
        };
        if !removed {
            return;
        }
        self.metrics.association_closed();
        if self.control_sender.try_send(association_id).is_err() {
            self.metrics
                .dissociate_failures
                .fetch_add(1, Ordering::Relaxed);
            self.connection.close(
                TUIC_CONTROL_STREAM_ERROR_CODE.into(),
                b"tuic dissociate queue unavailable",
            );
        }
    }

    fn insert_quarantine(
        &self,
        state: &mut TuicAssociationState,
        association_id: u16,
        now: Instant,
    ) {
        while !state.quarantine.contains_key(&association_id)
            && state.quarantine.len() >= self.resources.association_quarantine_limit()
        {
            let oldest = state
                .quarantine
                .iter()
                .min_by_key(|(_, expires_at)| **expires_at)
                .map(|(association_id, _)| *association_id);
            let Some(oldest) = oldest else {
                break;
            };
            state.quarantine.remove(&oldest);
            self.metrics.quarantine_released(1);
        }
        let expires_at = now
            .checked_add(self.resources.association_quarantine_ttl())
            .unwrap_or(now);
        if state
            .quarantine
            .insert(association_id, expires_at)
            .is_none()
        {
            self.metrics.quarantine_added();
        }
    }

    fn purge_quarantine(&self, state: &mut TuicAssociationState, now: Instant) {
        let before = state.quarantine.len();
        state.quarantine.retain(|_, expires_at| *expires_at > now);
        self.metrics
            .quarantine_released(before.saturating_sub(state.quarantine.len()));
    }

    fn active_associations(&self) -> usize {
        self.state.lock().unwrap().sessions.len()
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    fn close(&self) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        let (sessions, quarantine) = {
            let mut state = self.state.lock().unwrap();
            let sessions = state.sessions.len();
            let quarantine = state.quarantine.len();
            state.sessions.clear();
            state.quarantine.clear();
            (sessions, quarantine)
        };
        subtract_count(&self.metrics.active_udp_associations, sessions);
        self.metrics.quarantine_released(quarantine);
    }
}

fn allocate_association_id(state: &mut TuicAssociationState) -> Result<u16, String> {
    for _ in 0..u16::MAX {
        let candidate = state.next_id.max(1);
        state.next_id = candidate.wrapping_add(1).max(1);
        if !state.sessions.contains_key(&candidate) && !state.quarantine.contains_key(&candidate) {
            return Ok(candidate);
        }
    }
    Err("TUIC UDP association ID space is exhausted".to_owned())
}

fn reserve_queued_bytes(active: &AtomicUsize, bytes: usize, limit: usize) -> bool {
    let mut current = active.load(Ordering::Acquire);
    loop {
        let Some(next) = current.checked_add(bytes) else {
            return false;
        };
        if next > limit {
            return false;
        }
        match active.compare_exchange_weak(current, next, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return true,
            Err(observed) => current = observed,
        }
    }
}

struct TuicAssociationRegistration {
    manager: Option<Arc<TuicAssociationManager>>,
    association_id: u16,
}

impl Drop for TuicAssociationRegistration {
    fn drop(&mut self) {
        if let Some(manager) = self.manager.take() {
            manager.remove_association(self.association_id);
        }
    }
}

pub(crate) struct TuicSharedTransport {
    instance_id: u64,
    _identity: RedactedOwnerIdentity,
    remote: SocketAddr,
    endpoint: ObservedQuicEndpoint,
    connection: quinn::Connection,
    auth_report: TuicAuthReport,
    congestion: dae_outbound::tuic::TuicCongestionController,
    udp_relay_mode: TuicUdpRelayMode,
    leases: Arc<TuicLogicalLeaseAdmission>,
    udp_associations: Arc<TuicAssociationManager>,
}

impl TuicSharedTransport {
    fn try_lease(self: &Arc<Self>) -> Result<TuicTransportLease, String> {
        if self.connection.close_reason().is_some() {
            return Err("TUIC shared transport is closed".to_owned());
        }
        let reservation = self.leases.reserve()?;
        Ok(TuicTransportLease {
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

    pub(crate) fn auth_report(&self) -> &TuicAuthReport {
        &self.auth_report
    }

    pub(crate) fn congestion(&self) -> dae_outbound::tuic::TuicCongestionController {
        self.congestion
    }

    pub(crate) fn udp_relay_mode(&self) -> TuicUdpRelayMode {
        self.udp_relay_mode
    }

    fn begin_close(&self) -> ObservedQuicEndpoint {
        self.udp_associations.close();
        self.connection
            .close(0_u32.into(), b"resident tuic owner draining");
        self.endpoint
            .close(0_u32.into(), b"resident tuic owner draining");
        self.endpoint.clone()
    }
}

impl Drop for TuicSharedTransport {
    fn drop(&mut self) {
        self.udp_associations.close();
        self.connection
            .close(0_u32.into(), b"resident tuic owner released");
        self.endpoint
            .close(0_u32.into(), b"resident tuic owner released");
    }
}

pub(crate) struct TuicTransportLease {
    transport: Arc<TuicSharedTransport>,
    _reservation: TuicLogicalLeaseReservation,
}

impl TuicTransportLease {
    pub(crate) fn connection(&self) -> &quinn::Connection {
        self.transport.connection()
    }

    pub(crate) fn udp_relay_mode(&self) -> TuicUdpRelayMode {
        self.transport.udp_relay_mode()
    }

    pub(crate) fn remote(&self) -> SocketAddr {
        self.transport.remote()
    }

    pub(crate) fn auth_report(&self) -> &TuicAuthReport {
        self.transport.auth_report()
    }

    pub(crate) fn congestion(&self) -> dae_outbound::tuic::TuicCongestionController {
        self.transport.congestion()
    }

    pub(crate) fn open_udp_association(self) -> Result<TuicUdpAssociationLease, String> {
        let manager = Arc::clone(&self.transport.udp_associations);
        let (association_id, receiver, registration) = manager.register()?;
        Ok(TuicUdpAssociationLease {
            transport: self,
            association_id,
            receiver,
            manager,
            _registration: registration,
        })
    }
}

pub(crate) struct TuicUdpAssociationLease {
    transport: TuicTransportLease,
    association_id: u16,
    receiver: mpsc::Receiver<TuicQueuedUdpPacket>,
    manager: Arc<TuicAssociationManager>,
    _registration: TuicAssociationRegistration,
}

impl TuicUdpAssociationLease {
    pub(crate) fn association_id(&self) -> u16 {
        self.association_id
    }

    pub(crate) fn connection(&self) -> &quinn::Connection {
        self.transport.connection()
    }

    pub(crate) fn udp_relay_mode(&self) -> TuicUdpRelayMode {
        self.transport.udp_relay_mode()
    }

    pub(crate) fn try_receive(&mut self) -> Result<Option<TuicUdpPacket>, String> {
        if self.manager.is_closed() {
            return Err("TUIC UDP transport owner is closed".to_owned());
        }
        match self.receiver.try_recv() {
            Ok(packet) => Ok(Some(packet.into_packet())),
            Err(mpsc::error::TryRecvError::Empty) => Ok(None),
            Err(mpsc::error::TryRecvError::Disconnected) => {
                Err("TUIC UDP transport owner is closed".to_owned())
            }
        }
    }

    pub(crate) async fn receive_until(
        &mut self,
        expiration: Option<Instant>,
    ) -> Result<Option<TuicUdpPacket>, String> {
        if self.manager.is_closed() {
            return Err("TUIC UDP transport owner is closed".to_owned());
        }
        let Some(expiration) = expiration else {
            return self
                .receiver
                .recv()
                .await
                .map(TuicQueuedUdpPacket::into_packet)
                .map(Some)
                .ok_or_else(|| "TUIC UDP transport owner is closed".to_owned());
        };
        tokio::select! {
            packet = self.receiver.recv() => packet
                .map(TuicQueuedUdpPacket::into_packet)
                .map(Some)
                .ok_or_else(|| "TUIC UDP transport owner is closed".to_owned()),
            _ = time::sleep_until(time::Instant::from_std(expiration)) => Ok(None),
        }
    }
}

struct TuicOwnedTransport {
    shared: Arc<TuicSharedTransport>,
    cell: Arc<TuicOwnerCell>,
    control_receiver: Option<mpsc::Receiver<u16>>,
}

struct TuicBuildCommand {
    key: TuicOwnerKey,
    cell: Arc<TuicOwnerCell>,
    builder: SingleFlightBuilder<TuicSharedTransport>,
    binding: ResidentProxyBinding,
    caller: QuicEndpointCallerClass,
    deadline: AbsoluteDeadline,
    response: oneshot::Sender<Result<Arc<TuicSharedTransport>, String>>,
}

enum TuicOwnerCommand {
    Build(TuicBuildCommand),
}

struct TuicBuildCompletion {
    key: TuicOwnerKey,
    owner: Option<TuicOwnedTransport>,
}

enum TuicTransportEvent {
    Closed { key: TuicOwnerKey, instance_id: u64 },
    ControlStopped { key: TuicOwnerKey, instance_id: u64 },
}

enum TuicRegistryTaskCompletion {
    Build(TuicBuildCompletion),
    Transport(TuicTransportEvent),
}

#[derive(Clone)]
pub(crate) struct TuicOwnerRegistryHandle {
    generation: OwnerGeneration,
    sender: mpsc::Sender<TuicOwnerCommand>,
    index: Arc<Mutex<TuicOwnerIndex>>,
    cancellation: OwnerCancellationSignal,
    resources: TuicOwnerResourceProfile,
    metrics: Arc<TuicOwnerRegistryMetrics>,
}

impl TuicOwnerRegistryHandle {
    pub(crate) async fn acquire(
        &self,
        binding: ResidentProxyBinding,
        caller: QuicEndpointCallerClass,
        deadline: AbsoluteDeadline,
    ) -> Result<TuicTransportLease, String> {
        let key = TuicOwnerKey::for_binding(&binding);
        if key.generation != self.generation {
            return Err(format!(
                "TUIC owner generation mismatch: requested={} active={}",
                key.generation.get(),
                self.generation.get()
            ));
        }
        let cell = {
            let mut index = self.index.lock().unwrap();
            if index.draining {
                return Err("TUIC owner registry is draining".to_owned());
            }
            if let Some(cell) = index.cells.get(&key) {
                Arc::clone(cell)
            } else {
                if index.cells.len() >= self.resources.owner_limit() {
                    self.metrics
                        .owner_limit_rejections
                        .fetch_add(1, Ordering::Relaxed);
                    return Err(format!(
                        "TUIC owner budget is full ({})",
                        self.resources.owner_limit()
                    ));
                }
                let cell = Arc::new(TuicOwnerCell::new());
                index.cells.insert(key, Arc::clone(&cell));
                cell
            }
        };

        match cell
            .begin_or_observe(deadline, &self.cancellation)
            .map_err(tuic_single_flight_error)?
        {
            SingleFlightDecision::Ready(owner) => {
                self.metrics
                    .cumulative_reuses
                    .fetch_add(1, Ordering::Relaxed);
                owner.try_lease()
            }
            SingleFlightDecision::Observe(observer) => {
                let owner = observer.wait().await.map_err(tuic_single_flight_error)?;
                self.metrics
                    .cumulative_reuses
                    .fetch_add(1, Ordering::Relaxed);
                owner.try_lease()
            }
            SingleFlightDecision::Build(builder) => {
                let (response, receiver) = oneshot::channel();
                let command = TuicOwnerCommand::Build(TuicBuildCommand {
                    key,
                    cell: Arc::clone(&cell),
                    builder,
                    binding,
                    caller,
                    deadline,
                    response,
                });
                if let Err(err) = self.sender.try_send(command) {
                    self.metrics
                        .command_queue_rejections
                        .fetch_add(1, Ordering::Relaxed);
                    let TuicOwnerCommand::Build(command) = err.into_inner();
                    command.builder.publish_failed(PhysicalOwnerFailure::new(
                        OwnerFailureClass::Resource,
                        "tuic-owner-command-queue",
                    ));
                    let _ = cell.prepare_retry();
                    return Err("TUIC owner command queue is unavailable".to_owned());
                }
                let remaining = deadline
                    .remaining_at(Instant::now())
                    .ok_or_else(|| "TUIC owner acquisition deadline elapsed".to_owned())?;
                let owner = time::timeout(remaining, receiver)
                    .await
                    .map_err(|_| "TUIC owner acquisition timeout".to_owned())?
                    .map_err(|_| "TUIC owner runtime stopped during acquisition".to_owned())??;
                owner.try_lease()
            }
        }
    }

    pub(crate) fn metrics_snapshot(&self) -> Value {
        let index = self.index.lock().unwrap();
        json!({
            "schemaVersion": 1,
            "owner": "resident-tuic-owner-registry",
            "generation": self.generation.get(),
            "draining": index.draining,
            "registeredKeys": index.cells.len(),
            "activeOwners": self.metrics.active_owners.load(Ordering::Relaxed),
            "highWaterOwners": self.metrics.high_water_owners.load(Ordering::Relaxed),
            "activeLogicalLeases": self.metrics.active_leases.load(Ordering::Relaxed),
            "highWaterLogicalLeases": self.metrics.high_water_leases.load(Ordering::Relaxed),
            "activeUdpAssociations": self.metrics.active_udp_associations.load(Ordering::Relaxed),
            "highWaterUdpAssociations": self.metrics.high_water_udp_associations.load(Ordering::Relaxed),
            "activeAssociationQuarantine": self.metrics.active_association_quarantine.load(Ordering::Relaxed),
            "highWaterAssociationQuarantine": self.metrics.high_water_association_quarantine.load(Ordering::Relaxed),
            "currentUdpQueuedBytes": self.metrics.current_udp_queued_bytes.load(Ordering::Relaxed),
            "highWaterUdpQueuedBytes": self.metrics.high_water_udp_queued_bytes.load(Ordering::Relaxed),
            "cumulativeBuilds": self.metrics.cumulative_builds.load(Ordering::Relaxed),
            "cumulativeBuildFailures": self.metrics.cumulative_build_failures.load(Ordering::Relaxed),
            "cumulativeReuses": self.metrics.cumulative_reuses.load(Ordering::Relaxed),
            "cumulativeUdpDatagrams": self.metrics.cumulative_udp_datagrams.load(Ordering::Relaxed),
            "cumulativeUdpStreamPackets": self.metrics.cumulative_udp_stream_packets.load(Ordering::Relaxed),
            "malformedUdpDatagrams": self.metrics.malformed_udp_datagrams.load(Ordering::Relaxed),
            "malformedUdpStreams": self.metrics.malformed_udp_streams.load(Ordering::Relaxed),
            "unknownUdpAssociations": self.metrics.unknown_udp_associations.load(Ordering::Relaxed),
            "lateUdpAssociations": self.metrics.late_udp_associations.load(Ordering::Relaxed),
            "associationLimitRejections": self.metrics.association_limit_rejections.load(Ordering::Relaxed),
            "associationQueueDrops": self.metrics.association_queue_drops.load(Ordering::Relaxed),
            "associationQueueByteDrops": self.metrics.association_queue_byte_drops.load(Ordering::Relaxed),
            "ownerLimitRejections": self.metrics.owner_limit_rejections.load(Ordering::Relaxed),
            "commandQueueRejections": self.metrics.command_queue_rejections.load(Ordering::Relaxed),
            "logicalLeaseRejections": self.metrics.logical_lease_rejections.load(Ordering::Relaxed),
            "dissociateCommands": self.metrics.dissociate_commands.load(Ordering::Relaxed),
            "dissociateFailures": self.metrics.dissociate_failures.load(Ordering::Relaxed),
            "heartbeatCommands": self.metrics.heartbeat_commands.load(Ordering::Relaxed),
            "heartbeatFailures": self.metrics.heartbeat_failures.load(Ordering::Relaxed),
            "registryOwnershipReleased": self.metrics.active_owners.load(Ordering::Acquire) == 0,
            "endpointDrain": {
                "requested": self.metrics.endpoint_drain_requested.load(Ordering::Acquire),
                "completed": self.metrics.endpoint_drain_completed.load(Ordering::Acquire),
                "timedOut": self.metrics.endpoint_drain_timed_out.load(Ordering::Acquire),
            },
            "shutdownTimedOut": self.metrics.shutdown_timed_out.load(Ordering::Relaxed),
            "budget": {
                "owners": self.resources.owner_limit(),
                "commandQueueDepth": self.resources.command_queue_depth(),
                "logicalLeasesPerOwner": self.resources.logical_lease_limit(),
                "udpAssociationsPerOwner": self.resources.udp_association_limit(),
                "udpAssociationQueueDepth": self.resources.udp_association_queue_depth(),
                "udpAssociationQueueBytes": self.resources.udp_association_queue_bytes(),
                "udpOwnerQueueBytes": self.resources.udp_owner_queue_bytes(),
                "associationQuarantineLimit": self.resources.association_quarantine_limit(),
                "associationQuarantineTtlMs": self.resources.association_quarantine_ttl().as_millis(),
                "retryCooldownMs": self.resources.retry_cooldown().as_millis(),
            },
        })
    }
}

fn tuic_single_flight_error(error: SingleFlightError) -> String {
    match error {
        SingleFlightError::Cancelled(reason) => {
            format!("TUIC owner acquisition cancelled: {reason:?}")
        }
        SingleFlightError::Failed(failure) => format!(
            "TUIC owner construction failed: class={:?} operation={}",
            failure.class, failure.operation
        ),
        SingleFlightError::Draining(reason) => {
            format!("TUIC owner registry is draining: {reason:?}")
        }
        SingleFlightError::Closed => "TUIC owner registry is closed".to_owned(),
        SingleFlightError::Superseded => "TUIC owner construction was superseded".to_owned(),
        SingleFlightError::RetryUnavailable(state) => {
            format!("TUIC owner retry is unavailable from state {state:?}")
        }
    }
}

pub(crate) fn start_tuic_owner_registry(
    generation: u64,
    stop: SharedResidentStopSignal,
    stack_bytes: usize,
) -> Result<(TuicOwnerRegistryHandle, JoinHandle<()>), String> {
    start_tuic_owner_registry_with_resources(
        generation,
        stop,
        stack_bytes,
        TuicOwnerResourceProfile::selected(),
    )
}

pub(super) fn start_tuic_owner_registry_with_resources(
    generation: u64,
    stop: SharedResidentStopSignal,
    stack_bytes: usize,
    resources: TuicOwnerResourceProfile,
) -> Result<(TuicOwnerRegistryHandle, JoinHandle<()>), String> {
    let generation = OwnerGeneration::new(generation);
    let (sender, receiver) = mpsc::channel(resources.command_queue_depth().max(1));
    let index = Arc::new(Mutex::new(TuicOwnerIndex::new()));
    let cancellation = OwnerCancellationSignal::new();
    let metrics = Arc::new(TuicOwnerRegistryMetrics::default());
    let handle = TuicOwnerRegistryHandle {
        generation,
        sender,
        index: Arc::clone(&index),
        cancellation: cancellation.clone(),
        resources,
        metrics: Arc::clone(&metrics),
    };
    let (initialized, initialization) = std::sync::mpsc::sync_channel(1);
    let thread = std::thread::Builder::new()
        .name(format!("resident-tuic-owner-{}", generation.get()))
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
                    let _ = initialized.send(Err(format!("build TUIC owner Tokio runtime: {err}")));
                    return;
                }
            };
            runtime.block_on(run_tuic_owner_registry(
                receiver,
                index,
                cancellation,
                resources,
                metrics,
                stop,
            ));
        })
        .map_err(|err| format!("spawn TUIC owner runtime: {err}"))?;
    initialization
        .recv()
        .map_err(|_| "TUIC owner runtime stopped during initialization".to_owned())??;
    Ok((handle, thread))
}

pub(crate) fn start_tuic_owner_registry_on(
    runtime: &tokio::runtime::Handle,
    generation: u64,
    stop: SharedResidentStopSignal,
) -> (TuicOwnerRegistryHandle, tokio::task::JoinHandle<()>) {
    let generation = OwnerGeneration::new(generation);
    let resources = TuicOwnerResourceProfile::selected();
    let (sender, receiver) = mpsc::channel(resources.command_queue_depth().max(1));
    let index = Arc::new(Mutex::new(TuicOwnerIndex::new()));
    let cancellation = OwnerCancellationSignal::new();
    let metrics = Arc::new(TuicOwnerRegistryMetrics::default());
    let handle = TuicOwnerRegistryHandle {
        generation,
        sender,
        index: Arc::clone(&index),
        cancellation: cancellation.clone(),
        resources,
        metrics: Arc::clone(&metrics),
    };
    let task = runtime.spawn(run_tuic_owner_registry(
        receiver,
        index,
        cancellation,
        resources,
        metrics,
        stop,
    ));
    (handle, task)
}

async fn run_tuic_owner_registry(
    mut receiver: mpsc::Receiver<TuicOwnerCommand>,
    index: Arc<Mutex<TuicOwnerIndex>>,
    cancellation: OwnerCancellationSignal,
    resources: TuicOwnerResourceProfile,
    metrics: Arc<TuicOwnerRegistryMetrics>,
    stop: SharedResidentStopSignal,
) {
    let session_cache = cfg!(feature = "test-boringssl-quic")
        .then(dae_outbound::shared_transport::boring_quic::new_boring_quic_session_cache);
    let mut ownership_reconciler =
        TuicRegistryOwnershipReconciler::new(Arc::clone(&metrics), Arc::clone(&index));
    let mut tasks = JoinSet::new();
    let mut retirements = JoinSet::new();
    let mut owners = HashMap::<TuicOwnerKey, TuicOwnedTransport>::new();
    let mut stop_listener = stop.listener();
    loop {
        tokio::select! {
            _ = stop_listener.cancelled() => break,
            command = receiver.recv() => match command {
                Some(TuicOwnerCommand::Build(command)) => {
                    let metrics = Arc::clone(&metrics);
                    let session_cache = session_cache.clone();
                    tasks.spawn(async move {
                        TuicRegistryTaskCompletion::Build(
                            run_tuic_owner_build(command, resources, metrics, session_cache).await,
                        )
                    });
                }
                None => break,
            },
            completion = tasks.join_next(), if !tasks.is_empty() => {
                match completion {
                    Some(Ok(TuicRegistryTaskCompletion::Build(completion))) => {
                        if let Some(mut owner) = completion.owner {
                            let connection = owner.shared.connection.clone();
                            let instance_id = owner.shared.instance_id;
                            let udp_relay_mode = owner.shared.udp_relay_mode;
                            let udp_associations = Arc::clone(&owner.shared.udp_associations);
                            let reader_metrics = Arc::clone(&metrics);
                            let control_receiver = owner
                                .control_receiver
                                .take()
                                .expect("new TUIC owner has one control receiver");
                            let leases = Arc::clone(&owner.shared.leases);
                            let associations = Arc::clone(&owner.shared.udp_associations);
                            let control_metrics = Arc::clone(&metrics);
                            let previous = owners.insert(completion.key, owner);
                            metrics.owner_opened();
                            if let Some(previous) = previous {
                                enqueue_tuic_retirement(
                                    &mut retirements,
                                    previous,
                                    Arc::clone(&metrics),
                                    resources.owner_limit(),
                                )
                                .await;
                            }
                            let read_connection = connection.clone();
                            tasks.spawn(async move {
                                TuicRegistryTaskCompletion::Transport(
                                    run_tuic_transport_reader(
                                        completion.key,
                                        instance_id,
                                        read_connection,
                                        udp_associations,
                                        reader_metrics,
                                        udp_relay_mode,
                                        resources,
                                    )
                                    .await,
                                )
                            });
                            tasks.spawn(async move {
                                run_tuic_control_writer(
                                    connection,
                                    control_receiver,
                                    leases,
                                    associations,
                                    control_metrics,
                                )
                                .await;
                                TuicRegistryTaskCompletion::Transport(
                                    TuicTransportEvent::ControlStopped {
                                        key: completion.key,
                                        instance_id,
                                    },
                                )
                            });
                        }
                    }
                    Some(Ok(TuicRegistryTaskCompletion::Transport(
                        TuicTransportEvent::Closed { key, instance_id },
                    ))) => {
                        retire_tuic_owner(
                            &mut owners,
                            &index,
                            &metrics,
                            &mut retirements,
                            resources.owner_limit(),
                            key,
                            instance_id,
                        )
                        .await;
                    }
                    Some(Ok(TuicRegistryTaskCompletion::Transport(
                        TuicTransportEvent::ControlStopped { key, instance_id },
                    ))) => {
                        let unexpected = owners
                            .get(&key)
                            .is_some_and(|owner| {
                                owner.shared.instance_id == instance_id
                                    && !owner.shared.udp_associations.is_closed()
                            });
                        if unexpected {
                            retire_tuic_owner(
                                &mut owners,
                                &index,
                                &metrics,
                                &mut retirements,
                                resources.owner_limit(),
                                key,
                                instance_id,
                            )
                            .await;
                        }
                    }
                    Some(Err(_)) | None => {}
                }
            }
            retired = retirements.join_next(), if !retirements.is_empty() => {
                let _ = retired;
            }
        }
    }

    cancellation.cancel(dae_runtime_control::OwnerCancellation::GenerationDraining);
    receiver.close();
    let cells = {
        let mut index = index.lock().unwrap();
        index.draining = true;
        let cells = index.cells.values().cloned().collect::<Vec<_>>();
        index.cells.clear();
        cells
    };
    for cell in &cells {
        cell.begin_drain(OwnerDrainReason::Shutdown);
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    let mut endpoints = Vec::with_capacity(owners.len());
    for (_, owner) in owners.drain() {
        endpoints.push(owner.shared.begin_close());
        metrics.owner_closed();
    }
    for cell in cells {
        cell.close();
    }
    while retirements.join_next().await.is_some() {}
    let drain_guard = TuicEndpointDrainGuard::new(Arc::clone(&metrics), endpoints.len());
    let deadline = time::Instant::now() + RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE;
    let report = wait_quic_endpoints_idle_until(endpoints, deadline).await;
    drain_guard.finish(report);
    ownership_reconciler.finish_shutdown();
}

async fn retire_tuic_owner(
    owners: &mut HashMap<TuicOwnerKey, TuicOwnedTransport>,
    index: &Arc<Mutex<TuicOwnerIndex>>,
    metrics: &Arc<TuicOwnerRegistryMetrics>,
    retirements: &mut JoinSet<()>,
    retirement_limit: usize,
    key: TuicOwnerKey,
    instance_id: u64,
) {
    let is_current = owners
        .get(&key)
        .is_some_and(|owner| owner.shared.instance_id == instance_id);
    if !is_current {
        return;
    }
    let Some(owner) = owners.remove(&key) else {
        return;
    };
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
    enqueue_tuic_retirement(retirements, owner, Arc::clone(metrics), retirement_limit).await;
}

async fn enqueue_tuic_retirement(
    retirements: &mut JoinSet<()>,
    owner: TuicOwnedTransport,
    metrics: Arc<TuicOwnerRegistryMetrics>,
    limit: usize,
) {
    while retirements.len() >= limit.max(1) {
        let _ = retirements.join_next().await;
    }
    owner.cell.begin_drain(OwnerDrainReason::Fault);
    retirements.spawn(async move {
        let endpoint = owner.shared.begin_close();
        let _ = wait_quic_endpoint_idle_after_close(&endpoint).await;
        owner.cell.close();
        metrics.owner_closed();
    });
}

async fn run_tuic_transport_reader(
    key: TuicOwnerKey,
    instance_id: u64,
    connection: quinn::Connection,
    udp_associations: Arc<TuicAssociationManager>,
    metrics: Arc<TuicOwnerRegistryMetrics>,
    udp_relay_mode: TuicUdpRelayMode,
    resources: TuicOwnerResourceProfile,
) -> TuicTransportEvent {
    match udp_relay_mode {
        TuicUdpRelayMode::Native => {
            run_tuic_datagram_reader(&connection, &udp_associations, &metrics).await;
        }
        TuicUdpRelayMode::Quic => {
            run_tuic_udp_stream_reader(
                &connection,
                &udp_associations,
                &metrics,
                resources.udp_association_limit(),
            )
            .await;
        }
    }
    TuicTransportEvent::Closed { key, instance_id }
}

async fn run_tuic_datagram_reader(
    connection: &quinn::Connection,
    udp_associations: &TuicAssociationManager,
    metrics: &TuicOwnerRegistryMetrics,
) {
    while let Ok(datagram) = connection.read_datagram().await {
        match decode_tuic_udp_packet(&datagram) {
            Ok(packet) => udp_associations.dispatch(packet, TuicUdpRelayMode::Native),
            Err(_) => {
                metrics
                    .malformed_udp_datagrams
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

async fn run_tuic_udp_stream_reader(
    connection: &quinn::Connection,
    udp_associations: &TuicAssociationManager,
    metrics: &TuicOwnerRegistryMetrics,
    concurrent_stream_limit: usize,
) {
    let mut readers = JoinSet::new();
    let concurrent_stream_limit = concurrent_stream_limit.max(1);
    loop {
        tokio::select! {
            stream = connection.accept_uni(), if readers.len() < concurrent_stream_limit => {
                let Ok(mut stream) = stream else {
                    break;
                };
                readers.spawn(async move {
                    let frame = time::timeout(
                        TUIC_UDP_STREAM_READ_TIMEOUT,
                        stream.read_to_end(TUIC_MAX_UDP_STREAM_FRAME_LEN),
                    )
                    .await
                    .map_err(|_| ())?
                    .map_err(|_| ())?;
                    decode_tuic_udp_stream_packet(&frame).map_err(|_| ())
                });
            }
            completed = readers.join_next(), if !readers.is_empty() => {
                match completed {
                    Some(Ok(Ok(packet))) => {
                        udp_associations.dispatch(packet, TuicUdpRelayMode::Quic);
                    }
                    Some(_) => {
                        metrics.malformed_udp_streams.fetch_add(1, Ordering::Relaxed);
                    }
                    None => break,
                }
            }
            _ = connection.closed() => break,
        }
    }
    readers.abort_all();
    while readers.join_next().await.is_some() {}
}

async fn run_tuic_control_writer(
    connection: quinn::Connection,
    mut receiver: mpsc::Receiver<u16>,
    leases: Arc<TuicLogicalLeaseAdmission>,
    associations: Arc<TuicAssociationManager>,
    metrics: Arc<TuicOwnerRegistryMetrics>,
) {
    let heartbeat_interval =
        std::time::Duration::from_secs(dae_outbound::tuic::DEFAULT_TUIC_KEEPALIVE_SECS);
    let mut heartbeat = time::interval(heartbeat_interval);
    heartbeat.set_missed_tick_behavior(time::MissedTickBehavior::Delay);
    heartbeat.tick().await;
    loop {
        tokio::select! {
            association_id = receiver.recv() => {
                let Some(association_id) = association_id else {
                    break;
                };
                if send_tuic_dissociate(&connection, association_id).await.is_err() {
                    metrics.dissociate_failures.fetch_add(1, Ordering::Relaxed);
                    connection.close(
                        TUIC_CONTROL_STREAM_ERROR_CODE.into(),
                        b"tuic dissociate failed",
                    );
                    break;
                }
                metrics.dissociate_commands.fetch_add(1, Ordering::Relaxed);
            }
            _ = heartbeat.tick() => {
                if leases.active() == 0 && associations.active_associations() == 0 {
                    continue;
                }
                match connection.send_datagram(Bytes::copy_from_slice(&build_tuic_heartbeat_frame())) {
                    Ok(()) => {
                        metrics.heartbeat_commands.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(_) => {
                        metrics.heartbeat_failures.fetch_add(1, Ordering::Relaxed);
                        break;
                    }
                }
            }
            _ = connection.closed() => break,
        }
    }
}

async fn send_tuic_dissociate(
    connection: &quinn::Connection,
    association_id: u16,
) -> Result<(), String> {
    let write = async {
        let mut stream = connection
            .open_uni()
            .await
            .map_err(|err| format!("open TUIC dissociate stream: {err}"))?;
        stream
            .write_all(&build_tuic_dissociate_frame(association_id))
            .await
            .map_err(|err| format!("write TUIC dissociate stream: {err}"))?;
        stream
            .finish()
            .map_err(|err| format!("finish TUIC dissociate stream: {err}"))?;
        Ok::<(), String>(())
    };
    time::timeout(RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE, write)
        .await
        .map_err(|_| "TUIC dissociate stream deadline elapsed".to_owned())?
}

async fn run_tuic_owner_build(
    command: TuicBuildCommand,
    resources: TuicOwnerResourceProfile,
    metrics: Arc<TuicOwnerRegistryMetrics>,
    session_cache: Option<dae_outbound::shared_transport::boring_quic::BoringQuicSessionCache>,
) -> TuicBuildCompletion {
    metrics.cumulative_builds.fetch_add(1, Ordering::Relaxed);
    let result = build_tuic_transport(
        command.key,
        command.binding,
        command.caller,
        command.deadline,
        Arc::clone(&metrics),
        resources,
        session_cache,
    )
    .await;
    match result {
        Ok((transport, control_receiver)) => {
            let owner = command.builder.publish_ready(transport);
            match owner {
                Ok(shared) => {
                    let _ = command.response.send(Ok(Arc::clone(&shared)));
                    TuicBuildCompletion {
                        key: command.key,
                        owner: Some(TuicOwnedTransport {
                            shared,
                            cell: Arc::clone(&command.cell),
                            control_receiver: Some(control_receiver),
                        }),
                    }
                }
                Err(err) => {
                    let _ = command.response.send(Err(tuic_single_flight_error(err)));
                    TuicBuildCompletion {
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
            TuicBuildCompletion {
                key: command.key,
                owner: None,
            }
        }
    }
}

struct TuicOwnerBuildError {
    class: OwnerFailureClass,
    operation: &'static str,
    detail: String,
}

async fn build_tuic_transport(
    key: TuicOwnerKey,
    binding: ResidentProxyBinding,
    caller: QuicEndpointCallerClass,
    deadline: AbsoluteDeadline,
    metrics: Arc<TuicOwnerRegistryMetrics>,
    resources: TuicOwnerResourceProfile,
    session_cache: Option<dae_outbound::shared_transport::boring_quic::BoringQuicSessionCache>,
) -> Result<(TuicSharedTransport, mpsc::Receiver<u16>), TuicOwnerBuildError> {
    let proxy = binding.plan();
    let ResidentProxyProtocolPlan::TuicQuicTcp {
        uuid,
        password,
        alpn,
        allow_insecure,
        congestion,
        udp_relay_mode,
    } = &proxy.handler
    else {
        return Err(TuicOwnerBuildError {
            class: OwnerFailureClass::Transport,
            operation: "tuic-owner-shape",
            detail: "TUIC owner received a non-TUIC proxy shape".to_owned(),
        });
    };
    let connected = open_tuic_quic_connection_candidates_async(
        &binding,
        alpn,
        *allow_insecure,
        *congestion,
        *udp_relay_mode,
        deadline,
        caller,
        session_cache,
    )
    .await
    .map_err(|detail| TuicOwnerBuildError {
        class: OwnerFailureClass::Connect,
        operation: "tuic-owner-connect",
        detail,
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
            endpoint.close(0_u32.into(), b"tuic owner auth deadline elapsed");
            wait_quic_endpoint_idle_after_close(&endpoint).await;
            return Err(TuicOwnerBuildError {
                class: OwnerFailureClass::Cancelled,
                operation: "tuic-owner-auth-deadline",
                detail: "TUIC owner authentication deadline elapsed".to_owned(),
            });
        }
    };
    let auth_report = match time::timeout(
        remaining,
        authenticate_tuic_connection(&connection, uuid, password),
    )
    .await
    {
        Ok(Ok(report)) => report,
        Ok(Err(err)) => {
            endpoint.mark_failed();
            endpoint.close(0_u32.into(), b"tuic owner auth failed");
            wait_quic_endpoint_idle_after_close(&endpoint).await;
            return Err(TuicOwnerBuildError {
                class: OwnerFailureClass::Authentication,
                operation: "tuic-owner-auth",
                detail: format!("authenticate TUIC owner: {err}"),
            });
        }
        Err(_) => {
            endpoint.mark_failed();
            endpoint.close(0_u32.into(), b"tuic owner auth timeout");
            wait_quic_endpoint_idle_after_close(&endpoint).await;
            return Err(TuicOwnerBuildError {
                class: OwnerFailureClass::Cancelled,
                operation: "tuic-owner-auth-deadline",
                detail: "TUIC owner authentication deadline elapsed".to_owned(),
            });
        }
    };
    endpoint.mark_ready();
    let leases = Arc::new(TuicLogicalLeaseAdmission::new(
        resources.logical_lease_limit(),
        Arc::clone(&metrics),
    ));
    let (control_sender, control_receiver) =
        mpsc::channel(resources.udp_association_limit().max(1));
    let udp_associations = Arc::new(TuicAssociationManager::new(
        resources,
        metrics,
        control_sender,
        connection.clone(),
    ));
    static NEXT_INSTANCE_ID: AtomicU64 = AtomicU64::new(1);
    let instance_id = NEXT_INSTANCE_ID.fetch_add(1, Ordering::Relaxed).max(1);
    Ok((
        TuicSharedTransport {
            instance_id,
            _identity: key.redacted_identity(),
            remote,
            endpoint,
            connection,
            auth_report,
            congestion: *congestion,
            udp_relay_mode: *udp_relay_mode,
            leases,
            udp_associations,
        },
        control_receiver,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unfinished_registry_drop_closes_cells_and_marks_shutdown_incomplete() {
        let metrics = Arc::new(TuicOwnerRegistryMetrics::default());
        metrics.owner_opened();
        let index = Arc::new(Mutex::new(TuicOwnerIndex::new()));
        let cell = Arc::new(TuicOwnerCell::new());
        index.lock().unwrap().cells.insert(
            TuicOwnerKey {
                generation: OwnerGeneration::new(70),
                digest: [0_u8; 32],
            },
            Arc::clone(&cell),
        );

        drop(TuicRegistryOwnershipReconciler::new(
            Arc::clone(&metrics),
            Arc::clone(&index),
        ));

        let index = index.lock().unwrap();
        assert!(index.draining);
        assert!(index.cells.is_empty());
        assert_eq!(
            cell.snapshot().state,
            dae_runtime_control::PhysicalOwnerState::Closed
        );
        assert_eq!(metrics.active_owners.load(Ordering::Acquire), 0);
        assert!(metrics.shutdown_timed_out.load(Ordering::Acquire));
    }

    #[test]
    fn association_allocator_skips_active_and_quarantined_ids() {
        let mut state = TuicAssociationState {
            sessions: HashMap::new(),
            quarantine: HashMap::new(),
            next_id: 7,
        };
        let (sender, _receiver) = mpsc::channel(1);
        state.sessions.insert(
            7,
            TuicAssociationQueue {
                sender,
                queued_bytes: Arc::new(AtomicUsize::new(0)),
            },
        );
        state.quarantine.insert(8, Instant::now());
        assert_eq!(allocate_association_id(&mut state).unwrap(), 9);
    }

    #[test]
    fn logical_lease_and_queue_byte_admission_are_bounded() {
        let metrics = Arc::new(TuicOwnerRegistryMetrics::default());
        let admission = Arc::new(TuicLogicalLeaseAdmission::new(1, Arc::clone(&metrics)));
        let lease = admission.reserve().unwrap();
        assert!(admission.reserve().is_err());
        drop(lease);
        assert!(admission.reserve().is_ok());

        let queued = AtomicUsize::new(0);
        assert!(reserve_queued_bytes(&queued, 5, 8));
        assert!(!reserve_queued_bytes(&queued, 4, 8));
        subtract_count(&queued, 5);
        assert_eq!(queued.load(Ordering::Relaxed), 0);
    }
}
