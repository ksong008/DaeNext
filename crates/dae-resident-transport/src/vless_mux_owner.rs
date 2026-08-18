use std::collections::{HashMap, HashSet, VecDeque};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::task::{Context, Poll};
#[cfg(any(test, feature = "test-support"))]
use std::thread::JoinHandle;
use std::time::Instant;

use bytes::Bytes;
use dae_outbound::shared_transport::mux::{
    MuxFrame, MuxFrameDecoder, MuxFrameOptions, OPTION_DATA, SESSION_STATUS_END,
    SESSION_STATUS_KEEP, SESSION_STATUS_KEEPALIVE, SESSION_STATUS_NEW, mux_data_frame,
    mux_end_frame, mux_error_frame, mux_new_frame,
};
use dae_outbound::vless::{VlessEncryptedStream, packet};
use dae_outbound::vmess::VMessMetadata;
use dae_runtime_control::{AbsoluteDeadline, OwnerGeneration};
use serde_json::{Value, json};
use tokio::io::{
    AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf, ReadHalf, WriteHalf,
};
use tokio::sync::{mpsc, oneshot};
use tokio::time;

use crate::transport_identity::resident_transport_binding_identity_digest;
use crate::{
    AsyncResidentTlsClient, async_resident_tls_underlay_name,
    open_async_resident_tls_client_with_binding,
};
#[cfg(test)]
use dae_resident_core::ResidentRuntimeProfile;
use dae_resident_core::{
    RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE, SharedResidentStopSignal, VLESS_RESPONSE_VERSION,
    VlessMuxOwnerResourceProfile,
};
use dae_resident_model::{ResidentProtocolShape, ResidentProxyBinding, ResidentStreamWrapperPlan};

const VLESS_MUX_TRANSPORT_IDENTITY_DOMAIN: &[u8] = b"dae/vless-mux-transport-owner/v1";

static VLESS_MUX_TRANSPORT_GENERATIONS: OnceLock<
    Mutex<HashMap<u64, Weak<VlessMuxGenerationOwner>>>,
> = OnceLock::new();

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
struct VlessMuxTransportKey {
    generation: OwnerGeneration,
    digest: [u8; 32],
}

impl VlessMuxTransportKey {
    fn for_binding(binding: &ResidentProxyBinding) -> Self {
        Self {
            generation: binding.runtime_generation(),
            digest: resident_transport_binding_identity_digest(
                VLESS_MUX_TRANSPORT_IDENTITY_DOMAIN,
                binding,
            ),
        }
    }
}

impl std::fmt::Debug for VlessMuxTransportKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VlessMuxTransportKey")
            .field("generation", &self.generation)
            .field("digest", &"<redacted>")
            .finish()
    }
}

#[derive(Default)]
struct VlessMuxOwnerMetrics {
    reserved_physical: AtomicUsize,
    high_water_reserved_physical: AtomicUsize,
    active_physical: AtomicUsize,
    high_water_physical: AtomicUsize,
    active_logical: AtomicUsize,
    high_water_logical: AtomicUsize,
    current_logical_buffer_bytes: AtomicUsize,
    high_water_logical_buffer_bytes: AtomicUsize,
    idle_physical: AtomicUsize,
    high_water_idle: AtomicUsize,
    active_builds: AtomicUsize,
    cumulative_builds: AtomicU64,
    cumulative_build_failures: AtomicU64,
    cumulative_reuses: AtomicU64,
    cumulative_sid_allocations: AtomicU64,
    cumulative_retirements: AtomicU64,
    cumulative_idle_expirations: AtomicU64,
    cumulative_capacity_waits: AtomicU64,
    cumulative_unknown_sid_frames: AtomicU64,
    cumulative_late_sid_frames: AtomicU64,
    cumulative_server_new_rejections: AtomicU64,
    cumulative_logical_queue_rejections: AtomicU64,
    cumulative_physical_failures: AtomicU64,
    owner_limit_rejections: AtomicU64,
    physical_limit_rejections: AtomicU64,
    command_queue_rejections: AtomicU64,
    shutdown_timed_out: AtomicBool,
}

impl VlessMuxOwnerMetrics {
    fn update_high_water(counter: &AtomicUsize, value: usize) {
        let mut current = counter.load(Ordering::Relaxed);
        while value > current {
            match counter.compare_exchange_weak(
                current,
                value,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(observed) => current = observed,
            }
        }
    }

    fn physical_opened(&self) {
        let current = self.active_physical.fetch_add(1, Ordering::Relaxed) + 1;
        Self::update_high_water(&self.high_water_physical, current);
    }

    fn physical_closed(&self) {
        self.active_physical.fetch_sub(1, Ordering::Relaxed);
    }

    fn logical_opened(&self, charged_buffer_bytes: usize) {
        let current = self.active_logical.fetch_add(1, Ordering::Relaxed) + 1;
        Self::update_high_water(&self.high_water_logical, current);
        let current_bytes = self
            .current_logical_buffer_bytes
            .fetch_add(charged_buffer_bytes, Ordering::Relaxed)
            .saturating_add(charged_buffer_bytes);
        Self::update_high_water(&self.high_water_logical_buffer_bytes, current_bytes);
    }

    fn logical_closed(&self, charged_buffer_bytes: usize) {
        self.active_logical.fetch_sub(1, Ordering::Relaxed);
        self.current_logical_buffer_bytes
            .fetch_sub(charged_buffer_bytes, Ordering::Relaxed);
    }

    fn idle_opened(&self) {
        let current = self.idle_physical.fetch_add(1, Ordering::Relaxed) + 1;
        Self::update_high_water(&self.high_water_idle, current);
    }

    fn idle_closed(&self) {
        self.idle_physical.fetch_sub(1, Ordering::Relaxed);
    }
}

struct VlessMuxTransportPool {
    physical: Mutex<Vec<Arc<VlessMuxPhysicalHandle>>>,
    physical_count: AtomicUsize,
    acquisition_gate: tokio::sync::Mutex<()>,
}

impl VlessMuxTransportPool {
    fn new() -> Self {
        Self {
            physical: Mutex::new(Vec::new()),
            physical_count: AtomicUsize::new(0),
            acquisition_gate: tokio::sync::Mutex::new(()),
        }
    }
}

struct VlessMuxGenerationOwner {
    generation: OwnerGeneration,
    closing: AtomicBool,
    runtime: tokio::runtime::Handle,
    runtime_worker_threads: usize,
    uses_shared_data_plane_executor: bool,
    pools: Mutex<HashMap<VlessMuxTransportKey, Arc<VlessMuxTransportPool>>>,
    builds: Mutex<HashMap<u64, tokio::task::AbortHandle>>,
    resources: VlessMuxOwnerResourceProfile,
    metrics: Arc<VlessMuxOwnerMetrics>,
    changed: tokio::sync::Notify,
    next_build_id: AtomicU64,
    next_physical_id: AtomicU64,
}

#[allow(clippy::large_enum_variant)]
enum VlessMuxCarrier {
    Plain(AsyncResidentTlsClient),
    Encrypted(VlessEncryptedStream<AsyncResidentTlsClient>),
}

impl AsyncRead for VlessMuxCarrier {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        target: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut *self {
            Self::Plain(client) => Pin::new(client).poll_read(cx, target),
            Self::Encrypted(client) => Pin::new(client).poll_read(cx, target),
        }
    }
}

impl AsyncWrite for VlessMuxCarrier {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        payload: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match &mut *self {
            Self::Plain(client) => Pin::new(client).poll_write(cx, payload),
            Self::Encrypted(client) => Pin::new(client).poll_write(cx, payload),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut *self {
            Self::Plain(client) => Pin::new(client).poll_flush(cx),
            Self::Encrypted(client) => Pin::new(client).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut *self {
            Self::Plain(client) => Pin::new(client).poll_shutdown(cx),
            Self::Encrypted(client) => Pin::new(client).poll_shutdown(cx),
        }
    }
}

#[derive(Clone)]
pub struct VlessMuxGenerationOwnerHandle {
    owner: Arc<VlessMuxGenerationOwner>,
}

impl VlessMuxGenerationOwnerHandle {
    pub fn metrics_snapshot(&self) -> Value {
        // Poisoned locks are recovered via into_inner: the critical sections
        // below are pure state access, so a single panic must not permanently
        // wedge the mux owner.
        let pools = self
            .owner
            .pools
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let physical = pools
            .values()
            .map(|pool| pool.physical.lock().map_or(0, |physical| physical.len()))
            .sum::<usize>();
        let registered_build_tasks = self
            .owner
            .builds
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len();
        let owner_state_bytes_lower_bound = pools
            .len()
            .saturating_mul(
                std::mem::size_of::<VlessMuxTransportKey>()
                    .saturating_add(std::mem::size_of::<VlessMuxTransportPool>()),
            )
            .saturating_add(physical.saturating_mul(std::mem::size_of::<VlessMuxPhysicalHandle>()))
            .saturating_add(
                registered_build_tasks.saturating_mul(
                    std::mem::size_of::<u64>()
                        .saturating_add(std::mem::size_of::<tokio::task::AbortHandle>()),
                ),
            );
        json!({
            "schemaVersion": 1,
            "owner": "generation-vless-mux-transport-owner",
            "generation": self.owner.generation.get(),
            "closing": self.owner.closing.load(Ordering::Acquire),
            "executor": if self.owner.uses_shared_data_plane_executor {
                "process-owned-shared-multi-thread"
            } else if self.owner.runtime_worker_threads == 1 {
                "current-thread"
            } else {
                "multi-thread"
            },
            "sharedDataPlaneExecutor": self.owner.uses_shared_data_plane_executor,
            "runtimeWorkerThreads": self.owner.runtime_worker_threads,
            "registeredKeys": pools.len(),
            "registeredPhysicalConnections": physical,
            "registeredBuildTasks": registered_build_tasks,
            "reservedPhysicalConnections": self.owner.metrics.reserved_physical.load(Ordering::Relaxed),
            "highWaterReservedPhysicalConnections": self.owner.metrics.high_water_reserved_physical.load(Ordering::Relaxed),
            "activePhysicalConnections": self.owner.metrics.active_physical.load(Ordering::Relaxed),
            "highWaterPhysicalConnections": self.owner.metrics.high_water_physical.load(Ordering::Relaxed),
            "activeLogicalStreams": self.owner.metrics.active_logical.load(Ordering::Relaxed),
            "highWaterLogicalStreams": self.owner.metrics.high_water_logical.load(Ordering::Relaxed),
            "currentLogicalBufferBytes": self.owner.metrics.current_logical_buffer_bytes.load(Ordering::Relaxed),
            "highWaterLogicalBufferBytes": self.owner.metrics.high_water_logical_buffer_bytes.load(Ordering::Relaxed),
            "idlePhysicalConnections": self.owner.metrics.idle_physical.load(Ordering::Relaxed),
            "highWaterIdlePhysicalConnections": self.owner.metrics.high_water_idle.load(Ordering::Relaxed),
            "activeBuilds": self.owner.metrics.active_builds.load(Ordering::Relaxed),
            "cumulativeBuilds": self.owner.metrics.cumulative_builds.load(Ordering::Relaxed),
            "cumulativeBuildFailures": self.owner.metrics.cumulative_build_failures.load(Ordering::Relaxed),
            "cumulativeReuses": self.owner.metrics.cumulative_reuses.load(Ordering::Relaxed),
            "cumulativeSidAllocations": self.owner.metrics.cumulative_sid_allocations.load(Ordering::Relaxed),
            "cumulativeRetirements": self.owner.metrics.cumulative_retirements.load(Ordering::Relaxed),
            "cumulativeIdleExpirations": self.owner.metrics.cumulative_idle_expirations.load(Ordering::Relaxed),
            "cumulativeCapacityWaits": self.owner.metrics.cumulative_capacity_waits.load(Ordering::Relaxed),
            "cumulativeUnknownSidFrames": self.owner.metrics.cumulative_unknown_sid_frames.load(Ordering::Relaxed),
            "cumulativeLateSidFrames": self.owner.metrics.cumulative_late_sid_frames.load(Ordering::Relaxed),
            "cumulativeServerNewRejections": self.owner.metrics.cumulative_server_new_rejections.load(Ordering::Relaxed),
            "cumulativeLogicalQueueRejections": self.owner.metrics.cumulative_logical_queue_rejections.load(Ordering::Relaxed),
            "cumulativePhysicalFailures": self.owner.metrics.cumulative_physical_failures.load(Ordering::Relaxed),
            "ownerLimitRejections": self.owner.metrics.owner_limit_rejections.load(Ordering::Relaxed),
            "physicalLimitRejections": self.owner.metrics.physical_limit_rejections.load(Ordering::Relaxed),
            "commandQueueRejections": self.owner.metrics.command_queue_rejections.load(Ordering::Relaxed),
            "ownerStateBytesLowerBound": owner_state_bytes_lower_bound,
            "admissionEnforced": true,
            "shutdownTimedOut": self.owner.metrics.shutdown_timed_out.load(Ordering::Relaxed),
            "budget": {
                "owners": self.owner.resources.owner_limit(),
                "physicalConnections": self.owner.resources.physical_connection_limit(),
                "physicalConnectionsPerOwner": self.owner.resources.physical_connections_per_owner(),
                "logicalStreamsPerPhysical": self.owner.resources.logical_streams_per_physical(),
                "cumulativeLogicalStreamsPerPhysical": self.owner.resources.cumulative_logical_streams_per_physical(),
                "commandQueueDepth": self.owner.resources.command_queue_depth(),
                "logicalEventQueueDepth": self.owner.resources.logical_event_queue_depth(),
                "logicalBufferBytesPerDirection": self.owner.resources.logical_buffer_bytes(),
                "frameBytes": self.owner.resources.frame_bytes(),
                "sidQuarantineLimit": self.owner.resources.sid_quarantine_limit(),
                "sidQuarantineTtlMs": self.owner.resources.sid_quarantine_ttl().as_millis(),
                "idleTimeoutMs": self.owner.resources.idle_timeout().as_millis(),
            },
        })
    }
}

struct VlessMuxPhysicalHandle {
    instance_id: u64,
    sender: mpsc::Sender<VlessMuxPhysicalCommand>,
    active_logical: AtomicUsize,
    cumulative_logical: AtomicUsize,
    accepting: AtomicBool,
    closed: AtomicBool,
    idle: AtomicBool,
    idle_since: Mutex<Instant>,
    abort: OnceLock<tokio::task::AbortHandle>,
    metrics: Arc<VlessMuxOwnerMetrics>,
}

impl VlessMuxPhysicalHandle {
    fn reserve_logical(
        self: &Arc<Self>,
        owner: &Arc<VlessMuxGenerationOwner>,
    ) -> Option<VlessMuxLogicalPermit> {
        if self.closed.load(Ordering::Acquire) || !self.accepting.load(Ordering::Acquire) {
            return None;
        }
        let active = self.active_logical.load(Ordering::Relaxed);
        if active >= owner.resources.logical_streams_per_physical() {
            return None;
        }
        self.active_logical.fetch_add(1, Ordering::AcqRel);
        let cumulative = self.cumulative_logical.fetch_add(1, Ordering::AcqRel) + 1;
        if cumulative >= owner.resources.cumulative_logical_streams_per_physical() {
            self.accepting.store(false, Ordering::Release);
        }
        if self.idle.swap(false, Ordering::AcqRel) {
            owner.metrics.idle_closed();
            owner
                .metrics
                .cumulative_reuses
                .fetch_add(1, Ordering::Relaxed);
        }
        let charged_buffer_bytes = owner.resources.logical_buffer_bytes().saturating_mul(2);
        owner.metrics.logical_opened(charged_buffer_bytes);
        Some(VlessMuxLogicalPermit {
            physical: Arc::downgrade(self),
            owner: Arc::downgrade(owner),
            charged_buffer_bytes,
        })
    }

    fn close(&self) {
        let _ = self.sender.try_send(VlessMuxPhysicalCommand::Close);
    }
}

struct VlessMuxLogicalPermit {
    physical: Weak<VlessMuxPhysicalHandle>,
    owner: Weak<VlessMuxGenerationOwner>,
    charged_buffer_bytes: usize,
}

impl Drop for VlessMuxLogicalPermit {
    fn drop(&mut self) {
        let Some(owner) = self.owner.upgrade() else {
            return;
        };
        owner.metrics.logical_closed(self.charged_buffer_bytes);
        let Some(physical) = self.physical.upgrade() else {
            return;
        };
        let previous = physical.active_logical.fetch_sub(1, Ordering::AcqRel);
        if previous != 1 {
            owner.changed.notify_waiters();
            return;
        }
        if let Ok(mut idle_since) = physical.idle_since.lock() {
            *idle_since = Instant::now();
        }
        if !physical.idle.swap(true, Ordering::AcqRel) {
            owner.metrics.idle_opened();
        }
        if !physical.accepting.load(Ordering::Acquire) {
            physical.close();
        }
        owner.changed.notify_waiters();
    }
}

struct VlessMuxPhysicalCapacityGuard {
    owner: Weak<VlessMuxGenerationOwner>,
    pool: Weak<VlessMuxTransportPool>,
}

impl Drop for VlessMuxPhysicalCapacityGuard {
    fn drop(&mut self) {
        if let Some(pool) = self.pool.upgrade() {
            pool.physical_count.fetch_sub(1, Ordering::Relaxed);
        }
        if let Some(owner) = self.owner.upgrade() {
            owner
                .metrics
                .reserved_physical
                .fetch_sub(1, Ordering::Relaxed);
            owner.changed.notify_waiters();
        }
    }
}

struct VlessMuxPhysicalMetricGuard {
    physical: Arc<VlessMuxPhysicalHandle>,
    owner: Arc<VlessMuxGenerationOwner>,
    _capacity: VlessMuxPhysicalCapacityGuard,
}

impl Drop for VlessMuxPhysicalMetricGuard {
    fn drop(&mut self) {
        self.physical.closed.store(true, Ordering::Release);
        if self.physical.idle.swap(false, Ordering::AcqRel) {
            self.owner.metrics.idle_closed();
        }
        self.owner.metrics.physical_closed();
        self.owner.changed.notify_waiters();
    }
}

struct VlessMuxBuildGuard {
    owner: Arc<VlessMuxGenerationOwner>,
    build_id: u64,
}

impl Drop for VlessMuxBuildGuard {
    fn drop(&mut self) {
        self.owner
            .metrics
            .active_builds
            .fetch_sub(1, Ordering::Relaxed);
        if let Ok(mut builds) = self.owner.builds.lock() {
            builds.remove(&self.build_id);
        }
        self.owner.changed.notify_waiters();
    }
}

pub struct VlessMuxLogicalStream {
    stream: DuplexStream,
    sid: u16,
    physical_instance_id: u64,
    tls_underlay: &'static str,
    failure: Arc<OnceLock<String>>,
    eof_observed: bool,
}

impl VlessMuxLogicalStream {
    pub fn sid(&self) -> u16 {
        self.sid
    }

    pub fn physical_instance_id(&self) -> u64 {
        self.physical_instance_id
    }

    pub fn tls_underlay(&self) -> &'static str {
        self.tls_underlay
    }
}

impl AsyncRead for VlessMuxLogicalStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buffer.filled().len();
        match Pin::new(&mut self.stream).poll_read(context, buffer) {
            Poll::Ready(Ok(())) if buffer.filled().len() == before && !self.eof_observed => {
                self.eof_observed = true;
                if let Some(error) = self.failure.get() {
                    Poll::Ready(Err(std::io::Error::other(error.clone())))
                } else {
                    Poll::Ready(Ok(()))
                }
            }
            result => result,
        }
    }
}

impl AsyncWrite for VlessMuxLogicalStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(context, buffer)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(context)
    }
}

struct VlessMuxOpenCommand {
    target: String,
    deadline: AbsoluteDeadline,
    permit: VlessMuxLogicalPermit,
    response: oneshot::Sender<Result<VlessMuxLogicalStream, String>>,
}

enum VlessMuxPhysicalCommand {
    Open(VlessMuxOpenCommand),
    Payload { sid: u16, payload: Bytes },
    LocalEnd { sid: u16 },
    LogicalFault { sid: u16, error: String },
    Close,
}

enum VlessMuxLogicalEvent {
    Payload(Vec<u8>),
    RemoteEnd,
}

struct VlessMuxSession {
    events: mpsc::Sender<VlessMuxLogicalEvent>,
    uplink_abort: tokio::task::AbortHandle,
    downlink_abort: tokio::task::AbortHandle,
    failure: Arc<OnceLock<String>>,
    _permit: VlessMuxLogicalPermit,
}

struct VlessMuxSidAllocator {
    next: u16,
    quarantine: VecDeque<(u16, Instant)>,
    quarantined: HashSet<u16>,
}

impl VlessMuxSidAllocator {
    fn new() -> Self {
        Self {
            next: 0,
            quarantine: VecDeque::new(),
            quarantined: HashSet::new(),
        }
    }

    fn allocate(
        &mut self,
        active: &HashMap<u16, VlessMuxSession>,
        resources: VlessMuxOwnerResourceProfile,
    ) -> Result<u16, String> {
        self.prune(resources, Instant::now());
        for _ in 0..u16::MAX {
            self.next = self.next.wrapping_add(1).max(1);
            if !active.contains_key(&self.next) && !self.quarantined.contains(&self.next) {
                return Ok(self.next);
            }
        }
        Err("VLESS mux Session ID space is saturated".to_owned())
    }

    fn retire(&mut self, sid: u16, resources: VlessMuxOwnerResourceProfile) {
        self.prune(resources, Instant::now());
        if self.quarantined.insert(sid) {
            self.quarantine.push_back((sid, Instant::now()));
        }
        while self.quarantine.len() > resources.sid_quarantine_limit() {
            if let Some((expired, _)) = self.quarantine.pop_front() {
                self.quarantined.remove(&expired);
            }
        }
    }

    fn is_quarantined(&mut self, sid: u16, resources: VlessMuxOwnerResourceProfile) -> bool {
        self.prune(resources, Instant::now());
        self.quarantined.contains(&sid)
    }

    fn prune(&mut self, resources: VlessMuxOwnerResourceProfile, now: Instant) {
        while self.quarantine.front().is_some_and(|(_, retired)| {
            now.saturating_duration_since(*retired) >= resources.sid_quarantine_ttl()
        }) {
            if let Some((sid, _)) = self.quarantine.pop_front() {
                self.quarantined.remove(&sid);
            }
        }
    }
}

#[derive(Default)]
struct VlessMuxResponseHeaderDecoder {
    pending: Vec<u8>,
    done: bool,
}

impl VlessMuxResponseHeaderDecoder {
    fn consume(&mut self, input: &[u8]) -> Result<Vec<u8>, String> {
        if self.done {
            return Ok(input.to_vec());
        }
        self.pending.extend_from_slice(input);
        if self.pending.len() < 2 {
            return Ok(Vec::new());
        }
        if self.pending[0] != VLESS_RESPONSE_VERSION {
            return Err(format!(
                "unexpected VLESS mux response version: {}",
                self.pending[0]
            ));
        }
        let header_len = 2_usize.saturating_add(self.pending[1] as usize);
        if self.pending.len() < header_len {
            return Ok(Vec::new());
        }
        self.done = true;
        Ok(self.pending.split_off(header_len))
    }
}

#[cfg(any(test, feature = "test-support"))]
pub fn start_vless_mux_generation_owner(
    generation: u64,
    stop: SharedResidentStopSignal,
    thread_stack_bytes: usize,
    runtime_worker_threads: usize,
) -> Result<(VlessMuxGenerationOwnerHandle, JoinHandle<()>), String> {
    start_vless_mux_generation_owner_with_resources(
        generation,
        stop,
        thread_stack_bytes,
        runtime_worker_threads,
        VlessMuxOwnerResourceProfile::selected(),
    )
}

#[cfg(any(test, feature = "test-support"))]
pub fn start_vless_mux_generation_owner_for_test(
    generation: u64,
    stop: SharedResidentStopSignal,
    thread_stack_bytes: usize,
    runtime_worker_threads: usize,
    resources: VlessMuxOwnerResourceProfile,
) -> Result<(VlessMuxGenerationOwnerHandle, JoinHandle<()>), String> {
    start_vless_mux_generation_owner_with_resources(
        generation,
        stop,
        thread_stack_bytes,
        runtime_worker_threads,
        resources,
    )
}

#[cfg(any(test, feature = "test-support"))]
fn start_vless_mux_generation_owner_with_resources(
    generation: u64,
    stop: SharedResidentStopSignal,
    thread_stack_bytes: usize,
    runtime_worker_threads: usize,
    resources: VlessMuxOwnerResourceProfile,
) -> Result<(VlessMuxGenerationOwnerHandle, JoinHandle<()>), String> {
    let runtime_worker_threads = runtime_worker_threads.max(1);
    let runtime = if runtime_worker_threads == 1 {
        tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
    } else {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(runtime_worker_threads)
            .thread_name("resident-vless-mux-runtime")
            .thread_stack_size(thread_stack_bytes)
            .enable_io()
            .enable_time()
            .build()
    }
    .map_err(|error| format!("build VLESS mux owner runtime: {error}"))?;
    let owner = Arc::new(VlessMuxGenerationOwner {
        generation: OwnerGeneration::new(generation),
        closing: AtomicBool::new(false),
        runtime: runtime.handle().clone(),
        runtime_worker_threads,
        uses_shared_data_plane_executor: false,
        pools: Mutex::new(HashMap::new()),
        builds: Mutex::new(HashMap::new()),
        resources,
        metrics: Arc::new(VlessMuxOwnerMetrics::default()),
        changed: tokio::sync::Notify::new(),
        next_build_id: AtomicU64::new(1),
        next_physical_id: AtomicU64::new(1),
    });
    register_vless_mux_generation(&owner)?;
    let thread_owner = Arc::clone(&owner);
    let thread = std::thread::Builder::new()
        .name(format!("resident-vless-mux-owner-{generation}"))
        .stack_size(thread_stack_bytes)
        .spawn(move || {
            runtime.block_on(async move {
                let mut janitor = time::interval(thread_owner.resources.idle_janitor_interval());
                janitor.set_missed_tick_behavior(time::MissedTickBehavior::Delay);
                let mut stop_listener = stop.listener();
                loop {
                    tokio::select! {
                        _ = stop_listener.cancelled() => break,
                        _ = janitor.tick() => prune_vless_mux_owner(&thread_owner),
                    }
                }
                thread_owner.closing.store(true, Ordering::Release);
                unregister_vless_mux_generation(&thread_owner);
                cleanup_vless_mux_owner(&thread_owner).await;
            });
        })
        .map_err(|error| {
            unregister_vless_mux_generation(&owner);
            format!("spawn VLESS mux owner runtime: {error}")
        })?;
    Ok((VlessMuxGenerationOwnerHandle { owner }, thread))
}

pub fn start_vless_mux_generation_owner_on(
    runtime: &tokio::runtime::Handle,
    generation: u64,
    stop: SharedResidentStopSignal,
    runtime_worker_threads: usize,
) -> Result<(VlessMuxGenerationOwnerHandle, tokio::task::JoinHandle<()>), String> {
    let owner = Arc::new(VlessMuxGenerationOwner {
        generation: OwnerGeneration::new(generation),
        closing: AtomicBool::new(false),
        runtime: runtime.clone(),
        runtime_worker_threads: runtime_worker_threads.max(1),
        uses_shared_data_plane_executor: true,
        pools: Mutex::new(HashMap::new()),
        builds: Mutex::new(HashMap::new()),
        resources: VlessMuxOwnerResourceProfile::selected(),
        metrics: Arc::new(VlessMuxOwnerMetrics::default()),
        changed: tokio::sync::Notify::new(),
        next_build_id: AtomicU64::new(1),
        next_physical_id: AtomicU64::new(1),
    });
    register_vless_mux_generation(&owner)?;
    let task_owner = Arc::clone(&owner);
    let task = runtime.spawn(async move {
        let mut janitor = time::interval(task_owner.resources.idle_janitor_interval());
        janitor.set_missed_tick_behavior(time::MissedTickBehavior::Delay);
        let mut stop_listener = stop.listener();
        loop {
            tokio::select! {
                _ = stop_listener.cancelled() => break,
                _ = janitor.tick() => prune_vless_mux_owner(&task_owner),
            }
        }
        task_owner.closing.store(true, Ordering::Release);
        unregister_vless_mux_generation(&task_owner);
        cleanup_vless_mux_owner(&task_owner).await;
    });
    Ok((VlessMuxGenerationOwnerHandle { owner }, task))
}

fn register_vless_mux_generation(owner: &Arc<VlessMuxGenerationOwner>) -> Result<(), String> {
    let mut generations = VLESS_MUX_TRANSPORT_GENERATIONS
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .map_err(|_| "VLESS mux generation registry lock poisoned".to_owned())?;
    generations.retain(|_, owner| owner.strong_count() > 0);
    if generations
        .get(&owner.generation.get())
        .and_then(Weak::upgrade)
        .is_some_and(|registered| !registered.closing.load(Ordering::Acquire))
    {
        return Err(format!(
            "VLESS mux generation {} is already active",
            owner.generation.get()
        ));
    }
    generations.insert(owner.generation.get(), Arc::downgrade(owner));
    Ok(())
}

fn unregister_vless_mux_generation(owner: &Arc<VlessMuxGenerationOwner>) {
    if let Some(generations) = VLESS_MUX_TRANSPORT_GENERATIONS.get()
        && let Ok(mut generations) = generations.lock()
        && generations
            .get(&owner.generation.get())
            .and_then(Weak::upgrade)
            .is_some_and(|registered| Arc::ptr_eq(&registered, owner))
    {
        generations.remove(&owner.generation.get());
    }
}

fn vless_mux_generation(
    generation: OwnerGeneration,
) -> Result<Arc<VlessMuxGenerationOwner>, String> {
    let owner = VLESS_MUX_TRANSPORT_GENERATIONS
        .get()
        .and_then(|generations| generations.lock().ok())
        .and_then(|generations| generations.get(&generation.get()).and_then(Weak::upgrade))
        .ok_or_else(|| format!("VLESS mux generation {} is unavailable", generation.get()))?;
    if owner.closing.load(Ordering::Acquire) {
        return Err(format!(
            "VLESS mux generation {} is closing",
            generation.get()
        ));
    }
    Ok(owner)
}

fn vless_mux_pool(
    owner: &Arc<VlessMuxGenerationOwner>,
    key: VlessMuxTransportKey,
) -> Result<Arc<VlessMuxTransportPool>, String> {
    let mut pools = owner
        .pools
        .lock()
        .map_err(|_| "VLESS mux owner map lock poisoned".to_owned())?;
    if let Some(pool) = pools.get(&key) {
        return Ok(Arc::clone(pool));
    }
    if pools.len() >= owner.resources.owner_limit() {
        owner
            .metrics
            .owner_limit_rejections
            .fetch_add(1, Ordering::Relaxed);
        return Err(format!(
            "VLESS mux owner key budget is full ({})",
            owner.resources.owner_limit()
        ));
    }
    let pool = Arc::new(VlessMuxTransportPool::new());
    pools.insert(key, Arc::clone(&pool));
    Ok(pool)
}

pub async fn acquire_vless_mux_logical_stream(
    binding: ResidentProxyBinding,
    target: String,
    deadline: AbsoluteDeadline,
) -> Result<VlessMuxLogicalStream, String> {
    let execution = binding.execution();
    if execution.protocol != ResidentProtocolShape::VlessMux
        || execution.wrapper != ResidentStreamWrapperPlan::Mux
    {
        return Err("VLESS mux owner received a non-mux execution plan".to_owned());
    }
    VMessMetadata::parse("tcp", &target)
        .map_err(|error| format!("build VLESS mux target metadata: {error}"))?;
    let key = VlessMuxTransportKey::for_binding(&binding);
    let owner = vless_mux_generation(key.generation)?;
    let pool = vless_mux_pool(&owner, key)?;
    loop {
        let remaining = deadline
            .remaining_at(Instant::now())
            .ok_or_else(|| "VLESS mux acquisition deadline elapsed".to_owned())?;
        let gate = time::timeout(remaining, pool.acquisition_gate.lock())
            .await
            .map_err(|_| "VLESS mux acquisition deadline elapsed".to_owned())?;
        if owner.closing.load(Ordering::Acquire) {
            return Err(format!(
                "VLESS mux generation {} is closing",
                owner.generation.get()
            ));
        }
        let selected = select_vless_mux_physical(&owner, &pool);
        if let Some((physical, permit)) = selected {
            drop(gate);
            return open_vless_mux_logical(physical, permit, target, deadline).await;
        }
        let capacity = try_reserve_vless_mux_physical(&owner, &pool);
        if let Some(capacity) = capacity {
            drop(gate);
            let physical =
                build_vless_mux_physical(&owner, &pool, binding.clone(), key, deadline, capacity)
                    .await?;
            let permit = physical.reserve_logical(&owner).ok_or_else(|| {
                "new VLESS mux physical rejected its first logical stream".to_owned()
            })?;
            return open_vless_mux_logical(physical, permit, target, deadline).await;
        }
        let mut notified = Box::pin(owner.changed.notified());
        notified.as_mut().enable();
        let remaining = deadline
            .remaining_at(Instant::now())
            .ok_or_else(|| "VLESS mux capacity deadline elapsed".to_owned())?;
        drop(gate);
        owner
            .metrics
            .cumulative_capacity_waits
            .fetch_add(1, Ordering::Relaxed);
        time::timeout(remaining, notified)
            .await
            .map_err(|_| "VLESS mux capacity deadline elapsed".to_owned())?;
    }
}

fn select_vless_mux_physical(
    owner: &Arc<VlessMuxGenerationOwner>,
    pool: &Arc<VlessMuxTransportPool>,
) -> Option<(Arc<VlessMuxPhysicalHandle>, VlessMuxLogicalPermit)> {
    let mut physical = pool.physical.lock().ok()?;
    physical.retain(|candidate| !candidate.closed.load(Ordering::Acquire));
    loop {
        let candidate = Arc::clone(least_loaded_vless_mux_physical(
            &physical,
            owner.resources.logical_streams_per_physical(),
        )?);
        if let Some(permit) = candidate.reserve_logical(owner) {
            return Some((candidate, permit));
        }
    }
}

fn least_loaded_vless_mux_physical(
    physical: &[Arc<VlessMuxPhysicalHandle>],
    logical_stream_limit: usize,
) -> Option<&Arc<VlessMuxPhysicalHandle>> {
    let mut selected = None;
    let mut least_active = usize::MAX;
    for candidate in physical {
        if candidate.closed.load(Ordering::Acquire) || !candidate.accepting.load(Ordering::Acquire)
        {
            continue;
        }
        let active = candidate.active_logical.load(Ordering::Relaxed);
        if active >= logical_stream_limit || active >= least_active {
            continue;
        }
        selected = Some(candidate);
        least_active = active;
    }
    selected
}

fn try_reserve_vless_mux_physical(
    owner: &Arc<VlessMuxGenerationOwner>,
    pool: &Arc<VlessMuxTransportPool>,
) -> Option<VlessMuxPhysicalCapacityGuard> {
    if pool.physical_count.load(Ordering::Relaxed)
        >= owner.resources.physical_connections_per_owner()
    {
        owner
            .metrics
            .physical_limit_rejections
            .fetch_add(1, Ordering::Relaxed);
        return None;
    }
    let mut current = owner.metrics.reserved_physical.load(Ordering::Relaxed);
    let reserved = loop {
        if current >= owner.resources.physical_connection_limit() {
            owner
                .metrics
                .physical_limit_rejections
                .fetch_add(1, Ordering::Relaxed);
            return None;
        }
        match owner.metrics.reserved_physical.compare_exchange_weak(
            current,
            current + 1,
            Ordering::AcqRel,
            Ordering::Relaxed,
        ) {
            Ok(_) => break current + 1,
            Err(observed) => current = observed,
        }
    };
    pool.physical_count.fetch_add(1, Ordering::Relaxed);
    VlessMuxOwnerMetrics::update_high_water(&owner.metrics.high_water_reserved_physical, reserved);
    Some(VlessMuxPhysicalCapacityGuard {
        owner: Arc::downgrade(owner),
        pool: Arc::downgrade(pool),
    })
}

async fn build_vless_mux_physical(
    owner: &Arc<VlessMuxGenerationOwner>,
    pool: &Arc<VlessMuxTransportPool>,
    binding: ResidentProxyBinding,
    key: VlessMuxTransportKey,
    deadline: AbsoluteDeadline,
    capacity: VlessMuxPhysicalCapacityGuard,
) -> Result<Arc<VlessMuxPhysicalHandle>, String> {
    let build_id = loop {
        let candidate = owner.next_build_id.fetch_add(1, Ordering::Relaxed);
        if candidate != 0
            && owner
                .builds
                .lock()
                .is_ok_and(|builds| !builds.contains_key(&candidate))
        {
            break candidate;
        }
    };
    owner.metrics.active_builds.fetch_add(1, Ordering::Relaxed);
    owner
        .metrics
        .cumulative_builds
        .fetch_add(1, Ordering::Relaxed);
    let guard = VlessMuxBuildGuard {
        owner: Arc::clone(owner),
        build_id,
    };
    let build_owner = Arc::clone(owner);
    let build_pool = Arc::clone(pool);
    let (start_sender, start_receiver) = oneshot::channel();
    let mut task = owner.runtime.spawn(async move {
        let _guard = guard;
        start_receiver
            .await
            .map_err(|_| "VLESS mux physical build stopped before startup".to_owned())?;
        build_vless_mux_physical_on_owner(build_owner, build_pool, binding, key, deadline, capacity)
            .await
    });
    {
        let mut builds = match owner.builds.lock() {
            Ok(builds) => builds,
            Err(_) => {
                task.abort();
                return Err("VLESS mux build inventory lock poisoned".to_owned());
            }
        };
        builds.insert(build_id, task.abort_handle());
    }
    if start_sender.send(()).is_err() {
        task.abort();
        return Err("VLESS mux physical build stopped before startup".to_owned());
    }
    let remaining = deadline
        .remaining_at(Instant::now())
        .ok_or_else(|| "VLESS mux physical build deadline elapsed".to_owned())?;
    match time::timeout(remaining, &mut task).await {
        Ok(Ok(Ok(physical))) => Ok(physical),
        Ok(Ok(Err(error))) => {
            owner
                .metrics
                .cumulative_build_failures
                .fetch_add(1, Ordering::Relaxed);
            Err(error)
        }
        Ok(Err(error)) => {
            owner
                .metrics
                .cumulative_build_failures
                .fetch_add(1, Ordering::Relaxed);
            Err(format!("VLESS mux physical build task failed: {error}"))
        }
        Err(_) => {
            task.abort();
            owner
                .metrics
                .cumulative_build_failures
                .fetch_add(1, Ordering::Relaxed);
            Err("VLESS mux physical build deadline elapsed".to_owned())
        }
    }
}

async fn build_vless_mux_physical_on_owner(
    owner: Arc<VlessMuxGenerationOwner>,
    pool: Arc<VlessMuxTransportPool>,
    binding: ResidentProxyBinding,
    key: VlessMuxTransportKey,
    deadline: AbsoluteDeadline,
    capacity: VlessMuxPhysicalCapacityGuard,
) -> Result<Arc<VlessMuxPhysicalHandle>, String> {
    let proxy = binding.plan();
    let remaining = deadline
        .remaining_at(Instant::now())
        .ok_or_else(|| "VLESS mux physical TLS deadline elapsed".to_owned())?;
    let client = time::timeout(
        remaining,
        open_async_resident_tls_client_with_binding(&binding, proxy.mptcp),
    )
    .await
    .map_err(|_| "VLESS mux physical TLS deadline elapsed".to_owned())??;
    let key_bytes = proxy.vless_key()?;
    let tls_underlay = async_resident_tls_underlay_name(&client);
    let mut client = if let Some(encryption) = proxy.vless_encryption()? {
        VlessMuxCarrier::Encrypted(
            time::timeout(
                remaining,
                VlessEncryptedStream::handshake(client, encryption),
            )
            .await
            .map_err(|_| "VLESS mux Encryption handshake deadline elapsed".to_owned())?
            .map_err(|error| format!("VLESS mux Encryption handshake: {error}"))?,
        )
    } else {
        VlessMuxCarrier::Plain(client)
    };
    let header = packet::request_header(&key_bytes, "", "tcp", "0.0.0.0:0", true, &[])
        .map_err(|error| format!("build VLESS mux request header: {error}"))?;
    write_vless_mux_physical_until(
        &mut client,
        &header,
        "write VLESS mux request header",
        deadline,
    )
    .await?;
    let instance_id = owner
        .next_physical_id
        .fetch_add(1, Ordering::Relaxed)
        .max(1);
    let (sender, receiver) = mpsc::channel(owner.resources.command_queue_depth().max(1));
    let physical = Arc::new(VlessMuxPhysicalHandle {
        instance_id,
        sender: sender.clone(),
        active_logical: AtomicUsize::new(0),
        cumulative_logical: AtomicUsize::new(0),
        accepting: AtomicBool::new(true),
        closed: AtomicBool::new(false),
        idle: AtomicBool::new(false),
        idle_since: Mutex::new(Instant::now()),
        abort: OnceLock::new(),
        metrics: Arc::clone(&owner.metrics),
    });
    owner.metrics.physical_opened();
    let actor_physical = Arc::clone(&physical);
    let actor_owner = Arc::clone(&owner);
    let task = owner.runtime.spawn(async move {
        let metric_guard = VlessMuxPhysicalMetricGuard {
            physical: Arc::clone(&actor_physical),
            owner: Arc::clone(&actor_owner),
            _capacity: capacity,
        };
        run_vless_mux_physical(
            client,
            receiver,
            sender,
            actor_physical,
            actor_owner,
            key,
            tls_underlay,
        )
        .await;
        drop(metric_guard);
    });
    let _ = physical.abort.set(task.abort_handle());
    pool.physical
        .lock()
        .map_err(|_| "VLESS mux physical pool lock poisoned".to_owned())?
        .push(Arc::clone(&physical));
    Ok(physical)
}

async fn open_vless_mux_logical(
    physical: Arc<VlessMuxPhysicalHandle>,
    permit: VlessMuxLogicalPermit,
    target: String,
    deadline: AbsoluteDeadline,
) -> Result<VlessMuxLogicalStream, String> {
    let (response, receiver) = oneshot::channel();
    let command = VlessMuxPhysicalCommand::Open(VlessMuxOpenCommand {
        target,
        deadline,
        permit,
        response,
    });
    let remaining = deadline
        .remaining_at(Instant::now())
        .ok_or_else(|| "VLESS mux logical open deadline elapsed".to_owned())?;
    match time::timeout(remaining, physical.sender.send(command)).await {
        Ok(Ok(())) => {}
        Ok(Err(_)) => {
            physical
                .metrics
                .command_queue_rejections
                .fetch_add(1, Ordering::Relaxed);
            return Err("VLESS mux physical command channel closed".to_owned());
        }
        Err(_) => {
            physical
                .metrics
                .command_queue_rejections
                .fetch_add(1, Ordering::Relaxed);
            return Err("VLESS mux logical command deadline elapsed".to_owned());
        }
    }
    let remaining = deadline
        .remaining_at(Instant::now())
        .ok_or_else(|| "VLESS mux logical open deadline elapsed".to_owned())?;
    time::timeout(remaining, receiver)
        .await
        .map_err(|_| "VLESS mux logical open deadline elapsed".to_owned())?
        .map_err(|_| "VLESS mux physical stopped during logical open".to_owned())?
}

async fn run_vless_mux_physical(
    mut client: VlessMuxCarrier,
    mut commands: mpsc::Receiver<VlessMuxPhysicalCommand>,
    sender: mpsc::Sender<VlessMuxPhysicalCommand>,
    physical: Arc<VlessMuxPhysicalHandle>,
    owner: Arc<VlessMuxGenerationOwner>,
    _key: VlessMuxTransportKey,
    tls_underlay: &'static str,
) {
    let mut sessions = HashMap::<u16, VlessMuxSession>::new();
    let mut allocator = VlessMuxSidAllocator::new();
    let mut response_header = VlessMuxResponseHeaderDecoder::default();
    let mut decoder = MuxFrameDecoder::default();
    let mut read_buffer = vec![0_u8; owner.resources.frame_bytes().max(1024)];
    let mut terminal_error = None::<String>;
    loop {
        tokio::select! {
            command = commands.recv() => {
                let Some(command) = command else {
                    terminal_error = Some("VLESS mux command channel closed".to_owned());
                    break;
                };
                match command {
                    VlessMuxPhysicalCommand::Open(command) => {
                        if let Err(error) = open_vless_mux_session(
                            &mut client,
                            &mut sessions,
                            &mut allocator,
                            &sender,
                            &physical,
                            &owner,
                            tls_underlay,
                            command,
                        ).await {
                            terminal_error = Some(error);
                            break;
                        }
                    }
                    VlessMuxPhysicalCommand::Payload { sid, payload } => {
                        if !sessions.contains_key(&sid) {
                            continue;
                        }
                        let frame = match mux_data_frame(sid.to_be_bytes(), &payload) {
                            Ok(frame) => frame,
                            Err(error) => {
                                terminal_error = Some(format!("build VLESS mux payload frame: {error}"));
                                break;
                            }
                        };
                        if let Err(error) = client.write_all(&frame).await
                        {
                            terminal_error = Some(format!("write VLESS mux logical payload: {error}"));
                            break;
                        }
                    }
                    VlessMuxPhysicalCommand::LocalEnd { sid } => {
                        if sessions.contains_key(&sid) {
                            if let Err(error) = client
                                .write_all(&mux_end_frame(sid.to_be_bytes()))
                                .await
                            {
                                terminal_error = Some(format!("write VLESS mux logical end: {error}"));
                                break;
                            }
                            retire_vless_mux_session(
                                sid,
                                &mut sessions,
                                &mut allocator,
                                owner.resources,
                                None,
                                false,
                            );
                            owner.metrics.cumulative_retirements.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    VlessMuxPhysicalCommand::LogicalFault { sid, error } => {
                        if sessions.contains_key(&sid) {
                            if let Err(write_error) = client
                                .write_all(&mux_error_frame(sid.to_be_bytes()))
                                .await
                            {
                                terminal_error = Some(format!("write VLESS mux logical error: {write_error}"));
                                break;
                            }
                            retire_vless_mux_session(
                                sid,
                                &mut sessions,
                                &mut allocator,
                                owner.resources,
                                Some(error),
                                true,
                            );
                            owner.metrics.cumulative_retirements.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    VlessMuxPhysicalCommand::Close => break,
                }
            }
            read = client.read(&mut read_buffer) => {
                let read = match read {
                    Ok(0) => {
                        terminal_error = Some("VLESS mux physical closed by peer".to_owned());
                        break;
                    }
                    Ok(read) => read,
                    Err(error) => {
                        terminal_error = Some(format!("read VLESS mux physical: {error}"));
                        break;
                    }
                };
                let payload = match response_header.consume(&read_buffer[..read]) {
                    Ok(payload) => payload,
                    Err(error) => {
                        terminal_error = Some(error);
                        break;
                    }
                };
                if payload.is_empty() {
                    continue;
                }
                let frames = match decoder.push(&payload) {
                    Ok(frames) => frames,
                    Err(error) => {
                        terminal_error = Some(format!("decode VLESS mux response: {error}"));
                        break;
                    }
                };
                for frame in frames {
                    if let Err(error) = handle_vless_mux_response_frame(
                        &mut client,
                        frame,
                        &mut sessions,
                        &mut allocator,
                        &owner,
                    ).await {
                        terminal_error = Some(error);
                        break;
                    }
                }
                if terminal_error.is_some() {
                    break;
                }
            }
        }
    }
    physical.accepting.store(false, Ordering::Release);
    commands.close();
    while let Ok(command) = commands.try_recv() {
        if let VlessMuxPhysicalCommand::Open(command) = command {
            let _ = command.response.send(Err(terminal_error
                .clone()
                .unwrap_or_else(|| "VLESS mux physical is closing".to_owned())));
        }
    }
    if let Some(error) = terminal_error.as_ref() {
        owner
            .metrics
            .cumulative_physical_failures
            .fetch_add(1, Ordering::Relaxed);
        fan_out_vless_mux_failure(&mut sessions, &mut allocator, owner.resources, error);
    } else {
        fan_out_vless_mux_failure(
            &mut sessions,
            &mut allocator,
            owner.resources,
            "VLESS mux physical owner closed",
        );
    }
    let _ = client.shutdown().await;
}

#[allow(clippy::too_many_arguments)]
async fn open_vless_mux_session(
    client: &mut VlessMuxCarrier,
    sessions: &mut HashMap<u16, VlessMuxSession>,
    allocator: &mut VlessMuxSidAllocator,
    sender: &mpsc::Sender<VlessMuxPhysicalCommand>,
    physical: &Arc<VlessMuxPhysicalHandle>,
    owner: &Arc<VlessMuxGenerationOwner>,
    tls_underlay: &'static str,
    command: VlessMuxOpenCommand,
) -> Result<(), String> {
    let metadata = match VMessMetadata::parse("tcp", &command.target) {
        Ok(metadata) => metadata,
        Err(error) => {
            let _ = command
                .response
                .send(Err(format!("build VLESS mux target metadata: {error}")));
            return Ok(());
        }
    };
    let sid = match allocator.allocate(sessions, owner.resources) {
        Ok(sid) => sid,
        Err(error) => {
            let _ = command.response.send(Err(error));
            return Ok(());
        }
    };
    let options = MuxFrameOptions::new(
        sid.to_be_bytes(),
        metadata.hostname(),
        metadata.port(),
        "tcp",
    );
    let frame = match mux_new_frame(&options) {
        Ok(frame) => frame,
        Err(error) => {
            let _ = command
                .response
                .send(Err(format!("build VLESS mux new frame: {error}")));
            return Ok(());
        }
    };
    if let Err(error) = write_vless_mux_physical_until(
        client,
        &frame,
        "write VLESS mux new frame",
        command.deadline,
    )
    .await
    {
        let _ = command.response.send(Err(error.clone()));
        return Err(error);
    }
    owner
        .metrics
        .cumulative_sid_allocations
        .fetch_add(1, Ordering::Relaxed);
    let (caller, owner_stream) = tokio::io::duplex(owner.resources.logical_buffer_bytes());
    let (owner_read, owner_write) = tokio::io::split(owner_stream);
    let (events, event_receiver) =
        mpsc::channel(owner.resources.logical_event_queue_depth().max(1));
    let failure = Arc::new(OnceLock::new());
    let uplink = owner.runtime.spawn(run_vless_mux_uplink(
        owner_read,
        sid,
        sender.clone(),
        owner.resources.frame_bytes(),
    ));
    let downlink = owner.runtime.spawn(run_vless_mux_downlink(
        owner_write,
        event_receiver,
        sid,
        sender.clone(),
        Arc::clone(&failure),
    ));
    sessions.insert(
        sid,
        VlessMuxSession {
            events,
            uplink_abort: uplink.abort_handle(),
            downlink_abort: downlink.abort_handle(),
            failure: Arc::clone(&failure),
            _permit: command.permit,
        },
    );
    let lease = VlessMuxLogicalStream {
        stream: caller,
        sid,
        physical_instance_id: physical.instance_id,
        tls_underlay,
        failure,
        eof_observed: false,
    };
    if let Err(lease) = command.response.send(Ok(lease)) {
        drop(lease);
        let _ = client.write_all(&mux_end_frame(sid.to_be_bytes())).await;
        retire_vless_mux_session(sid, sessions, allocator, owner.resources, None, true);
    }
    Ok(())
}

async fn run_vless_mux_uplink(
    mut stream: ReadHalf<DuplexStream>,
    sid: u16,
    sender: mpsc::Sender<VlessMuxPhysicalCommand>,
    frame_bytes: usize,
) {
    let mut buffer = vec![0_u8; frame_bytes.max(1)];
    loop {
        match stream.read(&mut buffer).await {
            Ok(0) => {
                let _ = sender.send(VlessMuxPhysicalCommand::LocalEnd { sid }).await;
                return;
            }
            Ok(read) => {
                if sender
                    .send(VlessMuxPhysicalCommand::Payload {
                        sid,
                        payload: Bytes::copy_from_slice(&buffer[..read]),
                    })
                    .await
                    .is_err()
                {
                    return;
                }
            }
            Err(error) => {
                let _ = sender
                    .send(VlessMuxPhysicalCommand::LogicalFault {
                        sid,
                        error: format!("read VLESS mux logical uplink: {error}"),
                    })
                    .await;
                return;
            }
        }
    }
}

async fn run_vless_mux_downlink(
    mut stream: WriteHalf<DuplexStream>,
    mut events: mpsc::Receiver<VlessMuxLogicalEvent>,
    sid: u16,
    sender: mpsc::Sender<VlessMuxPhysicalCommand>,
    failure: Arc<OnceLock<String>>,
) {
    while let Some(event) = events.recv().await {
        match event {
            VlessMuxLogicalEvent::Payload(payload) => {
                if let Err(error) = stream.write_all(&payload).await {
                    let message = format!("write VLESS mux logical downlink: {error}");
                    let _ = failure.set(message.clone());
                    let _ = sender
                        .send(VlessMuxPhysicalCommand::LogicalFault {
                            sid,
                            error: message,
                        })
                        .await;
                    return;
                }
            }
            VlessMuxLogicalEvent::RemoteEnd => break,
        }
    }
    let _ = stream.shutdown().await;
}

async fn handle_vless_mux_response_frame(
    client: &mut VlessMuxCarrier,
    frame: MuxFrame,
    sessions: &mut HashMap<u16, VlessMuxSession>,
    allocator: &mut VlessMuxSidAllocator,
    owner: &Arc<VlessMuxGenerationOwner>,
) -> Result<(), String> {
    let sid = u16::from_be_bytes(frame.id);
    if frame.status == SESSION_STATUS_NEW {
        owner
            .metrics
            .cumulative_server_new_rejections
            .fetch_add(1, Ordering::Relaxed);
        return Err("VLESS mux server sent a forbidden New frame".to_owned());
    }
    if frame.metadata.len() != 4 {
        return Err(format!(
            "VLESS mux non-New metadata length is {}, expected 4",
            frame.metadata.len()
        ));
    }
    if frame.status == SESSION_STATUS_KEEPALIVE {
        return Ok(());
    }
    if frame.status == SESSION_STATUS_END {
        if sessions.contains_key(&sid) {
            retire_vless_mux_session(sid, sessions, allocator, owner.resources, None, false);
            owner
                .metrics
                .cumulative_retirements
                .fetch_add(1, Ordering::Relaxed);
        } else {
            observe_unknown_vless_mux_sid(sid, allocator, owner);
            client
                .write_all(&mux_error_frame(frame.id))
                .await
                .map_err(|error| format!("reject unknown VLESS mux Session ID: {error}"))?;
        }
        return Ok(());
    }
    if frame.status != SESSION_STATUS_KEEP {
        return Err(format!(
            "unsupported VLESS mux response status: {}",
            frame.status
        ));
    }
    let Some(session) = sessions.get(&sid) else {
        observe_unknown_vless_mux_sid(sid, allocator, owner);
        client
            .write_all(&mux_error_frame(frame.id))
            .await
            .map_err(|error| format!("reject unknown VLESS mux Session ID: {error}"))?;
        return Ok(());
    };
    if frame.option & OPTION_DATA == 0 || frame.payload.is_empty() {
        return Ok(());
    }
    if session
        .events
        .try_send(VlessMuxLogicalEvent::Payload(frame.payload))
        .is_err()
    {
        owner
            .metrics
            .cumulative_logical_queue_rejections
            .fetch_add(1, Ordering::Relaxed);
        client
            .write_all(&mux_error_frame(frame.id))
            .await
            .map_err(|error| format!("retire saturated VLESS mux logical stream: {error}"))?;
        retire_vless_mux_session(
            sid,
            sessions,
            allocator,
            owner.resources,
            Some("VLESS mux logical response queue is full".to_owned()),
            true,
        );
        owner
            .metrics
            .cumulative_retirements
            .fetch_add(1, Ordering::Relaxed);
    }
    Ok(())
}

fn observe_unknown_vless_mux_sid(
    sid: u16,
    allocator: &mut VlessMuxSidAllocator,
    owner: &VlessMuxGenerationOwner,
) {
    if allocator.is_quarantined(sid, owner.resources) {
        owner
            .metrics
            .cumulative_late_sid_frames
            .fetch_add(1, Ordering::Relaxed);
    } else {
        owner
            .metrics
            .cumulative_unknown_sid_frames
            .fetch_add(1, Ordering::Relaxed);
    }
}

fn retire_vless_mux_session(
    sid: u16,
    sessions: &mut HashMap<u16, VlessMuxSession>,
    allocator: &mut VlessMuxSidAllocator,
    resources: VlessMuxOwnerResourceProfile,
    error: Option<String>,
    abort_downlink: bool,
) {
    let Some(session) = sessions.remove(&sid) else {
        return;
    };
    allocator.retire(sid, resources);
    if let Some(error) = error {
        let _ = session.failure.set(error);
    }
    session.uplink_abort.abort();
    if abort_downlink {
        session.downlink_abort.abort();
    } else {
        let _ = session.events.try_send(VlessMuxLogicalEvent::RemoteEnd);
    }
}

fn fan_out_vless_mux_failure(
    sessions: &mut HashMap<u16, VlessMuxSession>,
    allocator: &mut VlessMuxSidAllocator,
    resources: VlessMuxOwnerResourceProfile,
    error: &str,
) {
    let sids = sessions.keys().copied().collect::<Vec<_>>();
    for sid in sids {
        retire_vless_mux_session(
            sid,
            sessions,
            allocator,
            resources,
            Some(error.to_owned()),
            true,
        );
    }
}

async fn write_vless_mux_physical_until(
    client: &mut (impl AsyncWrite + Unpin),
    payload: &[u8],
    label: &str,
    deadline: AbsoluteDeadline,
) -> Result<(), String> {
    let remaining = deadline
        .remaining_at(Instant::now())
        .ok_or_else(|| format!("{label}: absolute deadline elapsed"))?;
    time::timeout(remaining, async {
        client
            .write_all(payload)
            .await
            .map_err(|error| format!("{label}: {error}"))?;
        client
            .flush()
            .await
            .map_err(|error| format!("flush {label}: {error}"))
    })
    .await
    .map_err(|_| format!("{label}: absolute deadline elapsed"))?
}

fn prune_vless_mux_owner(owner: &Arc<VlessMuxGenerationOwner>) {
    let pools = owner
        .pools
        .lock()
        .map(|pools| pools.values().cloned().collect::<Vec<_>>())
        .unwrap_or_default();
    let now = Instant::now();
    for pool in pools {
        if let Ok(mut physical) = pool.physical.lock() {
            physical.retain(|candidate| !candidate.closed.load(Ordering::Acquire));
            for candidate in physical.iter() {
                if !candidate.idle.load(Ordering::Acquire) {
                    continue;
                }
                let expired = candidate.idle_since.lock().is_ok_and(|idle_since| {
                    now.saturating_duration_since(*idle_since) >= owner.resources.idle_timeout()
                });
                if expired {
                    candidate.accepting.store(false, Ordering::Release);
                    candidate.close();
                    owner
                        .metrics
                        .cumulative_idle_expirations
                        .fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }
}

async fn cleanup_vless_mux_owner(owner: &Arc<VlessMuxGenerationOwner>) {
    let builds = owner
        .builds
        .lock()
        .map(|mut builds| builds.drain().map(|(_, abort)| abort).collect::<Vec<_>>())
        .unwrap_or_default();
    for abort in builds {
        abort.abort();
    }
    let physical = owner
        .pools
        .lock()
        .map(|pools| {
            pools
                .values()
                .flat_map(|pool| {
                    pool.physical
                        .lock()
                        .map(|physical| physical.clone())
                        .unwrap_or_default()
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    for physical in &physical {
        physical.accepting.store(false, Ordering::Release);
        physical.close();
    }
    let cleanup = async {
        while owner.metrics.active_physical.load(Ordering::Relaxed) != 0
            || owner.metrics.active_logical.load(Ordering::Relaxed) != 0
            || owner.metrics.active_builds.load(Ordering::Relaxed) != 0
            || owner.metrics.reserved_physical.load(Ordering::Relaxed) != 0
        {
            tokio::task::yield_now().await;
        }
    };
    if time::timeout(RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE, cleanup)
        .await
        .is_err()
    {
        owner
            .metrics
            .shutdown_timed_out
            .store(true, Ordering::Relaxed);
        for physical in &physical {
            if let Some(abort) = physical.abort.get() {
                abort.abort();
            }
        }
        while owner.metrics.active_physical.load(Ordering::Relaxed) != 0 {
            tokio::task::yield_now().await;
        }
    }
    if let Ok(mut pools) = owner.pools.lock() {
        pools.clear();
    }
    owner.metrics.idle_physical.store(0, Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn selection_test_physical(
        instance_id: u64,
        active_logical: usize,
        accepting: bool,
        closed: bool,
    ) -> Arc<VlessMuxPhysicalHandle> {
        let (sender, _receiver) = mpsc::channel(1);
        Arc::new(VlessMuxPhysicalHandle {
            instance_id,
            sender,
            active_logical: AtomicUsize::new(active_logical),
            cumulative_logical: AtomicUsize::new(active_logical),
            accepting: AtomicBool::new(accepting),
            closed: AtomicBool::new(closed),
            idle: AtomicBool::new(active_logical == 0),
            idle_since: Mutex::new(Instant::now()),
            abort: OnceLock::new(),
            metrics: Arc::new(VlessMuxOwnerMetrics::default()),
        })
    }

    #[test]
    fn vless_mux_linear_selection_is_stable_and_skips_ineligible_physical() {
        let first = selection_test_physical(1, 2, true, false);
        let stable_tie = selection_test_physical(2, 1, true, false);
        let later_tie = selection_test_physical(3, 1, true, false);
        let closed = selection_test_physical(4, 0, true, true);
        let retired = selection_test_physical(5, 0, false, false);
        let saturated = selection_test_physical(6, 4, true, false);
        let physical = vec![
            Arc::clone(&first),
            Arc::clone(&stable_tie),
            later_tie,
            closed,
            retired,
            saturated,
        ];

        let selected = least_loaded_vless_mux_physical(&physical, 4).unwrap();
        assert_eq!(selected.instance_id, stable_tie.instance_id);
        assert_eq!(
            least_loaded_vless_mux_physical(&physical, 1).map(|selected| selected.instance_id),
            None
        );
    }

    #[test]
    fn vless_mux_sid_allocator_skips_active_and_quarantined_ids() {
        let resources =
            VlessMuxOwnerResourceProfile::from_runtime_profile(ResidentRuntimeProfile::LowMemory);
        let mut allocator = VlessMuxSidAllocator::new();
        allocator.next = u16::MAX;
        allocator.quarantined.insert(1);
        allocator.quarantine.push_back((1, Instant::now()));
        let active = HashMap::new();
        assert_eq!(allocator.allocate(&active, resources).unwrap(), 2);
    }

    #[test]
    fn vless_mux_response_header_decoder_preserves_coalesced_frames() {
        let mut decoder = VlessMuxResponseHeaderDecoder::default();
        assert!(decoder.consume(&[0]).unwrap().is_empty());
        assert_eq!(decoder.consume(&[1, 9, 7]).unwrap(), vec![7]);
    }

    #[test]
    fn vless_mux_source_keeps_tls_construction_inside_owner() {
        let owner = include_str!("vless_mux_owner.rs");
        let connection = include_str!("../../dae-resident-tcp/src/vless_handlers/connection.rs");
        let probe = include_str!("../../dae-resident-dataplane/src/probe/native_tcp/vless.rs");
        let runtime_owner = include_str!("../../dae-resident-dataplane/src/runtime_owner.rs");
        let subscription = include_str!("../../dae-resident-dataplane/src/subscription_fetch.rs");
        let control_owners =
            include_str!("../../dae-resident-dataplane/src/control_transport_owners/mod.rs");
        let requirements = include_str!(
            "../../dae-resident-dataplane/src/control_transport_owners/requirements.rs"
        );
        let model = include_str!("../../dae-resident-model/src/model.rs");
        let production = owner
            .split_once("#[cfg(test)]\nmod tests")
            .map_or(owner, |(production, _)| production);
        assert!(production.contains("open_async_resident_tls_client_with_binding"));
        assert!(connection.contains("acquire_vless_mux_logical_stream"));
        assert!(probe.contains("acquire_vless_mux_logical_stream"));
        assert!(runtime_owner.contains("start_vless_mux_generation_owner"));
        assert!(requirements.contains("requires_vless_mux_owner"));
        assert!(subscription.contains("ControlTransportOwners"));
        assert!(control_owners.contains("start_vless_mux_generation_owner_on"));
        assert!(model.contains("requires_vless_mux_owner"));
        assert!(!connection.contains("resident_mux_stream_id"));
        assert!(!connection.contains("relay_tcp_over_vless_mux_tls_async"));
        assert!(!probe.contains("target.port().to_be_bytes"));
        assert!(!production.contains("physical.sort_by_key"));
    }
}
