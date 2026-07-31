use std::collections::HashMap;
use std::future::poll_fn;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::task::{Context, Poll};
#[cfg(test)]
use std::thread::JoinHandle;
use std::time::Instant;

use bytes::Bytes;
use dae_runtime_control::{AbsoluteDeadline, OwnerGeneration};
use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Notify;
use tokio::time;

use super::*;
use crate::production_runtime_owner::resident_dataplane::client::{
    AsyncResidentTlsClient, async_resident_tls_underlay_name,
    open_async_resident_tls_client_with_binding, open_proxy_tcp_stream_with_binding,
};
use crate::production_runtime_owner::resident_dataplane::plan::{
    ResidentProtocolShape, ResidentProxyBinding, ResidentSecurityUnderlayPlan,
    ResidentStreamWrapperPlan,
};
use crate::production_runtime_owner::resident_dataplane::transport_identity::resident_transport_binding_identity_digest;

const H2_CARRIER_IDENTITY_DOMAIN: &[u8] = b"dae/h2-carrier-owner/v1";

enum H2CarrierIo {
    Plain(tokio::net::TcpStream),
    Tls(Box<AsyncResidentTlsClient>),
}

impl AsyncRead for H2CarrierIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut *self {
            Self::Plain(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::Tls(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for H2CarrierIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match &mut *self {
            Self::Plain(stream) => Pin::new(stream).poll_write(cx, buf),
            Self::Tls(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut *self {
            Self::Plain(stream) => Pin::new(stream).poll_flush(cx),
            Self::Tls(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut *self {
            Self::Plain(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::Tls(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

static H2_CARRIER_GENERATIONS: OnceLock<Mutex<HashMap<u64, Weak<H2CarrierGenerationOwner>>>> =
    OnceLock::new();

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
struct H2CarrierKey {
    generation: OwnerGeneration,
    digest: [u8; 32],
}

impl H2CarrierKey {
    fn for_binding(binding: &ResidentProxyBinding) -> Self {
        Self {
            generation: binding.runtime_generation(),
            digest: resident_transport_binding_identity_digest(H2_CARRIER_IDENTITY_DOMAIN, binding),
        }
    }
}

impl std::fmt::Debug for H2CarrierKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("H2CarrierKey")
            .field("generation", &self.generation)
            .field("digest", &"<redacted>")
            .finish()
    }
}

#[derive(Default)]
struct H2CarrierMetrics {
    reserved_physical: AtomicUsize,
    high_water_reserved_physical: AtomicUsize,
    active_physical: AtomicUsize,
    high_water_physical: AtomicUsize,
    active_logical: AtomicUsize,
    high_water_logical: AtomicUsize,
    active_builds: AtomicUsize,
    active_pending_opens: AtomicUsize,
    high_water_pending_opens: AtomicUsize,
    cumulative_builds: AtomicU64,
    cumulative_build_failures: AtomicU64,
    cumulative_reuses: AtomicU64,
    cumulative_invalidations: AtomicU64,
    owner_limit_rejections: AtomicU64,
    physical_limit_rejections: AtomicU64,
    pending_open_limit_rejections: AtomicU64,
    shutdown_timed_out: AtomicBool,
}

impl H2CarrierMetrics {
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

    fn logical_opened(&self) {
        let current = self.active_logical.fetch_add(1, Ordering::Relaxed) + 1;
        Self::update_high_water(&self.high_water_logical, current);
    }

    fn logical_closed(&self) {
        self.active_logical.fetch_sub(1, Ordering::Relaxed);
    }
}

struct H2CarrierManagerState {
    opening_build: Option<u64>,
    failure_revision: u64,
    last_failure: Option<String>,
    instance_id: u64,
    instance_acquisitions: u64,
    sender: Option<h2::client::SendRequest<Bytes>>,
    pending_open_admission: Option<Arc<tokio::sync::Semaphore>>,
    request_gate: Option<Arc<tokio::sync::Semaphore>>,
    tls_underlay: &'static str,
}

impl Default for H2CarrierManagerState {
    fn default() -> Self {
        Self {
            opening_build: None,
            failure_revision: 0,
            last_failure: None,
            instance_id: 0,
            instance_acquisitions: 0,
            sender: None,
            pending_open_admission: None,
            request_gate: None,
            tls_underlay: "standard-tls",
        }
    }
}

struct H2CarrierManager {
    state: tokio::sync::Mutex<H2CarrierManagerState>,
    changed: Notify,
}

impl H2CarrierManager {
    fn new() -> Self {
        Self {
            state: tokio::sync::Mutex::new(H2CarrierManagerState::default()),
            changed: Notify::new(),
        }
    }
}

struct H2CarrierGenerationOwner {
    generation: OwnerGeneration,
    closing: AtomicBool,
    runtime: tokio::runtime::Handle,
    runtime_worker_threads: usize,
    uses_shared_data_plane_executor: bool,
    managers: Mutex<HashMap<H2CarrierKey, Arc<H2CarrierManager>>>,
    builds: Mutex<HashMap<u64, tokio::task::AbortHandle>>,
    drivers: Mutex<HashMap<u64, tokio::task::AbortHandle>>,
    resources: H2CarrierOwnerResourceProfile,
    metrics: Arc<H2CarrierMetrics>,
    next_build_id: AtomicU64,
    next_instance_id: AtomicU64,
}

#[derive(Clone)]
pub(crate) struct H2CarrierGenerationOwnerHandle {
    owner: Arc<H2CarrierGenerationOwner>,
}

impl H2CarrierGenerationOwnerHandle {
    pub(crate) fn metrics_snapshot(&self) -> Value {
        let managers = self.owner.managers.lock().unwrap();
        let registered_keys = managers.len();
        let registered_build_tasks = self.owner.builds.lock().unwrap().len();
        let registered_driver_tasks = self.owner.drivers.lock().unwrap().len();
        let owner_state_bytes_lower_bound = registered_keys
            .saturating_mul(
                std::mem::size_of::<H2CarrierKey>()
                    .saturating_add(std::mem::size_of::<H2CarrierManager>()),
            )
            .saturating_add(
                registered_build_tasks.saturating_mul(
                    std::mem::size_of::<u64>()
                        .saturating_add(std::mem::size_of::<tokio::task::AbortHandle>()),
                ),
            )
            .saturating_add(
                registered_driver_tasks.saturating_mul(
                    std::mem::size_of::<u64>()
                        .saturating_add(std::mem::size_of::<tokio::task::AbortHandle>()),
                ),
            );
        json!({
            "schemaVersion": 1,
            "owner": "generation-h2-carrier-owner",
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
            "registeredKeys": registered_keys,
            "registeredBuildTasks": registered_build_tasks,
            "registeredDriverTasks": registered_driver_tasks,
            "reservedPhysicalConnections": self.owner.metrics.reserved_physical.load(Ordering::Relaxed),
            "highWaterReservedPhysicalConnections": self.owner.metrics.high_water_reserved_physical.load(Ordering::Relaxed),
            "activePhysicalConnections": self.owner.metrics.active_physical.load(Ordering::Relaxed),
            "highWaterPhysicalConnections": self.owner.metrics.high_water_physical.load(Ordering::Relaxed),
            "activeLogicalStreams": self.owner.metrics.active_logical.load(Ordering::Relaxed),
            "highWaterLogicalStreams": self.owner.metrics.high_water_logical.load(Ordering::Relaxed),
            "activeBuilds": self.owner.metrics.active_builds.load(Ordering::Relaxed),
            "activePendingOpens": self.owner.metrics.active_pending_opens.load(Ordering::Relaxed),
            "highWaterPendingOpens": self.owner.metrics.high_water_pending_opens.load(Ordering::Relaxed),
            "cumulativeBuilds": self.owner.metrics.cumulative_builds.load(Ordering::Relaxed),
            "cumulativeBuildFailures": self.owner.metrics.cumulative_build_failures.load(Ordering::Relaxed),
            "cumulativeReuses": self.owner.metrics.cumulative_reuses.load(Ordering::Relaxed),
            "cumulativeInvalidations": self.owner.metrics.cumulative_invalidations.load(Ordering::Relaxed),
            "ownerLimitRejections": self.owner.metrics.owner_limit_rejections.load(Ordering::Relaxed),
            "physicalLimitRejections": self.owner.metrics.physical_limit_rejections.load(Ordering::Relaxed),
            "pendingOpenLimitRejections": self.owner.metrics.pending_open_limit_rejections.load(Ordering::Relaxed),
            "ownerStateBytesLowerBound": owner_state_bytes_lower_bound,
            "admissionEnforced": true,
            "shutdownTimedOut": self.owner.metrics.shutdown_timed_out.load(Ordering::Relaxed),
            "budget": {
                "owners": self.owner.resources.owner_limit(),
                "physicalConnections": self.owner.resources.physical_connection_limit(),
                "reusablePhysicalConnectionsPerOwner": 1,
                "drainingConnectionsCountTowardPhysicalBudget": true,
                "logicalConcurrencySource": "peer-http2-settings",
                "pendingOpensPerPhysical": self.owner.resources.pending_open_limit(),
                "pendingOpenQueueing": false,
            },
        })
    }
}

pub(crate) struct H2CarrierLease {
    sender: h2::client::SendRequest<Bytes>,
    pending_open_admission: Arc<tokio::sync::Semaphore>,
    request_gate: Arc<tokio::sync::Semaphore>,
    key: H2CarrierKey,
    instance_id: u64,
    tls_underlay: &'static str,
    owner: Weak<H2CarrierGenerationOwner>,
    metrics: Arc<H2CarrierMetrics>,
}

impl H2CarrierLease {
    pub(crate) async fn open_request(
        &self,
        request: http::Request<()>,
        end_of_stream: bool,
        deadline: AbsoluteDeadline,
        context: &str,
    ) -> Result<(H2CarrierResponseFuture, h2::SendStream<Bytes>), String> {
        let pending_open =
            try_acquire_h2_pending_open(&self.pending_open_admission, &self.metrics, context)?;
        let mut sender = self.sender.clone();
        let remaining = deadline
            .remaining_at(Instant::now())
            .ok_or_else(|| format!("{context} HTTP/2 stream-capacity deadline elapsed"))?;
        match time::timeout(remaining, poll_fn(|cx| sender.poll_ready(cx))).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                self.invalidate();
                return Err(format!("{context} HTTP/2 carrier is not reusable: {error}"));
            }
            Err(_) => {
                return Err(format!("{context} HTTP/2 stream-capacity deadline elapsed"));
            }
        }
        let remaining = deadline
            .remaining_at(Instant::now())
            .ok_or_else(|| format!("{context} HTTP/2 stream-capacity deadline elapsed"))?;
        let request_permit =
            time::timeout(remaining, Arc::clone(&self.request_gate).acquire_owned())
                .await
                .map_err(|_| format!("{context} HTTP/2 stream-capacity deadline elapsed"))?
                .map_err(|_| format!("{context} HTTP/2 request gate is closed"))?;
        let (response, send_stream) =
            sender
                .send_request(request, end_of_stream)
                .map_err(|error| {
                    self.invalidate();
                    format!("send {context} HTTP/2 request headers: {error}")
                })?;
        drop(request_permit);
        Ok((
            H2CarrierResponseFuture {
                response: Box::pin(response),
                pending_open: Some(pending_open),
            },
            send_stream,
        ))
    }

    pub(crate) fn tls_underlay(&self) -> &'static str {
        self.tls_underlay
    }

    #[cfg(test)]
    pub(crate) fn physical_instance_id(&self) -> u64 {
        self.instance_id
    }

    #[cfg(test)]
    pub(crate) async fn current_max_send_streams(&self) -> usize {
        self.sender.current_max_send_streams()
    }

    pub(crate) fn invalidate(&self) {
        let Some(owner) = self.owner.upgrade() else {
            return;
        };
        let key = self.key;
        let instance_id = self.instance_id;
        let runtime = owner.runtime.clone();
        runtime.spawn(async move {
            invalidate_h2_carrier(&owner, key, instance_id).await;
        });
    }
}

struct H2PendingOpenPermit {
    _permit: tokio::sync::OwnedSemaphorePermit,
    metrics: Arc<H2CarrierMetrics>,
}

fn try_acquire_h2_pending_open(
    admission: &Arc<tokio::sync::Semaphore>,
    metrics: &Arc<H2CarrierMetrics>,
    context: &str,
) -> Result<H2PendingOpenPermit, String> {
    let permit = Arc::clone(admission).try_acquire_owned().map_err(|_| {
        metrics
            .pending_open_limit_rejections
            .fetch_add(1, Ordering::Relaxed);
        format!("{context} HTTP/2 pending-open capacity is full")
    })?;
    let current = metrics.active_pending_opens.fetch_add(1, Ordering::Relaxed) + 1;
    H2CarrierMetrics::update_high_water(&metrics.high_water_pending_opens, current);
    Ok(H2PendingOpenPermit {
        _permit: permit,
        metrics: Arc::clone(metrics),
    })
}

pub(crate) struct H2CarrierResponseFuture {
    response: Pin<Box<h2::client::ResponseFuture>>,
    pending_open: Option<H2PendingOpenPermit>,
}

impl std::future::Future for H2CarrierResponseFuture {
    type Output = Result<http::Response<h2::RecvStream>, h2::Error>;

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let result = self.response.as_mut().poll(context);
        if result.is_ready() {
            self.pending_open.take();
        }
        result
    }
}

impl Drop for H2PendingOpenPermit {
    fn drop(&mut self) {
        self.metrics
            .active_pending_opens
            .fetch_sub(1, Ordering::Relaxed);
    }
}

impl Drop for H2CarrierLease {
    fn drop(&mut self) {
        self.metrics.logical_closed();
    }
}

struct H2PhysicalPermit {
    metrics: Arc<H2CarrierMetrics>,
}

impl Drop for H2PhysicalPermit {
    fn drop(&mut self) {
        self.metrics
            .reserved_physical
            .fetch_sub(1, Ordering::Relaxed);
    }
}

fn try_reserve_h2_physical(
    owner: &Arc<H2CarrierGenerationOwner>,
) -> Result<H2PhysicalPermit, String> {
    let limit = owner.resources.physical_connection_limit();
    let mut current = owner.metrics.reserved_physical.load(Ordering::Relaxed);
    loop {
        if current >= limit {
            owner
                .metrics
                .physical_limit_rejections
                .fetch_add(1, Ordering::Relaxed);
            return Err(format!(
                "HTTP/2 carrier physical connection budget is full ({limit})"
            ));
        }
        match owner.metrics.reserved_physical.compare_exchange_weak(
            current,
            current + 1,
            Ordering::AcqRel,
            Ordering::Relaxed,
        ) {
            Ok(_) => {
                H2CarrierMetrics::update_high_water(
                    &owner.metrics.high_water_reserved_physical,
                    current + 1,
                );
                return Ok(H2PhysicalPermit {
                    metrics: Arc::clone(&owner.metrics),
                });
            }
            Err(observed) => current = observed,
        }
    }
}

struct H2BuildMetricGuard {
    owner: Arc<H2CarrierGenerationOwner>,
    build_id: u64,
}

impl Drop for H2BuildMetricGuard {
    fn drop(&mut self) {
        self.owner
            .metrics
            .active_builds
            .fetch_sub(1, Ordering::Relaxed);
        if let Ok(mut builds) = self.owner.builds.lock() {
            builds.remove(&self.build_id);
        }
    }
}

struct H2PhysicalMetricGuard {
    metrics: Arc<H2CarrierMetrics>,
}

impl Drop for H2PhysicalMetricGuard {
    fn drop(&mut self) {
        self.metrics.physical_closed();
    }
}

struct H2DriverInventoryGuard {
    owner: Arc<H2CarrierGenerationOwner>,
    instance_id: u64,
}

impl Drop for H2DriverInventoryGuard {
    fn drop(&mut self) {
        if let Ok(mut drivers) = self.owner.drivers.lock() {
            drivers.remove(&self.instance_id);
        }
    }
}

#[cfg(test)]
pub(crate) fn start_h2_carrier_generation_owner(
    generation: u64,
    stop: SharedResidentStopSignal,
    thread_stack_bytes: usize,
    runtime_worker_threads: usize,
) -> Result<(H2CarrierGenerationOwnerHandle, JoinHandle<()>), String> {
    let runtime_worker_threads = runtime_worker_threads.max(1);
    let runtime = if runtime_worker_threads == 1 {
        tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
    } else {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(runtime_worker_threads)
            .thread_name("resident-h2-carrier-runtime")
            .thread_stack_size(thread_stack_bytes)
            .enable_io()
            .enable_time()
            .build()
    }
    .map_err(|error| format!("build HTTP/2 carrier owner runtime: {error}"))?;
    let owner = Arc::new(H2CarrierGenerationOwner {
        generation: OwnerGeneration::new(generation),
        closing: AtomicBool::new(false),
        runtime: runtime.handle().clone(),
        runtime_worker_threads,
        uses_shared_data_plane_executor: false,
        managers: Mutex::new(HashMap::new()),
        builds: Mutex::new(HashMap::new()),
        drivers: Mutex::new(HashMap::new()),
        resources: H2CarrierOwnerResourceProfile::selected(),
        metrics: Arc::new(H2CarrierMetrics::default()),
        next_build_id: AtomicU64::new(1),
        next_instance_id: AtomicU64::new(1),
    });
    register_h2_carrier_generation(&owner)?;
    let thread_owner = Arc::clone(&owner);
    let thread = std::thread::Builder::new()
        .name(format!("resident-h2-carrier-owner-{generation}"))
        .stack_size(thread_stack_bytes)
        .spawn(move || {
            runtime.block_on(async move {
                stop.listener().cancelled().await;
                thread_owner.closing.store(true, Ordering::Release);
                unregister_h2_carrier_generation(&thread_owner);
                cleanup_h2_carrier_owner(&thread_owner).await;
            });
        })
        .map_err(|error| {
            unregister_h2_carrier_generation(&owner);
            format!("spawn HTTP/2 carrier owner runtime: {error}")
        })?;
    Ok((H2CarrierGenerationOwnerHandle { owner }, thread))
}

pub(crate) fn start_h2_carrier_generation_owner_on(
    runtime: &tokio::runtime::Handle,
    generation: u64,
    stop: SharedResidentStopSignal,
    runtime_worker_threads: usize,
) -> Result<(H2CarrierGenerationOwnerHandle, tokio::task::JoinHandle<()>), String> {
    let owner = Arc::new(H2CarrierGenerationOwner {
        generation: OwnerGeneration::new(generation),
        closing: AtomicBool::new(false),
        runtime: runtime.clone(),
        runtime_worker_threads: runtime_worker_threads.max(1),
        uses_shared_data_plane_executor: true,
        managers: Mutex::new(HashMap::new()),
        builds: Mutex::new(HashMap::new()),
        drivers: Mutex::new(HashMap::new()),
        resources: H2CarrierOwnerResourceProfile::selected(),
        metrics: Arc::new(H2CarrierMetrics::default()),
        next_build_id: AtomicU64::new(1),
        next_instance_id: AtomicU64::new(1),
    });
    register_h2_carrier_generation(&owner)?;
    let task_owner = Arc::clone(&owner);
    let task = runtime.spawn(async move {
        stop.listener().cancelled().await;
        task_owner.closing.store(true, Ordering::Release);
        unregister_h2_carrier_generation(&task_owner);
        cleanup_h2_carrier_owner(&task_owner).await;
    });
    Ok((H2CarrierGenerationOwnerHandle { owner }, task))
}

fn register_h2_carrier_generation(owner: &Arc<H2CarrierGenerationOwner>) -> Result<(), String> {
    let mut generations = H2_CARRIER_GENERATIONS
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .map_err(|_| "HTTP/2 carrier generation registry lock poisoned".to_owned())?;
    generations.retain(|_, owner| owner.strong_count() > 0);
    if generations
        .get(&owner.generation.get())
        .and_then(Weak::upgrade)
        .is_some_and(|registered| !registered.closing.load(Ordering::Acquire))
    {
        return Err(format!(
            "HTTP/2 carrier generation {} is already active",
            owner.generation.get()
        ));
    }
    generations.insert(owner.generation.get(), Arc::downgrade(owner));
    Ok(())
}

fn unregister_h2_carrier_generation(owner: &Arc<H2CarrierGenerationOwner>) {
    if let Some(generations) = H2_CARRIER_GENERATIONS.get()
        && let Ok(mut generations) = generations.lock()
        && generations
            .get(&owner.generation.get())
            .and_then(Weak::upgrade)
            .is_some_and(|registered| Arc::ptr_eq(&registered, owner))
    {
        generations.remove(&owner.generation.get());
    }
}

fn h2_carrier_generation(
    generation: OwnerGeneration,
) -> Result<Arc<H2CarrierGenerationOwner>, String> {
    let owner = H2_CARRIER_GENERATIONS
        .get()
        .and_then(|generations| generations.lock().ok())
        .and_then(|generations| generations.get(&generation.get()).and_then(Weak::upgrade))
        .ok_or_else(|| {
            format!(
                "HTTP/2 carrier generation {} is unavailable",
                generation.get()
            )
        })?;
    if owner.closing.load(Ordering::Acquire) {
        return Err(format!(
            "HTTP/2 carrier generation {} is closing",
            generation.get()
        ));
    }
    Ok(owner)
}

pub(crate) async fn acquire_h2_carrier(
    binding: ResidentProxyBinding,
    deadline: AbsoluteDeadline,
) -> Result<H2CarrierLease, String> {
    let key = H2CarrierKey::for_binding(&binding);
    let owner = h2_carrier_generation(key.generation)?;
    let manager = {
        let mut managers = owner
            .managers
            .lock()
            .map_err(|_| "HTTP/2 carrier owner map lock poisoned".to_owned())?;
        if let Some(manager) = managers.get(&key) {
            Arc::clone(manager)
        } else {
            if managers.len() >= owner.resources.owner_limit() {
                owner
                    .metrics
                    .owner_limit_rejections
                    .fetch_add(1, Ordering::Relaxed);
                return Err(format!(
                    "HTTP/2 carrier owner budget is full ({})",
                    owner.resources.owner_limit()
                ));
            }
            let manager = Arc::new(H2CarrierManager::new());
            managers.insert(key, Arc::clone(&manager));
            manager
        }
    };
    let initial_failure_revision = manager.state.lock().await.failure_revision;
    loop {
        if owner.closing.load(Ordering::Acquire) {
            return Err(format!(
                "HTTP/2 carrier generation {} is closing",
                owner.generation.get()
            ));
        }
        let notified = manager.changed.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        {
            let mut state = manager.state.lock().await;
            if let (Some(sender), Some(pending_open_admission), Some(request_gate)) = (
                state.sender.clone(),
                state.pending_open_admission.clone(),
                state.request_gate.clone(),
            ) {
                owner.metrics.logical_opened();
                if state.instance_acquisitions != 0 {
                    owner
                        .metrics
                        .cumulative_reuses
                        .fetch_add(1, Ordering::Relaxed);
                }
                state.instance_acquisitions = state.instance_acquisitions.saturating_add(1);
                return Ok(H2CarrierLease {
                    sender,
                    pending_open_admission,
                    request_gate,
                    key,
                    instance_id: state.instance_id,
                    tls_underlay: state.tls_underlay,
                    owner: Arc::downgrade(&owner),
                    metrics: Arc::clone(&owner.metrics),
                });
            }
            if state.failure_revision != initial_failure_revision {
                return Err(state
                    .last_failure
                    .clone()
                    .unwrap_or_else(|| "HTTP/2 carrier build failed".to_owned()));
            }
            if state.opening_build.is_none() {
                let physical = try_reserve_h2_physical(&owner)?;
                let (build_id, start) =
                    spawn_h2_carrier_build(&owner, &manager, binding.clone(), deadline, physical)?;
                state.opening_build = Some(build_id);
                if start.send(()).is_err() {
                    state.opening_build = None;
                    abort_h2_build(&owner, build_id);
                    return Err("HTTP/2 carrier build stopped before startup".to_owned());
                }
            }
        }
        let remaining = deadline
            .remaining_at(Instant::now())
            .ok_or_else(|| "HTTP/2 carrier acquisition deadline elapsed".to_owned())?;
        time::timeout(remaining, notified.as_mut())
            .await
            .map_err(|_| "HTTP/2 carrier acquisition deadline elapsed".to_owned())?;
    }
}

fn spawn_h2_carrier_build(
    owner: &Arc<H2CarrierGenerationOwner>,
    manager: &Arc<H2CarrierManager>,
    binding: ResidentProxyBinding,
    deadline: AbsoluteDeadline,
    physical: H2PhysicalPermit,
) -> Result<(u64, tokio::sync::oneshot::Sender<()>), String> {
    let mut builds = owner
        .builds
        .lock()
        .map_err(|_| "HTTP/2 carrier build inventory lock poisoned".to_owned())?;
    if owner.closing.load(Ordering::Acquire) {
        return Err(format!(
            "HTTP/2 carrier generation {} is closing",
            owner.generation.get()
        ));
    }
    let build_id = loop {
        let candidate = owner.next_build_id.fetch_add(1, Ordering::Relaxed);
        if candidate != 0 && !builds.contains_key(&candidate) {
            break candidate;
        }
    };
    owner.metrics.active_builds.fetch_add(1, Ordering::Relaxed);
    owner
        .metrics
        .cumulative_builds
        .fetch_add(1, Ordering::Relaxed);
    let guard = H2BuildMetricGuard {
        owner: Arc::clone(owner),
        build_id,
    };
    let build_owner = Arc::clone(owner);
    let build_manager = Arc::clone(manager);
    let (start, start_rx) = tokio::sync::oneshot::channel();
    let task = owner.runtime.spawn(async move {
        let _guard = guard;
        if start_rx.await.is_err() {
            return;
        }
        complete_h2_carrier_build(
            build_owner,
            build_manager,
            binding,
            deadline,
            build_id,
            physical,
        )
        .await;
    });
    builds.insert(build_id, task.abort_handle());
    Ok((build_id, start))
}

fn abort_h2_build(owner: &H2CarrierGenerationOwner, build_id: u64) {
    let abort = owner
        .builds
        .lock()
        .ok()
        .and_then(|mut builds| builds.remove(&build_id));
    if let Some(abort) = abort {
        abort.abort();
    }
}

async fn complete_h2_carrier_build(
    owner: Arc<H2CarrierGenerationOwner>,
    manager: Arc<H2CarrierManager>,
    binding: ResidentProxyBinding,
    deadline: AbsoluteDeadline,
    build_id: u64,
    physical: H2PhysicalPermit,
) {
    let result = build_h2_carrier(&owner, &manager, &binding, deadline, physical).await;
    let mut state = manager.state.lock().await;
    if state.opening_build != Some(build_id) {
        drop(state);
        if let Ok((instance_id, _, _, _, _, _)) = result {
            abort_h2_driver(&owner, instance_id);
        }
        manager.changed.notify_waiters();
        return;
    }
    state.opening_build = None;
    match result {
        Ok((
            instance_id,
            sender,
            pending_open_admission,
            request_gate,
            tls_underlay,
            driver_start,
        )) if !owner.closing.load(Ordering::Acquire) => {
            state.instance_id = instance_id;
            state.instance_acquisitions = 0;
            state.sender = Some(sender);
            state.pending_open_admission = Some(pending_open_admission);
            state.request_gate = Some(request_gate);
            state.tls_underlay = tls_underlay;
            state.last_failure = None;
            let _ = driver_start.send(());
        }
        Ok((instance_id, _, _, _, _, _)) => {
            abort_h2_driver(&owner, instance_id);
            state.failure_revision = state.failure_revision.wrapping_add(1).max(1);
            state.last_failure = Some(format!(
                "HTTP/2 carrier generation {} is closing",
                owner.generation.get()
            ));
        }
        Err(error) => {
            owner
                .metrics
                .cumulative_build_failures
                .fetch_add(1, Ordering::Relaxed);
            state.failure_revision = state.failure_revision.wrapping_add(1).max(1);
            state.last_failure = Some(error);
        }
    }
    drop(state);
    manager.changed.notify_waiters();
}

async fn build_h2_carrier(
    owner: &Arc<H2CarrierGenerationOwner>,
    manager: &Arc<H2CarrierManager>,
    binding: &ResidentProxyBinding,
    deadline: AbsoluteDeadline,
    physical: H2PhysicalPermit,
) -> Result<
    (
        u64,
        h2::client::SendRequest<Bytes>,
        Arc<tokio::sync::Semaphore>,
        Arc<tokio::sync::Semaphore>,
        &'static str,
        tokio::sync::oneshot::Sender<()>,
    ),
    String,
> {
    let proxy = binding.plan();
    let execution = proxy.execution_plan();
    let plain_vmess_grpc = execution.protocol == ResidentProtocolShape::VmessAead
        && execution.wrapper == ResidentStreamWrapperPlan::Grpc
        && execution.security == ResidentSecurityUnderlayPlan::None;
    let (client, tls_underlay) = if plain_vmess_grpc {
        let remaining = deadline
            .remaining_at(Instant::now())
            .ok_or_else(|| "HTTP/2 carrier connect deadline elapsed".to_owned())?;
        let stream = time::timeout(
            remaining,
            open_proxy_tcp_stream_with_binding(binding, proxy.mptcp),
        )
        .await
        .map_err(|_| "HTTP/2 carrier connect deadline elapsed".to_owned())??;
        (H2CarrierIo::Plain(stream), "plain-h2c")
    } else {
        let remaining = deadline
            .remaining_at(Instant::now())
            .ok_or_else(|| "HTTP/2 carrier TLS deadline elapsed".to_owned())?;
        let client = time::timeout(
            remaining,
            open_async_resident_tls_client_with_binding(binding, proxy.mptcp),
        )
        .await
        .map_err(|_| "HTTP/2 carrier TLS deadline elapsed".to_owned())??;
        if client.negotiated_alpn() != Some(b"h2") {
            return Err(format!(
                "HTTP/2 carrier negotiated unsupported ALPN {}",
                client
                    .negotiated_alpn()
                    .map(|alpn| String::from_utf8_lossy(alpn).into_owned())
                    .unwrap_or_else(|| "<none>".to_owned())
            ));
        }
        let tls_underlay = async_resident_tls_underlay_name(&client);
        (H2CarrierIo::Tls(Box::new(client)), tls_underlay)
    };
    let remaining = deadline
        .remaining_at(Instant::now())
        .ok_or_else(|| "HTTP/2 carrier handshake deadline elapsed".to_owned())?;
    let (sender, connection) = time::timeout(remaining, h2::client::handshake(client))
        .await
        .map_err(|_| "HTTP/2 carrier handshake deadline elapsed".to_owned())?
        .map_err(|error| format!("HTTP/2 carrier client handshake: {error}"))?;
    let pending_open_admission = Arc::new(tokio::sync::Semaphore::new(
        owner.resources.pending_open_limit(),
    ));
    let request_gate = Arc::new(tokio::sync::Semaphore::new(1));
    let mut drivers = owner
        .drivers
        .lock()
        .map_err(|_| "HTTP/2 carrier driver inventory lock poisoned".to_owned())?;
    let instance_id = loop {
        let candidate = owner.next_instance_id.fetch_add(1, Ordering::Relaxed);
        if candidate != 0 && !drivers.contains_key(&candidate) {
            break candidate;
        }
    };
    owner.metrics.physical_opened();
    let physical_guard = H2PhysicalMetricGuard {
        metrics: Arc::clone(&owner.metrics),
    };
    let completion_owner = Arc::clone(owner);
    let completion_manager = Arc::clone(manager);
    let inventory_guard = H2DriverInventoryGuard {
        owner: Arc::clone(owner),
        instance_id,
    };
    let (driver_start, driver_start_rx) = tokio::sync::oneshot::channel();
    let driver = tokio::spawn(async move {
        let _physical = physical;
        let _physical_guard = physical_guard;
        let _inventory_guard = inventory_guard;
        if driver_start_rx.await.is_err() {
            return;
        }
        let _ = connection.await;
        let mut state = completion_manager.state.lock().await;
        if state.instance_id == instance_id {
            state.sender = None;
            state.pending_open_admission = None;
            state.request_gate = None;
            state.instance_acquisitions = 0;
        }
        drop(state);
        completion_manager.changed.notify_waiters();
        drop(completion_owner);
    });
    drivers.insert(instance_id, driver.abort_handle());
    Ok((
        instance_id,
        sender,
        pending_open_admission,
        request_gate,
        tls_underlay,
        driver_start,
    ))
}

fn abort_h2_driver(owner: &H2CarrierGenerationOwner, instance_id: u64) {
    let abort = owner
        .drivers
        .lock()
        .ok()
        .and_then(|mut drivers| drivers.remove(&instance_id));
    if let Some(abort) = abort {
        abort.abort();
    }
}

async fn invalidate_h2_carrier(
    owner: &Arc<H2CarrierGenerationOwner>,
    key: H2CarrierKey,
    instance_id: u64,
) {
    let manager = owner
        .managers
        .lock()
        .ok()
        .and_then(|managers| managers.get(&key).cloned());
    let Some(manager) = manager else {
        return;
    };
    let mut state = manager.state.lock().await;
    if state.instance_id == instance_id && state.sender.take().is_some() {
        state.pending_open_admission = None;
        state.request_gate = None;
        state.instance_acquisitions = 0;
        owner
            .metrics
            .cumulative_invalidations
            .fetch_add(1, Ordering::Relaxed);
    }
    drop(state);
    manager.changed.notify_waiters();
}

async fn cleanup_h2_carrier_owner(owner: &Arc<H2CarrierGenerationOwner>) {
    let managers = owner
        .managers
        .lock()
        .map(|mut managers| {
            managers
                .drain()
                .map(|(_, manager)| manager)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let cleanup = async {
        let build_aborts = owner
            .builds
            .lock()
            .map(|mut builds| builds.drain().map(|(_, abort)| abort).collect::<Vec<_>>())
            .unwrap_or_default();
        for abort in build_aborts {
            abort.abort();
        }
        for manager in managers {
            let mut state = manager.state.lock().await;
            state.sender = None;
            state.pending_open_admission = None;
            state.request_gate = None;
            state.instance_acquisitions = 0;
            state.opening_build = None;
            drop(state);
            manager.changed.notify_waiters();
        }
        let driver_aborts = owner
            .drivers
            .lock()
            .map(|mut drivers| drivers.drain().map(|(_, abort)| abort).collect::<Vec<_>>())
            .unwrap_or_default();
        for abort in driver_aborts {
            abort.abort();
        }
        while owner.metrics.active_physical.load(Ordering::Relaxed) != 0
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn h2_carrier_source_keeps_physical_construction_inside_the_owner() {
        let owner = include_str!("h2_carrier_owner.rs");
        let grpc = include_str!("../tcp/transport_helpers/grpc_common/open_stream.rs");
        let body = include_str!("../tcp/transport_helpers/h2_body.rs");
        let production = owner
            .split_once("#[cfg(test)]\nmod tests")
            .map_or(owner, |(production, _)| production);
        let grpc_production = grpc
            .split_once("#[cfg(test)]\npub(super) async fn open_grpc_h2_stream_on_io")
            .map_or(grpc, |(production, _)| production);
        assert!(production.contains("h2::client::handshake(client)"));
        assert!(!grpc_production.contains("h2::client::handshake(client)"));
        assert!(!body.contains("h2::client::handshake(client)"));
    }

    #[test]
    fn pending_open_admission_is_bounded_and_releases_on_cancellation() {
        let admission = Arc::new(tokio::sync::Semaphore::new(2));
        let metrics = Arc::new(H2CarrierMetrics::default());
        let first = try_acquire_h2_pending_open(&admission, &metrics, "first").unwrap();
        let second = try_acquire_h2_pending_open(&admission, &metrics, "second").unwrap();

        let error = match try_acquire_h2_pending_open(&admission, &metrics, "third") {
            Ok(_) => panic!("pending-open admission exceeded its configured capacity"),
            Err(error) => error,
        };
        assert!(error.contains("pending-open capacity is full"));
        assert_eq!(metrics.active_pending_opens.load(Ordering::Relaxed), 2);
        assert_eq!(metrics.high_water_pending_opens.load(Ordering::Relaxed), 2);
        assert_eq!(
            metrics
                .pending_open_limit_rejections
                .load(Ordering::Relaxed),
            1
        );

        drop(first);
        assert_eq!(metrics.active_pending_opens.load(Ordering::Relaxed), 1);
        let replacement = try_acquire_h2_pending_open(&admission, &metrics, "replacement").unwrap();
        drop((second, replacement));
        assert_eq!(metrics.active_pending_opens.load(Ordering::Relaxed), 0);
        assert_eq!(admission.available_permits(), 2);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn request_gate_releases_before_response_headers_are_ready() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let (both_requests_tx, both_requests_rx) = tokio::sync::oneshot::channel();
        let server_task = tokio::spawn(async move {
            let mut connection = h2::server::handshake(server_io).await.unwrap();
            let (_, mut first_respond) = connection.accept().await.unwrap().unwrap();
            let (_, mut second_respond) = connection.accept().await.unwrap().unwrap();
            let _ = both_requests_tx.send(());
            let response = || {
                http::Response::builder()
                    .status(200)
                    .version(http::Version::HTTP_2)
                    .body(())
                    .unwrap()
            };
            first_respond.send_response(response(), true).unwrap();
            second_respond.send_response(response(), true).unwrap();
            let _ = time::timeout(std::time::Duration::from_millis(200), connection.accept()).await;
        });
        let (sender, connection) = h2::client::handshake(client_io).await.unwrap();
        let client_task = tokio::spawn(async move {
            let _ = connection.await;
        });
        let pending_open_admission = Arc::new(tokio::sync::Semaphore::new(2));
        let request_gate = Arc::new(tokio::sync::Semaphore::new(1));
        let metrics = Arc::new(H2CarrierMetrics::default());
        let lease = H2CarrierLease {
            sender,
            pending_open_admission: Arc::clone(&pending_open_admission),
            request_gate: Arc::clone(&request_gate),
            key: H2CarrierKey {
                generation: OwnerGeneration::new(91),
                digest: [0; 32],
            },
            instance_id: 1,
            tls_underlay: "test",
            owner: Weak::new(),
            metrics: Arc::clone(&metrics),
        };
        let request = |path: &str| {
            http::Request::builder()
                .method(http::Method::POST)
                .version(http::Version::HTTP_2)
                .uri(format!("https://h2.fixture.invalid/{path}"))
                .body(())
                .unwrap()
        };
        let deadline =
            || AbsoluteDeadline::from_now(Instant::now(), std::time::Duration::from_millis(500));

        let (first_response, _) = lease
            .open_request(request("first"), true, deadline(), "first")
            .await
            .unwrap();
        let (second_response, _) = time::timeout(
            std::time::Duration::from_millis(200),
            lease.open_request(request("second"), true, deadline(), "second"),
        )
        .await
        .expect("second request waited for the first response headers")
        .unwrap();
        assert_eq!(request_gate.available_permits(), 1);
        assert_eq!(metrics.active_pending_opens.load(Ordering::Relaxed), 2);
        time::timeout(std::time::Duration::from_millis(200), both_requests_rx)
            .await
            .expect("server did not receive both requests")
            .expect("server dropped request observation");
        first_response.await.unwrap();
        second_response.await.unwrap();
        assert_eq!(metrics.active_pending_opens.load(Ordering::Relaxed), 0);
        assert_eq!(pending_open_admission.available_permits(), 2);

        client_task.abort();
        let _ = client_task.await;
        server_task.abort();
        let _ = server_task.await;
    }
}
