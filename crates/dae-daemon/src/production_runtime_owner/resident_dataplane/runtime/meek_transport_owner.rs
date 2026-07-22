use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
#[cfg(test)]
use std::thread::JoinHandle;
use std::time::Instant;

use dae_runtime_control::{AbsoluteDeadline, OwnerGeneration};
use serde_json::{Value, json};
use tokio::sync::Notify;
use tokio::time;

use super::*;
use crate::production_runtime_owner::resident_dataplane::client::{
    AsyncResidentTlsClient, open_async_resident_tls_client_with_binding,
};
use crate::production_runtime_owner::resident_dataplane::plan::ResidentProxyBinding;
use crate::production_runtime_owner::resident_dataplane::transport_identity::resident_transport_binding_identity_digest;

const MEEK_TRANSPORT_IDENTITY_DOMAIN: &[u8] = b"dae/meek-transport-owner/v1";

static MEEK_TRANSPORT_GENERATIONS: OnceLock<
    Mutex<HashMap<u64, Weak<MeekTransportGenerationOwner>>>,
> = OnceLock::new();

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
struct MeekTransportKey {
    generation: OwnerGeneration,
    digest: [u8; 32],
}

impl MeekTransportKey {
    fn for_binding(binding: &ResidentProxyBinding) -> Self {
        Self {
            generation: binding.runtime_generation(),
            digest: resident_transport_binding_identity_digest(
                MEEK_TRANSPORT_IDENTITY_DOMAIN,
                binding,
            ),
        }
    }
}

impl std::fmt::Debug for MeekTransportKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MeekTransportKey")
            .field("generation", &self.generation)
            .field("digest", &"<redacted>")
            .finish()
    }
}

#[derive(Default)]
struct MeekTransportMetrics {
    reserved_physical: AtomicUsize,
    high_water_reserved_physical: AtomicUsize,
    active_physical: AtomicUsize,
    high_water_physical: AtomicUsize,
    active_leases: AtomicUsize,
    high_water_leases: AtomicUsize,
    idle_physical: AtomicUsize,
    high_water_idle_physical: AtomicUsize,
    active_builds: AtomicUsize,
    cumulative_builds: AtomicU64,
    cumulative_build_failures: AtomicU64,
    cumulative_reuses: AtomicU64,
    cumulative_retirements: AtomicU64,
    cumulative_idle_expirations: AtomicU64,
    owner_limit_rejections: AtomicU64,
    physical_limit_rejections: AtomicU64,
    capacity_waits: AtomicU64,
    shutdown_timed_out: AtomicBool,
}

impl MeekTransportMetrics {
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

    fn lease_opened(&self) {
        let current = self.active_leases.fetch_add(1, Ordering::Relaxed) + 1;
        Self::update_high_water(&self.high_water_leases, current);
    }

    fn lease_closed(&self) {
        self.active_leases.fetch_sub(1, Ordering::Relaxed);
    }

    fn idle_opened(&self) {
        let current = self.idle_physical.fetch_add(1, Ordering::Relaxed) + 1;
        Self::update_high_water(&self.high_water_idle_physical, current);
    }

    fn idle_closed(&self) {
        self.idle_physical.fetch_sub(1, Ordering::Relaxed);
    }
}

struct MeekTransportPool {
    idle: Mutex<VecDeque<MeekIdlePhysical>>,
    physical_count: AtomicUsize,
}

impl MeekTransportPool {
    fn new() -> Self {
        Self {
            idle: Mutex::new(VecDeque::new()),
            physical_count: AtomicUsize::new(0),
        }
    }
}

struct MeekTransportGenerationOwner {
    generation: OwnerGeneration,
    closing: AtomicBool,
    runtime: tokio::runtime::Handle,
    runtime_worker_threads: usize,
    uses_shared_data_plane_executor: bool,
    pools: Mutex<HashMap<MeekTransportKey, Arc<MeekTransportPool>>>,
    builds: Mutex<HashMap<u64, tokio::task::AbortHandle>>,
    resources: MeekTransportResourceProfile,
    metrics: Arc<MeekTransportMetrics>,
    changed: Notify,
    next_build_id: AtomicU64,
}

#[derive(Clone)]
pub(crate) struct MeekTransportGenerationOwnerHandle {
    owner: Arc<MeekTransportGenerationOwner>,
}

impl MeekTransportGenerationOwnerHandle {
    pub(crate) fn metrics_snapshot(&self) -> Value {
        let pools = self.owner.pools.lock().unwrap();
        let registered_keys = pools.len();
        let registered_build_tasks = self.owner.builds.lock().unwrap().len();
        let owner_state_bytes_lower_bound = registered_keys
            .saturating_mul(
                std::mem::size_of::<MeekTransportKey>()
                    .saturating_add(std::mem::size_of::<MeekTransportPool>()),
            )
            .saturating_add(
                registered_build_tasks.saturating_mul(
                    std::mem::size_of::<u64>()
                        .saturating_add(std::mem::size_of::<tokio::task::AbortHandle>()),
                ),
            );
        json!({
            "schemaVersion": 1,
            "owner": "generation-meek-http1-transport-owner",
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
            "reservedPhysicalConnections": self.owner.metrics.reserved_physical.load(Ordering::Relaxed),
            "highWaterReservedPhysicalConnections": self.owner.metrics.high_water_reserved_physical.load(Ordering::Relaxed),
            "activePhysicalConnections": self.owner.metrics.active_physical.load(Ordering::Relaxed),
            "highWaterPhysicalConnections": self.owner.metrics.high_water_physical.load(Ordering::Relaxed),
            "activeLeases": self.owner.metrics.active_leases.load(Ordering::Relaxed),
            "highWaterLeases": self.owner.metrics.high_water_leases.load(Ordering::Relaxed),
            "idlePhysicalConnections": self.owner.metrics.idle_physical.load(Ordering::Relaxed),
            "highWaterIdlePhysicalConnections": self.owner.metrics.high_water_idle_physical.load(Ordering::Relaxed),
            "activeBuilds": self.owner.metrics.active_builds.load(Ordering::Relaxed),
            "cumulativeBuilds": self.owner.metrics.cumulative_builds.load(Ordering::Relaxed),
            "cumulativeBuildFailures": self.owner.metrics.cumulative_build_failures.load(Ordering::Relaxed),
            "cumulativeReuses": self.owner.metrics.cumulative_reuses.load(Ordering::Relaxed),
            "cumulativeRetirements": self.owner.metrics.cumulative_retirements.load(Ordering::Relaxed),
            "cumulativeIdleExpirations": self.owner.metrics.cumulative_idle_expirations.load(Ordering::Relaxed),
            "ownerLimitRejections": self.owner.metrics.owner_limit_rejections.load(Ordering::Relaxed),
            "physicalLimitRejections": self.owner.metrics.physical_limit_rejections.load(Ordering::Relaxed),
            "capacityWaits": self.owner.metrics.capacity_waits.load(Ordering::Relaxed),
            "ownerStateBytesLowerBound": owner_state_bytes_lower_bound,
            "admissionEnforced": true,
            "shutdownTimedOut": self.owner.metrics.shutdown_timed_out.load(Ordering::Relaxed),
            "budget": {
                "owners": self.owner.resources.owner_limit(),
                "physicalConnections": self.owner.resources.physical_connection_limit(),
                "physicalConnectionsPerOwner": self.owner.resources.physical_connections_per_owner(),
                "idleConnectionsPerOwner": self.owner.resources.idle_connection_limit(),
                "idleConnectionTimeoutMs": self.owner.resources.idle_connection_timeout().as_millis().min(u128::from(u64::MAX)) as u64,
            },
        })
    }
}

struct MeekPhysicalPermit {
    owner: Weak<MeekTransportGenerationOwner>,
}

impl Drop for MeekPhysicalPermit {
    fn drop(&mut self) {
        let Some(owner) = self.owner.upgrade() else {
            return;
        };
        owner
            .metrics
            .reserved_physical
            .fetch_sub(1, Ordering::Relaxed);
        owner.changed.notify_waiters();
    }
}

struct MeekPhysicalSlot {
    pool: Arc<MeekTransportPool>,
    _permit: MeekPhysicalPermit,
}

impl Drop for MeekPhysicalSlot {
    fn drop(&mut self) {
        self.pool.physical_count.fetch_sub(1, Ordering::Relaxed);
    }
}

struct MeekPhysicalConnection {
    client: AsyncResidentTlsClient,
    _slot: MeekPhysicalSlot,
    metrics: Arc<MeekTransportMetrics>,
}

impl Drop for MeekPhysicalConnection {
    fn drop(&mut self) {
        self.metrics.physical_closed();
    }
}

struct MeekIdlePhysical {
    physical: MeekPhysicalConnection,
    idle_since: Instant,
}

pub(crate) struct MeekTransportLease {
    physical: Option<MeekPhysicalConnection>,
    pool: Arc<MeekTransportPool>,
    owner: Weak<MeekTransportGenerationOwner>,
    metrics: Arc<MeekTransportMetrics>,
    lease_counted: bool,
}

impl MeekTransportLease {
    pub(crate) fn client_mut(&mut self) -> &mut AsyncResidentTlsClient {
        &mut self
            .physical
            .as_mut()
            .expect("Meek transport lease must own a physical connection")
            .client
    }

    pub(crate) fn recycle(mut self) {
        self.close_lease_metric();
        let Some(physical) = self.physical.take() else {
            return;
        };
        let Some(owner) = self.owner.upgrade() else {
            return;
        };
        if owner.closing.load(Ordering::Acquire) {
            return;
        }
        let mut idle = match self.pool.idle.lock() {
            Ok(idle) => idle,
            Err(_) => return,
        };
        if idle.len() >= owner.resources.idle_connection_limit() {
            owner
                .metrics
                .cumulative_retirements
                .fetch_add(1, Ordering::Relaxed);
            return;
        }
        idle.push_back(MeekIdlePhysical {
            physical,
            idle_since: Instant::now(),
        });
        owner.metrics.idle_opened();
        drop(idle);
        owner.changed.notify_waiters();
    }

    fn close_lease_metric(&mut self) {
        if self.lease_counted {
            self.metrics.lease_closed();
            self.lease_counted = false;
        }
    }
}

impl Drop for MeekTransportLease {
    fn drop(&mut self) {
        self.close_lease_metric();
        if self.physical.is_some()
            && let Some(owner) = self.owner.upgrade()
        {
            owner
                .metrics
                .cumulative_retirements
                .fetch_add(1, Ordering::Relaxed);
            owner.changed.notify_waiters();
        }
    }
}

struct MeekBuildGuard {
    owner: Arc<MeekTransportGenerationOwner>,
    build_id: u64,
}

impl Drop for MeekBuildGuard {
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

enum MeekReservationError {
    Wait,
    Closing(String),
}

#[cfg(test)]
pub(crate) fn start_meek_transport_generation_owner(
    generation: u64,
    stop: SharedResidentStopSignal,
    thread_stack_bytes: usize,
    runtime_worker_threads: usize,
) -> Result<(MeekTransportGenerationOwnerHandle, JoinHandle<()>), String> {
    start_meek_transport_generation_owner_with_resources(
        generation,
        stop,
        thread_stack_bytes,
        runtime_worker_threads,
        MeekTransportResourceProfile::selected(),
    )
}

#[cfg(test)]
pub(crate) fn start_meek_transport_generation_owner_for_test(
    generation: u64,
    stop: SharedResidentStopSignal,
    thread_stack_bytes: usize,
    runtime_worker_threads: usize,
    resources: MeekTransportResourceProfile,
) -> Result<(MeekTransportGenerationOwnerHandle, JoinHandle<()>), String> {
    start_meek_transport_generation_owner_with_resources(
        generation,
        stop,
        thread_stack_bytes,
        runtime_worker_threads,
        resources,
    )
}

#[cfg(test)]
fn start_meek_transport_generation_owner_with_resources(
    generation: u64,
    stop: SharedResidentStopSignal,
    thread_stack_bytes: usize,
    runtime_worker_threads: usize,
    resources: MeekTransportResourceProfile,
) -> Result<(MeekTransportGenerationOwnerHandle, JoinHandle<()>), String> {
    let runtime_worker_threads = runtime_worker_threads.max(1);
    let runtime = if runtime_worker_threads == 1 {
        tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
    } else {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(runtime_worker_threads)
            .thread_name("resident-meek-transport-runtime")
            .thread_stack_size(thread_stack_bytes)
            .enable_io()
            .enable_time()
            .build()
    }
    .map_err(|error| format!("build Meek transport owner runtime: {error}"))?;
    let owner = Arc::new(MeekTransportGenerationOwner {
        generation: OwnerGeneration::new(generation),
        closing: AtomicBool::new(false),
        runtime: runtime.handle().clone(),
        runtime_worker_threads,
        uses_shared_data_plane_executor: false,
        pools: Mutex::new(HashMap::new()),
        builds: Mutex::new(HashMap::new()),
        resources,
        metrics: Arc::new(MeekTransportMetrics::default()),
        changed: Notify::new(),
        next_build_id: AtomicU64::new(1),
    });
    register_meek_transport_generation(&owner)?;
    let thread_owner = Arc::clone(&owner);
    let thread = std::thread::Builder::new()
        .name(format!("resident-meek-transport-owner-{generation}"))
        .stack_size(thread_stack_bytes)
        .spawn(move || {
            runtime.block_on(async move {
                let interval = thread_owner.resources.idle_janitor_interval();
                let mut janitor = time::interval(interval);
                janitor.set_missed_tick_behavior(time::MissedTickBehavior::Delay);
                let mut stop_listener = stop.listener();
                loop {
                    tokio::select! {
                        _ = stop_listener.cancelled() => break,
                        _ = janitor.tick() => prune_expired_meek_idle(&thread_owner),
                    }
                }
                thread_owner.closing.store(true, Ordering::Release);
                unregister_meek_transport_generation(&thread_owner);
                cleanup_meek_transport_owner(&thread_owner).await;
            });
        })
        .map_err(|error| {
            unregister_meek_transport_generation(&owner);
            format!("spawn Meek transport owner runtime: {error}")
        })?;
    Ok((MeekTransportGenerationOwnerHandle { owner }, thread))
}

pub(crate) fn start_meek_transport_generation_owner_on(
    runtime: &tokio::runtime::Handle,
    generation: u64,
    stop: SharedResidentStopSignal,
    runtime_worker_threads: usize,
) -> Result<
    (
        MeekTransportGenerationOwnerHandle,
        tokio::task::JoinHandle<()>,
    ),
    String,
> {
    let owner = Arc::new(MeekTransportGenerationOwner {
        generation: OwnerGeneration::new(generation),
        closing: AtomicBool::new(false),
        runtime: runtime.clone(),
        runtime_worker_threads: runtime_worker_threads.max(1),
        uses_shared_data_plane_executor: true,
        pools: Mutex::new(HashMap::new()),
        builds: Mutex::new(HashMap::new()),
        resources: MeekTransportResourceProfile::selected(),
        metrics: Arc::new(MeekTransportMetrics::default()),
        changed: Notify::new(),
        next_build_id: AtomicU64::new(1),
    });
    register_meek_transport_generation(&owner)?;
    let task_owner = Arc::clone(&owner);
    let task = runtime.spawn(async move {
        let mut janitor = time::interval(task_owner.resources.idle_janitor_interval());
        janitor.set_missed_tick_behavior(time::MissedTickBehavior::Delay);
        let mut stop_listener = stop.listener();
        loop {
            tokio::select! {
                _ = stop_listener.cancelled() => break,
                _ = janitor.tick() => prune_expired_meek_idle(&task_owner),
            }
        }
        task_owner.closing.store(true, Ordering::Release);
        unregister_meek_transport_generation(&task_owner);
        cleanup_meek_transport_owner(&task_owner).await;
    });
    Ok((MeekTransportGenerationOwnerHandle { owner }, task))
}

fn register_meek_transport_generation(
    owner: &Arc<MeekTransportGenerationOwner>,
) -> Result<(), String> {
    let mut generations = MEEK_TRANSPORT_GENERATIONS
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .map_err(|_| "Meek transport generation registry lock poisoned".to_owned())?;
    generations.retain(|_, owner| owner.strong_count() > 0);
    if generations
        .get(&owner.generation.get())
        .and_then(Weak::upgrade)
        .is_some_and(|registered| !registered.closing.load(Ordering::Acquire))
    {
        return Err(format!(
            "Meek transport generation {} is already active",
            owner.generation.get()
        ));
    }
    generations.insert(owner.generation.get(), Arc::downgrade(owner));
    Ok(())
}

fn unregister_meek_transport_generation(owner: &Arc<MeekTransportGenerationOwner>) {
    if let Some(generations) = MEEK_TRANSPORT_GENERATIONS.get()
        && let Ok(mut generations) = generations.lock()
        && generations
            .get(&owner.generation.get())
            .and_then(Weak::upgrade)
            .is_some_and(|registered| Arc::ptr_eq(&registered, owner))
    {
        generations.remove(&owner.generation.get());
    }
}

fn meek_transport_generation(
    generation: OwnerGeneration,
) -> Result<Arc<MeekTransportGenerationOwner>, String> {
    let owner = MEEK_TRANSPORT_GENERATIONS
        .get()
        .and_then(|generations| generations.lock().ok())
        .and_then(|generations| generations.get(&generation.get()).and_then(Weak::upgrade))
        .ok_or_else(|| {
            format!(
                "Meek transport generation {} is unavailable",
                generation.get()
            )
        })?;
    if owner.closing.load(Ordering::Acquire) {
        return Err(format!(
            "Meek transport generation {} is closing",
            generation.get()
        ));
    }
    Ok(owner)
}

fn meek_transport_pool(
    owner: &Arc<MeekTransportGenerationOwner>,
    key: MeekTransportKey,
) -> Result<Arc<MeekTransportPool>, String> {
    let mut pools = owner
        .pools
        .lock()
        .map_err(|_| "Meek transport owner map lock poisoned".to_owned())?;
    if let Some(pool) = pools.get(&key) {
        return Ok(Arc::clone(pool));
    }
    if pools.len() >= owner.resources.owner_limit() {
        owner
            .metrics
            .owner_limit_rejections
            .fetch_add(1, Ordering::Relaxed);
        return Err(format!(
            "Meek transport owner budget is full ({})",
            owner.resources.owner_limit()
        ));
    }
    let pool = Arc::new(MeekTransportPool::new());
    pools.insert(key, Arc::clone(&pool));
    Ok(pool)
}

pub(crate) async fn acquire_meek_transport(
    binding: ResidentProxyBinding,
    deadline: AbsoluteDeadline,
) -> Result<MeekTransportLease, String> {
    let key = MeekTransportKey::for_binding(&binding);
    let owner = meek_transport_generation(key.generation)?;
    let pool = meek_transport_pool(&owner, key)?;
    loop {
        if owner.closing.load(Ordering::Acquire) {
            return Err(format!(
                "Meek transport generation {} is closing",
                owner.generation.get()
            ));
        }
        prune_pool_expired_idle(&owner, &pool, Instant::now());
        if let Some(physical) = take_meek_idle(&owner, &pool) {
            owner.metrics.lease_opened();
            owner
                .metrics
                .cumulative_reuses
                .fetch_add(1, Ordering::Relaxed);
            return Ok(MeekTransportLease {
                physical: Some(physical),
                pool,
                owner: Arc::downgrade(&owner),
                metrics: Arc::clone(&owner.metrics),
                lease_counted: true,
            });
        }
        match try_reserve_meek_physical(&owner, &pool) {
            Ok(slot) => {
                let receiver = spawn_meek_transport_build(&owner, binding.clone(), deadline, slot)?;
                let remaining = deadline
                    .remaining_at(Instant::now())
                    .ok_or_else(|| "Meek transport acquisition deadline elapsed".to_owned())?;
                let physical = time::timeout(remaining, receiver)
                    .await
                    .map_err(|_| "Meek transport acquisition deadline elapsed".to_owned())?
                    .map_err(|_| "Meek transport build stopped before completion".to_owned())??;
                owner.metrics.lease_opened();
                return Ok(MeekTransportLease {
                    physical: Some(physical),
                    pool,
                    owner: Arc::downgrade(&owner),
                    metrics: Arc::clone(&owner.metrics),
                    lease_counted: true,
                });
            }
            Err(MeekReservationError::Closing(error)) => return Err(error),
            Err(MeekReservationError::Wait) => {
                owner.metrics.capacity_waits.fetch_add(1, Ordering::Relaxed);
                let notified = owner.changed.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                if pool.idle.lock().is_ok_and(|idle| !idle.is_empty()) {
                    continue;
                }
                let remaining = deadline
                    .remaining_at(Instant::now())
                    .ok_or_else(|| "Meek transport capacity deadline elapsed".to_owned())?;
                time::timeout(remaining, notified.as_mut())
                    .await
                    .map_err(|_| "Meek transport capacity deadline elapsed".to_owned())?;
            }
        }
    }
}

fn take_meek_idle(
    owner: &Arc<MeekTransportGenerationOwner>,
    pool: &Arc<MeekTransportPool>,
) -> Option<MeekPhysicalConnection> {
    let physical = pool.idle.lock().ok()?.pop_front()?.physical;
    owner.metrics.idle_closed();
    Some(physical)
}

fn try_reserve_meek_physical(
    owner: &Arc<MeekTransportGenerationOwner>,
    pool: &Arc<MeekTransportPool>,
) -> Result<MeekPhysicalSlot, MeekReservationError> {
    if owner.closing.load(Ordering::Acquire) {
        return Err(MeekReservationError::Closing(format!(
            "Meek transport generation {} is closing",
            owner.generation.get()
        )));
    }
    let per_owner_limit = owner.resources.physical_connections_per_owner();
    let mut pool_count = pool.physical_count.load(Ordering::Relaxed);
    loop {
        if pool_count >= per_owner_limit {
            return Err(MeekReservationError::Wait);
        }
        match pool.physical_count.compare_exchange_weak(
            pool_count,
            pool_count + 1,
            Ordering::AcqRel,
            Ordering::Relaxed,
        ) {
            Ok(_) => break,
            Err(observed) => pool_count = observed,
        }
    }
    let global_limit = owner.resources.physical_connection_limit();
    let mut global_count = owner.metrics.reserved_physical.load(Ordering::Relaxed);
    loop {
        if global_count >= global_limit {
            pool.physical_count.fetch_sub(1, Ordering::Relaxed);
            owner
                .metrics
                .physical_limit_rejections
                .fetch_add(1, Ordering::Relaxed);
            return Err(MeekReservationError::Wait);
        }
        match owner.metrics.reserved_physical.compare_exchange_weak(
            global_count,
            global_count + 1,
            Ordering::AcqRel,
            Ordering::Relaxed,
        ) {
            Ok(_) => {
                MeekTransportMetrics::update_high_water(
                    &owner.metrics.high_water_reserved_physical,
                    global_count + 1,
                );
                return Ok(MeekPhysicalSlot {
                    pool: Arc::clone(pool),
                    _permit: MeekPhysicalPermit {
                        owner: Arc::downgrade(owner),
                    },
                });
            }
            Err(observed) => global_count = observed,
        }
    }
}

fn spawn_meek_transport_build(
    owner: &Arc<MeekTransportGenerationOwner>,
    binding: ResidentProxyBinding,
    deadline: AbsoluteDeadline,
    slot: MeekPhysicalSlot,
) -> Result<tokio::sync::oneshot::Receiver<Result<MeekPhysicalConnection, String>>, String> {
    let mut builds = owner
        .builds
        .lock()
        .map_err(|_| "Meek transport build inventory lock poisoned".to_owned())?;
    if owner.closing.load(Ordering::Acquire) {
        return Err(format!(
            "Meek transport generation {} is closing",
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
    let guard = MeekBuildGuard {
        owner: Arc::clone(owner),
        build_id,
    };
    let build_owner = Arc::clone(owner);
    let (result_sender, result_receiver) = tokio::sync::oneshot::channel();
    let (start_sender, start_receiver) = tokio::sync::oneshot::channel();
    let task = owner.runtime.spawn(async move {
        let _guard = guard;
        if start_receiver.await.is_err() {
            return;
        }
        let result = build_meek_transport(&build_owner, &binding, deadline, slot).await;
        if result.is_err() {
            build_owner
                .metrics
                .cumulative_build_failures
                .fetch_add(1, Ordering::Relaxed);
        }
        let _ = result_sender.send(result);
    });
    builds.insert(build_id, task.abort_handle());
    if start_sender.send(()).is_err() {
        task.abort();
        return Err("Meek transport build stopped before startup".to_owned());
    }
    Ok(result_receiver)
}

async fn build_meek_transport(
    owner: &Arc<MeekTransportGenerationOwner>,
    binding: &ResidentProxyBinding,
    deadline: AbsoluteDeadline,
    slot: MeekPhysicalSlot,
) -> Result<MeekPhysicalConnection, String> {
    let proxy = binding.plan();
    let remaining = deadline
        .remaining_at(Instant::now())
        .ok_or_else(|| "Meek transport TLS deadline elapsed".to_owned())?;
    let client = time::timeout(
        remaining,
        open_async_resident_tls_client_with_binding(binding, proxy.mptcp),
    )
    .await
    .map_err(|_| "Meek transport TLS deadline elapsed".to_owned())??;
    match client.negotiated_alpn() {
        None | Some(b"http/1.1") => {}
        Some(protocol) => {
            return Err(format!(
                "Meek HTTP/1.1 transport negotiated unsupported ALPN {}",
                String::from_utf8_lossy(protocol)
            ));
        }
    }
    owner.metrics.physical_opened();
    Ok(MeekPhysicalConnection {
        client,
        _slot: slot,
        metrics: Arc::clone(&owner.metrics),
    })
}

fn prune_expired_meek_idle(owner: &Arc<MeekTransportGenerationOwner>) {
    let pools = owner
        .pools
        .lock()
        .map(|pools| pools.values().cloned().collect::<Vec<_>>())
        .unwrap_or_default();
    let now = Instant::now();
    for pool in pools {
        prune_pool_expired_idle(owner, &pool, now);
    }
}

fn prune_pool_expired_idle(
    owner: &Arc<MeekTransportGenerationOwner>,
    pool: &Arc<MeekTransportPool>,
    now: Instant,
) {
    let mut expired = Vec::new();
    if let Ok(mut idle) = pool.idle.lock() {
        while idle.front().is_some_and(|entry| {
            now.saturating_duration_since(entry.idle_since)
                >= owner.resources.idle_connection_timeout()
        }) {
            if let Some(entry) = idle.pop_front() {
                expired.push(entry.physical);
            }
        }
    }
    if expired.is_empty() {
        return;
    }
    owner
        .metrics
        .idle_physical
        .fetch_sub(expired.len(), Ordering::Relaxed);
    owner
        .metrics
        .cumulative_idle_expirations
        .fetch_add(expired.len() as u64, Ordering::Relaxed);
    drop(expired);
}

async fn cleanup_meek_transport_owner(owner: &Arc<MeekTransportGenerationOwner>) {
    let pools = owner
        .pools
        .lock()
        .map(|mut pools| pools.drain().map(|(_, pool)| pool).collect::<Vec<_>>())
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
        for pool in pools {
            let idle = pool
                .idle
                .lock()
                .map(|mut idle| idle.drain(..).collect::<Vec<_>>())
                .unwrap_or_default();
            owner
                .metrics
                .idle_physical
                .fetch_sub(idle.len(), Ordering::Relaxed);
            drop(idle);
        }
        owner.changed.notify_waiters();
        while owner.metrics.active_physical.load(Ordering::Relaxed) != 0
            || owner.metrics.active_leases.load(Ordering::Relaxed) != 0
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
    #[test]
    fn meek_transport_source_keeps_tls_construction_inside_the_owner() {
        let owner = include_str!("meek_transport_owner.rs");
        let polling = include_str!("../tcp/vless_handlers/meek.rs");
        let runtime_owner = include_str!("../runtime_owner.rs");
        let subscription = include_str!("../subscription_fetch.rs");
        let control_owners = include_str!("../control_transport_owners/mod.rs");
        let requirements = include_str!("../control_transport_owners/requirements.rs");
        let model = include_str!("../plan/model.rs");
        let production = owner
            .split_once("#[cfg(test)]\nmod tests")
            .map_or(owner, |(production, _)| production);
        assert!(production.contains("open_async_resident_tls_client_with_binding"));
        assert!(!polling.contains("open_async_resident_tls_client"));
        assert!(polling.contains("acquire_meek_transport"));
        assert!(runtime_owner.contains("start_meek_transport_generation_owner"));
        assert!(requirements.contains("requires_meek_transport_owner"));
        assert!(subscription.contains("ControlTransportOwners"));
        assert!(control_owners.contains("start_meek_transport_generation_owner_on"));
        assert!(model.contains("requires_meek_transport_owner"));
    }
}
