use std::collections::{HashMap, VecDeque};
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::thread::JoinHandle;
use std::time::Instant;

use dae_outbound_quic::juicity::{JuicityAuthStream, authenticate_juicity_connection};
use dae_runtime_control::{AbsoluteDeadline, OwnerGeneration};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinSet;
use tokio::time;

use dae_resident_core::{
    JuicityOwnerResourceProfile, RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE, SharedResidentStopSignal,
};
use dae_resident_model::{ResidentProxyBinding, ResidentProxyProtocolPlan};

use crate::quic_connections::{
    ResidentConnectedQuicEndpoint, open_juicity_quic_connection_candidates_async,
};
use crate::{
    ObservedQuicEndpoint, QuicEndpointCallerClass, QuicEndpointDrainReport,
    wait_quic_endpoint_idle_after_close_for, wait_quic_endpoints_idle_until,
};

async fn wait_quic_endpoint_idle_after_close(endpoint: &ObservedQuicEndpoint) -> bool {
    wait_quic_endpoint_idle_after_close_for(endpoint, RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE).await
}

#[derive(Clone, Debug, Eq)]
struct JuicityOwnerKey {
    generation: OwnerGeneration,
    graph_link_hash: String,
    mark: u32,
    congestion: dae_outbound_quic::juicity::JuicityCongestionController,
}

impl PartialEq for JuicityOwnerKey {
    fn eq(&self, other: &Self) -> bool {
        self.generation == other.generation
            && self.graph_link_hash == other.graph_link_hash
            && self.mark == other.mark
            && self.congestion == other.congestion
    }
}

impl Hash for JuicityOwnerKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.generation.hash(state);
        self.graph_link_hash.hash(state);
        self.mark.hash(state);
        self.congestion.hash(state);
    }
}

impl JuicityOwnerKey {
    fn for_binding(binding: &ResidentProxyBinding) -> Result<Self, String> {
        let proxy = binding.plan();
        let ResidentProxyProtocolPlan::JuicityQuicTcp { congestion, .. } = &proxy.handler else {
            return Err(
                "Juicity owner key received a non-Juicity proxy shape; refusing to panic on the data plane"
                    .to_owned(),
            );
        };
        Ok(Self {
            generation: binding.runtime_generation(),
            graph_link_hash: proxy.graph_link_hash.clone(),
            mark: binding.effective_socket_mark(),
            congestion: *congestion,
        })
    }

    fn report_identity(&self) -> String {
        format!(
            "generation:{}:graph:{}:mark:{}:congestion:{}",
            self.generation.get(),
            self.graph_link_hash,
            self.mark,
            self.congestion.as_str()
        )
    }
}

#[derive(Default)]
struct JuicityOwnerMetrics {
    active_pools: AtomicUsize,
    high_water_pools: AtomicUsize,
    active_physical_owners: AtomicUsize,
    high_water_physical_owners: AtomicUsize,
    active_builds: AtomicUsize,
    active_logical_leases: AtomicUsize,
    high_water_logical_leases: AtomicUsize,
    active_waiters: AtomicUsize,
    high_water_waiters: AtomicUsize,
    cumulative_builds: AtomicU64,
    cumulative_build_failures: AtomicU64,
    cumulative_reuses: AtomicU64,
    owner_limit_rejections: AtomicU64,
    pool_capacity_rejections: AtomicU64,
    waiter_limit_rejections: AtomicU64,
    retry_cooldown_rejections: AtomicU64,
    remote_closes: AtomicU64,
    shutdown_timed_out: AtomicBool,
    endpoint_drain_requested: AtomicUsize,
    endpoint_drain_completed: AtomicUsize,
    endpoint_drain_timed_out: AtomicUsize,
}

impl JuicityOwnerMetrics {
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

    fn pool_opened(&self) {
        let active = self.active_pools.fetch_add(1, Ordering::Relaxed) + 1;
        Self::update_high_water(&self.high_water_pools, active);
    }

    fn pool_closed(&self) {
        self.active_pools.fetch_sub(1, Ordering::Relaxed);
    }

    fn physical_owner_opened(&self) {
        let active = self.active_physical_owners.fetch_add(1, Ordering::Relaxed) + 1;
        Self::update_high_water(&self.high_water_physical_owners, active);
    }

    fn physical_owner_closed(&self) {
        self.active_physical_owners.fetch_sub(1, Ordering::Relaxed);
    }

    fn logical_lease_opened(&self) {
        let active = self.active_logical_leases.fetch_add(1, Ordering::Relaxed) + 1;
        Self::update_high_water(&self.high_water_logical_leases, active);
    }

    fn logical_lease_closed(&self) {
        self.active_logical_leases.fetch_sub(1, Ordering::Relaxed);
    }

    fn waiter_queued(&self) {
        let active = self.active_waiters.fetch_add(1, Ordering::Relaxed) + 1;
        Self::update_high_water(&self.high_water_waiters, active);
    }

    fn waiter_removed(&self) {
        self.active_waiters.fetch_sub(1, Ordering::Relaxed);
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

struct JuicityRegistryOwnershipReconciler {
    metrics: Arc<JuicityOwnerMetrics>,
    shutdown_finished: bool,
}

impl JuicityRegistryOwnershipReconciler {
    fn new(metrics: Arc<JuicityOwnerMetrics>) -> Self {
        Self {
            metrics,
            shutdown_finished: false,
        }
    }

    fn finish_shutdown(&mut self) {
        self.shutdown_finished = true;
    }
}

impl Drop for JuicityRegistryOwnershipReconciler {
    fn drop(&mut self) {
        self.metrics.active_pools.store(0, Ordering::Release);
        self.metrics
            .active_physical_owners
            .store(0, Ordering::Release);
        self.metrics.active_builds.store(0, Ordering::Release);
        self.metrics.active_waiters.store(0, Ordering::Release);
        if !self.shutdown_finished {
            self.metrics
                .shutdown_timed_out
                .store(true, Ordering::Release);
        }
    }
}

struct JuicityEndpointDrainGuard {
    metrics: Arc<JuicityOwnerMetrics>,
    requested: usize,
    finished: bool,
}

impl JuicityEndpointDrainGuard {
    fn new(metrics: Arc<JuicityOwnerMetrics>, requested: usize) -> Self {
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

impl Drop for JuicityEndpointDrainGuard {
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

struct JuicitySharedTransport {
    connection: quinn::Connection,
    instance_id: u64,
    active_leases: AtomicUsize,
    usable_streams: usize,
    auth_token_nonzero: bool,
    metrics: Arc<JuicityOwnerMetrics>,
}

impl JuicitySharedTransport {
    fn try_lease(self: &Arc<Self>) -> Option<JuicityTransportLease> {
        if self.connection.close_reason().is_some() {
            return None;
        }
        let mut active = self.active_leases.load(Ordering::Relaxed);
        loop {
            if active >= self.usable_streams {
                return None;
            }
            match self.active_leases.compare_exchange_weak(
                active,
                active + 1,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    self.metrics.logical_lease_opened();
                    return Some(JuicityTransportLease {
                        shared: Arc::clone(self),
                    });
                }
                Err(observed) => active = observed,
            }
        }
    }
}

pub struct JuicityTransportLease {
    shared: Arc<JuicitySharedTransport>,
}

impl JuicityTransportLease {
    #[cfg(any(test, feature = "test-support"))]
    pub fn connection_stable_id(&self) -> usize {
        self.shared.connection.stable_id()
    }

    pub fn physical_owner_id(&self) -> u64 {
        self.shared.instance_id
    }

    pub fn auth_token_nonzero(&self) -> bool {
        self.shared.auth_token_nonzero
    }

    pub async fn open_stream(
        &self,
        deadline: AbsoluteDeadline,
    ) -> Result<(quinn::SendStream, quinn::RecvStream), String> {
        let remaining = deadline
            .remaining_at(Instant::now())
            .ok_or_else(|| "Juicity stream open deadline elapsed".to_owned())?;
        match time::timeout(remaining, self.shared.connection.open_bi()).await {
            Ok(Ok(stream)) => Ok(stream),
            Ok(Err(err)) => {
                self.shared
                    .connection
                    .close(0x101_u32.into(), b"juicity stream open failed");
                Err(format!("open Juicity QUIC stream: {err}"))
            }
            Err(_) => Err("Juicity stream open deadline elapsed".to_owned()),
        }
    }
}

impl Drop for JuicityTransportLease {
    fn drop(&mut self) {
        self.shared.active_leases.fetch_sub(1, Ordering::AcqRel);
        self.shared.metrics.logical_lease_closed();
    }
}

struct JuicityOwnedTransport {
    shared: Arc<JuicitySharedTransport>,
    endpoint: ObservedQuicEndpoint,
    auth_stream: JuicityAuthStream,
}

impl JuicityOwnedTransport {
    fn begin_close(mut self) -> ObservedQuicEndpoint {
        let _ = self.auth_stream.request_finish();
        self.shared
            .connection
            .close(0_u32.into(), b"juicity owner stopped");
        self.endpoint.close(0_u32.into(), b"juicity owner stopped");
        self.endpoint
    }

    async fn close(self) {
        let endpoint = self.begin_close();
        wait_quic_endpoint_idle_after_close(&endpoint).await;
    }
}

struct JuicityAcquireCommand {
    key: JuicityOwnerKey,
    binding: ResidentProxyBinding,
    caller: QuicEndpointCallerClass,
    deadline: AbsoluteDeadline,
    response: oneshot::Sender<Result<JuicityTransportLease, String>>,
}

enum JuicityOwnerCommand {
    Acquire(JuicityAcquireCommand),
}

struct JuicityOwnerPool {
    transports: Vec<JuicityOwnedTransport>,
    building: bool,
    waiters: VecDeque<JuicityAcquireCommand>,
}

impl JuicityOwnerPool {
    fn new() -> Self {
        Self {
            transports: Vec::new(),
            building: false,
            waiters: VecDeque::new(),
        }
    }

    fn try_lease(&self) -> Option<JuicityTransportLease> {
        self.transports
            .iter()
            .find_map(|transport| transport.shared.try_lease())
    }
}

struct JuicityBuildCompletion {
    key: JuicityOwnerKey,
    result: Result<JuicityOwnedTransport, String>,
}

struct JuicityCloseEvent {
    key: JuicityOwnerKey,
    instance_id: u64,
}

enum JuicityOwnerTaskCompletion {
    Build(JuicityBuildCompletion),
    Closed(JuicityCloseEvent),
}

#[derive(Clone)]
pub struct JuicityOwnerRegistryHandle {
    generation: OwnerGeneration,
    sender: mpsc::Sender<JuicityOwnerCommand>,
    resources: JuicityOwnerResourceProfile,
    metrics: Arc<JuicityOwnerMetrics>,
}

impl JuicityOwnerRegistryHandle {
    pub async fn acquire(
        &self,
        binding: ResidentProxyBinding,
        caller: QuicEndpointCallerClass,
        deadline: AbsoluteDeadline,
    ) -> Result<JuicityTransportLease, String> {
        let key = JuicityOwnerKey::for_binding(&binding)?;
        if key.generation != self.generation {
            return Err(format!(
                "Juicity owner generation mismatch: requested={} active={}",
                key.generation.get(),
                self.generation.get()
            ));
        }
        let (response, receiver) = oneshot::channel();
        let command = JuicityOwnerCommand::Acquire(JuicityAcquireCommand {
            key,
            binding,
            caller,
            deadline,
            response,
        });
        let remaining = deadline
            .remaining_at(Instant::now())
            .ok_or_else(|| "Juicity owner acquisition deadline elapsed".to_owned())?;
        time::timeout(remaining, self.sender.send(command))
            .await
            .map_err(|_| "Juicity owner command deadline elapsed".to_owned())?
            .map_err(|_| "Juicity owner registry is closed".to_owned())?;
        let remaining = deadline
            .remaining_at(Instant::now())
            .ok_or_else(|| "Juicity owner acquisition deadline elapsed".to_owned())?;
        time::timeout(remaining, receiver)
            .await
            .map_err(|_| "Juicity owner acquisition deadline elapsed".to_owned())?
            .map_err(|_| "Juicity owner registry stopped during acquisition".to_owned())?
    }

    pub fn metrics_snapshot(&self) -> serde_json::Value {
        serde_json::json!({
            "schemaVersion": 1,
            "owner": "resident-juicity-owner-registry",
            "reloadGeneration": self.generation.get(),
            "activePools": self.metrics.active_pools.load(Ordering::Relaxed),
            "highWaterPools": self.metrics.high_water_pools.load(Ordering::Relaxed),
            "activePhysicalOwners": self.metrics.active_physical_owners.load(Ordering::Relaxed),
            "highWaterPhysicalOwners": self.metrics.high_water_physical_owners.load(Ordering::Relaxed),
            "activeBuilds": self.metrics.active_builds.load(Ordering::Relaxed),
            "activeLogicalLeases": self.metrics.active_logical_leases.load(Ordering::Relaxed),
            "highWaterLogicalLeases": self.metrics.high_water_logical_leases.load(Ordering::Relaxed),
            "activeWaiters": self.metrics.active_waiters.load(Ordering::Relaxed),
            "highWaterWaiters": self.metrics.high_water_waiters.load(Ordering::Relaxed),
            "cumulativeBuilds": self.metrics.cumulative_builds.load(Ordering::Relaxed),
            "cumulativeBuildFailures": self.metrics.cumulative_build_failures.load(Ordering::Relaxed),
            "cumulativeReuses": self.metrics.cumulative_reuses.load(Ordering::Relaxed),
            "ownerLimitRejections": self.metrics.owner_limit_rejections.load(Ordering::Relaxed),
            "poolCapacityRejections": self.metrics.pool_capacity_rejections.load(Ordering::Relaxed),
            "waiterLimitRejections": self.metrics.waiter_limit_rejections.load(Ordering::Relaxed),
            "retryCooldownRejections": self.metrics.retry_cooldown_rejections.load(Ordering::Relaxed),
            "remoteCloses": self.metrics.remote_closes.load(Ordering::Relaxed),
            "registryOwnershipReleased": self.metrics.active_pools.load(Ordering::Acquire) == 0
                && self.metrics.active_physical_owners.load(Ordering::Acquire) == 0
                && self.metrics.active_builds.load(Ordering::Acquire) == 0
                && self.metrics.active_waiters.load(Ordering::Acquire) == 0,
            "endpointDrain": {
                "requested": self.metrics.endpoint_drain_requested.load(Ordering::Acquire),
                "completed": self.metrics.endpoint_drain_completed.load(Ordering::Acquire),
                "timedOut": self.metrics.endpoint_drain_timed_out.load(Ordering::Acquire),
            },
            "shutdownTimedOut": self.metrics.shutdown_timed_out.load(Ordering::Relaxed),
            "budget": {
                "physicalOwners": self.resources.owner_limit(),
                "connectionsPerPool": self.resources.connections_per_pool(),
                "logicalStreamsPerConnection": self.resources.logical_streams_per_connection(),
                "reservedStreamsPerConnection": self.resources.reserved_streams_per_connection(),
                "usableStreamsPerConnection": self.resources.usable_streams_per_connection(),
                "commandQueueDepth": self.resources.command_queue_depth(),
                "retryCooldownMs": self.resources.retry_cooldown().as_millis(),
            },
        })
    }
}

pub fn start_juicity_owner_registry(
    generation: u64,
    stop: SharedResidentStopSignal,
    stack_bytes: usize,
) -> Result<(JuicityOwnerRegistryHandle, JoinHandle<()>), String> {
    start_juicity_owner_registry_with_resources(
        generation,
        stop,
        stack_bytes,
        JuicityOwnerResourceProfile::selected(),
    )
}

pub fn start_juicity_owner_registry_with_resources(
    generation: u64,
    stop: SharedResidentStopSignal,
    stack_bytes: usize,
    resources: JuicityOwnerResourceProfile,
) -> Result<(JuicityOwnerRegistryHandle, JoinHandle<()>), String> {
    let generation = OwnerGeneration::new(generation);
    let (sender, receiver) = mpsc::channel(resources.command_queue_depth().max(1));
    let metrics = Arc::new(JuicityOwnerMetrics::default());
    let handle = JuicityOwnerRegistryHandle {
        generation,
        sender,
        resources,
        metrics: Arc::clone(&metrics),
    };
    let (initialized, initialization) = std::sync::mpsc::sync_channel(1);
    let thread = std::thread::Builder::new()
        .name(format!("resident-juicity-owner-{}", generation.get()))
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
                    let _ =
                        initialized.send(Err(format!("build Juicity owner Tokio runtime: {err}")));
                    return;
                }
            };
            runtime.block_on(run_juicity_owner_registry(
                receiver, resources, metrics, stop,
            ));
        })
        .map_err(|err| format!("spawn Juicity owner runtime: {err}"))?;
    initialization
        .recv()
        .map_err(|_| "Juicity owner runtime stopped during initialization".to_owned())??;
    Ok((handle, thread))
}

pub fn start_juicity_owner_registry_on(
    runtime: &tokio::runtime::Handle,
    generation: u64,
    stop: SharedResidentStopSignal,
) -> (JuicityOwnerRegistryHandle, tokio::task::JoinHandle<()>) {
    let generation = OwnerGeneration::new(generation);
    let resources = JuicityOwnerResourceProfile::selected();
    let (sender, receiver) = mpsc::channel(resources.command_queue_depth().max(1));
    let metrics = Arc::new(JuicityOwnerMetrics::default());
    let handle = JuicityOwnerRegistryHandle {
        generation,
        sender,
        resources,
        metrics: Arc::clone(&metrics),
    };
    let task = runtime.spawn(run_juicity_owner_registry(
        receiver, resources, metrics, stop,
    ));
    (handle, task)
}

async fn run_juicity_owner_registry(
    mut receiver: mpsc::Receiver<JuicityOwnerCommand>,
    resources: JuicityOwnerResourceProfile,
    metrics: Arc<JuicityOwnerMetrics>,
    stop: SharedResidentStopSignal,
) {
    let session_cache = Some(dae_outbound_quic::boring_quic::new_boring_quic_session_cache());
    let mut ownership_reconciler = JuicityRegistryOwnershipReconciler::new(Arc::clone(&metrics));
    let mut pools = HashMap::<JuicityOwnerKey, JuicityOwnerPool>::new();
    let mut cooldowns = VecDeque::<(JuicityOwnerKey, Instant)>::new();
    let mut tasks = JoinSet::<JuicityOwnerTaskCompletion>::new();
    let mut physical_slots = 0_usize;
    let mut next_instance_id = 1_u64;
    let mut stop_listener = stop.listener();

    loop {
        tokio::select! {
            _ = stop_listener.cancelled() => break,
            command = receiver.recv() => match command {
                Some(JuicityOwnerCommand::Acquire(command)) => {
                        handle_juicity_acquire(
                        command,
                        &mut pools,
                        &mut cooldowns,
                        &mut tasks,
                        &mut physical_slots,
                        &mut next_instance_id,
                        resources,
                        Arc::clone(&metrics),
                        session_cache.clone(),
                    );
                }
                None => break,
            },
            completion = tasks.join_next(), if !tasks.is_empty() => {
                match completion {
                    Some(Ok(JuicityOwnerTaskCompletion::Build(completion))) => {
                        physical_slots = physical_slots.saturating_sub(1);
                        metrics.active_builds.fetch_sub(1, Ordering::Relaxed);
                        handle_juicity_build_completion(
                            completion,
                            &mut pools,
                            &mut cooldowns,
                            &mut tasks,
                            &mut physical_slots,
                            &mut next_instance_id,
                            resources,
                            Arc::clone(&metrics),
                            session_cache.clone(),
                        );
                    }
                    Some(Ok(JuicityOwnerTaskCompletion::Closed(event))) => {
                        if let Some(pool) = pools.get_mut(&event.key)
                            && let Some(position) = pool.transports.iter().position(|transport| {
                                transport.shared.instance_id == event.instance_id
                            })
                        {
                            let transport = pool.transports.swap_remove(position);
                            physical_slots = physical_slots.saturating_sub(1);
                            metrics.remote_closes.fetch_add(1, Ordering::Relaxed);
                            metrics.physical_owner_closed();
                            transport.close().await;
                        }
                        remove_empty_juicity_pool(&event.key, &mut pools, &metrics);
                    }
                    Some(Err(_)) | None => {}
                }
            }
        }
    }

    receiver.close();
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    for pool in pools.values_mut() {
        for waiter in pool.waiters.drain(..) {
            metrics.waiter_removed();
            let _ = waiter
                .response
                .send(Err("Juicity owner registry is draining".to_owned()));
        }
    }
    let mut endpoints = Vec::with_capacity(physical_slots);
    for (_, mut pool) in pools.drain() {
        while let Some(transport) = pool.transports.pop() {
            metrics.physical_owner_closed();
            endpoints.push(transport.begin_close());
        }
        metrics.pool_closed();
    }
    metrics.active_builds.store(0, Ordering::Relaxed);
    let drain_guard = JuicityEndpointDrainGuard::new(Arc::clone(&metrics), endpoints.len());
    let deadline = time::Instant::now() + RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE;
    let report = wait_quic_endpoints_idle_until(endpoints, deadline).await;
    drain_guard.finish(report);
    if let Some(session_cache) = session_cache {
        let _ = session_cache.clear();
    }
    ownership_reconciler.finish_shutdown();
}

#[allow(clippy::too_many_arguments)]
fn handle_juicity_acquire(
    command: JuicityAcquireCommand,
    pools: &mut HashMap<JuicityOwnerKey, JuicityOwnerPool>,
    cooldowns: &mut VecDeque<(JuicityOwnerKey, Instant)>,
    tasks: &mut JoinSet<JuicityOwnerTaskCompletion>,
    physical_slots: &mut usize,
    next_instance_id: &mut u64,
    resources: JuicityOwnerResourceProfile,
    metrics: Arc<JuicityOwnerMetrics>,
    session_cache: Option<dae_outbound_quic::boring_quic::BoringQuicSessionCache>,
) {
    let now = Instant::now();
    while cooldowns.front().is_some_and(|(_, expiry)| *expiry <= now) {
        cooldowns.pop_front();
    }
    if cooldowns
        .iter()
        .any(|(key, expiry)| key == &command.key && *expiry > now)
    {
        metrics
            .retry_cooldown_rejections
            .fetch_add(1, Ordering::Relaxed);
        let _ = command.response.send(Err(format!(
            "Juicity owner retry cooldown is active for {}",
            command.key.report_identity()
        )));
        return;
    }

    if let Some(pool) = pools.get(&command.key)
        && let Some(lease) = pool.try_lease()
    {
        metrics.cumulative_reuses.fetch_add(1, Ordering::Relaxed);
        let _ = command.response.send(Ok(lease));
        return;
    }

    let is_new_pool = !pools.contains_key(&command.key);
    let pool = pools
        .entry(command.key.clone())
        .or_insert_with(JuicityOwnerPool::new);
    if is_new_pool {
        metrics.pool_opened();
    }
    if pool.waiters.len() >= resources.command_queue_depth() {
        metrics
            .waiter_limit_rejections
            .fetch_add(1, Ordering::Relaxed);
        let _ = command
            .response
            .send(Err("Juicity owner waiter budget is full".to_owned()));
        return;
    }
    if pool.building {
        pool.waiters.push_back(command);
        metrics.waiter_queued();
        return;
    }
    if pool.transports.len() >= resources.connections_per_pool() {
        metrics
            .pool_capacity_rejections
            .fetch_add(1, Ordering::Relaxed);
        let _ = command.response.send(Err(format!(
            "Juicity connection pool is at its bounded capacity ({})",
            resources.connections_per_pool()
        )));
        return;
    }
    if *physical_slots >= resources.owner_limit() {
        metrics
            .owner_limit_rejections
            .fetch_add(1, Ordering::Relaxed);
        let _ = command.response.send(Err(format!(
            "Juicity physical owner budget is full ({})",
            resources.owner_limit()
        )));
        remove_empty_juicity_pool(&command.key, pools, &metrics);
        return;
    }

    pool.waiters.push_back(command);
    metrics.waiter_queued();
    spawn_juicity_transport_build(
        pool,
        tasks,
        physical_slots,
        next_instance_id,
        resources,
        metrics,
        session_cache,
    );
}

fn spawn_juicity_transport_build(
    pool: &mut JuicityOwnerPool,
    tasks: &mut JoinSet<JuicityOwnerTaskCompletion>,
    physical_slots: &mut usize,
    next_instance_id: &mut u64,
    resources: JuicityOwnerResourceProfile,
    metrics: Arc<JuicityOwnerMetrics>,
    session_cache: Option<dae_outbound_quic::boring_quic::BoringQuicSessionCache>,
) {
    pool.building = true;
    *physical_slots += 1;
    metrics.active_builds.fetch_add(1, Ordering::Relaxed);
    metrics.cumulative_builds.fetch_add(1, Ordering::Relaxed);
    let instance_id = *next_instance_id;
    *next_instance_id = next_instance_id.wrapping_add(1).max(1);
    let build = pool
        .waiters
        .front()
        .expect("a Juicity build has its elected waiter");
    let key = build.key.clone();
    let binding = build.binding.clone();
    let caller = build.caller;
    let deadline = build.deadline;
    tasks.spawn(async move {
        JuicityOwnerTaskCompletion::Build(JuicityBuildCompletion {
            key,
            result: build_juicity_transport(
                binding,
                caller,
                deadline,
                instance_id,
                resources,
                metrics,
                session_cache,
            )
            .await,
        })
    });
}

#[allow(clippy::too_many_arguments)]
fn handle_juicity_build_completion(
    completion: JuicityBuildCompletion,
    pools: &mut HashMap<JuicityOwnerKey, JuicityOwnerPool>,
    cooldowns: &mut VecDeque<(JuicityOwnerKey, Instant)>,
    tasks: &mut JoinSet<JuicityOwnerTaskCompletion>,
    physical_slots: &mut usize,
    next_instance_id: &mut u64,
    resources: JuicityOwnerResourceProfile,
    metrics: Arc<JuicityOwnerMetrics>,
    session_cache: Option<dae_outbound_quic::boring_quic::BoringQuicSessionCache>,
) {
    let Some(pool) = pools.get_mut(&completion.key) else {
        return;
    };
    pool.building = false;
    match completion.result {
        Ok(transport) => {
            *physical_slots += 1;
            metrics.physical_owner_opened();
            let connection = transport.shared.connection.clone();
            let instance_id = transport.shared.instance_id;
            let key = completion.key.clone();
            tasks.spawn(async move {
                let _ = connection.closed().await;
                JuicityOwnerTaskCompletion::Closed(JuicityCloseEvent { key, instance_id })
            });
            pool.transports.push(transport);
            while let Some(waiter) = pool.waiters.pop_front() {
                if waiter.deadline.remaining_at(Instant::now()).is_none() {
                    metrics.waiter_removed();
                    let _ = waiter
                        .response
                        .send(Err("Juicity owner acquisition deadline elapsed".to_owned()));
                } else if let Some(lease) = pool.try_lease() {
                    metrics.waiter_removed();
                    let _ = waiter.response.send(Ok(lease));
                } else {
                    pool.waiters.push_front(waiter);
                    break;
                }
            }
            if !pool.waiters.is_empty() {
                if pool.transports.len() >= resources.connections_per_pool() {
                    metrics
                        .pool_capacity_rejections
                        .fetch_add(pool.waiters.len() as u64, Ordering::Relaxed);
                    while let Some(waiter) = pool.waiters.pop_front() {
                        metrics.waiter_removed();
                        let _ = waiter.response.send(Err(format!(
                            "Juicity connection pool is at its bounded capacity ({})",
                            resources.connections_per_pool()
                        )));
                    }
                } else if *physical_slots >= resources.owner_limit() {
                    metrics
                        .owner_limit_rejections
                        .fetch_add(pool.waiters.len() as u64, Ordering::Relaxed);
                    while let Some(waiter) = pool.waiters.pop_front() {
                        metrics.waiter_removed();
                        let _ = waiter.response.send(Err(format!(
                            "Juicity physical owner budget is full ({})",
                            resources.owner_limit()
                        )));
                    }
                } else {
                    spawn_juicity_transport_build(
                        pool,
                        tasks,
                        physical_slots,
                        next_instance_id,
                        resources,
                        Arc::clone(&metrics),
                        session_cache,
                    );
                }
            }
        }
        Err(error) => {
            metrics
                .cumulative_build_failures
                .fetch_add(1, Ordering::Relaxed);
            while let Some(waiter) = pool.waiters.pop_front() {
                metrics.waiter_removed();
                let _ = waiter.response.send(Err(error.clone()));
            }
            if cooldowns.len() >= resources.owner_limit() {
                cooldowns.pop_front();
            }
            cooldowns.push_back((
                completion.key.clone(),
                Instant::now() + resources.retry_cooldown(),
            ));
            remove_empty_juicity_pool(&completion.key, pools, &metrics);
        }
    }
}

fn remove_empty_juicity_pool(
    key: &JuicityOwnerKey,
    pools: &mut HashMap<JuicityOwnerKey, JuicityOwnerPool>,
    metrics: &JuicityOwnerMetrics,
) {
    let removable = pools.get(key).is_some_and(|pool| {
        !pool.building && pool.transports.is_empty() && pool.waiters.is_empty()
    });
    if removable {
        pools.remove(key);
        metrics.pool_closed();
    }
}

async fn build_juicity_transport(
    binding: ResidentProxyBinding,
    caller: QuicEndpointCallerClass,
    deadline: AbsoluteDeadline,
    instance_id: u64,
    resources: JuicityOwnerResourceProfile,
    metrics: Arc<JuicityOwnerMetrics>,
    session_cache: Option<dae_outbound_quic::boring_quic::BoringQuicSessionCache>,
) -> Result<JuicityOwnedTransport, String> {
    let proxy = binding.plan();
    let ResidentProxyProtocolPlan::JuicityQuicTcp {
        uuid,
        password,
        allow_insecure,
        congestion,
        pinned_certchain_sha256,
    } = &proxy.handler
    else {
        return Err("Juicity owner received a non-Juicity proxy shape".to_owned());
    };
    let ResidentConnectedQuicEndpoint {
        endpoint,
        connection,
        ..
    } = open_juicity_quic_connection_candidates_async(
        &binding,
        *allow_insecure,
        pinned_certchain_sha256,
        *congestion,
        deadline,
        caller,
        session_cache,
    )
    .await?;
    let Some(remaining) = deadline.remaining_at(Instant::now()) else {
        endpoint.mark_failed();
        endpoint.close(0_u32.into(), b"juicity auth deadline elapsed");
        wait_quic_endpoint_idle_after_close(&endpoint).await;
        return Err("Juicity owner authentication deadline elapsed".to_owned());
    };
    let (auth_report, auth_stream) = match time::timeout(
        remaining,
        authenticate_juicity_connection(&connection, uuid, password),
    )
    .await
    {
        Ok(Ok(auth)) => auth,
        Ok(Err(err)) => {
            endpoint.mark_failed();
            endpoint.close(0_u32.into(), b"juicity owner auth failed");
            wait_quic_endpoint_idle_after_close(&endpoint).await;
            return Err(format!("authenticate Juicity owner: {err}"));
        }
        Err(_) => {
            endpoint.mark_failed();
            endpoint.close(0_u32.into(), b"juicity owner auth timeout");
            wait_quic_endpoint_idle_after_close(&endpoint).await;
            return Err("Juicity owner authentication deadline elapsed".to_owned());
        }
    };
    endpoint.mark_ready();
    Ok(JuicityOwnedTransport {
        shared: Arc::new(JuicitySharedTransport {
            connection,
            instance_id,
            active_leases: AtomicUsize::new(0),
            usable_streams: resources.usable_streams_per_connection().max(1),
            auth_token_nonzero: auth_report.auth_token_nonzero,
            metrics,
        }),
        endpoint,
        auth_stream,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unfinished_registry_drop_reconciles_accounting_and_marks_shutdown_incomplete() {
        let metrics = Arc::new(JuicityOwnerMetrics::default());
        metrics.active_pools.store(1, Ordering::Release);
        metrics.active_physical_owners.store(2, Ordering::Release);
        metrics.active_builds.store(1, Ordering::Release);
        metrics.active_waiters.store(3, Ordering::Release);

        drop(JuicityRegistryOwnershipReconciler::new(Arc::clone(
            &metrics,
        )));

        assert_eq!(metrics.active_pools.load(Ordering::Acquire), 0);
        assert_eq!(metrics.active_physical_owners.load(Ordering::Acquire), 0);
        assert_eq!(metrics.active_builds.load(Ordering::Acquire), 0);
        assert_eq!(metrics.active_waiters.load(Ordering::Acquire), 0);
        assert!(metrics.shutdown_timed_out.load(Ordering::Acquire));
    }
}
