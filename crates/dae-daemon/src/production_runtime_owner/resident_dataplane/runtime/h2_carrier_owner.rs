use std::collections::HashMap;
use std::future::poll_fn;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::thread::JoinHandle;
use std::time::Instant;

use bytes::Bytes;
use dae_runtime_control::{AbsoluteDeadline, OwnerGeneration};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::sync::Notify;
use tokio::time;

use super::*;
use crate::production_runtime_owner::resident_dataplane::client::{
    async_resident_tls_underlay_name, open_async_resident_tls_client_with_flow,
};
use crate::production_runtime_owner::resident_dataplane::plan::ResidentProxyPlan;

const H2_CARRIER_IDENTITY_DOMAIN: &[u8] = b"dae/h2-carrier-owner/v1";

static H2_CARRIER_GENERATIONS: OnceLock<Mutex<HashMap<u64, Weak<H2CarrierGenerationOwner>>>> =
    OnceLock::new();

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
struct H2CarrierKey {
    generation: OwnerGeneration,
    digest: [u8; 32],
}

impl H2CarrierKey {
    fn for_proxy(proxy: &ResidentProxyPlan) -> Self {
        let mut digest = Sha256::new();
        digest.update(H2_CARRIER_IDENTITY_DOMAIN);
        update_h2_proxy_identity(&mut digest, proxy);
        Self {
            generation: proxy.execution_plan().runtime_generation(),
            digest: digest.finalize().into(),
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

fn update_h2_identity_part(digest: &mut Sha256, field: &[u8], value: &[u8]) {
    digest.update((field.len() as u64).to_be_bytes());
    digest.update(field);
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value);
}

fn update_h2_proxy_identity(digest: &mut Sha256, proxy: &ResidentProxyPlan) {
    update_h2_identity_part(digest, b"proxy", b"begin");
    update_h2_identity_part(digest, b"graph-link-hash", proxy.graph_link_hash.as_bytes());
    update_h2_identity_part(digest, b"server-host", proxy.server_host.as_bytes());
    update_h2_identity_part(digest, b"server-port", &proxy.server_port.to_be_bytes());
    update_h2_identity_part(digest, b"server-name", proxy.server_name.as_bytes());
    update_h2_identity_part(digest, b"tls", proxy.tls.as_bytes());
    update_h2_identity_part(digest, b"mark", &proxy.mark.to_be_bytes());
    update_h2_identity_part(digest, b"mptcp", &[u8::from(proxy.mptcp)]);
    update_h2_identity_part(digest, b"allow-insecure", &[u8::from(proxy.allow_insecure)]);
    update_h2_identity_part(
        digest,
        b"alpn-count",
        &(proxy.alpn.len() as u64).to_be_bytes(),
    );
    for alpn in &proxy.alpn {
        update_h2_identity_part(digest, b"alpn", alpn.as_bytes());
    }
    update_h2_identity_part(
        digest,
        b"tls-fragment-present",
        &[u8::from(proxy.tls_fragment.is_some())],
    );
    if let Some(fragment) = proxy.tls_fragment.as_ref() {
        update_h2_identity_part(
            digest,
            b"fragment-min-length",
            &fragment.min_length.to_be_bytes(),
        );
        update_h2_identity_part(
            digest,
            b"fragment-max-length",
            &fragment.max_length.to_be_bytes(),
        );
        update_h2_identity_part(
            digest,
            b"fragment-min-interval",
            &fragment.min_interval_ms.to_be_bytes(),
        );
        update_h2_identity_part(
            digest,
            b"fragment-max-interval",
            &fragment.max_interval_ms.to_be_bytes(),
        );
    }
    update_h2_identity_part(
        digest,
        b"fingerprint-present",
        &[u8::from(proxy.utls_fingerprint.is_some())],
    );
    if let Some(fingerprint) = proxy.utls_fingerprint.as_ref() {
        update_h2_identity_part(digest, b"fp-source", fingerprint.source.as_bytes());
        update_h2_identity_part(digest, b"fp-requested", fingerprint.requested.as_bytes());
        update_h2_identity_part(digest, b"fp-name", fingerprint.name.as_bytes());
        update_h2_identity_part(digest, b"fp-canonical", fingerprint.canonical.as_bytes());
        update_h2_identity_part(digest, b"fp-family", fingerprint.family.as_bytes());
        update_h2_identity_part(digest, b"fp-client", fingerprint.client.as_bytes());
        update_h2_identity_part(
            digest,
            b"fp-randomized",
            &[u8::from(fingerprint.randomized)],
        );
        update_h2_identity_part(
            digest,
            b"fp-alpn-policy",
            fingerprint.alpn_policy.as_bytes(),
        );
        update_h2_identity_part(
            digest,
            b"fp-default-alpn-count",
            &(fingerprint.default_alpn.len() as u64).to_be_bytes(),
        );
        for alpn in &fingerprint.default_alpn {
            update_h2_identity_part(digest, b"fp-default-alpn", alpn.as_bytes());
        }
    }
    update_h2_identity_part(
        digest,
        b"reality-present",
        &[u8::from(proxy.reality.is_some())],
    );
    if let Some(reality) = proxy.reality.as_ref() {
        update_h2_identity_part(digest, b"reality-public-key", &reality.public_key);
        update_h2_identity_part(digest, b"reality-short-id", &reality.short_id);
        update_h2_identity_part(digest, b"reality-spider-x", reality.spider_x.as_bytes());
    }
    update_h2_identity_part(
        digest,
        b"parent-present",
        &[u8::from(proxy.chain_parent.is_some())],
    );
    if let Some(parent) = proxy.chain_parent.as_deref() {
        update_h2_proxy_identity(digest, parent);
    }
    update_h2_identity_part(digest, b"proxy", b"end");
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
    cumulative_builds: AtomicU64,
    cumulative_build_failures: AtomicU64,
    cumulative_reuses: AtomicU64,
    cumulative_invalidations: AtomicU64,
    owner_limit_rejections: AtomicU64,
    physical_limit_rejections: AtomicU64,
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
    sender: Option<Arc<tokio::sync::Mutex<h2::client::SendRequest<Bytes>>>>,
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
            "executor": if self.owner.runtime_worker_threads == 1 { "current-thread" } else { "multi-thread" },
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
            "cumulativeBuilds": self.owner.metrics.cumulative_builds.load(Ordering::Relaxed),
            "cumulativeBuildFailures": self.owner.metrics.cumulative_build_failures.load(Ordering::Relaxed),
            "cumulativeReuses": self.owner.metrics.cumulative_reuses.load(Ordering::Relaxed),
            "cumulativeInvalidations": self.owner.metrics.cumulative_invalidations.load(Ordering::Relaxed),
            "ownerLimitRejections": self.owner.metrics.owner_limit_rejections.load(Ordering::Relaxed),
            "physicalLimitRejections": self.owner.metrics.physical_limit_rejections.load(Ordering::Relaxed),
            "ownerStateBytesLowerBound": owner_state_bytes_lower_bound,
            "admissionEnforced": true,
            "shutdownTimedOut": self.owner.metrics.shutdown_timed_out.load(Ordering::Relaxed),
            "budget": {
                "owners": self.owner.resources.owner_limit(),
                "physicalConnections": self.owner.resources.physical_connection_limit(),
                "reusablePhysicalConnectionsPerOwner": 1,
                "drainingConnectionsCountTowardPhysicalBudget": true,
                "logicalConcurrencySource": "peer-http2-settings",
            },
        })
    }
}

pub(crate) struct H2CarrierLease {
    sender: Arc<tokio::sync::Mutex<h2::client::SendRequest<Bytes>>>,
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
    ) -> Result<(h2::client::ResponseFuture, h2::SendStream<Bytes>), String> {
        let remaining = deadline
            .remaining_at(Instant::now())
            .ok_or_else(|| format!("{context} HTTP/2 stream-capacity deadline elapsed"))?;
        let mut sender = time::timeout(remaining, self.sender.lock())
            .await
            .map_err(|_| format!("{context} HTTP/2 stream-capacity deadline elapsed"))?;
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
        sender
            .send_request(request, end_of_stream)
            .map_err(|error| {
                self.invalidate();
                format!("send {context} HTTP/2 request headers: {error}")
            })
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
        self.sender.lock().await.current_max_send_streams()
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
    proxy: Arc<ResidentProxyPlan>,
    deadline: AbsoluteDeadline,
) -> Result<H2CarrierLease, String> {
    let key = H2CarrierKey::for_proxy(&proxy);
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
            if let Some(sender) = state.sender.clone() {
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
                let (build_id, start) = spawn_h2_carrier_build(
                    &owner,
                    &manager,
                    Arc::clone(&proxy),
                    deadline,
                    physical,
                )?;
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
    proxy: Arc<ResidentProxyPlan>,
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
            proxy,
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
    proxy: Arc<ResidentProxyPlan>,
    deadline: AbsoluteDeadline,
    build_id: u64,
    physical: H2PhysicalPermit,
) {
    let result = build_h2_carrier(&owner, &manager, &proxy, deadline, physical).await;
    let mut state = manager.state.lock().await;
    if state.opening_build != Some(build_id) {
        drop(state);
        if let Ok((instance_id, _, _, _)) = result {
            abort_h2_driver(&owner, instance_id);
        }
        manager.changed.notify_waiters();
        return;
    }
    state.opening_build = None;
    match result {
        Ok((instance_id, sender, tls_underlay, driver_start))
            if !owner.closing.load(Ordering::Acquire) =>
        {
            state.instance_id = instance_id;
            state.instance_acquisitions = 0;
            state.sender = Some(sender);
            state.tls_underlay = tls_underlay;
            state.last_failure = None;
            let _ = driver_start.send(());
        }
        Ok((instance_id, _, _, _)) => {
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
    proxy: &ResidentProxyPlan,
    deadline: AbsoluteDeadline,
    physical: H2PhysicalPermit,
) -> Result<
    (
        u64,
        Arc<tokio::sync::Mutex<h2::client::SendRequest<Bytes>>>,
        &'static str,
        tokio::sync::oneshot::Sender<()>,
    ),
    String,
> {
    let remaining = deadline
        .remaining_at(Instant::now())
        .ok_or_else(|| "HTTP/2 carrier TLS deadline elapsed".to_owned())?;
    let client = time::timeout(
        remaining,
        open_async_resident_tls_client_with_flow(proxy, proxy.mark, proxy.mptcp),
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
    let remaining = deadline
        .remaining_at(Instant::now())
        .ok_or_else(|| "HTTP/2 carrier handshake deadline elapsed".to_owned())?;
    let (sender, connection) = time::timeout(remaining, h2::client::handshake(client))
        .await
        .map_err(|_| "HTTP/2 carrier handshake deadline elapsed".to_owned())?
        .map_err(|error| format!("HTTP/2 carrier client handshake: {error}"))?;
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
            state.instance_acquisitions = 0;
        }
        drop(state);
        completion_manager.changed.notify_waiters();
        drop(completion_owner);
    });
    drivers.insert(instance_id, driver.abort_handle());
    Ok((
        instance_id,
        Arc::new(tokio::sync::Mutex::new(sender)),
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
}
