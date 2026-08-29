use std::io;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use dae_product_core::{ProductHttpProfile, ProductHttpWorkerConfig};
use serde_json::{Value, json};

use crate::{
    GeodataKind, GeodataPreparationMode, GeodataUpdateCallbacks, ProductGeodataUpdateCoordinator,
    ProductGeodataUpdateLease, update_geodata_with_lease_using,
};

const PRODUCT_GEODATA_UPDATE_WORKERS: usize = 2;
const PRODUCT_GEODATA_UPDATE_QUEUE_CAPACITY: usize = 2;
const PRODUCT_GEODATA_UPDATE_WORKER_RECV_TIMEOUT: Duration = Duration::from_millis(100);
const PRODUCT_GEODATA_UPDATE_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug)]
pub struct ProductGeodataUpdateRuntimeConfig {
    pub profile: ProductHttpProfile,
    pub worker_count: usize,
    pub queue_capacity: usize,
    pub worker_stack_bytes: usize,
    pub worker_recv_timeout: Duration,
    pub shutdown_timeout: Duration,
    pub preparation_mode: GeodataPreparationMode,
}

impl ProductGeodataUpdateRuntimeConfig {
    pub fn from_http_config(http: ProductHttpWorkerConfig) -> Self {
        Self {
            profile: http.profile,
            worker_count: PRODUCT_GEODATA_UPDATE_WORKERS,
            queue_capacity: PRODUCT_GEODATA_UPDATE_QUEUE_CAPACITY,
            worker_stack_bytes: http.worker_stack_bytes,
            worker_recv_timeout: PRODUCT_GEODATA_UPDATE_WORKER_RECV_TIMEOUT,
            shutdown_timeout: PRODUCT_GEODATA_UPDATE_SHUTDOWN_TIMEOUT,
            preparation_mode: GeodataPreparationMode::IsolatedProcess,
        }
    }

    #[cfg(feature = "test-support")]
    pub fn for_test() -> Self {
        Self {
            profile: ProductHttpProfile::LowMemory,
            worker_count: PRODUCT_GEODATA_UPDATE_WORKERS,
            queue_capacity: PRODUCT_GEODATA_UPDATE_QUEUE_CAPACITY,
            worker_stack_bytes:
                dae_product_core::PRODUCT_HTTP_LOW_MEMORY_WORKER_STACK_BYTES_DEFAULT,
            worker_recv_timeout: Duration::from_millis(10),
            shutdown_timeout: Duration::from_millis(100),
            preparation_mode: GeodataPreparationMode::Inline,
        }
    }
}

pub struct ProductGeodataUpdateMetrics {
    configured_workers: u64,
    queue_capacity: u64,
    queue_depth: AtomicU64,
    active_workers: AtomicU64,
    active_geosite: AtomicU64,
    active_geoip: AtomicU64,
    next_generation: AtomicU64,
    geosite_generation: AtomicU64,
    geoip_generation: AtomicU64,
    geosite_phase: AtomicU64,
    geoip_phase: AtomicU64,
    submitted_total: AtomicU64,
    completed_total: AtomicU64,
    rejected_same_kind_total: AtomicU64,
    rejected_capacity_total: AtomicU64,
    rejected_unavailable_total: AtomicU64,
    worker_panic_total: AtomicU64,
    workers_joined_total: AtomicU64,
    workers_detached_total: AtomicU64,
}

pub trait ProductGeodataUpdateJob: Send {
    fn complete(self, result: io::Result<Value>);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProductGeodataUpdateSubmissionReason {
    Unavailable,
    SameKind,
    Capacity,
}

pub struct ProductGeodataUpdateSubmissionError<J> {
    pub job: J,
    pub reason: ProductGeodataUpdateSubmissionReason,
}

impl<J> std::fmt::Debug for ProductGeodataUpdateSubmissionError<J> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProductGeodataUpdateSubmissionError")
            .field("reason", &self.reason)
            .finish_non_exhaustive()
    }
}

pub trait ProductGeodataUpdateWorkerHooks: Send + Sync {
    fn worker_started(&self) -> Box<dyn ProductGeodataUpdateWorker> {
        Box::new(NoopProductGeodataUpdateWorker)
    }
    fn job_started(&self) -> Option<Box<dyn Send>> {
        None
    }
}

pub trait ProductGeodataUpdateWorker: Send {
    fn poll(&mut self);
}

#[derive(Debug, Default)]
pub struct NoopProductGeodataUpdateWorkerHooks;

impl ProductGeodataUpdateWorkerHooks for NoopProductGeodataUpdateWorkerHooks {}

struct NoopProductGeodataUpdateWorker;

impl ProductGeodataUpdateWorker for NoopProductGeodataUpdateWorker {
    fn poll(&mut self) {}
}

pub struct ProductGeodataUpdateRuntime<C, J> {
    config: ProductGeodataUpdateRuntimeConfig,
    context: C,
    updates: Arc<ProductGeodataUpdateCoordinator>,
    sender: Mutex<Option<std::sync::mpsc::SyncSender<ProductGeodataQueuedJob<J>>>>,
    receiver: Arc<Mutex<std::sync::mpsc::Receiver<ProductGeodataQueuedJob<J>>>>,
    workers: Mutex<Vec<ProductGeodataUpdateWorkerHandle>>,
    metrics: Arc<ProductGeodataUpdateMetrics>,
    stopping: Arc<AtomicBool>,
    hooks: Arc<dyn ProductGeodataUpdateWorkerHooks>,
}

struct ProductGeodataQueuedJob<J> {
    job: J,
    kind: GeodataKind,
    generation: u64,
    lease: ProductGeodataUpdateLease,
}

impl<J> ProductGeodataQueuedJob<J> {
    fn into_submission_error(
        self,
        reason: ProductGeodataUpdateSubmissionReason,
    ) -> Box<ProductGeodataUpdateSubmissionError<J>> {
        let Self { job, lease, .. } = self;
        drop(lease);
        Box::new(ProductGeodataUpdateSubmissionError { job, reason })
    }
}

struct ProductGeodataUpdateWorkerHandle {
    join: Option<thread::JoinHandle<()>>,
    completed: std::sync::mpsc::Receiver<()>,
}

impl ProductGeodataUpdateWorkerHandle {
    fn join_if_finished(mut self) {
        if !matches!(
            self.completed.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ) && let Some(join) = self.join.take()
        {
            let _ = join.join();
        }
    }

    fn try_join(&mut self) -> bool {
        if matches!(
            self.completed.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ) {
            return false;
        }
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
        true
    }
}

impl<C, J> ProductGeodataUpdateRuntime<C, J>
where
    C: GeodataUpdateRuntimeContext + Clone + Send + Sync + 'static,
    J: ProductGeodataUpdateJob + 'static,
{
    pub fn start(
        config: ProductGeodataUpdateRuntimeConfig,
        context: C,
        updates: Arc<ProductGeodataUpdateCoordinator>,
        hooks: Arc<dyn ProductGeodataUpdateWorkerHooks>,
    ) -> io::Result<Arc<Self>> {
        let metrics = Arc::new(ProductGeodataUpdateMetrics::new(config));
        let stopping = Arc::new(AtomicBool::new(false));
        let (sender, receiver) = std::sync::mpsc::sync_channel(config.queue_capacity);
        Ok(Arc::new(Self {
            config,
            context,
            updates,
            sender: Mutex::new(Some(sender)),
            receiver: Arc::new(Mutex::new(receiver)),
            workers: Mutex::new(Vec::new()),
            metrics,
            stopping,
            hooks,
        }))
    }

    fn ensure_workers(&self) -> io::Result<()> {
        let mut workers = self
            .workers
            .lock()
            .map_err(|_| io::Error::other("geodata update worker lock poisoned"))?;
        if !workers.is_empty() {
            return Ok(());
        }
        let mut started = Vec::with_capacity(self.config.worker_count);
        for index in 0..self.config.worker_count {
            let worker = ProductGeodataUpdateWorkerStart {
                config: self.config,
                context: self.context.clone(),
                updates: Arc::clone(&self.updates),
                receiver: Arc::clone(&self.receiver),
                metrics: Arc::clone(&self.metrics),
                stopping: Arc::clone(&self.stopping),
                hooks: Arc::clone(&self.hooks),
            };
            match start_product_geodata_update_worker(index, worker) {
                Ok(worker) => started.push(worker),
                Err(error) => {
                    self.stopping.store(true, Ordering::Release);
                    for worker in started {
                        worker.join_if_finished();
                    }
                    return Err(error);
                }
            }
        }
        *workers = started;
        Ok(())
    }

    pub fn submit(
        &self,
        kind: GeodataKind,
        job: J,
    ) -> Result<(), Box<ProductGeodataUpdateSubmissionError<J>>> {
        if self.stopping.load(Ordering::Acquire) {
            self.metrics.rejected_unavailable();
            return Err(submission_error(
                job,
                ProductGeodataUpdateSubmissionReason::Unavailable,
            ));
        }
        if let Err(error) = self.ensure_workers() {
            self.metrics.rejected_unavailable();
            let _ = error;
            return Err(submission_error(
                job,
                ProductGeodataUpdateSubmissionReason::Unavailable,
            ));
        }
        let lease = match self.updates.acquire(kind) {
            Ok(lease) => lease,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                self.metrics.rejected_same_kind();
                let _ = error;
                return Err(submission_error(
                    job,
                    ProductGeodataUpdateSubmissionReason::SameKind,
                ));
            }
            Err(error) => {
                self.metrics.rejected_unavailable();
                let _ = error;
                return Err(submission_error(
                    job,
                    ProductGeodataUpdateSubmissionReason::Unavailable,
                ));
            }
        };
        let sender = match self
            .sender
            .lock()
            .ok()
            .and_then(|sender| sender.as_ref().cloned())
        {
            Some(sender) => sender,
            None => {
                self.metrics.rejected_unavailable();
                drop(lease);
                return Err(submission_error(
                    job,
                    ProductGeodataUpdateSubmissionReason::Unavailable,
                ));
            }
        };
        let generation = self.metrics.submitted(kind);
        let job = ProductGeodataQueuedJob {
            job,
            kind,
            generation,
            lease,
        };
        self.metrics.enqueued();
        match sender.try_send(job) {
            Ok(()) => Ok(()),
            Err(std::sync::mpsc::TrySendError::Full(job)) => {
                self.metrics.dequeue_rollback(kind, generation);
                self.metrics.rejected_capacity();
                Err(job.into_submission_error(ProductGeodataUpdateSubmissionReason::Capacity))
            }
            Err(std::sync::mpsc::TrySendError::Disconnected(job)) => {
                self.metrics.dequeue_rollback(kind, generation);
                self.metrics.rejected_unavailable();
                Err(job.into_submission_error(ProductGeodataUpdateSubmissionReason::Unavailable))
            }
        }
    }

    pub fn snapshot(&self) -> Value {
        self.metrics.snapshot(self.config)
    }

    pub fn startup_fields(&self) -> std::collections::BTreeMap<String, String> {
        let mut fields = std::collections::BTreeMap::new();
        let active_workers = self.workers.lock().ok().map_or(0, |workers| workers.len());
        fields.insert(
            "geodataUpdateWorkers".to_owned(),
            self.config.worker_count.to_string(),
        );
        fields.insert(
            "geodataUpdateWorkersActive".to_owned(),
            active_workers.to_string(),
        );
        fields.insert(
            "geodataUpdateQueueCapacity".to_owned(),
            self.config.queue_capacity.to_string(),
        );
        fields
    }

    pub fn shutdown(&self) -> io::Result<()> {
        self.stopping.store(true, Ordering::Release);
        self.sender
            .lock()
            .map_err(|_| io::Error::other("geodata update sender lock poisoned"))?
            .take();
        let deadline = Instant::now()
            .checked_add(self.config.shutdown_timeout)
            .unwrap_or_else(Instant::now);
        let workers = std::mem::take(
            &mut *self
                .workers
                .lock()
                .map_err(|_| io::Error::other("geodata update worker lock poisoned"))?,
        );
        join_product_geodata_update_workers(workers, deadline, &self.metrics);
        Ok(())
    }
}

impl<C, J> std::fmt::Debug for ProductGeodataUpdateRuntime<C, J> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProductGeodataUpdateRuntime")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl<C, J> Drop for ProductGeodataUpdateRuntime<C, J> {
    fn drop(&mut self) {
        self.stopping.store(true, Ordering::Release);
        if let Ok(mut sender) = self.sender.lock() {
            sender.take();
        }
        let workers = self
            .workers
            .get_mut()
            .map(std::mem::take)
            .unwrap_or_default();
        let deadline = Instant::now()
            .checked_add(self.config.shutdown_timeout)
            .unwrap_or_else(Instant::now);
        join_product_geodata_update_workers(workers, deadline, &self.metrics);
    }
}

fn submission_error<J>(
    job: J,
    reason: ProductGeodataUpdateSubmissionReason,
) -> Box<ProductGeodataUpdateSubmissionError<J>> {
    Box::new(ProductGeodataUpdateSubmissionError { job, reason })
}

fn join_product_geodata_update_workers(
    mut workers: Vec<ProductGeodataUpdateWorkerHandle>,
    deadline: Instant,
    metrics: &ProductGeodataUpdateMetrics,
) {
    while !workers.is_empty() {
        let mut index = 0;
        let mut joined_any = false;
        while index < workers.len() {
            if workers[index].try_join() {
                workers.swap_remove(index);
                metrics.worker_joined();
                joined_any = true;
            } else {
                index += 1;
            }
        }
        if workers.is_empty() || Instant::now() >= deadline {
            break;
        }
        if !joined_any {
            thread::sleep(
                Duration::from_millis(1).min(deadline.saturating_duration_since(Instant::now())),
            );
        }
    }
    for _ in workers {
        metrics.worker_detached();
    }
}

struct ProductGeodataUpdateWorkerStart<C, J> {
    config: ProductGeodataUpdateRuntimeConfig,
    context: C,
    updates: Arc<ProductGeodataUpdateCoordinator>,
    receiver: Arc<Mutex<std::sync::mpsc::Receiver<ProductGeodataQueuedJob<J>>>>,
    metrics: Arc<ProductGeodataUpdateMetrics>,
    stopping: Arc<AtomicBool>,
    hooks: Arc<dyn ProductGeodataUpdateWorkerHooks>,
}

fn start_product_geodata_update_worker<C, J>(
    index: usize,
    worker: ProductGeodataUpdateWorkerStart<C, J>,
) -> io::Result<ProductGeodataUpdateWorkerHandle>
where
    C: GeodataUpdateRuntimeContext + Clone + Send + Sync + 'static,
    J: ProductGeodataUpdateJob + 'static,
{
    let ProductGeodataUpdateWorkerStart {
        config,
        context,
        updates,
        receiver,
        metrics,
        stopping,
        hooks,
    } = worker;
    let (completed_sender, completed) = std::sync::mpsc::sync_channel(1);
    let join = thread::Builder::new()
        .name(format!("daed-geodata-update-{index}"))
        .stack_size(config.worker_stack_bytes)
        .spawn(move || {
            let _completion = ProductGeodataUpdateWorkerCompletion(completed_sender);
            product_geodata_update_worker_loop(
                config, context, updates, receiver, metrics, stopping, hooks,
            );
        })?;
    Ok(ProductGeodataUpdateWorkerHandle {
        join: Some(join),
        completed,
    })
}

struct ProductGeodataUpdateWorkerCompletion(std::sync::mpsc::SyncSender<()>);

impl Drop for ProductGeodataUpdateWorkerCompletion {
    fn drop(&mut self) {
        let _ = self.0.try_send(());
    }
}

fn product_geodata_update_worker_loop<C, J>(
    config: ProductGeodataUpdateRuntimeConfig,
    context: C,
    updates: Arc<ProductGeodataUpdateCoordinator>,
    receiver: Arc<Mutex<std::sync::mpsc::Receiver<ProductGeodataQueuedJob<J>>>>,
    metrics: Arc<ProductGeodataUpdateMetrics>,
    stopping: Arc<AtomicBool>,
    hooks: Arc<dyn ProductGeodataUpdateWorkerHooks>,
) where
    C: GeodataUpdateRuntimeContext + Clone + Send + Sync + 'static,
    J: ProductGeodataUpdateJob + 'static,
{
    let mut worker = hooks.worker_started();
    loop {
        worker.poll();
        let received = {
            let Ok(receiver) = receiver.lock() else {
                return;
            };
            receiver.recv_timeout(config.worker_recv_timeout)
        };
        let job = match received {
            Ok(job) => job,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                if stopping.load(Ordering::Acquire) {
                    return;
                }
                thread::sleep(Duration::from_millis(1));
                continue;
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return,
        };
        run_product_geodata_update_job(
            &context,
            &updates,
            &metrics,
            &stopping,
            config.preparation_mode,
            job,
            &hooks,
        );
    }
}

fn run_product_geodata_update_job<C, J>(
    context: &C,
    updates: &Arc<ProductGeodataUpdateCoordinator>,
    metrics: &Arc<ProductGeodataUpdateMetrics>,
    stopping: &AtomicBool,
    preparation_mode: GeodataPreparationMode,
    job: ProductGeodataQueuedJob<J>,
    hooks: &Arc<dyn ProductGeodataUpdateWorkerHooks>,
) where
    C: GeodataUpdateRuntimeContext + Clone + Send + Sync + 'static,
    J: ProductGeodataUpdateJob + 'static,
{
    let ProductGeodataQueuedJob {
        job,
        kind,
        generation,
        lease,
    } = job;
    metrics.dequeued(kind, generation);
    let job_guard = hooks.job_started();
    let _completion = ProductGeodataUpdateJobCompletion {
        kind,
        generation,
        geodata_metrics: Arc::clone(metrics),
        _job_guard: job_guard,
    };
    let response = if stopping.load(Ordering::Acquire) {
        drop(lease);
        Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "geodata update runtime is stopping",
        ))
    } else {
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            update_geodata_with_lease_using(
                context,
                updates,
                context.state_path(),
                context.directory(),
                kind,
                lease,
                preparation_mode,
            )
        })) {
            Ok(result) => result,
            Err(_) => {
                metrics.worker_panicked();
                Err(io::Error::other("geodata update worker failed"))
            }
        }
    };
    job.complete(response);
}

pub trait GeodataUpdateRuntimeContext: GeodataUpdateCallbacks {
    fn state_path(&self) -> &std::path::Path;
    fn directory(&self) -> &std::path::Path;
}

struct ProductGeodataUpdateJobCompletion {
    kind: GeodataKind,
    generation: u64,
    geodata_metrics: Arc<ProductGeodataUpdateMetrics>,
    _job_guard: Option<Box<dyn Send>>,
}

impl Drop for ProductGeodataUpdateJobCompletion {
    fn drop(&mut self) {
        self.geodata_metrics.completed(self.kind, self.generation);
    }
}

impl ProductGeodataUpdateMetrics {
    pub fn new(config: ProductGeodataUpdateRuntimeConfig) -> Self {
        Self {
            configured_workers: config.worker_count as u64,
            queue_capacity: config.queue_capacity as u64,
            queue_depth: AtomicU64::new(0),
            active_workers: AtomicU64::new(0),
            active_geosite: AtomicU64::new(0),
            active_geoip: AtomicU64::new(0),
            next_generation: AtomicU64::new(0),
            geosite_generation: AtomicU64::new(0),
            geoip_generation: AtomicU64::new(0),
            geosite_phase: AtomicU64::new(0),
            geoip_phase: AtomicU64::new(0),
            submitted_total: AtomicU64::new(0),
            completed_total: AtomicU64::new(0),
            rejected_same_kind_total: AtomicU64::new(0),
            rejected_capacity_total: AtomicU64::new(0),
            rejected_unavailable_total: AtomicU64::new(0),
            worker_panic_total: AtomicU64::new(0),
            workers_joined_total: AtomicU64::new(0),
            workers_detached_total: AtomicU64::new(0),
        }
    }

    pub fn submitted(&self, kind: GeodataKind) -> u64 {
        let generation = self.next_generation.fetch_add(1, Ordering::Relaxed) + 1;
        self.generation(kind).store(generation, Ordering::Relaxed);
        self.phase(kind).store(1, Ordering::Relaxed);
        self.submitted_total.fetch_add(1, Ordering::Relaxed);
        generation
    }

    pub fn enqueued(&self) {
        self.queue_depth.fetch_add(1, Ordering::Relaxed);
    }

    pub fn dequeued(&self, kind: GeodataKind, generation: u64) {
        decrement_saturating(&self.queue_depth);
        self.active_workers.fetch_add(1, Ordering::Relaxed);
        self.active_kind(kind).store(1, Ordering::Relaxed);
        self.generation(kind).store(generation, Ordering::Relaxed);
        self.phase(kind).store(2, Ordering::Relaxed);
    }

    pub fn dequeue_rollback(&self, kind: GeodataKind, generation: u64) {
        decrement_saturating(&self.queue_depth);
        if self.generation(kind).load(Ordering::Relaxed) == generation {
            self.phase(kind).store(0, Ordering::Relaxed);
        }
    }

    pub fn completed(&self, kind: GeodataKind, generation: u64) {
        decrement_saturating(&self.active_workers);
        self.active_kind(kind).store(0, Ordering::Relaxed);
        if self.generation(kind).load(Ordering::Relaxed) == generation {
            self.phase(kind).store(0, Ordering::Relaxed);
        }
        self.completed_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn rejected_same_kind(&self) {
        self.rejected_same_kind_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn rejected_capacity(&self) {
        self.rejected_capacity_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn rejected_unavailable(&self) {
        self.rejected_unavailable_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn worker_panicked(&self) {
        self.worker_panic_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn worker_joined(&self) {
        self.workers_joined_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn worker_detached(&self) {
        self.workers_detached_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self, config: ProductGeodataUpdateRuntimeConfig) -> Value {
        json!({
            "profile": config.profile.name(),
            "configuredWorkers": self.configured_workers,
            "queueCapacity": self.queue_capacity,
            "workerStackBytes": config.worker_stack_bytes,
            "preparationMode": config.preparation_mode.name(),
            "queueDepth": self.queue_depth.load(Ordering::Relaxed),
            "activeWorkers": self.active_workers.load(Ordering::Relaxed),
            "active": {
                "geosite": self.active_geosite.load(Ordering::Relaxed) != 0,
                "geoip": self.active_geoip.load(Ordering::Relaxed) != 0,
            },
            "jobs": {
                "geosite": {
                    "generation": self.geosite_generation.load(Ordering::Relaxed),
                    "phase": phase_name(self.geosite_phase.load(Ordering::Relaxed)),
                },
                "geoip": {
                    "generation": self.geoip_generation.load(Ordering::Relaxed),
                    "phase": phase_name(self.geoip_phase.load(Ordering::Relaxed)),
                },
            },
            "submittedTotal": self.submitted_total.load(Ordering::Relaxed),
            "completedTotal": self.completed_total.load(Ordering::Relaxed),
            "rejectedSameKindTotal": self.rejected_same_kind_total.load(Ordering::Relaxed),
            "rejectedCapacityTotal": self.rejected_capacity_total.load(Ordering::Relaxed),
            "rejectedUnavailableTotal": self.rejected_unavailable_total.load(Ordering::Relaxed),
            "workerPanicTotal": self.worker_panic_total.load(Ordering::Relaxed),
            "workersJoinedTotal": self.workers_joined_total.load(Ordering::Relaxed),
            "workersDetachedTotal": self.workers_detached_total.load(Ordering::Relaxed),
        })
    }

    fn active_kind(&self, kind: GeodataKind) -> &AtomicU64 {
        match kind {
            GeodataKind::Geosite => &self.active_geosite,
            GeodataKind::Geoip => &self.active_geoip,
        }
    }

    fn generation(&self, kind: GeodataKind) -> &AtomicU64 {
        match kind {
            GeodataKind::Geosite => &self.geosite_generation,
            GeodataKind::Geoip => &self.geoip_generation,
        }
    }

    fn phase(&self, kind: GeodataKind) -> &AtomicU64 {
        match kind {
            GeodataKind::Geosite => &self.geosite_phase,
            GeodataKind::Geoip => &self.geoip_phase,
        }
    }
}

fn decrement_saturating(value: &AtomicU64) {
    let _ = value.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
        Some(current.saturating_sub(1))
    });
}

fn phase_name(phase: u64) -> &'static str {
    match phase {
        1 => "queued",
        2 => "running",
        _ => "idle",
    }
}
