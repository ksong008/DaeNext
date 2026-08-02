use super::*;
use std::cell::{Cell, RefCell};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Condvar, Weak};
use std::time::Duration;

mod runtime;
pub(crate) use self::runtime::AllocatorRuntimeReclaimHooks;
use self::runtime::{AllocatorRuntimeState, flush_runtime_workers};

const ALLOCATOR_WORKER_RECLAIM_TIMEOUT: Duration = Duration::from_secs(1);

static WORKER_RECLAIM: OnceLock<AllocatorWorkerReclaim> = OnceLock::new();

thread_local! {
    static ATTACHED_WORKER: RefCell<Option<Weak<AllocatorWorkerState>>> = const { RefCell::new(None) };
    static ATTACHED_RUNTIME: Cell<u64> = const { Cell::new(0) };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AllocatorWorkerKind {
    Http,
    Sse,
    ProductControl,
    ResidentData,
    ControlAux,
}

impl AllocatorWorkerKind {
    const ALL: [Self; 5] = [
        Self::Http,
        Self::Sse,
        Self::ProductControl,
        Self::ResidentData,
        Self::ControlAux,
    ];

    const fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Sse => "sse",
            Self::ProductControl => "product-control",
            Self::ResidentData => "resident-data",
            Self::ControlAux => "control-aux",
        }
    }
}

#[derive(Debug)]
struct AllocatorWorkerState {
    kind: AllocatorWorkerKind,
    active: AtomicBool,
    acknowledged_epoch: AtomicU64,
    failed_epoch: AtomicU64,
}

impl AllocatorWorkerState {
    fn new(kind: AllocatorWorkerKind, epoch: u64) -> Self {
        Self {
            kind,
            active: AtomicBool::new(true),
            acknowledged_epoch: AtomicU64::new(epoch),
            failed_epoch: AtomicU64::new(0),
        }
    }

    fn poll(&self, reclaim: &AllocatorWorkerReclaim) {
        let epoch = reclaim.desired_epoch.load(Ordering::Acquire);
        if self.acknowledged_epoch.load(Ordering::Acquire) >= epoch {
            return;
        }
        if allocator_flush_current_thread_cache().is_err() {
            self.failed_epoch.store(epoch, Ordering::Relaxed);
        }
        self.acknowledged_epoch.store(epoch, Ordering::Release);
        reclaim.waiter.notify_all();
    }
}

pub(crate) struct AllocatorReclaimWorker {
    state: Arc<AllocatorWorkerState>,
}

impl AllocatorReclaimWorker {
    pub(crate) fn poll(&mut self) {
        self.state.poll(worker_reclaim());
    }
}

impl Drop for AllocatorReclaimWorker {
    fn drop(&mut self) {
        self.poll();
        self.state.active.store(false, Ordering::Release);
        ATTACHED_WORKER.with(|attached| {
            let mut attached = attached.borrow_mut();
            if attached
                .as_ref()
                .and_then(Weak::upgrade)
                .is_some_and(|state| Arc::ptr_eq(&state, &self.state))
            {
                *attached = None;
            }
        });
        worker_reclaim().waiter.notify_all();
    }
}

pub(crate) fn allocator_register_reclaim_worker(
    kind: AllocatorWorkerKind,
) -> AllocatorReclaimWorker {
    let reclaim = worker_reclaim();
    let state = Arc::new(AllocatorWorkerState::new(
        kind,
        reclaim.desired_epoch.load(Ordering::Acquire),
    ));
    if let Ok(mut workers) = reclaim.workers.lock() {
        workers.retain(|worker| worker.strong_count() > 0);
        workers.push(Arc::downgrade(&state));
    }
    ATTACHED_WORKER.with(|attached| {
        *attached.borrow_mut() = Some(Arc::downgrade(&state));
    });
    AllocatorReclaimWorker { state }
}

struct AllocatorWorkerReclaim {
    desired_epoch: AtomicU64,
    next_runtime_id: AtomicU64,
    workers: Mutex<Vec<Weak<AllocatorWorkerState>>>,
    runtimes: Mutex<Vec<Weak<AllocatorRuntimeState>>>,
    wait_lock: Mutex<()>,
    waiter: Condvar,
    requested_total: AtomicU64,
    completed_total: AtomicU64,
    partial_total: AtomicU64,
    last: Mutex<Option<Value>>,
}

impl Default for AllocatorWorkerReclaim {
    fn default() -> Self {
        Self {
            desired_epoch: AtomicU64::new(0),
            next_runtime_id: AtomicU64::new(1),
            workers: Mutex::new(Vec::new()),
            runtimes: Mutex::new(Vec::new()),
            wait_lock: Mutex::new(()),
            waiter: Condvar::new(),
            requested_total: AtomicU64::new(0),
            completed_total: AtomicU64::new(0),
            partial_total: AtomicU64::new(0),
            last: Mutex::new(None),
        }
    }
}

fn worker_reclaim() -> &'static AllocatorWorkerReclaim {
    WORKER_RECLAIM.get_or_init(AllocatorWorkerReclaim::default)
}

pub(super) fn allocator_flush_registered_worker_caches() -> (bool, Value) {
    let reclaim = worker_reclaim();
    let epoch = reclaim.desired_epoch.fetch_add(1, Ordering::AcqRel) + 1;
    reclaim.requested_total.fetch_add(1, Ordering::Relaxed);
    let deadline = Instant::now() + ALLOCATOR_WORKER_RECLAIM_TIMEOUT;

    let workers = reclaim
        .workers
        .lock()
        .map(|mut workers| {
            let active = workers
                .iter()
                .filter_map(Weak::upgrade)
                .filter(|worker| worker.active.load(Ordering::Acquire))
                .collect::<Vec<_>>();
            workers.retain(|worker| worker.strong_count() > 0);
            active
        })
        .unwrap_or_default();
    let runtimes = reclaim
        .runtimes
        .lock()
        .map(|mut runtimes| {
            let active = runtimes
                .iter()
                .filter_map(Weak::upgrade)
                .filter(|runtime| runtime.active.load(Ordering::Acquire))
                .collect::<Vec<_>>();
            runtimes.retain(|runtime| runtime.strong_count() > 0);
            active
        })
        .unwrap_or_default();

    let mut current_thread_flushed = ATTACHED_WORKER.with(|attached| {
        attached
            .borrow()
            .as_ref()
            .and_then(Weak::upgrade)
            .is_some_and(|worker| {
                worker.poll(reclaim);
                true
            })
    });
    let current_runtime = ATTACHED_RUNTIME.with(Cell::get);
    let mut runtime_reports = Vec::with_capacity(runtimes.len());
    for runtime in &runtimes {
        let current_worker = current_runtime == runtime.id;
        if current_worker && !current_thread_flushed {
            current_thread_flushed = allocator_flush_current_thread_cache().is_ok();
        }
        runtime_reports.push(flush_runtime_workers(runtime, current_worker, deadline));
    }
    if !current_thread_flushed {
        current_thread_flushed = allocator_flush_current_thread_cache().is_ok();
    }

    wait_for_direct_workers(reclaim, &workers, epoch, deadline);
    let mut expected_by_kind = BTreeMap::new();
    let mut acknowledged_by_kind = BTreeMap::new();
    let mut failures_by_kind = BTreeMap::new();
    for kind in AllocatorWorkerKind::ALL {
        expected_by_kind.insert(kind.as_str(), 0_u64);
        acknowledged_by_kind.insert(kind.as_str(), 0_u64);
        failures_by_kind.insert(kind.as_str(), 0_u64);
    }
    for worker in &workers {
        *expected_by_kind.entry(worker.kind.as_str()).or_default() += 1;
        if !worker.active.load(Ordering::Acquire)
            || worker.acknowledged_epoch.load(Ordering::Acquire) >= epoch
        {
            *acknowledged_by_kind
                .entry(worker.kind.as_str())
                .or_default() += 1;
        }
        if worker.failed_epoch.load(Ordering::Relaxed) == epoch {
            *failures_by_kind.entry(worker.kind.as_str()).or_default() += 1;
        }
    }
    for report in &runtime_reports {
        let kind = report.kind.as_str();
        *expected_by_kind.entry(kind).or_default() += report.expected as u64;
        *acknowledged_by_kind.entry(kind).or_default() += report.acknowledged as u64;
        *failures_by_kind.entry(kind).or_default() += report.failures as u64;
    }
    let expected = expected_by_kind.values().sum::<u64>();
    let acknowledged = acknowledged_by_kind.values().sum::<u64>();
    let failures = failures_by_kind.values().sum::<u64>();
    let complete = expected == acknowledged && failures == 0 && current_thread_flushed;
    if complete {
        reclaim.completed_total.fetch_add(1, Ordering::Relaxed);
    } else {
        reclaim.partial_total.fetch_add(1, Ordering::Relaxed);
    }
    let report = json!({
        "epoch": epoch,
        "status": if complete { "pass" } else { "partial" },
        "timeoutMillis": ALLOCATOR_WORKER_RECLAIM_TIMEOUT.as_millis().to_string(),
        "currentThreadFlushed": current_thread_flushed,
        "expectedWorkers": expected,
        "acknowledgedWorkers": acknowledged,
        "flushFailures": failures,
        "expectedByClass": expected_by_kind,
        "acknowledgedByClass": acknowledged_by_kind,
        "failuresByClass": failures_by_kind,
        "runtimeParticipants": runtime_reports.into_iter().map(|report| report.json()).collect::<Vec<_>>(),
    });
    if let Ok(mut last) = reclaim.last.lock() {
        *last = Some(report.clone());
    }
    (complete, report)
}

fn wait_for_direct_workers(
    reclaim: &AllocatorWorkerReclaim,
    workers: &[Arc<AllocatorWorkerState>],
    epoch: u64,
    deadline: Instant,
) {
    let Ok(mut guard) = reclaim.wait_lock.lock() else {
        return;
    };
    while workers.iter().any(|worker| {
        worker.active.load(Ordering::Acquire)
            && worker.acknowledged_epoch.load(Ordering::Acquire) < epoch
    }) {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        let Ok((next, timeout)) = reclaim.waiter.wait_timeout(guard, remaining) else {
            break;
        };
        guard = next;
        if timeout.timed_out() {
            break;
        }
    }
}

pub(super) fn allocator_worker_reclaim_snapshot_json() -> Value {
    let reclaim = worker_reclaim();
    let last = reclaim.last.lock().ok().and_then(|last| last.clone());
    let mut registered_by_kind = BTreeMap::new();
    for kind in AllocatorWorkerKind::ALL {
        registered_by_kind.insert(kind.as_str(), 0_u64);
    }
    if let Ok(workers) = reclaim.workers.lock() {
        for worker in workers.iter().filter_map(Weak::upgrade) {
            if worker.active.load(Ordering::Acquire) {
                *registered_by_kind.entry(worker.kind.as_str()).or_default() += 1;
            }
        }
    }
    if let Ok(runtimes) = reclaim.runtimes.lock() {
        for runtime in runtimes.iter().filter_map(Weak::upgrade) {
            if runtime.active.load(Ordering::Acquire) {
                *registered_by_kind.entry(runtime.kind.as_str()).or_default() +=
                    runtime.worker_threads as u64;
            }
        }
    }
    json!({
        "requestedTotal": reclaim.requested_total.load(Ordering::Relaxed),
        "completedTotal": reclaim.completed_total.load(Ordering::Relaxed),
        "partialTotal": reclaim.partial_total.load(Ordering::Relaxed),
        "registeredWorkers": registered_by_kind.values().sum::<u64>(),
        "registeredByClass": registered_by_kind,
        "last": last,
    })
}
