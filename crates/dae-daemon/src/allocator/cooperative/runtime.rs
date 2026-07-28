use super::*;

#[derive(Clone)]
pub(crate) struct AllocatorRuntimeReclaimHooks {
    state: Arc<AllocatorRuntimeState>,
}

impl AllocatorRuntimeReclaimHooks {
    pub(crate) fn new(kind: AllocatorWorkerKind, worker_threads: usize) -> Self {
        let reclaim = worker_reclaim();
        let state = Arc::new(AllocatorRuntimeState {
            id: reclaim.next_runtime_id.fetch_add(1, Ordering::Relaxed),
            kind,
            worker_threads: worker_threads.max(1),
            active: AtomicBool::new(false),
            handle: Mutex::new(None),
        });
        if let Ok(mut runtimes) = reclaim.runtimes.lock() {
            runtimes.retain(|runtime| runtime.strong_count() > 0);
            runtimes.push(Arc::downgrade(&state));
        }
        Self { state }
    }

    pub(crate) fn thread_start(&self) {
        ATTACHED_RUNTIME.with(|runtime| runtime.set(self.state.id));
    }

    pub(crate) fn thread_stop(&self) {
        ATTACHED_RUNTIME.with(|runtime| {
            if runtime.get() == self.state.id {
                runtime.set(0);
            }
        });
    }

    pub(crate) fn activate(&self, handle: tokio::runtime::Handle) {
        if let Ok(mut stored) = self.state.handle.lock() {
            *stored = Some(handle);
            self.state.active.store(true, Ordering::Release);
        }
    }

    pub(crate) fn deactivate(&self) {
        self.state.active.store(false, Ordering::Release);
        if let Ok(mut handle) = self.state.handle.lock() {
            handle.take();
        }
        worker_reclaim().waiter.notify_all();
    }
}

impl Drop for AllocatorRuntimeReclaimHooks {
    fn drop(&mut self) {
        if Arc::strong_count(&self.state) == 1 {
            self.deactivate();
        }
    }
}

pub(super) struct AllocatorRuntimeState {
    pub(super) id: u64,
    pub(super) kind: AllocatorWorkerKind,
    pub(super) worker_threads: usize,
    pub(super) active: AtomicBool,
    handle: Mutex<Option<tokio::runtime::Handle>>,
}

struct AllocatorRuntimeFlushBatch {
    released: AtomicBool,
    started: AtomicU64,
    completed: AtomicU64,
    failures: AtomicU64,
    lock: Mutex<()>,
    waiter: Condvar,
}

impl Default for AllocatorRuntimeFlushBatch {
    fn default() -> Self {
        Self {
            released: AtomicBool::new(false),
            started: AtomicU64::new(0),
            completed: AtomicU64::new(0),
            failures: AtomicU64::new(0),
            lock: Mutex::new(()),
            waiter: Condvar::new(),
        }
    }
}

pub(super) struct AllocatorRuntimeFlushReport {
    pub(super) kind: AllocatorWorkerKind,
    pub(super) expected: usize,
    pub(super) acknowledged: usize,
    pub(super) failures: usize,
}

impl AllocatorRuntimeFlushReport {
    pub(super) fn json(self) -> Value {
        json!({
            "class": self.kind.as_str(),
            "expectedWorkers": self.expected,
            "acknowledgedWorkers": self.acknowledged,
            "flushFailures": self.failures,
        })
    }
}

pub(super) fn flush_runtime_workers(
    runtime: &AllocatorRuntimeState,
    current_worker: bool,
    deadline: Instant,
) -> AllocatorRuntimeFlushReport {
    if current_worker {
        return tokio::task::block_in_place(|| {
            flush_runtime_workers_blocking(runtime, true, deadline)
        });
    }
    flush_runtime_workers_blocking(runtime, false, deadline)
}

fn flush_runtime_workers_blocking(
    runtime: &AllocatorRuntimeState,
    current_worker: bool,
    deadline: Instant,
) -> AllocatorRuntimeFlushReport {
    let current_count = usize::from(current_worker);
    let task_count = runtime.worker_threads.saturating_sub(current_count);
    let Some(handle) = runtime.handle.lock().ok().and_then(|handle| handle.clone()) else {
        return AllocatorRuntimeFlushReport {
            kind: runtime.kind,
            expected: runtime.worker_threads,
            acknowledged: current_count,
            failures: 0,
        };
    };
    let batch = Arc::new(AllocatorRuntimeFlushBatch::default());
    for _ in 0..task_count {
        let batch = Arc::clone(&batch);
        handle.spawn(async move {
            if batch.released.load(Ordering::Acquire) {
                return;
            }
            batch.started.fetch_add(1, Ordering::AcqRel);
            batch.waiter.notify_all();
            let Ok(mut guard) = batch.lock.lock() else {
                return;
            };
            while !batch.released.load(Ordering::Acquire) {
                let Ok(next) = batch.waiter.wait(guard) else {
                    return;
                };
                guard = next;
            }
            drop(guard);
            if allocator_flush_current_thread_cache().is_err() {
                batch.failures.fetch_add(1, Ordering::Relaxed);
            }
            batch.completed.fetch_add(1, Ordering::Release);
            batch.waiter.notify_all();
        });
    }
    wait_for_runtime_count(&batch, &batch.started, task_count as u64, deadline);
    let started = batch.started.load(Ordering::Acquire).min(task_count as u64);
    batch.released.store(true, Ordering::Release);
    batch.waiter.notify_all();
    wait_for_runtime_count(&batch, &batch.completed, started, deadline);
    AllocatorRuntimeFlushReport {
        kind: runtime.kind,
        expected: runtime.worker_threads,
        acknowledged: current_count
            .saturating_add(batch.completed.load(Ordering::Acquire) as usize),
        failures: batch.failures.load(Ordering::Relaxed) as usize,
    }
}

fn wait_for_runtime_count(
    batch: &AllocatorRuntimeFlushBatch,
    counter: &AtomicU64,
    expected: u64,
    deadline: Instant,
) {
    let Ok(mut guard) = batch.lock.lock() else {
        return;
    };
    while counter.load(Ordering::Acquire) < expected {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        let Ok((next, timeout)) = batch.waiter.wait_timeout(guard, remaining) else {
            break;
        };
        guard = next;
        if timeout.timed_out() {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_flush_occupies_each_worker_before_releasing_the_batch() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let state = AllocatorRuntimeState {
            id: 101,
            kind: AllocatorWorkerKind::ResidentData,
            worker_threads: 2,
            active: AtomicBool::new(true),
            handle: Mutex::new(Some(runtime.handle().clone())),
        };
        let report = flush_runtime_workers(&state, false, Instant::now() + Duration::from_secs(1));
        assert_eq!(report.expected, 2);
        assert_eq!(report.acknowledged, 2);
        assert_eq!(report.failures, 0);
    }

    #[test]
    fn runtime_flush_counts_the_calling_worker_without_self_deadlock() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let state = Arc::new(AllocatorRuntimeState {
            id: 102,
            kind: AllocatorWorkerKind::ProductControl,
            worker_threads: 2,
            active: AtomicBool::new(true),
            handle: Mutex::new(Some(runtime.handle().clone())),
        });
        let worker_state = Arc::clone(&state);
        let report = runtime.block_on(async move {
            tokio::spawn(async move {
                flush_runtime_workers(&worker_state, true, Instant::now() + Duration::from_secs(1))
            })
            .await
            .unwrap()
        });
        assert_eq!(report.expected, 2);
        assert_eq!(report.acknowledged, 2);
        assert_eq!(report.failures, 0);
    }
}
