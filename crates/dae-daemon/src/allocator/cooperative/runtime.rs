use super::*;

thread_local! {
    static RUNTIME_WORKER: RefCell<Option<Arc<AllocatorWorkerState>>> = const { RefCell::new(None) };
    static PARKED_TCACHE_ENABLED: Cell<Option<bool>> = const { Cell::new(None) };
}

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
            workers: Mutex::new(Vec::new()),
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

    pub(crate) fn thread_poll(&self) {
        if ATTACHED_RUNTIME.with(Cell::get) == self.state.id {
            // Tokio also calls thread_start for its blocking pool. Register at
            // scheduler park/unpark hooks so idle blocking-pool threads cannot
            // become unreachable participants in every future flush request.
            RUNTIME_WORKER.with(|slot| {
                let mut slot = slot.borrow_mut();
                if let Some(worker) = slot.as_ref() {
                    worker.parked_cache_empty.store(false, Ordering::Release);
                }
                PARKED_TCACHE_ENABLED.with(|enabled| {
                    if let Some(previous) = enabled.take() {
                        let _ = mallctl::write_bool(b"thread.tcache.enabled\0", previous);
                    }
                });
                if slot.is_none() {
                    let worker = Arc::new(AllocatorWorkerState::new(self.state.kind, 0));
                    let mut workers = self.state.workers.lock().unwrap_or_else(|e| e.into_inner());
                    workers.retain(|worker| worker.strong_count() > 0);
                    workers.push(Arc::downgrade(&worker));
                    *slot = Some(worker);
                }
            });
            poll_runtime_worker();
        }
    }

    pub(crate) fn thread_park(&self) {
        self.thread_poll();
        if ATTACHED_RUNTIME.with(Cell::get) != self.state.id {
            return;
        }
        // Control workers can remain parked indefinitely: scheduling N probe
        // tasks cannot wake N distinct Tokio workers. Publish an empty cache
        // before parking, and invalidate it before the worker resumes tasks.
        // Disable tcache until unpark so scheduler maintenance cannot refill it.
        // Data-plane runtimes keep their existing on-demand polling hooks.
        RUNTIME_WORKER.with(|slot| {
            if let Some(worker) = slot.borrow().as_ref()
                && let Ok(enabled) = mallctl::read_bool(b"thread.tcache.enabled\0")
                && mallctl::write_bool(b"thread.tcache.enabled\0", false).is_ok()
            {
                PARKED_TCACHE_ENABLED.with(|previous| previous.set(Some(enabled)));
                let reclaim = worker_reclaim();
                let _guard = reclaim.wait_lock.lock().unwrap_or_else(|e| e.into_inner());
                worker.failed_epoch.store(0, Ordering::Relaxed);
                worker.parked_cache_empty.store(true, Ordering::Release);
                reclaim.waiter.notify_all();
            }
        });
    }

    pub(crate) fn thread_stop(&self) {
        if ATTACHED_RUNTIME.with(Cell::get) != self.state.id {
            return;
        }
        poll_runtime_worker();
        RUNTIME_WORKER.with(|slot| {
            if let Some(worker) = slot.borrow_mut().take() {
                let reclaim = worker_reclaim();
                let _guard = reclaim.wait_lock.lock().unwrap_or_else(|e| e.into_inner());
                worker.active.store(false, Ordering::Release);
                reclaim.waiter.notify_all();
            }
        });
        ATTACHED_RUNTIME.with(|runtime| runtime.set(0));
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

fn poll_runtime_worker() {
    RUNTIME_WORKER.with(|slot| {
        if let Some(worker) = slot.borrow().as_ref() {
            worker.poll(worker_reclaim());
        }
    });
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
    workers: Mutex<Vec<Weak<AllocatorWorkerState>>>,
    handle: Mutex<Option<tokio::runtime::Handle>>,
}

impl AllocatorRuntimeState {
    pub(super) fn registered_worker_count(&self) -> usize {
        self.workers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter_map(Weak::upgrade)
            .filter(|worker| worker.active.load(Ordering::Acquire))
            .count()
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
    runtime: &Arc<AllocatorRuntimeState>,
    current_worker: bool,
    deadline: Instant,
) -> AllocatorRuntimeFlushReport {
    if current_worker {
        AllocatorRuntimeReclaimHooks {
            state: Arc::clone(runtime),
        }
        .thread_poll();
    }
    flush_runtime_workers_blocking(runtime, deadline)
}

fn flush_runtime_workers_blocking(
    runtime: &Arc<AllocatorRuntimeState>,
    deadline: Instant,
) -> AllocatorRuntimeFlushReport {
    let reclaim = worker_reclaim();
    let epoch = reclaim.desired_epoch.load(Ordering::Acquire);
    let workers = {
        let mut registered = runtime.workers.lock().unwrap_or_else(|e| e.into_inner());
        registered.retain(|worker| worker.strong_count() > 0);
        registered
            .iter()
            .filter_map(Weak::upgrade)
            .filter(|worker| worker.active.load(Ordering::Acquire))
            .collect::<Vec<_>>()
    };
    if let Some(handle) = runtime.handle.lock().ok().and_then(|handle| handle.clone()) {
        // These tasks only prompt scheduling/park hooks. Acknowledgments belong
        // to registered OS threads, never to the number of tasks that ran.
        for _ in 0..runtime.worker_threads {
            let hooks = AllocatorRuntimeReclaimHooks {
                state: Arc::clone(runtime),
            };
            handle.spawn(async move {
                if Instant::now() < deadline {
                    hooks.thread_poll();
                    tokio::task::yield_now().await;
                    hooks.thread_poll();
                }
            });
        }
    }
    wait_for_direct_workers(reclaim, &workers, epoch, deadline);
    AllocatorRuntimeFlushReport {
        kind: runtime.kind,
        // A worker may not have reached its first scheduler hook yet. Keep the
        // configured worker count as a floor: incomplete registration must not
        // turn an empty snapshot into a successful flush. Later registrations
        // participate in the next epoch.
        expected: workers.len().max(runtime.worker_threads),
        acknowledged: workers
            .iter()
            .filter(|worker| worker.acknowledged(epoch))
            .count(),
        failures: workers
            .iter()
            .filter(|worker| worker.failed_epoch.load(Ordering::Relaxed) == epoch)
            .count(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_runtime() -> (AllocatorRuntimeReclaimHooks, tokio::runtime::Runtime) {
        test_runtime_with_workers(AllocatorWorkerKind::ResidentData, 1)
    }

    fn test_runtime_with_workers(
        kind: AllocatorWorkerKind,
        worker_threads: usize,
    ) -> (AllocatorRuntimeReclaimHooks, tokio::runtime::Runtime) {
        let hooks = AllocatorRuntimeReclaimHooks::new(kind, worker_threads);
        let start = hooks.clone();
        let stop = hooks.clone();
        let park = hooks.clone();
        let unpark = hooks.clone();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(worker_threads)
            .on_thread_start(move || start.thread_start())
            .on_thread_stop(move || stop.thread_stop())
            .on_thread_park(move || {
                if kind == AllocatorWorkerKind::ProductControl {
                    park.thread_park();
                } else {
                    park.thread_poll();
                }
            })
            .on_thread_unpark(move || unpark.thread_poll())
            .enable_all()
            .build()
            .unwrap();
        hooks.activate(runtime.handle().clone());
        let initialize = hooks.clone();
        runtime.block_on(async {
            tokio::spawn(async move { initialize.thread_poll() })
                .await
                .unwrap();
        });
        (hooks, runtime)
    }

    #[test]
    fn parked_control_cache_is_disabled_and_restores_the_previous_setting() {
        std::thread::spawn(|| {
            let hooks = AllocatorRuntimeReclaimHooks::new(AllocatorWorkerKind::ProductControl, 1);
            hooks.thread_start();
            for enabled in [true, false] {
                mallctl::write_bool(b"thread.tcache.enabled\0", enabled).unwrap();
                hooks.thread_park();
                assert!(!mallctl::read_bool(b"thread.tcache.enabled\0").unwrap());
                hooks.thread_poll();
                assert_eq!(
                    mallctl::read_bool(b"thread.tcache.enabled\0").unwrap(),
                    enabled
                );
            }
            hooks.thread_stop();
        })
        .join()
        .unwrap();
    }

    #[test]
    fn parked_control_workers_satisfy_reclaim_without_each_running_a_probe_task() {
        let (hooks, runtime) = test_runtime_with_workers(AllocatorWorkerKind::ProductControl, 4);
        let deadline = Instant::now() + Duration::from_secs(3);
        let all_parked = loop {
            let parked = hooks
                .state
                .workers
                .lock()
                .unwrap()
                .iter()
                .filter_map(Weak::upgrade)
                .filter(|worker| worker.parked_cache_empty.load(Ordering::Acquire))
                .count();
            if parked == 4 || Instant::now() >= deadline {
                break parked == 4;
            }
            std::thread::sleep(Duration::from_millis(1));
        };
        let epoch = worker_reclaim()
            .desired_epoch
            .fetch_add(1, Ordering::AcqRel)
            + 1;
        // No probe tasks are submitted: all four caches were flushed before park.
        let all_acknowledged = hooks
            .state
            .workers
            .lock()
            .unwrap()
            .iter()
            .filter_map(Weak::upgrade)
            .all(|worker| worker.acknowledged(epoch));
        let resumed = hooks.clone();
        let clears_parked = runtime.block_on(async {
            tokio::spawn(async move {
                resumed.thread_poll();
                RUNTIME_WORKER.with(|slot| {
                    !slot
                        .borrow()
                        .as_ref()
                        .unwrap()
                        .parked_cache_empty
                        .load(Ordering::Acquire)
                })
            })
            .await
            .unwrap()
        });
        hooks.deactivate();
        runtime.shutdown_timeout(Duration::from_secs(1));
        assert!(all_parked, "control workers did not publish empty caches");
        assert!(
            all_acknowledged,
            "parked workers required a scheduling probe"
        );
        assert!(
            clears_parked,
            "running worker retained its parked cache state"
        );
    }

    #[test]
    fn missing_worker_ack_does_not_block_runtime_or_count_duplicate_tasks() {
        let (hooks, runtime) = test_runtime();
        let missing = Arc::new(AllocatorWorkerState::new(
            AllocatorWorkerKind::ResidentData,
            0,
        ));
        hooks
            .state
            .workers
            .lock()
            .unwrap()
            .push(Arc::downgrade(&missing));
        worker_reclaim()
            .desired_epoch
            .fetch_add(1, Ordering::AcqRel);
        let state = Arc::clone(&hooks.state);
        let coordinator = std::thread::spawn(move || {
            flush_runtime_workers(&state, false, Instant::now() + Duration::from_millis(500))
        });
        let (done, received) = std::sync::mpsc::channel();
        runtime.spawn(async move {
            for _ in 0..32 {
                poll_runtime_worker();
                tokio::task::yield_now().await;
            }
            done.send(()).unwrap();
        });
        let responsive = received.recv_timeout(Duration::from_millis(250)).is_ok();
        let report = coordinator.join().unwrap();
        assert!(responsive, "a missing peer stalled data-plane work");
        assert_eq!(report.expected, 2);
        assert_eq!(
            report.acknowledged, 1,
            "duplicate tasks must not acknowledge another OS thread"
        );
        // A late acknowledgment cannot mutate a completed report or satisfy a
        // later request until the actual worker flushes that later epoch.
        missing.poll(worker_reclaim());
        worker_reclaim()
            .desired_epoch
            .fetch_add(1, Ordering::AcqRel);
        assert!(
            missing.acknowledged_epoch.load(Ordering::Acquire)
                < worker_reclaim().desired_epoch.load(Ordering::Acquire)
        );
        hooks.deactivate();
        runtime.shutdown_timeout(Duration::from_secs(1));
    }

    #[test]
    fn unregistered_scheduler_worker_is_reported_as_partial() {
        let hooks = AllocatorRuntimeReclaimHooks::new(AllocatorWorkerKind::ResidentData, 1);
        worker_reclaim()
            .desired_epoch
            .fetch_add(1, Ordering::AcqRel);
        let report = flush_runtime_workers(&hooks.state, false, Instant::now());
        assert_eq!(report.expected, 1);
        assert_eq!(report.acknowledged, 0);
    }

    #[test]
    fn idle_blocking_pool_thread_is_not_a_flush_participant() {
        let (hooks, runtime) = test_runtime();
        runtime.block_on(async {
            tokio::task::spawn_blocking(|| {}).await.unwrap();
        });
        assert_eq!(hooks.state.registered_worker_count(), 1);
        worker_reclaim()
            .desired_epoch
            .fetch_add(1, Ordering::AcqRel);
        let report = flush_runtime_workers(
            &hooks.state,
            false,
            Instant::now() + Duration::from_millis(500),
        );
        assert_eq!(report.expected, 1);
        assert_eq!(report.acknowledged, 1);
        hooks.deactivate();
        runtime.shutdown_timeout(Duration::from_secs(1));
    }

    #[test]
    fn coordinator_on_scheduler_releases_capacity_while_waiting_for_direct_worker() {
        let (hooks, runtime) = test_runtime();
        let missing = Arc::new(AllocatorWorkerState::new(AllocatorWorkerKind::Http, 0));
        worker_reclaim()
            .workers
            .lock()
            .unwrap()
            .push(Arc::downgrade(&missing));
        let (started, receive_start) = std::sync::mpsc::channel();
        let coordinator = runtime.spawn(async move {
            started.send(()).unwrap();
            allocator_flush_registered_worker_caches()
        });
        receive_start.recv_timeout(Duration::from_secs(1)).unwrap();
        let (done, received) = std::sync::mpsc::channel();
        runtime.spawn(async move { done.send(()).unwrap() });
        let responsive = received.recv_timeout(Duration::from_millis(250)).is_ok();
        let (complete, report) = runtime.block_on(coordinator).unwrap();
        assert!(
            responsive,
            "coordinator held scheduler capacity while waiting"
        );
        assert!(
            !complete,
            "an absent direct worker must leave a partial report"
        );
        assert_eq!(report["acknowledgedByClass"]["http"], 0);
        assert!(
            report["acknowledgedByClass"]["resident-data"]
                .as_u64()
                .unwrap()
                >= 1
        );
        hooks.deactivate();
        runtime.shutdown_timeout(Duration::from_secs(1));
    }
}
