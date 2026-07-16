use super::*;

const RESIDENT_HEALTH_RUNTIME_WORKERS_MAX: usize = 4;
const RESIDENT_HEALTH_RUNTIME_BLOCKING_THREADS_MAX: usize = 4;
const RESIDENT_HEALTH_BOOTSTRAP_CONCURRENCY_MAX: usize = 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ResidentHealthExecutor {
    CurrentThread,
    MultiThread,
}

impl ResidentHealthExecutor {
    const fn name(self) -> &'static str {
        match self {
            Self::CurrentThread => "current-thread",
            Self::MultiThread => "multi-thread",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::production_runtime_owner::resident_dataplane) struct ResidentHealthRuntimeConfig {
    executor: ResidentHealthExecutor,
    worker_threads: usize,
    owner_threads: usize,
    max_blocking_threads: usize,
    available_parallelism: usize,
}

impl ResidentHealthRuntimeConfig {
    pub(in crate::production_runtime_owner::resident_dataplane) fn detect(
        group_count: usize,
        per_group_candidate_concurrency: usize,
        bootstrap_candidate_count: usize,
    ) -> Self {
        let available_parallelism = std::thread::available_parallelism()
            .map(|parallelism| parallelism.get())
            .unwrap_or(1);
        Self::from_parallelism(
            available_parallelism,
            group_count,
            per_group_candidate_concurrency,
            bootstrap_candidate_count,
        )
    }

    pub(super) fn from_parallelism(
        available_parallelism: usize,
        group_count: usize,
        per_group_candidate_concurrency: usize,
        bootstrap_candidate_count: usize,
    ) -> Self {
        let available_parallelism = available_parallelism.max(1);
        let periodic_probe_tasks = group_count
            .saturating_mul(per_group_candidate_concurrency.max(1))
            .max(1);
        let runnable_probe_tasks = periodic_probe_tasks.max(bootstrap_candidate_count.max(1));
        let worker_threads = available_parallelism
            .min(runnable_probe_tasks)
            .clamp(1, RESIDENT_HEALTH_RUNTIME_WORKERS_MAX);
        let max_blocking_threads = available_parallelism
            .min(runnable_probe_tasks)
            .clamp(1, RESIDENT_HEALTH_RUNTIME_BLOCKING_THREADS_MAX);
        if worker_threads == 1 {
            Self {
                executor: ResidentHealthExecutor::CurrentThread,
                worker_threads,
                owner_threads: 0,
                max_blocking_threads,
                available_parallelism,
            }
        } else {
            Self {
                executor: ResidentHealthExecutor::MultiThread,
                worker_threads,
                owner_threads: 1,
                max_blocking_threads,
                available_parallelism,
            }
        }
    }

    pub(super) fn json(self) -> Value {
        json!({
            "executor": self.executor.name(),
            "workerThreads": self.worker_threads,
            "ownerThreads": self.owner_threads,
            "maximumBlockingThreads": self.max_blocking_threads,
            "maximumWorkerThreads": RESIDENT_HEALTH_RUNTIME_WORKERS_MAX,
            "maximumOsThreads": RESIDENT_HEALTH_RUNTIME_WORKERS_MAX
                + 1
                + RESIDENT_HEALTH_RUNTIME_BLOCKING_THREADS_MAX,
            "availableParallelism": self.available_parallelism,
        })
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn os_thread_count(self) -> usize {
        self.worker_threads.saturating_add(self.owner_threads)
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn maximum_os_thread_count(
        self,
    ) -> usize {
        self.os_thread_count()
            .saturating_add(self.max_blocking_threads)
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn bootstrap_concurrency(
        self,
        candidate_count: usize,
        configured_periodic_concurrency: usize,
    ) -> usize {
        self.available_parallelism
            .min(candidate_count.max(1))
            .min(RESIDENT_HEALTH_BOOTSTRAP_CONCURRENCY_MAX)
            .max(configured_periodic_concurrency.max(1))
    }
}

pub(super) fn build_resident_health_runtime(
    config: ResidentHealthRuntimeConfig,
) -> Result<tokio::runtime::Runtime, String> {
    let result = match config.executor {
        ResidentHealthExecutor::CurrentThread => tokio::runtime::Builder::new_current_thread()
            .max_blocking_threads(config.max_blocking_threads)
            .enable_io()
            .enable_time()
            .build(),
        ResidentHealthExecutor::MultiThread => tokio::runtime::Builder::new_multi_thread()
            .worker_threads(config.worker_threads)
            .max_blocking_threads(config.max_blocking_threads)
            .thread_name("resident-health-runtime")
            .enable_io()
            .enable_time()
            .build(),
    };
    result.map_err(|err| format!("build resident shared health runtime: {err}"))
}

pub(super) fn resident_health_runtime_contract() -> Value {
    json!({
        "executor": "CPU-aware current-thread or shared multi-thread Tokio runtime",
        "workerDefault": "min(available_parallelism, materialized_groups * per_group_candidate_concurrency, maximumWorkerThreads)",
        "blockingThreadDefault": "min(available_parallelism, materialized_groups * per_group_candidate_concurrency, maximumBlockingThreads)",
        "maximumWorkerThreads": RESIDENT_HEALTH_RUNTIME_WORKERS_MAX,
        "maximumBlockingThreads": RESIDENT_HEALTH_RUNTIME_BLOCKING_THREADS_MAX,
        "maximumOsThreads": RESIDENT_HEALTH_RUNTIME_WORKERS_MAX
            + 1
            + RESIDENT_HEALTH_RUNTIME_BLOCKING_THREADS_MAX,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    static HEALTH_RUNTIME_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn health_runtime_workers_follow_cpu_and_static_work_bounds() {
        let single = ResidentHealthRuntimeConfig::from_parallelism(1, 128, 8, 1_024);
        assert_eq!(single.executor, ResidentHealthExecutor::CurrentThread);
        assert_eq!(single.worker_threads, 1);
        assert_eq!(single.owner_threads, 0);
        assert_eq!(single.max_blocking_threads, 1);

        let small = ResidentHealthRuntimeConfig::from_parallelism(8, 1, 1, 1);
        assert_eq!(small.executor, ResidentHealthExecutor::CurrentThread);
        assert_eq!(small.worker_threads, 1);

        let disabled = ResidentHealthRuntimeConfig::from_parallelism(64, 0, 128, 0);
        assert_eq!(disabled.executor, ResidentHealthExecutor::CurrentThread);
        assert_eq!(disabled.worker_threads, 1);

        let bounded = ResidentHealthRuntimeConfig::from_parallelism(64, 128, 8, 1_024);
        assert_eq!(bounded.executor, ResidentHealthExecutor::MultiThread);
        assert_eq!(bounded.worker_threads, RESIDENT_HEALTH_RUNTIME_WORKERS_MAX);
        assert_eq!(bounded.owner_threads, 1);
        assert_eq!(
            bounded.max_blocking_threads,
            RESIDENT_HEALTH_RUNTIME_BLOCKING_THREADS_MAX
        );
    }

    #[test]
    fn health_runtime_detection_honors_the_live_host_parallelism() {
        let available = std::thread::available_parallelism()
            .map(|parallelism| parallelism.get())
            .unwrap_or(1)
            .max(1);
        let detected = ResidentHealthRuntimeConfig::detect(128, 8, 1_024);
        assert_eq!(
            detected.worker_threads,
            available.min(RESIDENT_HEALTH_RUNTIME_WORKERS_MAX)
        );
        assert_eq!(
            detected.max_blocking_threads,
            available.min(RESIDENT_HEALTH_RUNTIME_BLOCKING_THREADS_MAX)
        );
    }

    #[test]
    fn health_runtime_builds_current_and_multi_thread_executors() {
        #[cfg(target_os = "linux")]
        let _guard = HEALTH_RUNTIME_TEST_LOCK.lock().unwrap();
        let current = ResidentHealthRuntimeConfig::from_parallelism(1, 4, 4, 16);
        let runtime = build_resident_health_runtime(current).unwrap();
        assert_eq!(runtime.block_on(async { 3 }), 3);
        drop(runtime);

        let multi = ResidentHealthRuntimeConfig::from_parallelism(4, 4, 4, 16);
        let runtime = build_resident_health_runtime(multi).unwrap();
        let result = runtime.block_on(async { tokio::spawn(async { 7 }).await.unwrap() });
        assert_eq!(result, 7);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn health_runtime_worker_and_blocking_thread_counts_match_detected_bounds() {
        let _guard = HEALTH_RUNTIME_TEST_LOCK.lock().unwrap();
        let config = ResidentHealthRuntimeConfig::from_parallelism(64, 128, 8, 1_024);
        let runtime = build_resident_health_runtime(config).unwrap();
        let active = Arc::new(AtomicUsize::new(0));
        let maximum_active = Arc::new(AtomicUsize::new(0));
        runtime.block_on(async {
            let mut tasks = tokio::task::JoinSet::new();
            for _ in 0..16 {
                let active = Arc::clone(&active);
                let maximum_active = Arc::clone(&maximum_active);
                tasks.spawn_blocking(move || {
                    let current = active.fetch_add(1, Ordering::Relaxed).saturating_add(1);
                    maximum_active.fetch_max(current, Ordering::Relaxed);
                    std::thread::sleep(Duration::from_millis(20));
                    active.fetch_sub(1, Ordering::Relaxed);
                });
            }
            while let Some(result) = tasks.join_next().await {
                result.unwrap();
            }
        });
        assert_eq!(
            maximum_active.load(Ordering::Relaxed),
            config.max_blocking_threads
        );

        let mut runtime_threads = 0_usize;
        for entry in std::fs::read_dir("/proc/self/task").unwrap().flatten() {
            let comm = std::fs::read_to_string(entry.path().join("comm")).unwrap_or_default();
            if comm.trim().starts_with("resident-health") {
                runtime_threads = runtime_threads.saturating_add(1);
            }
        }
        assert_eq!(
            runtime_threads,
            config
                .worker_threads
                .saturating_add(config.max_blocking_threads)
        );
    }
}
