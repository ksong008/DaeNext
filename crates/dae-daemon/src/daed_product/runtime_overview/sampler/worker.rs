use super::*;
use std::sync::Condvar;

pub(super) struct ProductRuntimeSamplerStop {
    stopped: Mutex<bool>,
    changed: Condvar,
}

impl ProductRuntimeSamplerStop {
    pub(super) fn new() -> Self {
        Self {
            stopped: Mutex::new(false),
            changed: Condvar::new(),
        }
    }

    pub(super) fn stop(&self) {
        let Ok(mut stopped) = self.stopped.lock() else {
            return;
        };
        *stopped = true;
        self.changed.notify_all();
    }

    fn wait_until(&self, deadline: Instant) -> bool {
        let Ok(mut stopped) = self.stopped.lock() else {
            return true;
        };
        while !*stopped {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return false;
            }
            let Ok((next, wait)) = self.changed.wait_timeout(stopped, remaining) else {
                return true;
            };
            stopped = next;
            if wait.timed_out() {
                return *stopped;
            }
        }
        true
    }
}

pub(super) struct ProductRuntimeSamplerWorkerHandle {
    join: Option<thread::JoinHandle<()>>,
    completed: mpsc::Receiver<()>,
}

impl ProductRuntimeSamplerWorkerHandle {
    pub(super) fn join_until(mut self, deadline: Instant) -> bool {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() || self.completed.recv_timeout(remaining).is_err() {
            return false;
        }
        self.join.take().is_none_or(|join| join.join().is_ok())
    }
}

pub(super) fn start_product_runtime_sampler_worker(
    config: ProductRuntimeSamplerConfig,
    runtime: std::sync::Weak<ProductRuntimeManager>,
    state: Arc<Mutex<ProductRuntimeSamplerState>>,
    stop: Arc<ProductRuntimeSamplerStop>,
    metrics: Arc<ProductRuntimeSamplerMetrics>,
) -> io::Result<ProductRuntimeSamplerWorkerHandle> {
    let (ready_sender, ready) = mpsc::sync_channel(1);
    let (completed_sender, completed) = mpsc::sync_channel(1);
    let worker_stop = Arc::clone(&stop);
    let join = thread::Builder::new()
        .name("daed-metrics-rt".to_owned())
        .stack_size(config.worker_stack_bytes)
        .spawn(move || {
            let _completion = ProductRuntimeSamplerWorkerCompletion(completed_sender);
            run_product_runtime_sampler(config, runtime, state, worker_stop, metrics, ready_sender);
        })?;
    match ready.recv_timeout(config.start_timeout) {
        Ok(()) => Ok(ProductRuntimeSamplerWorkerHandle {
            join: Some(join),
            completed,
        }),
        Err(RecvTimeoutError::Timeout) => {
            stop.stop();
            drop(join);
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "start runtime sampler timed out",
            ))
        }
        Err(RecvTimeoutError::Disconnected) => {
            stop.stop();
            let _ = join.join();
            Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "runtime sampler stopped during startup",
            ))
        }
    }
}

struct ProductRuntimeSamplerWorkerCompletion(mpsc::SyncSender<()>);

impl Drop for ProductRuntimeSamplerWorkerCompletion {
    fn drop(&mut self) {
        let _ = self.0.try_send(());
    }
}

fn run_product_runtime_sampler(
    config: ProductRuntimeSamplerConfig,
    runtime: std::sync::Weak<ProductRuntimeManager>,
    state: Arc<Mutex<ProductRuntimeSamplerState>>,
    stop: Arc<ProductRuntimeSamplerStop>,
    metrics: Arc<ProductRuntimeSamplerMetrics>,
    ready: mpsc::SyncSender<()>,
) {
    let mut process_tracker = ProcessCpuTracker::default();
    let mut previous_traffic = None;
    let mut next_sample_at = Instant::now();
    let mut first = true;
    loop {
        let observed_at = Instant::now();
        let timestamp = unix_now();
        let runtime_traffic = runtime
            .upgrade()
            .and_then(|runtime| runtime.resident_traffic_counters())
            .unwrap_or_default();
        let (traffic, totals_reset) =
            runtime_traffic_observation(runtime_traffic, timestamp, observed_at, previous_traffic);
        previous_traffic = Some(RuntimeTrafficTotalSample {
            upload_total: traffic.upload_total,
            download_total: traffic.download_total,
            observed_at,
        });
        let process = match process_tracker.sample() {
            Ok(process) => Some(process),
            Err(_) => {
                metrics.process_read_failed();
                None
            }
        };
        let allocator = allocator_stats_snapshot();
        let cgroup_memory = cgroup_memory_snapshot_json();
        if let Ok(mut state) = state.lock() {
            state.record(
                traffic,
                totals_reset,
                process,
                allocator,
                cgroup_memory,
                config,
            );
        }
        metrics.sampled();
        if first {
            first = false;
            let _ = ready.try_send(());
        }

        next_sample_at = next_sample_at
            .checked_add(config.interval)
            .unwrap_or_else(Instant::now);
        if next_sample_at <= Instant::now() {
            metrics.schedule_missed();
            next_sample_at = Instant::now()
                .checked_add(config.interval)
                .unwrap_or_else(Instant::now);
        }
        if stop.wait_until(next_sample_at) {
            break;
        }
    }
}
