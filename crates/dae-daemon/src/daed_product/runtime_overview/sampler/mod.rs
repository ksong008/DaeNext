use super::*;

mod config;
use self::config::*;
mod metrics;
use self::metrics::*;
mod state;
use self::state::*;
mod worker;
use self::worker::*;
#[cfg(test)]
mod tests;

pub(crate) struct ProductRuntimeSampler {
    config: ProductRuntimeSamplerConfig,
    runtime: std::sync::Weak<ProductRuntimeManager>,
    state: Arc<Mutex<ProductRuntimeSamplerState>>,
    stop: Arc<ProductRuntimeSamplerStop>,
    worker: Mutex<Option<ProductRuntimeSamplerWorkerHandle>>,
    metrics: Arc<ProductRuntimeSamplerMetrics>,
}

impl std::fmt::Debug for ProductRuntimeSampler {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProductRuntimeSampler")
            .field("config", &self.config)
            .field("metrics", &self.snapshot())
            .finish_non_exhaustive()
    }
}

impl ProductRuntimeSampler {
    fn start_with_config(
        runtime: std::sync::Weak<ProductRuntimeManager>,
        config: ProductRuntimeSamplerConfig,
    ) -> io::Result<Arc<Self>> {
        let state = Arc::new(Mutex::new(ProductRuntimeSamplerState::default()));
        let stop = Arc::new(ProductRuntimeSamplerStop::new());
        let metrics = Arc::new(ProductRuntimeSamplerMetrics::default());
        metrics.configure(config);
        Ok(Arc::new(Self {
            config,
            runtime,
            state,
            stop,
            worker: Mutex::new(None),
            metrics,
        }))
    }

    pub(crate) fn start(runtime: std::sync::Weak<ProductRuntimeManager>) -> io::Result<Arc<Self>> {
        Self::start_with_config(runtime, ProductRuntimeSamplerConfig::product_default())
    }

    pub(crate) fn view(&self, window_sec: u64, max_points: usize) -> ProductRuntimeSampleView {
        let _ = self.ensure_worker();
        self.state
            .lock()
            .map(|state| state.view(window_sec, max_points))
            .unwrap_or_else(|_| fallback_runtime_sample_view(None, window_sec, max_points))
    }

    pub(crate) fn snapshot(&self) -> Value {
        let _ = self.ensure_worker();
        let history_length = self
            .state
            .lock()
            .map(|state| state.history_len())
            .unwrap_or(0);
        self.metrics.snapshot(history_length)
    }

    pub(crate) fn sequence(&self) -> u64 {
        let _ = self.ensure_worker();
        self.state
            .lock()
            .map(|state| state.sequence())
            .unwrap_or_default()
    }

    fn ensure_worker(&self) -> io::Result<()> {
        let mut worker = self
            .worker
            .lock()
            .map_err(|_| io::Error::other("runtime sampler worker lock poisoned"))?;
        if worker.is_none() {
            *worker = Some(start_product_runtime_sampler_worker(
                self.config,
                self.runtime.clone(),
                Arc::clone(&self.state),
                Arc::clone(&self.stop),
                Arc::clone(&self.metrics),
            )?);
        }
        Ok(())
    }
}

impl Drop for ProductRuntimeSampler {
    fn drop(&mut self) {
        self.stop.stop();
        let worker = self
            .worker
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        let Some(worker) = worker else {
            return;
        };
        let deadline = Instant::now()
            .checked_add(self.config.shutdown_timeout)
            .unwrap_or_else(Instant::now);
        if worker.join_until(deadline) {
            self.metrics.runtime_joined();
        } else {
            self.metrics.runtime_detached();
        }
    }
}

pub(super) fn runtime_sample_view_for_app(
    app: &AppState,
    window_sec: u64,
    max_points: usize,
) -> ProductRuntimeSampleView {
    app.runtime_sampler.as_ref().map_or_else(
        || {
            fallback_runtime_sample_view(
                app.runtime.resident_traffic_counters(),
                window_sec,
                max_points,
            )
        },
        |sampler| sampler.view(window_sec, max_points),
    )
}

fn fallback_runtime_sample_view(
    counters: Option<ResidentTrafficCounters>,
    window_sec: u64,
    max_points: usize,
) -> ProductRuntimeSampleView {
    let sampled_at = unix_now();
    let observation = runtime_traffic_observation(
        counters.unwrap_or_default(),
        0,
        sampled_at,
        Instant::now(),
        None,
    )
    .0;
    let traffic = RuntimeTrafficStats {
        upload_total: observation.upload_total,
        download_total: observation.download_total,
        upload_rate: observation.upload_rate,
        download_rate: observation.download_rate,
        active_connections: observation.active_connections,
        udp_sessions: observation.udp_sessions,
        ..RuntimeTrafficStats::default()
    };
    let history = VecDeque::from([RuntimeTrafficRateSample {
        timestamp: sampled_at,
        upload_rate: traffic.upload_rate,
        download_rate: traffic.download_rate,
    }]);
    ProductRuntimeSampleView {
        sampled_at,
        sample_count: 0,
        traffic: RuntimeTrafficStats {
            samples: runtime_traffic_stats_from_history(
                observation,
                &history,
                window_sec,
                max_points,
            )
            .samples,
            ..traffic
        },
        process: process_metrics_lifetime_snapshot(),
        allocator: allocator_stats_snapshot(),
        cgroup_memory: cgroup_memory_snapshot_json(),
        traffic_availability: counters
            .map(|_| RuntimeTrafficAvailability::Active)
            .unwrap_or(RuntimeTrafficAvailability::RuntimeStopped),
        counter_epoch: 0,
        last_runtime_counter_at: counters.map(|_| sampled_at),
    }
}
