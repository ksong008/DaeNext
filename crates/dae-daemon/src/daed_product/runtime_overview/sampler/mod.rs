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
        let worker = start_product_runtime_sampler_worker(
            config,
            runtime,
            Arc::clone(&state),
            Arc::clone(&stop),
            Arc::clone(&metrics),
        )?;
        Ok(Arc::new(Self {
            config,
            state,
            stop,
            worker: Mutex::new(Some(worker)),
            metrics,
        }))
    }

    pub(crate) fn start(runtime: std::sync::Weak<ProductRuntimeManager>) -> io::Result<Arc<Self>> {
        Self::start_with_config(runtime, ProductRuntimeSamplerConfig::product_default())
    }

    pub(crate) fn view(&self, window_sec: u64, max_points: usize) -> ProductRuntimeSampleView {
        self.state
            .lock()
            .map(|state| state.view(window_sec, max_points))
            .unwrap_or_else(|_| fallback_runtime_sample_view(None, window_sec, max_points))
    }

    pub(crate) fn snapshot(&self) -> Value {
        let history_length = self
            .state
            .lock()
            .map(|state| state.history_len())
            .unwrap_or(0);
        self.metrics.snapshot(history_length)
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
                app.runtime.resident_dataplane_metrics_snapshot().as_ref(),
                window_sec,
                max_points,
            )
        },
        |sampler| sampler.view(window_sec, max_points),
    )
}

fn fallback_runtime_sample_view(
    metrics: Option<&Value>,
    window_sec: u64,
    max_points: usize,
) -> ProductRuntimeSampleView {
    let sampled_at = unix_now();
    let traffic = metrics
        .map(resident_runtime_traffic_stats_from_metrics)
        .unwrap_or_default();
    ProductRuntimeSampleView {
        sampled_at,
        sample_count: 0,
        traffic: RuntimeTrafficStats {
            samples: runtime_traffic_stats_from_history(
                RuntimeTrafficObservation {
                    timestamp: sampled_at,
                    upload_total: traffic.upload_total,
                    download_total: traffic.download_total,
                    upload_rate: traffic.upload_rate,
                    download_rate: traffic.download_rate,
                    active_connections: traffic.active_connections,
                    udp_sessions: traffic.udp_sessions,
                },
                &VecDeque::new(),
                window_sec,
                max_points,
            )
            .samples,
            ..traffic
        },
        process: process_metrics_lifetime_snapshot(),
    }
}
