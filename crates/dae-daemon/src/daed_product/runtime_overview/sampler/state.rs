use super::*;

#[derive(Debug, Default)]
pub(super) struct ProductRuntimeSamplerState {
    latest_traffic: RuntimeTrafficObservation,
    latest_process: ProcessMetrics,
    latest_allocator: Option<AllocatorStatsSnapshot>,
    latest_cgroup_memory: Value,
    history: VecDeque<RuntimeTrafficRateSample>,
    sample_count: u64,
}

pub(crate) struct ProductRuntimeSampleView {
    pub(crate) sampled_at: u64,
    pub(crate) sample_count: u64,
    pub(crate) traffic: RuntimeTrafficStats,
    pub(crate) process: ProcessMetrics,
    pub(crate) allocator: Option<AllocatorStatsSnapshot>,
    pub(crate) cgroup_memory: Value,
}

impl ProductRuntimeSamplerState {
    pub(super) fn record(
        &mut self,
        traffic: RuntimeTrafficObservation,
        totals_reset: bool,
        process: Option<ProcessMetrics>,
        allocator: Option<AllocatorStatsSnapshot>,
        cgroup_memory: Value,
        config: ProductRuntimeSamplerConfig,
    ) {
        if totals_reset {
            self.history.clear();
        }
        let rate = RuntimeTrafficRateSample {
            timestamp: traffic.timestamp,
            upload_rate: traffic.upload_rate,
            download_rate: traffic.download_rate,
        };
        if self
            .history
            .back()
            .is_some_and(|sample| sample.timestamp == rate.timestamp)
        {
            if let Some(back) = self.history.back_mut() {
                *back = rate;
            }
        } else {
            self.history.push_back(rate);
        }
        let retention_start = traffic.timestamp.saturating_sub(config.retention.as_secs());
        while self
            .history
            .front()
            .is_some_and(|sample| sample.timestamp < retention_start)
        {
            self.history.pop_front();
        }
        while self.history.len() > config.history_capacity {
            self.history.pop_front();
        }
        self.latest_traffic = traffic;
        if let Some(process) = process {
            self.latest_process = process;
        }
        self.latest_allocator = allocator;
        self.latest_cgroup_memory = cgroup_memory;
        self.sample_count = self.sample_count.saturating_add(1);
    }

    pub(super) fn view(&self, window_sec: u64, max_points: usize) -> ProductRuntimeSampleView {
        ProductRuntimeSampleView {
            sampled_at: self.latest_traffic.timestamp,
            sample_count: self.sample_count,
            traffic: runtime_traffic_stats_from_history(
                self.latest_traffic,
                &self.history,
                window_sec,
                max_points,
            ),
            process: self.latest_process,
            allocator: self.latest_allocator,
            cgroup_memory: self.latest_cgroup_memory.clone(),
        }
    }

    pub(super) fn history_len(&self) -> usize {
        self.history.len()
    }
}
