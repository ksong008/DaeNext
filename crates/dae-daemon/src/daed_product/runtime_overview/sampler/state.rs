use super::*;

#[derive(Debug, Default)]
pub(super) struct ProductRuntimeSamplerState {
    latest_traffic: RuntimeTrafficObservation,
    latest_process: ProcessMetrics,
    latest_allocator: Option<AllocatorStatsSnapshot>,
    latest_cgroup_memory: Value,
    history: VecDeque<RuntimeTrafficRateSample>,
    sample_count: u64,
    latest_tick_at: u64,
    last_runtime_counter_at: Option<u64>,
    traffic_availability: RuntimeTrafficAvailability,
    counter_epoch: u64,
}

pub(crate) struct ProductRuntimeSampleView {
    pub(crate) sampled_at: u64,
    pub(crate) sample_count: u64,
    pub(crate) traffic: RuntimeTrafficStats,
    pub(crate) process: ProcessMetrics,
    pub(crate) allocator: Option<AllocatorStatsSnapshot>,
    pub(crate) cgroup_memory: Value,
    pub(crate) traffic_availability: RuntimeTrafficAvailability,
    pub(crate) counter_epoch: u64,
    pub(crate) last_runtime_counter_at: Option<u64>,
}

impl ProductRuntimeSamplerState {
    pub(super) fn record(
        &mut self,
        counter_epoch: u64,
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
        self.latest_tick_at = traffic.timestamp;
        self.last_runtime_counter_at = Some(traffic.timestamp);
        self.traffic_availability = RuntimeTrafficAvailability::Active;
        self.counter_epoch = counter_epoch;
        if let Some(process) = process {
            self.latest_process = process;
        }
        self.latest_allocator = allocator;
        self.latest_cgroup_memory = cgroup_memory;
        self.sample_count = self.sample_count.saturating_add(1);
    }

    pub(super) fn record_unavailable(
        &mut self,
        timestamp: u64,
        counter_epoch: u64,
        availability: RuntimeTrafficAvailability,
        process: Option<ProcessMetrics>,
        allocator: Option<AllocatorStatsSnapshot>,
        cgroup_memory: Value,
    ) {
        // Keep the last valid traffic totals/history intact. A missing runtime is not a zero
        // counter sample and must not erase the rate baseline or manufacture a spike later.
        self.latest_tick_at = timestamp;
        self.traffic_availability = availability;
        self.counter_epoch = counter_epoch;
        if let Some(process) = process {
            self.latest_process = process;
        }
        self.latest_allocator = allocator;
        self.latest_cgroup_memory = cgroup_memory;
        self.sample_count = self.sample_count.saturating_add(1);
    }

    pub(super) fn view(&self, window_sec: u64, max_points: usize) -> ProductRuntimeSampleView {
        ProductRuntimeSampleView {
            sampled_at: self.latest_tick_at,
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
            traffic_availability: self.traffic_availability,
            counter_epoch: self.counter_epoch,
            last_runtime_counter_at: self.last_runtime_counter_at,
        }
    }

    pub(super) fn history_len(&self) -> usize {
        self.history.len()
    }

    pub(super) fn sequence(&self) -> u64 {
        self.sample_count
    }
}
