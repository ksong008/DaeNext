use std::collections::VecDeque;
use std::time::Instant;

use dae_product_core::product_iso8601_utc;
use serde_json::{Value, json};

#[derive(Debug, Default)]
pub struct RuntimeTrafficStats {
    pub upload_total: u64,
    pub download_total: u64,
    pub upload_rate: u64,
    pub download_rate: u64,
    pub active_connections: u64,
    pub udp_sessions: u64,
    pub samples: Vec<Value>,
}

#[derive(Clone, Copy, Debug)]
pub struct RuntimeTrafficTotalSample {
    pub epoch: u64,
    pub upload_total: u64,
    pub download_total: u64,
    pub observed_at: Instant,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RuntimeTrafficObservation {
    pub timestamp: u64,
    pub upload_total: u64,
    pub download_total: u64,
    pub upload_rate: u64,
    pub download_rate: u64,
    pub active_connections: u64,
    pub udp_sessions: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RuntimeTrafficRateSample {
    pub timestamp: u64,
    pub upload_rate: u64,
    pub download_rate: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RuntimeTrafficCounters {
    pub upload_total: u64,
    pub download_total: u64,
    pub active_tcp_connections: u64,
    pub active_udp_sessions: u64,
}

pub fn calculate_runtime_traffic_observation(
    counters: RuntimeTrafficCounters,
    epoch: u64,
    timestamp: u64,
    observed_at: Instant,
    previous: Option<RuntimeTrafficTotalSample>,
) -> (RuntimeTrafficObservation, bool) {
    let upload_total = counters.upload_total;
    let download_total = counters.download_total;
    let mut upload_rate = 0_u64;
    let mut download_rate = 0_u64;
    let mut totals_reset = false;
    if let Some(previous) = previous {
        if previous.epoch != epoch {
            // A newly published physical runtime has a fresh timing baseline. The manager's
            // carry keeps totals monotonic, so do not turn the carried total into a reload spike.
        } else if upload_total < previous.upload_total || download_total < previous.download_total {
            totals_reset = true;
        } else {
            let elapsed = observed_at
                .saturating_duration_since(previous.observed_at)
                .as_secs_f64();
            if elapsed > 0.0 {
                upload_rate = ((upload_total - previous.upload_total) as f64 / elapsed) as u64;
                download_rate =
                    ((download_total - previous.download_total) as f64 / elapsed) as u64;
            }
        }
    }
    (
        RuntimeTrafficObservation {
            timestamp,
            upload_total,
            download_total,
            upload_rate,
            download_rate,
            active_connections: counters.active_tcp_connections,
            udp_sessions: counters.active_udp_sessions,
        },
        totals_reset,
    )
}

pub fn runtime_traffic_stats_from_history(
    latest: RuntimeTrafficObservation,
    history: &VecDeque<RuntimeTrafficRateSample>,
    window_sec: u64,
    max_points: usize,
) -> RuntimeTrafficStats {
    let window_start = latest.timestamp.saturating_sub(window_sec);
    let matching = history
        .iter()
        .copied()
        .filter(|sample| sample.timestamp >= window_start)
        .collect::<Vec<_>>();
    let samples = evenly_downsample(&matching, max_points.max(1))
        .into_iter()
        .map(|sample| {
            json!({
                "timestamp": product_iso8601_utc(sample.timestamp),
                "uploadRate": sample.upload_rate.to_string(),
                "downloadRate": sample.download_rate.to_string(),
            })
        })
        .collect();
    RuntimeTrafficStats {
        upload_total: latest.upload_total,
        download_total: latest.download_total,
        upload_rate: latest.upload_rate,
        download_rate: latest.download_rate,
        active_connections: latest.active_connections,
        udp_sessions: latest.udp_sessions,
        samples,
    }
}

fn evenly_downsample(
    samples: &[RuntimeTrafficRateSample],
    max_points: usize,
) -> Vec<RuntimeTrafficRateSample> {
    if samples.len() <= max_points {
        return samples.to_vec();
    }
    if max_points == 1 {
        return samples.last().copied().into_iter().collect();
    }
    let last = samples.len() - 1;
    (0..max_points)
        .map(|index| samples[index * last / (max_points - 1)])
        .collect()
}
