use std::collections::VecDeque;
use std::time::Instant;

use dae_product_core::product_iso8601_utc;
pub use dae_resident_core::ResidentTrafficCounters as RuntimeTrafficCounters;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum RuntimeTrafficAvailability {
    Active,
    TemporarilyUnavailable,
    #[default]
    RuntimeStopped,
}

impl RuntimeTrafficAvailability {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::TemporarilyUnavailable => "temporarily-unavailable",
            Self::RuntimeStopped => "runtime-stopped",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeTrafficRead {
    pub epoch: u64,
    pub counters: RuntimeTrafficCounters,
    pub availability: RuntimeTrafficAvailability,
}

impl RuntimeTrafficRead {
    pub fn runtime_stopped(epoch: u64) -> Self {
        Self {
            epoch,
            counters: RuntimeTrafficCounters::default(),
            availability: RuntimeTrafficAvailability::RuntimeStopped,
        }
    }
}
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
pub struct RuntimeTrafficCarry {
    pub upload_total: u64,
    pub download_total: u64,
    pub packet_total: u64,
    pub request_total: u64,
}

impl RuntimeTrafficCarry {
    pub fn absorb_counters(self, counters: RuntimeTrafficCounters) -> Self {
        Self {
            upload_total: self.upload_total.saturating_add(counters.upload_total),
            download_total: self.download_total.saturating_add(counters.download_total),
            packet_total: self.packet_total.saturating_add(counters.packet_total),
            request_total: self.request_total.saturating_add(counters.request_total),
        }
    }

    pub fn apply_to_metrics(self, metrics: &mut Value) {
        if self.upload_total == 0 && self.download_total == 0 {
            return;
        }
        apply_runtime_traffic_metric_carry(metrics, "uploadTotal", self.upload_total);
        apply_runtime_traffic_metric_carry(metrics, "downloadTotal", self.download_total);
    }

    pub fn apply_to_runtime_summary(self, summary: &mut Value) {
        if let Some(metrics) = summary.pointer_mut("/residentDataplane/metrics") {
            self.apply_to_metrics(metrics);
        }
    }

    pub fn apply_to_counters(self, counters: RuntimeTrafficCounters) -> RuntimeTrafficCounters {
        RuntimeTrafficCounters {
            upload_total: counters.upload_total.saturating_add(self.upload_total),
            download_total: counters.download_total.saturating_add(self.download_total),
            packet_total: counters.packet_total.saturating_add(self.packet_total),
            request_total: counters.request_total.saturating_add(self.request_total),
            ..counters
        }
    }
}

fn apply_runtime_traffic_metric_carry(metrics: &mut Value, key: &str, carry: u64) {
    if carry == 0 {
        return;
    }
    metrics[key] = json!(
        metrics
            .get(key)
            .and_then(|value| {
                value
                    .as_u64()
                    .or_else(|| value.as_str().and_then(|value| value.parse::<u64>().ok()))
            })
            .unwrap_or(0)
            .saturating_add(carry)
    );
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

pub fn resident_runtime_traffic_stats(
    runtime: &Value,
    _window_sec: u64,
    _max_points: usize,
) -> RuntimeTrafficStats {
    runtime
        .pointer("/residentDataplane/metrics")
        .map(resident_runtime_traffic_stats_from_metrics)
        .unwrap_or_default()
}

fn resident_runtime_traffic_stats_from_metrics(metrics: &Value) -> RuntimeTrafficStats {
    let observation = calculate_runtime_traffic_observation(
        RuntimeTrafficCounters {
            upload_total: event_u64(metrics, "uploadTotal"),
            download_total: event_u64(metrics, "downloadTotal"),
            active_tcp_connections: event_u64(metrics, "activeTcpConnections"),
            active_udp_sessions: event_u64(metrics, "activeUdpSessions"),
            ..RuntimeTrafficCounters::default()
        },
        0,
        0,
        Instant::now(),
        None,
    )
    .0;
    RuntimeTrafficStats {
        upload_total: observation.upload_total,
        download_total: observation.download_total,
        active_connections: observation.active_connections,
        udp_sessions: observation.udp_sessions,
        ..RuntimeTrafficStats::default()
    }
}

fn event_u64(event: &Value, key: &str) -> u64 {
    event
        .get(key)
        .and_then(|value| {
            value
                .as_u64()
                .or_else(|| value.as_str().and_then(|value| value.parse::<u64>().ok()))
        })
        .unwrap_or(0)
}

pub fn runtime_traffic_observation(
    counters: RuntimeTrafficCounters,
    epoch: u64,
    timestamp: u64,
    observed_at: Instant,
    previous: Option<RuntimeTrafficTotalSample>,
) -> (RuntimeTrafficObservation, bool) {
    calculate_runtime_traffic_observation(counters, epoch, timestamp, observed_at, previous)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn carry_applies_only_to_monotonic_totals() {
        let counters = RuntimeTrafficCounters {
            upload_total: 25,
            download_total: 50,
            packet_total: 75,
            request_total: 100,
            queue_depth: 4,
            inflight_work: 5,
            active_tcp_connections: 3,
            active_udp_sessions: 2,
        };
        let carried = RuntimeTrafficCarry {
            upload_total: 500,
            download_total: 700,
            packet_total: 900,
            request_total: 1_100,
        }
        .apply_to_counters(counters);

        assert_eq!(carried.upload_total, 525);
        assert_eq!(carried.download_total, 750);
        assert_eq!(carried.packet_total, 975);
        assert_eq!(carried.request_total, 1_200);
        assert_eq!(carried.queue_depth, 4);
        assert_eq!(carried.inflight_work, 5);
        assert_eq!(carried.active_tcp_connections, 3);
        assert_eq!(carried.active_udp_sessions, 2);
    }

    #[test]
    fn carry_saturates_without_changing_active_gauges() {
        let counters = RuntimeTrafficCounters {
            upload_total: u64::MAX - 1,
            download_total: u64::MAX,
            packet_total: u64::MAX - 2,
            request_total: u64::MAX - 3,
            queue_depth: 4,
            inflight_work: 5,
            active_tcp_connections: 7,
            active_udp_sessions: 8,
        };
        let carried = RuntimeTrafficCarry {
            upload_total: 2,
            download_total: 1,
            packet_total: 4,
            request_total: 6,
        }
        .apply_to_counters(counters);

        assert_eq!(carried.upload_total, u64::MAX);
        assert_eq!(carried.download_total, u64::MAX);
        assert_eq!(carried.packet_total, u64::MAX);
        assert_eq!(carried.request_total, u64::MAX);
        assert_eq!(carried.active_tcp_connections, 7);
        assert_eq!(carried.active_udp_sessions, 8);
    }
}
