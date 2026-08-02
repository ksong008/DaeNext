use super::*;

#[derive(Debug, Default)]
pub(crate) struct RuntimeTrafficStats {
    pub(in crate::daed_product) upload_total: u64,
    pub(in crate::daed_product) download_total: u64,
    pub(in crate::daed_product) upload_rate: u64,
    pub(in crate::daed_product) download_rate: u64,
    pub(in crate::daed_product) active_connections: u64,
    pub(in crate::daed_product) udp_sessions: u64,
    pub(in crate::daed_product) samples: Vec<Value>,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct RuntimeTrafficTotalSample {
    pub(in crate::daed_product) upload_total: u64,
    pub(in crate::daed_product) download_total: u64,
    pub(in crate::daed_product) observed_at: Instant,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct RuntimeTrafficObservation {
    pub(crate) timestamp: u64,
    pub(crate) upload_total: u64,
    pub(crate) download_total: u64,
    pub(crate) upload_rate: u64,
    pub(crate) download_rate: u64,
    pub(crate) active_connections: u64,
    pub(crate) udp_sessions: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct RuntimeTrafficRateSample {
    pub(crate) timestamp: u64,
    pub(crate) upload_rate: u64,
    pub(crate) download_rate: u64,
}

#[cfg(test)]
pub(crate) fn resident_runtime_traffic_stats(
    runtime: &Value,
    _window_sec: u64,
    _max_points: usize,
) -> RuntimeTrafficStats {
    runtime
        .pointer("/residentDataplane/metrics")
        .map(resident_runtime_traffic_stats_from_metrics)
        .unwrap_or_default()
}

#[cfg(test)]
fn resident_runtime_traffic_stats_from_metrics(metrics: &Value) -> RuntimeTrafficStats {
    let observation = runtime_traffic_observation(
        ResidentTrafficCounters {
            upload_total: event_u64(metrics, "uploadTotal"),
            download_total: event_u64(metrics, "downloadTotal"),
            active_tcp_connections: event_u64(metrics, "activeTcpConnections"),
            active_udp_sessions: event_u64(metrics, "activeUdpSessions"),
            ..ResidentTrafficCounters::default()
        },
        unix_now(),
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

pub(crate) fn runtime_traffic_observation(
    counters: ResidentTrafficCounters,
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
        if upload_total < previous.upload_total || download_total < previous.download_total {
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

pub(crate) fn runtime_traffic_stats_from_history(
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
                "timestamp": iso8601_utc(sample.timestamp),
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

#[cfg(test)]
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
