use super::*;

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
        0,
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
    epoch: u64,
    timestamp: u64,
    observed_at: Instant,
    previous: Option<RuntimeTrafficTotalSample>,
) -> (RuntimeTrafficObservation, bool) {
    calculate_runtime_traffic_observation(
        RuntimeTrafficCounters {
            upload_total: counters.upload_total,
            download_total: counters.download_total,
            active_tcp_connections: counters.active_tcp_connections,
            active_udp_sessions: counters.active_udp_sessions,
        },
        epoch,
        timestamp,
        observed_at,
        previous,
    )
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
