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

pub(crate) static LAST_RUNTIME_TRAFFIC_TOTAL_SAMPLE: OnceLock<
    Mutex<Option<RuntimeTrafficTotalSample>>,
> = OnceLock::new();
pub(crate) static RUNTIME_TRAFFIC_RATE_SAMPLES: OnceLock<Mutex<VecDeque<(u64, u64, u64)>>> =
    OnceLock::new();

pub(crate) fn resident_runtime_traffic_stats(
    runtime: &Value,
    window_sec: u64,
    max_points: usize,
) -> RuntimeTrafficStats {
    resident_live_runtime_traffic_stats(runtime, window_sec, max_points).unwrap_or_default()
}

pub(crate) fn resident_live_runtime_traffic_stats(
    runtime: &Value,
    window_sec: u64,
    max_points: usize,
) -> Option<RuntimeTrafficStats> {
    let metrics = runtime.pointer("/residentDataplane/metrics")?;
    let upload_total = event_u64(metrics, "uploadTotal");
    let download_total = event_u64(metrics, "downloadTotal");
    let (upload_rate, download_rate, samples) =
        live_runtime_traffic_rate_samples(upload_total, download_total, window_sec, max_points);
    Some(RuntimeTrafficStats {
        upload_total,
        download_total,
        upload_rate,
        download_rate,
        active_connections: event_u64(metrics, "activeTcpConnections"),
        udp_sessions: event_u64(metrics, "activeUdpSessions"),
        samples,
    })
}

pub(crate) fn live_runtime_traffic_rate_samples(
    upload_total: u64,
    download_total: u64,
    window_sec: u64,
    max_points: usize,
) -> (u64, u64, Vec<Value>) {
    let now = unix_now();
    let observed_at = Instant::now();
    let sample_lock = LAST_RUNTIME_TRAFFIC_TOTAL_SAMPLE.get_or_init(|| Mutex::new(None));
    let mut previous = sample_lock.lock().ok();
    let mut upload_rate = 0_u64;
    let mut download_rate = 0_u64;
    let mut totals_reset = false;
    if let Some(previous_guard) = previous.as_deref_mut() {
        if let Some(previous_sample) = *previous_guard {
            if upload_total < previous_sample.upload_total
                || download_total < previous_sample.download_total
            {
                totals_reset = true;
            } else {
                let elapsed = observed_at
                    .duration_since(previous_sample.observed_at)
                    .as_secs_f64();
                if elapsed > 0.0 {
                    upload_rate =
                        ((upload_total - previous_sample.upload_total) as f64 / elapsed) as u64;
                    download_rate =
                        ((download_total - previous_sample.download_total) as f64 / elapsed) as u64;
                }
            }
        }
        *previous_guard = Some(RuntimeTrafficTotalSample {
            upload_total,
            download_total,
            observed_at,
        });
    }

    let history_lock = RUNTIME_TRAFFIC_RATE_SAMPLES.get_or_init(|| Mutex::new(VecDeque::new()));
    let mut history = match history_lock.lock() {
        Ok(history) => history,
        Err(_) => return (upload_rate, download_rate, Vec::new()),
    };
    if totals_reset {
        history.clear();
    }
    if history
        .back()
        .is_some_and(|(timestamp, _, _)| *timestamp == now)
    {
        if let Some(back) = history.back_mut() {
            *back = (now, upload_rate, download_rate);
        }
    } else {
        history.push_back((now, upload_rate, download_rate));
    }
    let window_start = now.saturating_sub(window_sec);
    while history
        .front()
        .is_some_and(|(timestamp, _, _)| *timestamp < window_start)
    {
        history.pop_front();
    }
    while history.len() > max_points {
        history.pop_front();
    }
    let samples = history
        .iter()
        .map(|(timestamp, upload, download)| {
            json!({
                "timestamp": iso8601_utc(*timestamp),
                "uploadRate": upload.to_string(),
                "downloadRate": download.to_string(),
            })
        })
        .collect();
    (upload_rate, download_rate, samples)
}

pub(crate) fn event_u64(event: &Value, key: &str) -> u64 {
    event
        .get(key)
        .and_then(|value| {
            value
                .as_u64()
                .or_else(|| value.as_str().and_then(|value| value.parse::<u64>().ok()))
        })
        .unwrap_or(0)
}
