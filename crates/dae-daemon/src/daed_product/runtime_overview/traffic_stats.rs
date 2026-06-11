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

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct RuntimeTrafficSecond {
    pub(in crate::daed_product) upload: u64,
    pub(in crate::daed_product) download: u64,
    pub(in crate::daed_product) active_connections: u64,
    pub(in crate::daed_product) udp_sessions: u64,
}

#[derive(Debug, Default)]
pub(crate) struct RuntimeTrafficEventFileCache {
    pub(in crate::daed_product) path: String,
    pub(in crate::daed_product) offset: u64,
    pub(in crate::daed_product) upload_total: u64,
    pub(in crate::daed_product) download_total: u64,
    pub(in crate::daed_product) seconds: BTreeMap<u64, RuntimeTrafficSecond>,
}

pub(crate) static LAST_RUNTIME_TRAFFIC_TOTAL_SAMPLE: OnceLock<
    Mutex<Option<RuntimeTrafficTotalSample>>,
> = OnceLock::new();
pub(crate) static RUNTIME_TRAFFIC_RATE_SAMPLES: OnceLock<Mutex<VecDeque<(u64, u64, u64)>>> =
    OnceLock::new();
pub(crate) static RUNTIME_TRAFFIC_EVENT_FILE_CACHE: OnceLock<Mutex<RuntimeTrafficEventFileCache>> =
    OnceLock::new();

pub(crate) fn resident_runtime_traffic_stats(
    runtime: &Value,
    window_sec: u64,
    max_points: usize,
) -> RuntimeTrafficStats {
    if let Some(stats) = resident_live_runtime_traffic_stats(runtime, window_sec, max_points) {
        return stats;
    }
    let Some(event_file) = runtime
        .pointer("/residentDataplane/event_file")
        .and_then(Value::as_str)
        .filter(|path| !path.is_empty())
    else {
        return RuntimeTrafficStats::default();
    };
    resident_event_file_traffic_stats(event_file, window_sec, max_points).unwrap_or_default()
}

pub(crate) fn resident_event_file_traffic_stats(
    event_file: &str,
    window_sec: u64,
    max_points: usize,
) -> io::Result<RuntimeTrafficStats> {
    let mut file = fs::File::open(event_file)?;
    let len = file.metadata()?.len();
    let cache_lock = RUNTIME_TRAFFIC_EVENT_FILE_CACHE
        .get_or_init(|| Mutex::new(RuntimeTrafficEventFileCache::default()));
    let mut cache = cache_lock.lock().map_err(|_| {
        io::Error::new(
            io::ErrorKind::Other,
            "runtime traffic event file cache lock poisoned",
        )
    })?;
    if cache.path != event_file || len < cache.offset {
        *cache = RuntimeTrafficEventFileCache {
            path: event_file.to_owned(),
            ..RuntimeTrafficEventFileCache::default()
        };
    }
    file.seek(SeekFrom::Start(cache.offset))?;
    let mut reader = io::BufReader::new(file);
    let mut line = String::new();
    loop {
        line.clear();
        let read = reader.read_line(&mut line)?;
        if read == 0 {
            break;
        }
        cache.offset = cache.offset.saturating_add(read as u64);
        let Ok(event) = serde_json::from_str::<Value>(&line) else {
            continue;
        };
        let (upload, download) = event_traffic_bytes(&event);
        cache.upload_total = cache.upload_total.saturating_add(upload);
        cache.download_total = cache.download_total.saturating_add(download);
        let Some(timestamp) = event["timestampUnix"].as_u64() else {
            continue;
        };
        let entry = cache.seconds.entry(timestamp).or_default();
        entry.upload = entry.upload.saturating_add(upload);
        entry.download = entry.download.saturating_add(download);
        if is_tcp_connection_event(&event) {
            entry.active_connections = entry.active_connections.saturating_add(1);
        }
        if is_udp_session_event(&event) {
            entry.udp_sessions = entry.udp_sessions.saturating_add(1);
        }
    }
    let now = unix_now();
    let max_retained_window = 3_600_u64;
    let retain_start = now.saturating_sub(max_retained_window);
    let old_keys = cache
        .seconds
        .keys()
        .copied()
        .take_while(|timestamp| *timestamp < retain_start)
        .collect::<Vec<_>>();
    for timestamp in old_keys {
        cache.seconds.remove(&timestamp);
    }

    let window_start = now.saturating_sub(window_sec);
    let rate_window_start = now.saturating_sub(5);
    let mut stats = RuntimeTrafficStats {
        upload_total: cache.upload_total,
        download_total: cache.download_total,
        ..RuntimeTrafficStats::default()
    };
    let mut sample_values = Vec::new();
    for (timestamp, second) in cache.seconds.range(window_start..) {
        stats.active_connections = stats
            .active_connections
            .saturating_add(second.active_connections);
        stats.udp_sessions = stats.udp_sessions.saturating_add(second.udp_sessions);
        if *timestamp >= rate_window_start {
            stats.upload_rate = stats.upload_rate.saturating_add(second.upload);
            stats.download_rate = stats.download_rate.saturating_add(second.download);
        }
        sample_values.push(json!({
            "timestamp": iso8601_utc(*timestamp),
            "uploadRate": second.upload.to_string(),
            "downloadRate": second.download.to_string(),
        }));
    }
    stats.upload_rate /= 5;
    stats.download_rate /= 5;
    if sample_values.len() > max_points {
        sample_values = sample_values.split_off(sample_values.len() - max_points);
    }
    stats.samples = sample_values;
    Ok(stats)
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

pub(crate) fn event_traffic_bytes(event: &Value) -> (u64, u64) {
    let upload = event_u64(event, "bytes_client_to_proxy")
        .saturating_add(event_u64(event, "bytes_client_to_direct"))
        .saturating_add(event_u64(event, "request_len"));
    let download = event_u64(event, "bytes_proxy_to_client")
        .saturating_add(event_u64(event, "bytes_direct_to_client"))
        .saturating_add(event_u64(event, "response_len"));
    (upload, download)
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

pub(crate) fn is_tcp_connection_event(event: &Value) -> bool {
    matches!(
        event.get("event").and_then(Value::as_str),
        Some("tcp_connection_finished" | "tcp_connection_failed")
    )
}

pub(crate) fn is_udp_session_event(event: &Value) -> bool {
    matches!(
        event.get("event").and_then(Value::as_str),
        Some("udp_packet_finished" | "udp_dns_packet_finished")
    )
}
