#[derive(Debug, Default)]
struct RuntimeTrafficStats {
    upload_total: u64,
    download_total: u64,
    upload_rate: u64,
    download_rate: u64,
    active_connections: u64,
    udp_sessions: u64,
    samples: Vec<Value>,
}

#[derive(Clone, Copy, Debug)]
struct RuntimeTrafficTotalSample {
    upload_total: u64,
    download_total: u64,
    observed_at: Instant,
}

#[derive(Clone, Copy, Debug, Default)]
struct RuntimeTrafficSecond {
    upload: u64,
    download: u64,
    active_connections: u64,
    udp_sessions: u64,
}

#[derive(Debug, Default)]
struct RuntimeTrafficEventFileCache {
    path: String,
    offset: u64,
    upload_total: u64,
    download_total: u64,
    seconds: BTreeMap<u64, RuntimeTrafficSecond>,
}

static LAST_RUNTIME_TRAFFIC_TOTAL_SAMPLE: OnceLock<Mutex<Option<RuntimeTrafficTotalSample>>> =
    OnceLock::new();
static RUNTIME_TRAFFIC_RATE_SAMPLES: OnceLock<Mutex<VecDeque<(u64, u64, u64)>>> = OnceLock::new();
static RUNTIME_TRAFFIC_EVENT_FILE_CACHE: OnceLock<Mutex<RuntimeTrafficEventFileCache>> =
    OnceLock::new();

fn runtime_overview_report(app: &AppState, request: &HttpRequest) -> Value {
    let runtime = app.runtime.summary();
    let window_sec = query_u64(request, "windowSec")
        .unwrap_or(60)
        .clamp(1, 3_600);
    let max_points = query_usize(request, "maxPoints")
        .unwrap_or(120)
        .clamp(1, 1_000);
    let traffic = resident_runtime_traffic_stats(&runtime, window_sec, max_points);
    let process = current_process_metrics();
    let allocator_live_heap = allocator_live_heap_bytes();
    json!({
        "updatedAt": now_text(),
        "uploadRate": traffic.upload_rate.to_string(),
        "downloadRate": traffic.download_rate.to_string(),
        "uploadTotal": traffic.upload_total.to_string(),
        "downloadTotal": traffic.download_total.to_string(),
        "activeConnections": traffic.active_connections,
        "udpSessions": traffic.udp_sessions,
        "udpTaskQueues": 0,
        "udpTaskDropTotal": "0",
        "packetSnifferSessions": 0,
        "cpuUsagePercent": process.cpu_usage_percent,
        "rssBytes": process.rss_bytes.to_string(),
        "rssAnonBytes": process.anonymous_rss_bytes.to_string(),
        "rssFileBytes": process.file_rss_bytes.to_string(),
        "anonymousRssBytes": process.anonymous_rss_bytes.to_string(),
        "fileRssBytes": process.file_rss_bytes.to_string(),
        "vmDataBytes": process.vm_data_bytes.to_string(),
        "heapLiveBytes": allocator_live_heap.map(|bytes| json!(bytes.to_string())).unwrap_or(Value::Null),
        "heapMetricSource": if allocator_live_heap.is_some() { "allocator-stats" } else { "unavailable" },
        "heapCompatBytes": process.heap_alloc_bytes_compat().to_string(),
        "heapCompatBytesSource": "compat-alias-rss-anon-not-live-heap",
        "heapAllocBytes": process.heap_alloc_bytes_compat().to_string(),
        "heapAllocBytesSource": "compat-alias-rss-anon-not-live-heap",
        "allocatorProfile": allocator_profile(),
        "allocatorStats": allocator_stats_json(),
        "allocatorReclaim": allocator_reclaim_snapshot_json(),
        "resourcePools": resource_pool_policy_json(),
        "goroutines": process.thread_count,
        "productHttp": app.http_metrics.snapshot(),
        "runtime": runtime,
        "samples": traffic.samples,
    })
}

fn runtime_overview_delta_report(app: &AppState, request: &HttpRequest) -> Value {
    let runtime = app.runtime.summary();
    let window_sec = query_u64(request, "windowSec")
        .unwrap_or(60)
        .clamp(1, 3_600);
    let max_points = query_usize(request, "maxPoints")
        .unwrap_or(120)
        .clamp(1, 1_000);
    let traffic = resident_runtime_traffic_stats(&runtime, window_sec, max_points);
    let process = current_process_metrics();
    let allocator_live_heap = allocator_live_heap_bytes();
    json!({
        "updatedAt": now_text(),
        "uploadRate": traffic.upload_rate.to_string(),
        "downloadRate": traffic.download_rate.to_string(),
        "uploadTotal": traffic.upload_total.to_string(),
        "downloadTotal": traffic.download_total.to_string(),
        "activeConnections": traffic.active_connections,
        "udpSessions": traffic.udp_sessions,
        "cpuUsagePercent": process.cpu_usage_percent,
        "rssBytes": process.rss_bytes.to_string(),
        "rssAnonBytes": process.anonymous_rss_bytes.to_string(),
        "rssFileBytes": process.file_rss_bytes.to_string(),
        "anonymousRssBytes": process.anonymous_rss_bytes.to_string(),
        "fileRssBytes": process.file_rss_bytes.to_string(),
        "vmDataBytes": process.vm_data_bytes.to_string(),
        "heapLiveBytes": allocator_live_heap.map(|bytes| json!(bytes.to_string())).unwrap_or(Value::Null),
        "heapMetricSource": if allocator_live_heap.is_some() { "allocator-stats" } else { "unavailable" },
        "heapCompatBytes": process.heap_alloc_bytes_compat().to_string(),
        "heapCompatBytesSource": "compat-alias-rss-anon-not-live-heap",
        "heapAllocBytes": process.heap_alloc_bytes_compat().to_string(),
        "heapAllocBytesSource": "compat-alias-rss-anon-not-live-heap",
        "goroutines": process.thread_count,
        "reloadCount": runtime["reloadCount"].clone(),
        "samples": traffic.samples,
    })
}

fn resource_pool_policy_json() -> Value {
    json!({
        "udpEndpoint": {
            "defaultMaxEntries": DEFAULT_UDP_ENDPOINT_POOL_MAX_ENTRIES,
            "trimTarget": udp_endpoint_pool_trim_target(DEFAULT_UDP_ENDPOINT_POOL_MAX_ENTRIES),
            "defaultNatTimeoutMs": DEFAULT_NAT_TIMEOUT_MS,
            "dnsNatTimeoutMs": DNS_NAT_TIMEOUT_MS,
            "anyfromTimeoutMs": ANYFROM_TIMEOUT_MS,
            "maxRetry": MAX_RETRY,
            "currentEntries": 0,
            "evictions": 0,
        },
        "udpTask": {
            "queueLength": UDP_TASK_QUEUE_LENGTH,
            "maxQueues": UDP_TASK_POOL_MAX_QUEUES,
            "currentQueues": 0,
            "dropTotal": 0,
        },
        "packetSniffer": {
            "ttlMs": PACKET_SNIFFER_TTL_MS,
            "maxEntries": PACKET_SNIFFER_POOL_MAX_ENTRIES,
            "currentEntries": 0,
            "evictions": 0,
        },
        "bufferPool": {
            "status": "planned",
            "maxClassBytes": 65536,
            "source": "DAEX_RUST_NATIVE_OUTBOUND_PLAN_2026-06-01.md:RSS allocator/reclaim and Go structural cleanup plan",
        }
    })
}

fn resident_runtime_traffic_stats(
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

fn resident_event_file_traffic_stats(
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
    let mut stats = RuntimeTrafficStats::default();
    stats.upload_total = cache.upload_total;
    stats.download_total = cache.download_total;
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

fn resident_live_runtime_traffic_stats(
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

fn live_runtime_traffic_rate_samples(
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

fn event_traffic_bytes(event: &Value) -> (u64, u64) {
    let upload = event_u64(event, "bytes_client_to_proxy")
        .saturating_add(event_u64(event, "bytes_client_to_direct"))
        .saturating_add(event_u64(event, "request_len"));
    let download = event_u64(event, "bytes_proxy_to_client")
        .saturating_add(event_u64(event, "bytes_direct_to_client"))
        .saturating_add(event_u64(event, "response_len"));
    (upload, download)
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

fn is_tcp_connection_event(event: &Value) -> bool {
    matches!(
        event.get("event").and_then(Value::as_str),
        Some("tcp_connection_finished" | "tcp_connection_failed")
    )
}

fn is_udp_session_event(event: &Value) -> bool {
    matches!(
        event.get("event").and_then(Value::as_str),
        Some("udp_packet_finished" | "udp_dns_packet_finished")
    )
}

fn query_u64(request: &HttpRequest, key: &str) -> Option<u64> {
    request
        .query
        .get(key)
        .and_then(|values| values.first())
        .and_then(|value| value.parse::<u64>().ok())
}

fn query_usize(request: &HttpRequest, key: &str) -> Option<usize> {
    request
        .query
        .get(key)
        .and_then(|values| values.first())
        .and_then(|value| value.parse::<usize>().ok())
}

fn query_bool(request: &HttpRequest, key: &str) -> Option<bool> {
    request
        .query
        .get(key)
        .and_then(|values| values.first())
        .and_then(|value| parse_bool(value))
}

fn parse_bool(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

fn list_system_interfaces(up: Option<bool>, only_global_scope: bool) -> io::Result<Vec<Value>> {
    let routes_by_iface = default_routes_by_iface();
    match ip_address_interfaces(up, only_global_scope, &routes_by_iface) {
        Ok(items) => Ok(items),
        Err(_) => sysfs_interfaces(up, &routes_by_iface),
    }
}

fn ip_address_interfaces(
    up: Option<bool>,
    only_global_scope: bool,
    routes_by_iface: &HashMap<String, Vec<Value>>,
) -> io::Result<Vec<Value>> {
    let output = Command::new("ip")
        .args(["-j", "address", "show"])
        .output()?;
    if !output.status.success() {
        return Err(io::Error::other("ip address query failed"));
    }
    let interfaces = serde_json::from_slice::<Value>(&output.stdout)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    let mut items = Vec::new();
    for iface in interfaces.as_array().into_iter().flatten() {
        let name = iface["ifname"].as_str().unwrap_or_default();
        if name.is_empty() {
            continue;
        }
        let flags = iface["flags"].as_array().cloned().unwrap_or_default();
        let iface_up = flags
            .iter()
            .filter_map(Value::as_str)
            .any(|flag| flag.eq_ignore_ascii_case("UP"));
        if up.is_some_and(|wanted| wanted != iface_up) {
            continue;
        }
        let mut addresses = Vec::new();
        for addr in iface["addr_info"].as_array().into_iter().flatten() {
            if only_global_scope
                && addr["scope"]
                    .as_str()
                    .is_some_and(|scope| scope != "global")
            {
                continue;
            }
            let Some(local) = addr["local"].as_str() else {
                continue;
            };
            let prefix = addr["prefixlen"].as_u64().unwrap_or(0);
            addresses.push(format!("{local}/{prefix}"));
        }
        let mut item = Map::new();
        item.insert("name".to_owned(), json!(name));
        item.insert("index".to_owned(), iface["ifindex"].clone());
        item.insert("up".to_owned(), json!(iface_up));
        item.insert("addresses".to_owned(), json!(addresses));
        if let Some(routes) = routes_by_iface
            .get(name)
            .filter(|routes| !routes.is_empty())
        {
            item.insert("defaultRoutes".to_owned(), json!(routes));
        }
        items.push(Value::Object(item));
    }
    Ok(items)
}

fn default_routes_by_iface() -> HashMap<String, Vec<Value>> {
    let mut out = HashMap::<String, Vec<Value>>::new();
    collect_default_routes(&mut out, "4", &["-j", "route", "show", "default"]);
    collect_default_routes(&mut out, "6", &["-j", "-6", "route", "show", "default"]);
    out
}

fn collect_default_routes(out: &mut HashMap<String, Vec<Value>>, ip_version: &str, args: &[&str]) {
    let Ok(output) = Command::new("ip").args(args).output() else {
        return;
    };
    if !output.status.success() {
        return;
    }
    let Ok(routes) = serde_json::from_slice::<Value>(&output.stdout) else {
        return;
    };
    for route in routes.as_array().into_iter().flatten() {
        let Some(dev) = route["dev"].as_str().filter(|value| !value.is_empty()) else {
            continue;
        };
        let mut item = Map::new();
        item.insert("ipVersion".to_owned(), json!(ip_version));
        if let Some(gateway) = route["gateway"].as_str() {
            item.insert("gateway".to_owned(), json!(gateway));
        }
        if let Some(source) = route["prefsrc"].as_str().or_else(|| route["src"].as_str()) {
            item.insert("source".to_owned(), json!(source));
        }
        out.entry(dev.to_owned())
            .or_default()
            .push(Value::Object(item));
    }
}

fn sysfs_interfaces(
    up: Option<bool>,
    routes_by_iface: &HashMap<String, Vec<Value>>,
) -> io::Result<Vec<Value>> {
    let mut items = Vec::new();
    for entry in fs::read_dir("/sys/class/net")? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let base = entry.path();
        let index = fs::read_to_string(base.join("ifindex"))
            .ok()
            .and_then(|value| value.trim().parse::<i64>().ok())
            .unwrap_or(0);
        let iface_up = fs::read_to_string(base.join("operstate"))
            .map(|value| matches!(value.trim(), "up" | "unknown"))
            .unwrap_or(false);
        if up.is_some_and(|wanted| wanted != iface_up) {
            continue;
        }
        let mut item = Map::new();
        item.insert("name".to_owned(), json!(name));
        item.insert("index".to_owned(), json!(index));
        item.insert("up".to_owned(), json!(iface_up));
        item.insert("addresses".to_owned(), json!([]));
        if let Some(routes) = routes_by_iface
            .get(&name)
            .filter(|routes| !routes.is_empty())
        {
            item.insert("defaultRoutes".to_owned(), json!(routes));
        }
        items.push(Value::Object(item));
    }
    items.sort_by(|left, right| {
        left["index"]
            .as_i64()
            .unwrap_or(i64::MAX)
            .cmp(&right["index"].as_i64().unwrap_or(i64::MAX))
    });
    Ok(items)
}
