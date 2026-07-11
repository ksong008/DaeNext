use super::*;
pub(crate) fn runtime_overview_report(app: &AppState, request: &HttpRequest) -> Value {
    let runtime = app.runtime.summary();
    let window_sec = query_u64(request, "windowSec")
        .unwrap_or(60)
        .clamp(1, 3_600);
    let max_points = query_usize(request, "maxPoints")
        .unwrap_or(120)
        .clamp(1, 1_000);
    let traffic = resident_runtime_traffic_stats(&runtime, window_sec, max_points);
    let process = current_process_metrics();
    let allocator_stats = allocator_stats_snapshot();
    let allocator_live_heap = allocator_stats.map(|stats| stats.allocated);
    let cgroup_memory = cgroup_memory_snapshot_json();
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
        "allocatorProfile": allocator_profile(),
        "allocatorStats": allocator_stats_json_from(allocator_stats.as_ref()),
        "allocatorDerived": allocator_derived_stats_json_from(
            allocator_stats.as_ref(),
            process.anonymous_rss_bytes
        ),
        "allocatorReclaim": allocator_reclaim_snapshot_json(),
        "allocatorIdleReclaim": allocator_idle_reclaim_snapshot_json(app),
        "cgroupMemory": cgroup_memory,
        "resourcePools": resource_pool_policy_json(),
        "goroutines": process.thread_count,
        "productHttp": app.http_metrics.snapshot(),
        "productAuth": app.auth_runtime.snapshot(),
        "runtime": runtime,
        "samples": traffic.samples,
    })
}

pub(crate) fn runtime_overview_delta_report(app: &AppState, request: &HttpRequest) -> Value {
    let runtime_delta = app.runtime.runtime_overview_delta_state();
    let window_sec = query_u64(request, "windowSec")
        .unwrap_or(60)
        .clamp(1, 3_600);
    let max_points = query_usize(request, "maxPoints")
        .unwrap_or(120)
        .clamp(1, 1_000);
    let traffic = resident_runtime_traffic_stats_from_metrics(
        runtime_delta.resident_dataplane_metrics.as_ref(),
        window_sec,
        max_points,
    );
    let process = current_process_metrics();
    let allocator_live_heap = allocator_live_heap_bytes();
    let cgroup_memory = cgroup_memory_snapshot_json();
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
        "cgroupMemory": cgroup_memory,
        "goroutines": process.thread_count,
        "productAuth": app.auth_runtime.snapshot(),
        "reloadCount": runtime_delta.reload_count,
        "samples": traffic.samples,
    })
}
