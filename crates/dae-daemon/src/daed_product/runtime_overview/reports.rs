use super::*;
pub(crate) fn runtime_overview_report(app: &AppState, request: &HttpRequest) -> Value {
    let runtime = app.runtime.summary();
    let runtime_revision = runtime_revision_report(&app.state, &app.runtime, &runtime)
        .unwrap_or_else(|err| json!({"error": err.to_string()}));
    let window_sec = query_u64(request, "windowSec")
        .unwrap_or(60)
        .clamp(1, 3_600);
    let max_points = query_usize(request, "maxPoints")
        .unwrap_or(120)
        .clamp(1, 1_000);
    let sampled = runtime_sample_view_for_app(app, window_sec, max_points);
    let traffic = sampled.traffic;
    let process = sampled.process;
    let allocator_stats = sampled.allocator;
    let allocator_live_heap = allocator_stats.map(|stats| stats.allocated);
    let cgroup_memory = sampled.cgroup_memory;
    json!({
        "updatedAt": iso8601_utc(sampled.sampled_at),
        "uploadRate": traffic.upload_rate.to_string(),
        "downloadRate": traffic.download_rate.to_string(),
        "uploadTotal": traffic.upload_total.to_string(),
        "downloadTotal": traffic.download_total.to_string(),
        "activeConnections": traffic.active_connections,
        "udpSessions": traffic.udp_sessions,
        "udpTaskQueues": Value::Null,
        "udpTaskDropTotal": Value::Null,
        "packetSnifferSessions": Value::Null,
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
        "productUi": app.ui_runtime.snapshot(),
        "productLogWriter": product_log_runtime_snapshot(&app.config_dir),
        "productAuth": app.auth_runtime.snapshot(),
        "productUi": app.ui_runtime.snapshot(),
        "productGeodataUpdate": app.geodata_update_runtime.as_ref().map(|runtime| runtime.snapshot()).unwrap_or(Value::Null),
        "runtimeSampler": app.runtime_sampler.as_ref().map(|sampler| sampler.snapshot()).unwrap_or(Value::Null),
        "runtimeSampleCount": sampled.sample_count,
        "runtime": runtime,
        "runtimeRevision": runtime_revision,
        "samples": traffic.samples,
    })
}

pub(crate) fn runtime_overview_delta_report(app: &AppState) -> Value {
    let runtime_delta = app.runtime.runtime_overview_delta_state();
    let sampled = runtime_sample_view_for_app(app, 1, 1);
    let traffic = sampled.traffic;
    let process = sampled.process;
    let allocator_live_heap = sampled.allocator.map(|stats| stats.allocated);
    let cgroup_memory = sampled.cgroup_memory;
    json!({
        "updatedAt": iso8601_utc(sampled.sampled_at),
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
        "productLogWriter": product_log_runtime_snapshot(&app.config_dir),
        "productGeodataUpdate": app.geodata_update_runtime.as_ref().map(|runtime| runtime.snapshot()).unwrap_or(Value::Null),
        "runtimeSampler": app.runtime_sampler.as_ref().map(|sampler| sampler.snapshot()).unwrap_or(Value::Null),
        "runtimeSampleCount": sampled.sample_count,
        "sequence": sampled.sample_count,
        "reloadCount": runtime_delta.reload_count,
        "samples": traffic.samples,
    })
}
