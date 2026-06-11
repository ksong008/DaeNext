use super::*;
pub(crate) fn resident_group_health_check_loop(
    group: Arc<plan::ResidentProxyGroupPlan>,
    stop: Arc<AtomicBool>,
    event_file: PathBuf,
    event_lock: Arc<Mutex<()>>,
    concurrency: usize,
) {
    let interval = group.check_interval();
    let candidates = group.probe_candidates();
    let concurrency = concurrency.max(1);
    append_event(
        &event_file,
        &event_lock,
        json!({
            "event": "resident_health_checker_started",
            "group": group.group_name,
            "group_policy": group.group_policy_name(),
            "candidate_count": group.candidate_count(),
            "admitted_candidate_count": group.admitted_candidate_count(),
            "check_interval": format!("{interval:?}"),
            "concurrency": concurrency,
            "probe": "tokio-proxy-tcp-and-dns-udp-check",
            "tcp_probe_executor": "tokio-proxy-tcp-probe",
            "udp_probe_executor": "tokio-proxy-packet-dns-probe",
            "tcp_check_target": candidates.first().map(|candidate| candidate.tcp_check.target.clone()),
            "udp_check_target": candidates.first().map(|candidate| candidate.udp_check.target.authority().to_owned()),
        }),
    );
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
    {
        Ok(runtime) => runtime,
        Err(err) => {
            append_event(
                &event_file,
                &event_lock,
                json!({"event": "resident_health_checker_runtime_failed", "error": err.to_string()}),
            );
            return;
        }
    };
    runtime.block_on(run_resident_group_health_checks_concurrent_async(
        Arc::clone(&group),
        &candidates,
        concurrency,
    ));
    loop {
        if interval.is_zero() || sleep_until_stopped(&stop, interval) {
            return;
        }
        if stop.load(Ordering::Relaxed) {
            return;
        }
        runtime.block_on(run_resident_group_health_checks_concurrent_async(
            Arc::clone(&group),
            &candidates,
            concurrency,
        ));
    }
}

async fn run_resident_group_health_checks_concurrent_async(
    group: Arc<plan::ResidentProxyGroupPlan>,
    candidates: &[plan::ResidentProxyProbePlan],
    concurrency: usize,
) {
    if concurrency <= 1 {
        run_resident_group_health_checks_async(&group, candidates).await;
        return;
    }
    for chunk in candidates.chunks(concurrency.max(1)) {
        let mut handles = Vec::new();
        for candidate in chunk.iter().cloned() {
            let group = Arc::clone(&group);
            handles.push(tokio::spawn(async move {
                run_resident_candidate_health_check_async(&group, &candidate).await;
            }));
        }
        for handle in handles {
            let _ = handle.await;
        }
    }
}

pub(crate) async fn run_resident_group_health_checks_async(
    group: &plan::ResidentProxyGroupPlan,
    candidates: &[plan::ResidentProxyProbePlan],
) {
    for candidate in candidates {
        run_resident_candidate_health_check_async(group, candidate).await;
    }
}

async fn run_resident_candidate_health_check_async(
    group: &plan::ResidentProxyGroupPlan,
    candidate: &plan::ResidentProxyProbePlan,
) {
    let checked_at = unix_now_secs();
    let latency_ms = probe_resident_candidate_tcp_endpoint_async(candidate)
        .await
        .ok();
    let _ = group.record_check_result(
        &candidate.node_tag,
        NetworkType::TCP4,
        latency_ms,
        checked_at,
    );
    let udp_checked_at = unix_now_secs();
    let udp_latency_ms = probe_resident_candidate_udp_endpoint_async(candidate)
        .await
        .ok();
    let _ = group.record_check_result(
        &candidate.node_tag,
        NetworkType::DNS_UDP4,
        udp_latency_ms,
        udp_checked_at,
    );
}

#[cfg(test)]
pub(crate) fn run_resident_group_health_checks(
    group: &plan::ResidentProxyGroupPlan,
    candidates: &[plan::ResidentProxyProbePlan],
) {
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
    else {
        return;
    };
    runtime.block_on(run_resident_group_health_checks_async(group, candidates));
}

pub(crate) async fn probe_resident_candidate_tcp_latency_snapshot(
    groups: Vec<Arc<plan::ResidentProxyGroupPlan>>,
    candidate: plan::ResidentProxyProbePlan,
    reload_generation: u64,
) -> Value {
    let checked_at = unix_now_secs();
    let probe = probe_resident_candidate_tcp_endpoint_async(&candidate).await;
    let latency_ms = probe.as_ref().ok().copied();
    let link = candidate.link.clone();
    for group in groups {
        let _ =
            group.record_check_result_for_link(&link, NetworkType::TCP4, latency_ms, checked_at);
    }
    let display_name = candidate.node_tag.as_str();
    let graph_id = candidate.proxy.graph_id.as_str();
    let link_hash = candidate.link_hash.as_str();
    let redacted_source = candidate.redacted_link_source.as_str();
    json!({
        "name": display_name,
        "displayName": display_name,
        "graphId": graph_id,
        "reloadGeneration": reload_generation,
        "linkHash": link_hash,
        "linkIdentity": latency_link_identity_value(display_name, link_hash, redacted_source),
        "probeExecutor": resident_probe_executor_value(graph_id, reload_generation),
        "runtimeComponents": candidate
            .proxy
            .runtime_component_evidence_value_for_reload_generation(reload_generation),
        "latencyMs": latency_ms,
        "alive": latency_ms.is_some(),
        "checkedAtUnix": checked_at,
        "message": probe.err(),
        "scope": "proxy-tcp-check",
    })
}

pub(crate) fn manual_probe_unavailable_snapshot(
    link: &str,
    reason: &str,
    detail: &str,
    checked_at: i64,
    reload_generation: u64,
) -> Value {
    let display_name = display_name_from_link(link);
    let link_hash = link_hash(link);
    let graph_id = graph_id_from_link_hash(&link_hash);
    let redacted_source = redacted_link_source(link);
    json!({
        "name": display_name,
        "displayName": display_name,
        "graphId": graph_id,
        "reloadGeneration": reload_generation,
        "linkHash": link_hash,
        "linkIdentity": latency_link_identity_value(&display_name, &link_hash, &redacted_source),
        "probeExecutor": resident_probe_executor_value(&graph_id, reload_generation),
        "admission": {
            "status": "fail-closed",
            "unsupportedReason": detail,
        },
        "latencyMs": Value::Null,
        "alive": false,
        "checkedAtUnix": checked_at,
        "message": format!("{reason}: {detail}"),
        "scope": "proxy-tcp-check",
    })
}

pub(crate) fn resident_latency_snapshot_json(
    snapshot: plan::ResidentProxyLatencySnapshot,
    reload_generation: u64,
) -> Value {
    let display_name = snapshot.node_tag.as_str();
    let graph_id = snapshot.graph_id.as_str();
    let link_hash = snapshot.link_hash.as_str();
    let redacted_source = snapshot.redacted_link_source.as_str();
    json!({
        "name": display_name,
        "displayName": display_name,
        "graphId": graph_id,
        "reloadGeneration": reload_generation,
        "linkHash": link_hash,
        "linkIdentity": latency_link_identity_value(display_name, link_hash, redacted_source),
        "probeExecutor": resident_probe_executor_value(graph_id, reload_generation),
        "latencyMs": snapshot.latency_ms,
        "alive": snapshot.alive,
        "checkedAtUnix": snapshot.checked_at_unix,
        "message": snapshot.message,
    })
}

pub(crate) fn resident_probe_executor_value(graph_id: &str, reload_generation: u64) -> Value {
    json!({
        "schemaVersion": 1,
        "executor": "resident-executable-graph",
        "graphId": graph_id,
        "reloadGeneration": reload_generation,
        "sharesTrafficExecutor": true,
    })
}

pub(crate) fn preferred_latency_snapshots(values: impl IntoIterator<Item = Value>) -> Vec<Value> {
    let mut by_link_hash = BTreeMap::<String, Value>::new();
    for value in values {
        let Some(link_hash) = latency_snapshot_link_hash(&value) else {
            continue;
        };
        if link_hash.is_empty() {
            continue;
        }
        let replace = by_link_hash
            .get(link_hash)
            .map(|current| prefer_latency_snapshot(&value, current))
            .unwrap_or(true);
        if replace {
            by_link_hash.insert(link_hash.to_owned(), value);
        }
    }
    by_link_hash.into_values().collect()
}

pub(crate) fn latency_snapshot_link_hash(value: &Value) -> Option<&str> {
    value.get("linkHash").and_then(Value::as_str).or_else(|| {
        value
            .pointer("/linkIdentity/linkHash")
            .and_then(Value::as_str)
    })
}

pub(crate) fn prefer_latency_snapshot(next: &Value, current: &Value) -> bool {
    let next_latency = next.get("latencyMs").and_then(Value::as_i64);
    let current_latency = current.get("latencyMs").and_then(Value::as_i64);
    match (next_latency, current_latency) {
        (Some(_), None) => true,
        (None, Some(_)) => false,
        (Some(next), Some(current)) => next < current,
        (None, None) => {
            next.get("checkedAtUnix")
                .and_then(Value::as_i64)
                .unwrap_or(0)
                > current
                    .get("checkedAtUnix")
                    .and_then(Value::as_i64)
                    .unwrap_or(0)
        }
    }
}

pub(crate) fn latency_link_identity_value(
    display_name: &str,
    link_hash: &str,
    redacted_source: &str,
) -> Value {
    json!({
        "schemaVersion": 1,
        "displayName": display_name,
        "linkHash": link_hash,
        "redactedSource": redacted_source,
    })
}

pub(crate) fn link_hash(link: &str) -> String {
    format!("sha256:{}", hex_encode(&Sha256::digest(link.as_bytes())))
}

pub(crate) fn graph_id_from_link_hash(link_hash: &str) -> String {
    let graph_hash = link_hash.trim_start_matches("sha256:");
    format!("resident-graph:{}", &graph_hash[..16.min(graph_hash.len())])
}

pub(crate) fn redacted_link_source(link: &str) -> String {
    let Ok(url) = url::Url::parse(link) else {
        return "link:<redacted>".to_owned();
    };
    let mut value = format!("{}:<redacted>", url.scheme());
    if let Some(fragment) = url.fragment().filter(|fragment| !fragment.is_empty()) {
        value.push('#');
        value.push_str(fragment);
    }
    value
}

pub(crate) fn display_name_from_link(link: &str) -> String {
    url::Url::parse(link)
        .ok()
        .and_then(|url| url.fragment().map(str::to_owned))
        .filter(|fragment| !fragment.is_empty())
        .unwrap_or_else(|| "<redacted>".to_owned())
}

pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

pub(crate) async fn probe_resident_candidate_tcp_endpoint_async(
    candidate: &plan::ResidentProxyProbePlan,
) -> Result<i64, String> {
    let started = Instant::now();
    probe_resident_proxy_tcp_async(
        &candidate.proxy,
        &candidate.tcp_check.scheme,
        &candidate.tcp_check.target,
        &candidate.tcp_check.host,
        &candidate.tcp_check.path,
        &candidate.tcp_check.method,
        Duration::from_secs(4),
    )
    .await?;
    Ok(elapsed_millis(started.elapsed()))
}

pub(crate) async fn probe_resident_candidate_udp_endpoint_async(
    candidate: &plan::ResidentProxyProbePlan,
) -> Result<i64, String> {
    let started = Instant::now();
    let target = candidate.udp_check.target.resolve().await?;
    probe_resident_proxy_dns_udp_async(&candidate.proxy, target, &candidate.udp_check.lookup_host)
        .await?;
    Ok(elapsed_millis(started.elapsed()))
}

pub(crate) fn elapsed_millis(elapsed: Duration) -> i64 {
    elapsed.as_millis().min(i64::MAX as u128) as i64
}

pub(crate) fn unix_now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs().min(i64::MAX as u64) as i64)
        .unwrap_or(0)
}

pub(crate) fn sleep_until_stopped(stop: &AtomicBool, duration: Duration) -> bool {
    if duration.is_zero() {
        return stop.load(Ordering::Relaxed);
    }
    let started = Instant::now();
    while !stop.load(Ordering::Relaxed) {
        let elapsed = started.elapsed();
        if elapsed >= duration {
            return false;
        }
        thread::sleep((duration - elapsed).min(Duration::from_millis(100)));
    }
    true
}
