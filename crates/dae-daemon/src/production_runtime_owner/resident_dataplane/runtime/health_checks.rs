use super::tcp::{QuicEndpointCallerClass, scope_quic_endpoint_observation};
use super::*;
use crate::allocator::{AllocatorReclaimReason, allocator_reclaim};

#[path = "health_checks/family.rs"]
mod family;
use family::run_resident_candidate_family_health_checks;
#[path = "health_checks/tcp_family_probe.rs"]
mod tcp_family_probe;
use tcp_family_probe::{
    ResidentTcpFamilyProbeResult, preferred_tcp_family_probe_result,
    probe_resident_candidate_tcp_families,
};
#[path = "health_checks/udp_family_probe.rs"]
mod udp_family_probe;
use udp_family_probe::{
    ResidentUdpFamilyProbeResult, preferred_udp_family_probe_result,
    probe_resident_candidate_udp_families,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum HealthCheckRoundStatus {
    Completed,
    Cancelled,
}

impl HealthCheckRoundStatus {
    pub(super) fn is_cancelled(self) -> bool {
        matches!(self, Self::Cancelled)
    }
}

pub(super) async fn run_resident_group_health_check_round_async(
    group: Arc<plan::ResidentProxyGroupPlan>,
    stop: SharedResidentStopSignal,
    concurrency: usize,
) -> HealthCheckRoundStatus {
    if stop.load(Ordering::Relaxed) {
        return HealthCheckRoundStatus::Cancelled;
    }
    let candidates = group.probe_candidates();
    if candidates.is_empty() {
        return HealthCheckRoundStatus::Completed;
    }
    let status = run_resident_group_health_checks_concurrent_async(
        group,
        &candidates,
        concurrency.max(1),
        stop,
    )
    .await;
    drop(candidates);
    let _ = allocator_reclaim(AllocatorReclaimReason::GroupHealthProbe);
    status
}

async fn run_resident_group_health_checks_concurrent_async(
    group: Arc<plan::ResidentProxyGroupPlan>,
    candidates: &[plan::ResidentProxyProbePlan],
    concurrency: usize,
    stop: SharedResidentStopSignal,
) -> HealthCheckRoundStatus {
    if stop.load(Ordering::Relaxed) {
        return HealthCheckRoundStatus::Cancelled;
    }
    if concurrency <= 1 {
        return run_resident_group_health_checks_until_stopped(&group, candidates, stop).await;
    }
    for chunk in candidates.chunks(concurrency.max(1)) {
        if stop.load(Ordering::Relaxed) {
            return HealthCheckRoundStatus::Cancelled;
        }
        let mut handles = Vec::new();
        for candidate in chunk {
            let candidate = candidate.clone();
            let group = Arc::clone(&group);
            let stop = Arc::clone(&stop);
            handles.push(tokio::spawn(async move {
                run_resident_candidate_health_check_until_stopped(&group, &candidate, stop).await
            }));
        }
        for handle in handles {
            if matches!(handle.await, Ok(HealthCheckRoundStatus::Cancelled)) {
                return HealthCheckRoundStatus::Cancelled;
            }
        }
    }
    HealthCheckRoundStatus::Completed
}

#[cfg(test)]
pub(crate) async fn run_resident_group_health_checks_async(
    group: &plan::ResidentProxyGroupPlan,
    candidates: &[plan::ResidentProxyProbePlan],
) {
    let stop = ResidentStopSignal::shared();
    let _ = run_resident_group_health_checks_until_stopped(group, candidates, stop).await;
}

async fn run_resident_group_health_checks_until_stopped(
    group: &plan::ResidentProxyGroupPlan,
    candidates: &[plan::ResidentProxyProbePlan],
    stop: SharedResidentStopSignal,
) -> HealthCheckRoundStatus {
    for candidate in candidates {
        if stop.load(Ordering::Relaxed) {
            return HealthCheckRoundStatus::Cancelled;
        }
        if run_resident_candidate_health_check_until_stopped(group, candidate, Arc::clone(&stop))
            .await
            == HealthCheckRoundStatus::Cancelled
        {
            return HealthCheckRoundStatus::Cancelled;
        }
    }
    HealthCheckRoundStatus::Completed
}

async fn run_resident_candidate_health_check_until_stopped(
    group: &plan::ResidentProxyGroupPlan,
    candidate: &plan::ResidentProxyProbePlan,
    stop: SharedResidentStopSignal,
) -> HealthCheckRoundStatus {
    if stop.load(Ordering::Relaxed) {
        return HealthCheckRoundStatus::Cancelled;
    }
    run_resident_candidate_family_health_checks(group, candidate, stop).await
}

#[cfg(test)]
fn record_resident_candidate_health_result(
    group: &plan::ResidentProxyGroupPlan,
    node_tag: &str,
    network_type: Option<NetworkType>,
    latency_ms: Option<i64>,
    checked_at_unix: i64,
) -> bool {
    let Some(network_type) = network_type else {
        return false;
    };
    let _ = group.record_check_result(node_tag, network_type, latency_ms, checked_at_unix);
    true
}

async fn wait_until_stopped_async(stop: SharedResidentStopSignal) {
    while !stop.load(Ordering::Relaxed) {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
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

async fn probe_resident_candidate_tcp_latency_snapshot_scoped(
    candidate: plan::ResidentProxyProbePlan,
    reload_generation: u64,
) -> Value {
    let checked_at = unix_now_secs();
    let probe = probe_resident_candidate_tcp_endpoint_async(&candidate).await;
    let latency_ms = probe.latency_ms;
    let family_results = probe
        .family_results
        .iter()
        .map(ResidentTcpFamilyProbeResult::to_json)
        .collect::<Vec<_>>();
    let preferred_health_state = preferred_tcp_family_probe_result(&probe.family_results)
        .map(|result| result.health_state.as_str());
    let display_name = candidate.node_tag.as_str();
    let graph_id = candidate.proxy.graph_id.as_str();
    let link_hash = candidate.link_hash.as_str();
    let execution_identity = candidate.execution_identity.as_str();
    let redacted_source = candidate.redacted_link_source.as_str();
    let network_type = probe.network_type.map(NetworkType::string_without_dns);
    let network_dimension = probe.network_type.map(NetworkType::dimension_name);
    json!({
        "name": display_name,
        "displayName": display_name,
        "graphId": graph_id,
        "reloadGeneration": reload_generation,
        "linkHash": link_hash,
        "executionIdentity": execution_identity,
        "linkIdentity": latency_link_identity_value(display_name, link_hash, redacted_source),
        "probeExecutor": resident_probe_executor_value(graph_id, reload_generation),
        "runtimeComponents": candidate
            .proxy
            .runtime_component_evidence_value_for_reload_generation(reload_generation),
        "latencyMs": latency_ms,
        "alive": latency_ms.is_some(),
        "healthState": preferred_health_state,
        "checkedAtUnix": checked_at,
        "message": probe.message,
        "networkType": network_type,
        "networkDimension": network_dimension,
        "familyResults": family_results,
        "scope": "proxy-tcp-check",
    })
}

pub(crate) async fn probe_resident_candidate_manual_latency_snapshot(
    candidate: plan::ResidentProxyProbePlan,
    reload_generation: u64,
) -> Value {
    scope_quic_endpoint_observation(
        QuicEndpointCallerClass::ManualProbe,
        Some(dae_runtime_control::OwnerGeneration::new(reload_generation)),
        async move {
            match candidate.proxy.execution_plan().manual_probe_dispatch() {
                plan::ResidentManualProbeDispatch::Tcp => {
                    probe_resident_candidate_tcp_latency_snapshot_scoped(
                        candidate,
                        reload_generation,
                    )
                    .await
                }
                plan::ResidentManualProbeDispatch::Udp => {
                    probe_resident_candidate_udp_latency_snapshot(candidate, reload_generation)
                        .await
                }
                plan::ResidentManualProbeDispatch::PolicyClosed => {
                    manual_probe_unavailable_snapshot(
                        &candidate.link,
                        "native outbound probe not admitted for this node",
                        candidate
                            .proxy
                            .execution_plan()
                            .udp
                            .agreement()
                            .unsupported_reason()
                            .unwrap_or(
                                "manual probe is policy-closed for this exact protocol shape",
                            ),
                        unix_now_secs(),
                        reload_generation,
                    )
                }
            }
        },
    )
    .await
}

async fn probe_resident_candidate_udp_latency_snapshot(
    candidate: plan::ResidentProxyProbePlan,
    reload_generation: u64,
) -> Value {
    let checked_at = unix_now_secs();
    let family_results = probe_resident_candidate_udp_families(&candidate, None)
        .await
        .unwrap_or_default();
    let preferred = preferred_udp_family_probe_result(&family_results);
    let latency_ms = preferred.and_then(|result| result.latency_ms);
    let preferred_health_state = preferred.map(|result| result.health_state.as_str());
    let message = preferred
        .and_then(|result| result.message.clone())
        .or_else(|| {
            family_results
                .is_empty()
                .then(|| "all UDP health family probes were cancelled".to_owned())
        });
    let family_results_json = family_results
        .iter()
        .map(ResidentUdpFamilyProbeResult::to_json)
        .collect::<Vec<_>>();
    let display_name = candidate.node_tag.as_str();
    let graph_id = candidate.proxy.graph_id.as_str();
    let link_hash = candidate.link_hash.as_str();
    let execution_identity = candidate.execution_identity.as_str();
    let redacted_source = candidate.redacted_link_source.as_str();
    let network_type = preferred.map(|result| result.network_type.string_without_dns());
    let network_dimension = preferred.map(|result| result.network_type.dimension_name());
    json!({
        "name": display_name,
        "displayName": display_name,
        "graphId": graph_id,
        "reloadGeneration": reload_generation,
        "linkHash": link_hash,
        "executionIdentity": execution_identity,
        "linkIdentity": latency_link_identity_value(display_name, link_hash, redacted_source),
        "probeExecutor": resident_probe_executor_value(graph_id, reload_generation),
        "runtimeComponents": candidate
            .proxy
            .runtime_component_evidence_value_for_reload_generation(reload_generation),
        "latencyMs": latency_ms,
        "alive": latency_ms.is_some(),
        "healthState": preferred_health_state,
        "checkedAtUnix": checked_at,
        "message": message,
        "networkType": network_type,
        "networkDimension": network_dimension,
        "familyResults": family_results_json,
        "scope": "proxy-udp-check",
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
    let execution_identity = execution_link_hash(link);
    let graph_id = graph_id_from_link_hash(&link_hash);
    let redacted_source = redacted_link_source(link);
    json!({
        "name": display_name,
        "displayName": display_name,
        "graphId": graph_id,
        "reloadGeneration": reload_generation,
        "linkHash": link_hash,
        "executionIdentity": execution_identity,
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
    let execution_identity = snapshot.execution_identity.as_str();
    let redacted_source = snapshot.redacted_link_source.as_str();
    json!({
        "name": display_name,
        "displayName": display_name,
        "graphId": graph_id,
        "reloadGeneration": reload_generation,
        "linkHash": link_hash,
        "executionIdentity": execution_identity,
        "linkIdentity": latency_link_identity_value(display_name, link_hash, redacted_source),
        "probeExecutor": resident_probe_executor_value(graph_id, reload_generation),
        "networkType": snapshot.network_type.string_without_dns(),
        "networkDimension": snapshot.network_type.dimension_name(),
        "latencyMs": snapshot.latency_ms,
        "alive": snapshot.alive,
        "healthState": snapshot.health_state.as_str(),
        "checkedAtUnix": snapshot.checked_at_unix,
        "lastSuccessAtUnix": snapshot.last_success_at_unix,
        "lastFailureAtUnix": snapshot.last_failure_at_unix,
        "lastUnknownAtUnix": snapshot.last_unknown_at_unix,
        "targetIdentity": snapshot.target_identity,
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
    let next_alive = next
        .get("alive")
        .and_then(Value::as_bool)
        .unwrap_or_else(|| next_latency.is_some());
    let current_alive = current
        .get("alive")
        .and_then(Value::as_bool)
        .unwrap_or_else(|| current_latency.is_some());
    match (next_alive, current_alive) {
        (true, false) => true,
        (false, true) => false,
        (true, true) => match (next_latency, current_latency) {
            (Some(next), Some(current)) => next < current,
            (Some(_), None) => true,
            (None, Some(_)) => false,
            (None, None) => latency_snapshot_is_newer(next, current),
        },
        (false, false) => latency_snapshot_is_newer(next, current),
    }
}

fn latency_snapshot_is_newer(next: &Value, current: &Value) -> bool {
    next.get("checkedAtUnix")
        .and_then(Value::as_i64)
        .unwrap_or(0)
        > current
            .get("checkedAtUnix")
            .and_then(Value::as_i64)
            .unwrap_or(0)
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

pub(crate) fn execution_link_hash(link: &str) -> String {
    link_hash(&canonical_link_without_display_name(link))
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResidentTcpProbeResult {
    pub(in crate::production_runtime_owner::resident_dataplane) network_type: Option<NetworkType>,
    pub(in crate::production_runtime_owner::resident_dataplane) latency_ms: Option<i64>,
    pub(in crate::production_runtime_owner::resident_dataplane) message: Option<String>,
    family_results: Vec<ResidentTcpFamilyProbeResult>,
}

#[cfg(test)]
#[derive(Clone, Debug, Eq, PartialEq)]
struct ResidentTcpTargetProbeResult {
    index: usize,
    target: String,
    network_type: Option<NetworkType>,
    latency_ms: Option<i64>,
    message: Option<String>,
}

pub(crate) async fn probe_resident_candidate_tcp_endpoint_async(
    candidate: &plan::ResidentProxyProbePlan,
) -> ResidentTcpProbeResult {
    let family_results = probe_resident_candidate_tcp_families(candidate, None)
        .await
        .unwrap_or_default();
    let preferred = preferred_tcp_family_probe_result(&family_results);
    ResidentTcpProbeResult {
        network_type: preferred.map(|result| result.network_type),
        latency_ms: preferred.and_then(|result| result.latency_ms),
        message: preferred
            .and_then(|result| result.message.clone())
            .or_else(|| {
                family_results
                    .is_empty()
                    .then(|| "all TCP health family probes were cancelled".to_owned())
            }),
        family_results,
    }
}

#[cfg(test)]
fn preferred_tcp_probe_result(
    results: &[ResidentTcpTargetProbeResult],
) -> Option<ResidentTcpProbeResult> {
    let preferred = results.iter().reduce(|current, next| {
        if prefer_tcp_probe_target(next, current) {
            next
        } else {
            current
        }
    })?;
    let message = if preferred.latency_ms.is_some() {
        None
    } else {
        tcp_probe_failure_message(results)
    };
    Some(ResidentTcpProbeResult {
        network_type: preferred.network_type,
        latency_ms: preferred.latency_ms,
        message,
        family_results: Vec::new(),
    })
}

#[cfg(test)]
fn prefer_tcp_probe_target(
    next: &ResidentTcpTargetProbeResult,
    current: &ResidentTcpTargetProbeResult,
) -> bool {
    match (next.latency_ms, current.latency_ms) {
        (Some(next_latency), Some(current_latency)) => {
            next_latency < current_latency
                || (next_latency == current_latency && next.index < current.index)
        }
        (Some(_), None) => true,
        (None, Some(_)) => false,
        (None, None) => next.index < current.index,
    }
}

#[cfg(test)]
fn tcp_probe_failure_message(results: &[ResidentTcpTargetProbeResult]) -> Option<String> {
    let mut failures = results
        .iter()
        .filter_map(|result| {
            result
                .message
                .as_ref()
                .map(|message| format!("{}: {message}", result.target))
        })
        .collect::<Vec<_>>();
    failures.sort();
    match failures.len() {
        0 => None,
        1 => failures.pop(),
        _ => Some(format!(
            "all TCP check targets failed: {}",
            failures.join("; ")
        )),
    }
}

async fn probe_resident_candidate_tcp_target_endpoint_async(
    candidate: &plan::ResidentProxyProbePlan,
    target: &plan::ResidentTcpCheckTarget,
) -> Result<i64, String> {
    let started = Instant::now();
    probe_native_proxy_tcp_async(
        Arc::clone(&candidate.proxy),
        &candidate.tcp_check.scheme,
        &target.target,
        &candidate.tcp_check.host,
        &candidate.tcp_check.path,
        &candidate.tcp_check.method,
        candidate.tcp_probe_timeout,
    )
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostname_check_target_does_not_invent_ipv4_family() {
        let target = plan::ResidentTcpCheckTarget {
            target: "health.example:80".to_owned(),
            network_type: None,
        };
        assert_eq!(target.network_type_hint(), None);
    }

    #[test]
    fn health_result_without_attempted_family_is_not_recorded() {
        let config = parse_test_config(
            r#"
            global {
                lan_interface: daerust0
                tcp_check_url: 'http://health.example'
            }
            node {
                node_a: 'socks5://127.0.0.1:1080#node_a'
            }
            group {
                proxy {
                    filter: name(node_a)
                    policy: min
                }
            }
            routing {
                l4proto(tcp) -> proxy
                fallback: direct
            }
            "#,
        );
        let plan = build_resident_dataplane_plan(&config).unwrap();
        let group = plan.default_proxy_group().unwrap();

        assert!(!record_resident_candidate_health_result(
            group, "node_a", None, None, 10,
        ));
        let snapshot = group.latency_snapshots().pop().unwrap();
        assert_eq!(snapshot.checked_at_unix, 0);
        assert!(!snapshot.alive);
    }

    #[test]
    fn resident_health_check_round_cancelled_before_probe_does_not_seed_latency_state() {
        let config = parse_test_config(
            r#"
            global {
                lan_interface: daerust0
            }
            node {
                node_a: 'socks5://127.0.0.1:1080#node_a'
                node_b: 'socks5://127.0.0.1:1081#node_b'
            }
            group {
                proxy {
                    filter: name(node_a, node_b)
                    policy: min
                }
            }
            routing {
                l4proto(tcp) -> proxy
                fallback: direct
            }
            "#,
        );
        let plan = build_resident_dataplane_plan(&config).unwrap();
        let group = Arc::new(plan.default_proxy_group().unwrap().clone());
        let candidates = group.probe_candidates();
        assert!(!candidates.is_empty());

        let stop = ResidentStopSignal::shared();
        stop.store(true, Ordering::Relaxed);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        let status = runtime.block_on(run_resident_group_health_checks_concurrent_async(
            Arc::clone(&group),
            &candidates,
            2,
            stop,
        ));

        assert_eq!(status, HealthCheckRoundStatus::Cancelled);
        assert!(
            group
                .latency_snapshots()
                .iter()
                .all(|snapshot| !snapshot.alive
                    && snapshot.latency_ms.is_none()
                    && snapshot.checked_at_unix == 0)
        );
    }

    #[test]
    fn absent_health_families_become_unavailable_without_fake_timeout_latency() {
        let config = parse_test_config(
            r#"
            global {
                lan_interface: daerust0
            }
            node {
                node_a: 'socks5://192.0.2.1:1080#node_a'
            }
            group {
                proxy {
                    filter: name(node_a)
                    policy: min
                }
            }
            routing {
                l4proto(tcp) -> proxy
                fallback: direct
            }
            "#,
        );
        let plan = build_resident_dataplane_plan(&config).unwrap();
        let group = plan.default_proxy_group().unwrap();
        let mut candidates = group.probe_candidates();
        let absent = plan::ResidentHealthTargetFamilies {
            ipv4: plan::ResidentHealthTargetFamily::Absent,
            ipv6: plan::ResidentHealthTargetFamily::Absent,
        };
        candidates[0].tcp_check.resolver = candidates[0]
            .tcp_check
            .resolver
            .clone()
            .with_test_result(absent.clone());
        candidates[0].udp_check.resolver = candidates[0]
            .udp_check
            .resolver
            .clone()
            .with_test_result(absent);

        run_resident_group_health_checks(group, &candidates);

        let snapshots = group.health_state_snapshots();
        for network_type in [
            NetworkType::TCP4,
            NetworkType::TCP6,
            NetworkType::DNS_UDP4,
            NetworkType::DNS_UDP6,
        ] {
            let snapshot = snapshots
                .iter()
                .find(|snapshot| snapshot.network_type == network_type)
                .unwrap();
            assert_eq!(
                snapshot.health_state,
                dae_outbound::HealthState::Unavailable
            );
            assert_eq!(snapshot.latency_ms, None);
            assert_ne!(snapshot.latency_ms, Some(dae_outbound::dialer::TIMEOUT_MS));
        }
    }

    #[test]
    fn transient_resolver_unknown_preserves_a_known_alive_family() {
        let config = parse_test_config(
            r#"
            global {
                lan_interface: daerust0
            }
            node {
                node_a: 'socks5://192.0.2.1:1080#node_a'
            }
            group {
                proxy {
                    filter: name(node_a)
                    policy: min
                }
            }
            routing {
                l4proto(tcp) -> proxy
                fallback: direct
            }
            "#,
        );
        let plan = build_resident_dataplane_plan(&config).unwrap();
        let group = plan.default_proxy_group().unwrap();
        group
            .record_health_state(
                "node_a",
                NetworkType::TCP4,
                dae_outbound::HealthState::Alive,
                Some(19),
                10,
            )
            .unwrap();
        let mut candidates = group.probe_candidates();
        let unknown = plan::ResidentHealthTargetFamilies {
            ipv4: plan::ResidentHealthTargetFamily::Unknown(
                "temporary resolver failure".to_owned(),
            ),
            ipv6: plan::ResidentHealthTargetFamily::Unknown(
                "temporary resolver failure".to_owned(),
            ),
        };
        candidates[0].tcp_check.resolver = candidates[0]
            .tcp_check
            .resolver
            .clone()
            .with_test_result(unknown);
        candidates[0].udp_check.resolver =
            candidates[0].udp_check.resolver.clone().with_test_result(
                plan::ResidentHealthTargetFamilies {
                    ipv4: plan::ResidentHealthTargetFamily::Absent,
                    ipv6: plan::ResidentHealthTargetFamily::Absent,
                },
            );

        run_resident_group_health_checks(group, &candidates);

        let snapshot = group
            .health_state_snapshots()
            .into_iter()
            .find(|snapshot| snapshot.network_type == NetworkType::TCP4)
            .unwrap();
        assert_eq!(snapshot.health_state, dae_outbound::HealthState::Alive);
        assert_eq!(snapshot.latency_ms, Some(19));
        assert_eq!(snapshot.last_success_at_unix, 10);
        assert!(snapshot.last_unknown_at_unix >= 10);
    }

    #[test]
    fn preferred_latency_snapshots_prefers_newer_failed_error_over_old_placeholder_latency() {
        let values = preferred_latency_snapshots([
            json!({
                "linkHash": "sha256:one",
                "latencyMs": 10000,
                "alive": false,
                "checkedAtUnix": 10,
                "message": "unavailable",
            }),
            json!({
                "linkHash": "sha256:one",
                "latencyMs": null,
                "alive": false,
                "checkedAtUnix": 11,
                "message": "TLS handshake failed unexpected EOF",
            }),
        ]);
        assert_eq!(values.len(), 1);
        assert_eq!(
            values[0]["message"],
            json!("TLS handshake failed unexpected EOF")
        );
        assert_eq!(values[0]["latencyMs"], Value::Null);
    }

    #[test]
    fn preferred_latency_snapshots_keeps_alive_result_over_newer_failure() {
        let values = preferred_latency_snapshots([
            json!({
                "linkHash": "sha256:one",
                "latencyMs": 120,
                "alive": true,
                "checkedAtUnix": 10,
                "message": null,
            }),
            json!({
                "linkHash": "sha256:one",
                "latencyMs": null,
                "alive": false,
                "checkedAtUnix": 11,
                "message": "timeout",
            }),
        ]);
        assert_eq!(values.len(), 1);
        assert_eq!(values[0]["latencyMs"], json!(120));
        assert_eq!(values[0]["alive"], json!(true));
    }

    #[test]
    fn preferred_tcp_probe_result_uses_best_successful_target() {
        let result = preferred_tcp_probe_result(&[
            ResidentTcpTargetProbeResult {
                index: 0,
                target: "192.0.2.1:80".to_owned(),
                network_type: Some(NetworkType::TCP4),
                latency_ms: Some(90),
                message: None,
            },
            ResidentTcpTargetProbeResult {
                index: 1,
                target: "[2001:db8::1]:80".to_owned(),
                network_type: Some(NetworkType::TCP6),
                latency_ms: Some(30),
                message: None,
            },
        ])
        .unwrap();

        assert_eq!(result.network_type, Some(NetworkType::TCP6));
        assert_eq!(result.latency_ms, Some(30));
        assert_eq!(result.message, None);
    }

    #[test]
    fn preferred_tcp_probe_result_keeps_success_over_earlier_failure() {
        let result = preferred_tcp_probe_result(&[
            ResidentTcpTargetProbeResult {
                index: 0,
                target: "192.0.2.1:80".to_owned(),
                network_type: Some(NetworkType::TCP4),
                latency_ms: None,
                message: Some("timeout".to_owned()),
            },
            ResidentTcpTargetProbeResult {
                index: 1,
                target: "[2001:db8::1]:80".to_owned(),
                network_type: Some(NetworkType::TCP6),
                latency_ms: Some(42),
                message: None,
            },
        ])
        .unwrap();

        assert_eq!(result.network_type, Some(NetworkType::TCP6));
        assert_eq!(result.latency_ms, Some(42));
        assert_eq!(result.message, None);
    }

    #[test]
    fn preferred_tcp_probe_result_reports_all_target_failures() {
        let result = preferred_tcp_probe_result(&[
            ResidentTcpTargetProbeResult {
                index: 0,
                target: "192.0.2.1:80".to_owned(),
                network_type: Some(NetworkType::TCP4),
                latency_ms: None,
                message: Some("connect failed".to_owned()),
            },
            ResidentTcpTargetProbeResult {
                index: 1,
                target: "[2001:db8::1]:80".to_owned(),
                network_type: Some(NetworkType::TCP6),
                latency_ms: None,
                message: Some("timeout".to_owned()),
            },
        ])
        .unwrap();

        assert_eq!(result.network_type, Some(NetworkType::TCP4));
        assert_eq!(result.latency_ms, None);
        assert_eq!(
            result.message.as_deref(),
            Some(
                "all TCP check targets failed: 192.0.2.1:80: connect failed; [2001:db8::1]:80: timeout"
            )
        );
    }

    #[test]
    fn failed_hostname_probe_preserves_unknown_family() {
        let result = preferred_tcp_probe_result(&[ResidentTcpTargetProbeResult {
            index: 0,
            target: "health.example:80".to_owned(),
            network_type: None,
            latency_ms: None,
            message: Some("resolve failed".to_owned()),
        }])
        .unwrap();

        assert_eq!(result.network_type, None);
        assert_eq!(result.latency_ms, None);
        assert_eq!(
            result.message.as_deref(),
            Some("health.example:80: resolve failed")
        );
    }

    fn parse_test_config(input: &str) -> Config {
        let sections = dae_config::parser::parse_config(input).unwrap();
        dae_config::schema::build_config(&sections).unwrap()
    }
}
