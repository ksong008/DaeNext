use super::*;

mod shutdown;
mod task;

use self::shutdown::shutdown_resident_runtime_owner;
use self::task::*;

pub(crate) struct ResidentRuntimeOwner {
    stop: SharedResidentStopSignal,
    tasks: Vec<ResidentRuntimeTask>,
    event_file: PathBuf,
    event_lock: Arc<Mutex<()>>,
    reload_generation: u64,
    metrics: Arc<ResidentDataplaneMetrics>,
    udp_sessions_active: Arc<AtomicUsize>,
    resource_config: ResidentRuntimeResourceConfig,
    event_writer: ResidentEventWriterRuntime,
}

#[derive(Clone)]
pub(crate) struct ResidentManualProbeHandle {
    groups: Vec<Arc<plan::ResidentProxyGroupPlan>>,
    manual_probe_plans: BTreeMap<String, Result<plan::ResidentProxyProbePlan, String>>,
    reload_generation: u64,
    resource_config: ResidentRuntimeResourceConfig,
}

impl std::fmt::Debug for ResidentRuntimeOwner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResidentRuntimeOwner")
            .field("task_count", &self.tasks.len())
            .field("event_file_status", &"disabled")
            .field("reload_generation", &self.reload_generation)
            .field("resource_config", &self.resource_config.json())
            .field("manual_probe_runtime_persistent", &false)
            .field("event_writer", &self.event_writer.metrics_snapshot())
            .finish_non_exhaustive()
    }
}

impl ResidentRuntimeOwner {
    pub(crate) fn new(
        event_file: PathBuf,
        event_lock: Arc<Mutex<()>>,
        reload_generation: u64,
        metrics: Arc<ResidentDataplaneMetrics>,
        udp_sessions_active: Arc<AtomicUsize>,
        resource_config: ResidentRuntimeResourceConfig,
    ) -> Self {
        let event_writer = ResidentEventWriterRuntime::start(
            event_file.clone(),
            Arc::clone(&event_lock),
            resource_config.event_queue_depth.value(),
        );
        Self {
            stop: ResidentStopSignal::shared(),
            tasks: Vec::new(),
            event_file,
            event_lock,
            reload_generation,
            metrics,
            udp_sessions_active,
            resource_config,
            event_writer,
        }
    }

    pub(crate) fn stop_handle(&self) -> SharedResidentStopSignal {
        Arc::clone(&self.stop)
    }

    pub(crate) fn event_file(&self) -> PathBuf {
        self.event_file.clone()
    }

    pub(crate) fn event_lock(&self) -> Arc<Mutex<()>> {
        Arc::clone(&self.event_lock)
    }

    pub(crate) fn metrics(&self) -> Arc<ResidentDataplaneMetrics> {
        Arc::clone(&self.metrics)
    }

    pub(crate) fn udp_sessions_active(&self) -> Arc<AtomicUsize> {
        Arc::clone(&self.udp_sessions_active)
    }

    pub(crate) fn reload_generation(&self) -> u64 {
        self.reload_generation
    }

    pub(crate) fn manual_probe_handle(
        &self,
        groups: &[Arc<plan::ResidentProxyGroupPlan>],
        manual_probe_plans: &BTreeMap<String, Result<plan::ResidentProxyProbePlan, String>>,
    ) -> ResidentManualProbeHandle {
        ResidentManualProbeHandle {
            groups: groups.to_vec(),
            manual_probe_plans: manual_probe_plans.clone(),
            reload_generation: self.reload_generation,
            resource_config: self.resource_config.clone(),
        }
    }

    pub(crate) fn register_thread(
        &mut self,
        name: &'static str,
        kind: &'static str,
        handle: JoinHandle<()>,
    ) {
        self.tasks
            .push(registered_resident_runtime_task(name, kind, handle));
    }

    pub(crate) fn spawn_thread<F>(&mut self, name: &'static str, kind: &'static str, run: F)
    where
        F: FnOnce() + Send + 'static,
    {
        self.tasks
            .push(spawn_resident_runtime_task(name, kind, None, run));
    }

    pub(crate) fn spawn_thread_with_stack<F>(
        &mut self,
        name: &'static str,
        kind: &'static str,
        stack_bytes: usize,
        run: F,
    ) where
        F: FnOnce() + Send + 'static,
    {
        self.tasks.push(spawn_resident_runtime_task(
            name,
            kind,
            Some(stack_bytes),
            run,
        ));
    }

    pub(crate) fn task_registry_value(&self) -> Value {
        json!({
            "schemaVersion": 1,
            "owner": "resident-runtime-owner",
            "reloadGeneration": self.reload_generation,
            "taskCount": self.tasks.len(),
            "runtimeHandle": self.manual_probe_runtime_value(),
            "resources": self.resource_config.json(),
            "eventLog": "product-log-sink",
            "eventFileStatus": "disabled",
            "eventWriter": self.event_writer.metrics_snapshot(),
            "tasks": self.tasks.iter().map(|task| {
                json!({
                    "name": task.name,
                    "kind": task.kind,
                    "joinPolicy": "bounded-join-on-owner-shutdown",
                })
            }).collect::<Vec<_>>(),
        })
    }

    pub(crate) fn metrics_snapshot(&self) -> Value {
        let mut snapshot = self.metrics.snapshot();
        snapshot["reloadGeneration"] = json!(self.reload_generation);
        snapshot["runtimeOwner"] = self.runtime_owner_value();
        snapshot["packetSessionManager"] = json!({
            "schemaVersion": 1,
            "manager": "resident-udp-session-manager",
            "reloadGeneration": self.reload_generation,
        });
        snapshot["resources"] = self.resource_config.json();
        snapshot["eventWriter"] = self.event_writer.metrics_snapshot();
        snapshot
    }

    pub(crate) fn prune_event_log(&self) -> std::io::Result<()> {
        self.event_writer.prune()
    }

    pub(crate) fn clear_event_log(&self) -> std::io::Result<()> {
        self.event_writer.clear()
    }

    pub(crate) fn shutdown(&mut self) -> Value {
        shutdown_resident_runtime_owner(self, shutdown::RESIDENT_RUNTIME_TASK_JOIN_GRACE)
    }

    #[cfg(test)]
    fn shutdown_with_grace(&mut self, grace: Duration) -> Value {
        shutdown_resident_runtime_owner(self, grace)
    }

    fn runtime_owner_value(&self) -> Value {
        json!({
            "schemaVersion": 1,
            "owner": "resident-runtime-owner",
            "reloadGeneration": self.reload_generation,
            "taskCount": self.tasks.len(),
            "runtimeHandle": self.manual_probe_runtime_value(),
            "eventLog": "product-log-sink",
            "eventFileStatus": "disabled",
            "eventWriter": self.event_writer.metrics_snapshot(),
        })
    }

    fn manual_probe_runtime_value(&self) -> Value {
        json!({
            "schemaVersion": 1,
            "owner": "resident-runtime-owner",
            "executor": "per-probe-tokio-current-thread",
            "scope": "manual-latency-probes",
            "available": true,
            "persistent": false,
            "lifecycle": "created-per-probe-and-dropped-after-probe",
            "error": Value::Null,
        })
    }
}

fn duration_millis(duration: Duration) -> u64 {
    duration.as_millis().min(u128::from(u64::MAX)) as u64
}

impl ResidentManualProbeHandle {
    pub(crate) fn reload_generation(&self) -> u64 {
        self.reload_generation
    }

    pub(crate) fn probe_concurrency(&self) -> usize {
        self.resource_config.manual_probe_concurrency.value()
    }

    pub(crate) fn probe_timeout(&self) -> Duration {
        self.resource_config.tcp_probe_timeout()
    }

    pub(crate) fn probe_node_latencies_without_group_update(&self, links: &[String]) -> Vec<Value> {
        probe_resident_manual_latency_snapshots(
            &self.manual_probe_plans,
            links,
            self.reload_generation,
            self.probe_concurrency(),
        )
    }

    pub(crate) fn apply_latency_probe_snapshots_to_groups(&self, snapshots: &[Value]) {
        if self.groups.is_empty() || snapshots.is_empty() {
            return;
        }
        let mut links_by_hash = BTreeMap::<&str, Vec<&str>>::new();
        for (link, candidate) in &self.manual_probe_plans {
            let Ok(candidate) = candidate else {
                continue;
            };
            links_by_hash
                .entry(candidate.link_hash.as_str())
                .or_default()
                .push(link.as_str());
        }
        if links_by_hash.is_empty() {
            return;
        }
        for snapshot in snapshots {
            if snapshot.get("admission").is_some() {
                continue;
            }
            let Some(link_hash) = latency_snapshot_link_hash(snapshot) else {
                continue;
            };
            let Some(links) = links_by_hash.get(link_hash) else {
                continue;
            };
            let checked_at = snapshot
                .get("checkedAtUnix")
                .and_then(Value::as_i64)
                .unwrap_or_else(unix_now_secs);
            let latency_ms = latency_snapshot_group_latency_ms(snapshot);
            let Some(network_type) = latency_snapshot_group_network_type(snapshot) else {
                continue;
            };
            for link in links {
                for group in &self.groups {
                    let _ = group.record_manual_latency_result_for_link(
                        link,
                        network_type,
                        latency_ms,
                        checked_at,
                    );
                }
            }
        }
    }
}

fn latency_snapshot_group_latency_ms(snapshot: &Value) -> Option<i64> {
    let latency_ms = snapshot.get("latencyMs").and_then(Value::as_i64);
    let alive = snapshot
        .get("alive")
        .and_then(Value::as_bool)
        .unwrap_or_else(|| latency_ms.is_some());
    if alive { latency_ms } else { None }
}

fn latency_snapshot_group_network_type(snapshot: &Value) -> Option<NetworkType> {
    let raw = snapshot.get("networkType").and_then(Value::as_str)?;
    [NetworkType::TCP4, NetworkType::TCP6]
        .into_iter()
        .find(|network_type| network_type.string_without_dns() == raw)
}

pub(crate) fn run_resident_manual_latency_probe_helper(
    config: &Config,
    links: &[String],
    reload_generation: u64,
    concurrency: usize,
) -> Vec<Value> {
    let manual_probe_plans = plan::build_resident_manual_probe_plans_for_helper(config);
    probe_resident_manual_latency_snapshots(
        &manual_probe_plans,
        links,
        reload_generation,
        concurrency,
    )
}

pub(crate) fn run_resident_manual_latency_probe_helper_streaming<F>(
    config: &Config,
    links: &[String],
    reload_generation: u64,
    concurrency: usize,
    mut on_snapshot: F,
) -> Result<(), String>
where
    F: FnMut(Value) -> Result<(), String>,
{
    let manual_probe_plans = plan::build_resident_manual_probe_plans_for_helper(config);
    probe_resident_manual_latency_snapshots_streaming(
        &manual_probe_plans,
        links,
        reload_generation,
        concurrency,
        &mut on_snapshot,
    )
}

fn probe_resident_manual_latency_snapshots(
    manual_probe_plans: &BTreeMap<String, Result<plan::ResidentProxyProbePlan, String>>,
    links: &[String],
    reload_generation: u64,
    concurrency: usize,
) -> Vec<Value> {
    if links.is_empty() {
        return Vec::new();
    }
    let requested = links
        .iter()
        .filter(|link| !link.is_empty())
        .cloned()
        .collect::<HashSet<_>>();
    if requested.is_empty() {
        return Vec::new();
    }

    let checked_at = unix_now_secs();
    let mut snapshots = Vec::new();
    let mut tasks = Vec::new();
    for link in requested {
        match manual_probe_plans.get(&link) {
            Some(Ok(candidate)) => tasks.push(candidate.clone()),
            Some(Err(err)) => snapshots.push(manual_probe_unavailable_snapshot(
                &link,
                "native outbound probe not admitted for this node",
                err,
                checked_at,
                reload_generation,
            )),
            None => snapshots.push(manual_probe_unavailable_snapshot(
                &link,
                "node is not present in the current runtime config",
                "materialize/reload runtime before testing this node",
                checked_at,
                reload_generation,
            )),
        }
    }

    if tasks.is_empty() {
        return preferred_latency_snapshots(snapshots);
    }

    let runtime = match build_transient_probe_runtime("manual latency probe") {
        Ok(runtime) => runtime,
        Err(detail) => {
            snapshots.extend(tasks.into_iter().map(|candidate| {
                manual_probe_unavailable_snapshot(
                    &candidate.link,
                    "native outbound probe runtime unavailable",
                    &detail,
                    checked_at,
                    reload_generation,
                )
            }));
            return preferred_latency_snapshots(snapshots);
        }
    };

    let mut task_queue = std::collections::VecDeque::from(tasks);
    let mut task_snapshots = runtime.block_on(async {
        let mut values = Vec::new();
        let mut handles = tokio::task::JoinSet::new();
        fill_manual_probe_join_set(
            &mut handles,
            &mut task_queue,
            concurrency,
            reload_generation,
        );
        while let Some(result) = handles.join_next().await {
            if let Ok(value) = result {
                values.push(value);
            }
            fill_manual_probe_join_set(
                &mut handles,
                &mut task_queue,
                concurrency,
                reload_generation,
            );
        }
        values
    });
    snapshots.append(&mut task_snapshots);
    drop(runtime);
    preferred_latency_snapshots(snapshots)
}

fn probe_resident_manual_latency_snapshots_streaming<F>(
    manual_probe_plans: &BTreeMap<String, Result<plan::ResidentProxyProbePlan, String>>,
    links: &[String],
    reload_generation: u64,
    concurrency: usize,
    on_snapshot: &mut F,
) -> Result<(), String>
where
    F: FnMut(Value) -> Result<(), String>,
{
    if links.is_empty() {
        return Ok(());
    }
    let requested = links
        .iter()
        .filter(|link| !link.is_empty())
        .cloned()
        .collect::<HashSet<_>>();
    if requested.is_empty() {
        return Ok(());
    }

    let checked_at = unix_now_secs();
    let mut tasks = Vec::new();
    for link in requested {
        match manual_probe_plans.get(&link) {
            Some(Ok(candidate)) => tasks.push(candidate.clone()),
            Some(Err(err)) => on_snapshot(manual_probe_unavailable_snapshot(
                &link,
                "native outbound probe not admitted for this node",
                err,
                checked_at,
                reload_generation,
            ))?,
            None => on_snapshot(manual_probe_unavailable_snapshot(
                &link,
                "node is not present in the current runtime config",
                "materialize/reload runtime before testing this node",
                checked_at,
                reload_generation,
            ))?,
        }
    }

    if tasks.is_empty() {
        return Ok(());
    }

    let runtime = match build_transient_probe_runtime("manual latency probe") {
        Ok(runtime) => runtime,
        Err(detail) => {
            for candidate in tasks {
                on_snapshot(manual_probe_unavailable_snapshot(
                    &candidate.link,
                    "native outbound probe runtime unavailable",
                    &detail,
                    checked_at,
                    reload_generation,
                ))?;
            }
            return Ok(());
        }
    };

    let mut task_queue = std::collections::VecDeque::from(tasks);
    runtime.block_on(async {
        let mut handles = tokio::task::JoinSet::new();
        fill_manual_probe_join_set(
            &mut handles,
            &mut task_queue,
            concurrency,
            reload_generation,
        );
        while let Some(result) = handles.join_next().await {
            if let Ok(value) = result {
                on_snapshot(value)?;
            }
            fill_manual_probe_join_set(
                &mut handles,
                &mut task_queue,
                concurrency,
                reload_generation,
            );
        }
        Ok::<(), String>(())
    })?;
    drop(runtime);
    Ok(())
}

fn fill_manual_probe_join_set(
    handles: &mut tokio::task::JoinSet<Value>,
    task_queue: &mut std::collections::VecDeque<plan::ResidentProxyProbePlan>,
    concurrency: usize,
    reload_generation: u64,
) {
    let concurrency = concurrency.max(1);
    while handles.len() < concurrency {
        let Some(candidate) = task_queue.pop_front() else {
            break;
        };
        handles.spawn(async move {
            probe_resident_candidate_tcp_latency_snapshot(candidate, reload_generation).await
        });
    }
}

pub(crate) fn build_transient_probe_runtime(
    scope: &str,
) -> Result<tokio::runtime::Runtime, String> {
    tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(|err| format!("start Tokio {scope} runtime: {err}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resident_runtime_lifecycle_owner_reports_shutdown_evidence() {
        let metrics = Arc::new(ResidentDataplaneMetrics::default());
        metrics.tcp_opened();
        metrics.udp_opened();
        let udp_sessions_active = Arc::new(AtomicUsize::new(1));
        let config = Config {
            global: dae_config::Global::default(),
            subscription: Vec::new(),
            node: Vec::new(),
            group: Vec::new(),
            routing: dae_config::Routing::default(),
            dns: dae_config::Dns::default(),
        };
        let mut owner = ResidentRuntimeOwner::new(
            PathBuf::from("/tmp/resident-runtime-owner-test.jsonl"),
            Arc::new(Mutex::new(())),
            9,
            metrics,
            Arc::clone(&udp_sessions_active),
            ResidentRuntimeResourceConfig::from_config(&config),
        );
        owner.spawn_thread("test-worker", "runtime-lifecycle-test", || {});
        let registry = owner.task_registry_value();
        assert_eq!(registry["owner"], "resident-runtime-owner");
        assert_eq!(registry["runtimeHandle"]["owner"], "resident-runtime-owner");
        assert_eq!(registry["runtimeHandle"]["scope"], "manual-latency-probes");
        assert_eq!(registry["runtimeHandle"]["persistent"], false);

        let evidence = owner.shutdown();
        assert_eq!(evidence["owner"], "resident-runtime-owner");
        assert_eq!(evidence["reloadGeneration"], 9);
        assert_eq!(evidence["task_count_started"], 1);
        assert_eq!(evidence["task_count_joined"], 1);
        assert_eq!(evidence["task_count_timed_out"], 0);
        assert_eq!(evidence["task_count_aborted"], 0);
        assert_eq!(evidence["active_tcp_connections_at_shutdown"], 1);
        assert_eq!(evidence["active_udp_sessions_at_shutdown"], 1);
        assert_eq!(evidence["udp_sessions_active_at_shutdown"], 1);
        assert_eq!(evidence["runtime_handle_owner"], "resident-runtime-owner");
        assert_eq!(evidence["manual_probe_runtime_persistent"], false);
        assert_eq!(evidence["manual_probe_runtime_stopped"], true);
    }

    #[test]
    fn latency_snapshot_group_latency_ignores_failed_placeholder_latency() {
        let snapshot = json!({
            "latencyMs": 10000,
            "alive": false,
            "message": "TLS handshake failed unexpected EOF",
        });
        assert_eq!(latency_snapshot_group_latency_ms(&snapshot), None);
    }

    #[test]
    fn latency_snapshot_group_latency_keeps_alive_latency() {
        let snapshot = json!({
            "latencyMs": 37,
            "alive": true,
            "message": null,
        });
        assert_eq!(latency_snapshot_group_latency_ms(&snapshot), Some(37));
    }

    #[test]
    fn latency_snapshot_group_network_type_reads_snapshot_value() {
        let snapshot = json!({
            "networkType": NetworkType::TCP6.string_without_dns(),
        });
        assert_eq!(
            latency_snapshot_group_network_type(&snapshot),
            Some(NetworkType::TCP6)
        );
    }

    #[test]
    fn latency_snapshot_without_family_does_not_default_to_tcp4() {
        let snapshot = json!({});
        assert_eq!(latency_snapshot_group_network_type(&snapshot), None);
    }

    #[test]
    fn manual_latency_snapshots_update_groups_only_when_explicitly_applied() {
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
        group
            .record_check_result("node_a", NetworkType::TCP4, Some(40), 1)
            .unwrap();
        group
            .record_check_result("node_b", NetworkType::TCP4, Some(90), 2)
            .unwrap();
        assert_eq!(group.select_proxy_for_tcp().unwrap().node_tag, "node_a");

        let node_b_hash = group
            .probe_candidates()
            .into_iter()
            .find(|candidate| candidate.node_tag == "node_b")
            .unwrap()
            .link_hash;
        let snapshots = [json!({
            "linkHash": node_b_hash,
            "latencyMs": 20,
            "alive": true,
            "checkedAtUnix": 3,
            "networkType": NetworkType::TCP4.string_without_dns(),
        })];
        let handle = ResidentManualProbeHandle {
            groups: vec![Arc::clone(&group)],
            manual_probe_plans: plan::build_resident_manual_probe_plans(&config),
            reload_generation: 7,
            resource_config: ResidentRuntimeResourceConfig::from_config(&config),
        };

        assert_eq!(group.select_proxy_for_tcp().unwrap().node_tag, "node_a");
        handle.apply_latency_probe_snapshots_to_groups(&snapshots);
        assert_eq!(group.select_proxy_for_tcp().unwrap().node_tag, "node_b");
    }

    fn parse_test_config(input: &str) -> Config {
        let sections = dae_config::parser::parse_config(input).unwrap();
        dae_config::schema::build_config(&sections).unwrap()
    }
}
