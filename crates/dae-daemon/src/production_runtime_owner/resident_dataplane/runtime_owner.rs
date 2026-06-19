use super::*;

pub(crate) struct ResidentRuntimeOwner {
    stop: Arc<AtomicBool>,
    tasks: Vec<ResidentRuntimeTask>,
    event_file: PathBuf,
    event_lock: Arc<Mutex<()>>,
    reload_generation: u64,
    metrics: Arc<ResidentDataplaneMetrics>,
    udp_sessions_active: Arc<AtomicUsize>,
    resource_config: ResidentRuntimeResourceConfig,
    event_writer: ResidentEventWriterRuntime,
    manual_probe_runtime: Arc<Mutex<Option<tokio::runtime::Runtime>>>,
    manual_probe_runtime_error: Option<String>,
}

#[derive(Clone)]
pub(crate) struct ResidentManualProbeHandle {
    groups: Vec<Arc<plan::ResidentProxyGroupPlan>>,
    manual_probe_plans: BTreeMap<String, Result<plan::ResidentProxyProbePlan, String>>,
    manual_probe_runtime: Arc<Mutex<Option<tokio::runtime::Runtime>>>,
    manual_probe_runtime_error: Option<String>,
    reload_generation: u64,
    resource_config: ResidentRuntimeResourceConfig,
}

#[derive(Debug)]
struct ResidentRuntimeTask {
    name: &'static str,
    kind: &'static str,
    handle: JoinHandle<()>,
}

impl std::fmt::Debug for ResidentRuntimeOwner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResidentRuntimeOwner")
            .field("task_count", &self.tasks.len())
            .field("event_file_status", &"disabled")
            .field("reload_generation", &self.reload_generation)
            .field("resource_config", &self.resource_config.json())
            .field(
                "manual_probe_runtime_available",
                &self.manual_probe_runtime_error.is_none(),
            )
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
        let (manual_probe_runtime, manual_probe_runtime_error) =
            match tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .enable_time()
                .build()
            {
                Ok(runtime) => (Some(runtime), None),
                Err(err) => (
                    None,
                    Some(format!("start Tokio manual latency probe runtime: {err}")),
                ),
            };
        Self {
            stop: Arc::new(AtomicBool::new(false)),
            tasks: Vec::new(),
            event_file,
            event_lock,
            reload_generation,
            metrics,
            udp_sessions_active,
            resource_config,
            event_writer,
            manual_probe_runtime: Arc::new(Mutex::new(manual_probe_runtime)),
            manual_probe_runtime_error,
        }
    }

    pub(crate) fn stop_handle(&self) -> Arc<AtomicBool> {
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
            manual_probe_runtime: Arc::clone(&self.manual_probe_runtime),
            manual_probe_runtime_error: self.manual_probe_runtime_error.clone(),
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
        self.tasks.push(ResidentRuntimeTask { name, kind, handle });
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
                    "joinPolicy": "join-on-owner-shutdown",
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
        let started = Instant::now();
        self.stop.store(true, Ordering::Relaxed);
        let task_count_started = self.tasks.len();
        let mut task_count_joined = 0_usize;
        let mut task_count_panicked = 0_usize;
        let mut task_results = Vec::with_capacity(task_count_started);

        for task in self.tasks.drain(..) {
            let ResidentRuntimeTask { name, kind, handle } = task;
            match handle.join() {
                Ok(()) => {
                    task_count_joined += 1;
                    task_results.push(json!({
                        "name": name,
                        "kind": kind,
                        "status": "joined",
                    }));
                }
                Err(_) => {
                    task_count_panicked += 1;
                    task_results.push(json!({
                        "name": name,
                        "kind": kind,
                        "status": "panicked",
                    }));
                }
            }
        }

        let metrics = self.metrics.snapshot();
        let active_tcp = metrics["activeTcpConnections"].as_u64().unwrap_or(0);
        let active_udp = metrics["activeUdpSessions"].as_u64().unwrap_or(0);
        let legacy_udp_active = self.udp_sessions_active.load(Ordering::Relaxed);
        let manual_probe_runtime_stopped = match self.manual_probe_runtime.lock() {
            Ok(mut runtime) => runtime.take().is_some(),
            Err(poisoned) => poisoned.into_inner().take().is_some(),
        };
        let event_writer = self.event_writer.shutdown();
        let shutdown_elapsed_ns = started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64;
        json!({
            "name": "stop-resident-dataplane-runtime",
            "status": if task_count_panicked == 0 && event_writer["status"].as_str() == Some("pass") { "pass" } else { "fail" },
            "owner": "resident-runtime-owner",
            "reload_generation": self.reload_generation,
            "reloadGeneration": self.reload_generation,
            "task_count_started": task_count_started,
            "task_count_joined": task_count_joined,
            "task_count_timed_out": 0,
            "task_count_aborted": 0,
            "task_count_panicked": task_count_panicked,
            "joined_worker_threads": task_count_joined,
            "panicked_worker_threads": task_count_panicked,
            "active_tcp_connections_at_shutdown": active_tcp,
            "active_udp_sessions_at_shutdown": active_udp,
            "udp_sessions_active_at_shutdown": legacy_udp_active,
            "runtime_handle_owner": "resident-runtime-owner",
            "manual_probe_runtime_available": self.manual_probe_runtime_error.is_none(),
            "manual_probe_runtime_stopped": manual_probe_runtime_stopped,
            "event_writer": event_writer,
            "shutdown_elapsed_ns": shutdown_elapsed_ns,
            "event_file": Value::Null,
            "event_file_status": "disabled",
            "event_log": "product-log-sink",
            "tasks": task_results,
        })
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
            "executor": "tokio-current-thread",
            "scope": "manual-latency-probes",
            "available": self.manual_probe_runtime_error.is_none(),
            "error": self.manual_probe_runtime_error.as_deref(),
        })
    }
}

impl ResidentManualProbeHandle {
    pub(crate) fn probe_concurrency(&self) -> usize {
        self.resource_config.manual_probe_concurrency.value()
    }

    pub(crate) fn probe_node_latencies(&self, links: &[String]) -> Vec<Value> {
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
        let reload_generation = self.reload_generation;
        let mut snapshots = Vec::new();
        let mut tasks = Vec::new();
        for link in requested {
            match self.manual_probe_plans.get(&link) {
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

        let runtime_guard = match self.manual_probe_runtime.lock() {
            Ok(guard) => guard,
            Err(_) => {
                snapshots.extend(tasks.into_iter().map(|candidate| {
                    manual_probe_unavailable_snapshot(
                        &candidate.link,
                        "native outbound probe runtime unavailable",
                        "manual latency probe runtime lock poisoned",
                        checked_at,
                        reload_generation,
                    )
                }));
                return preferred_latency_snapshots(snapshots);
            }
        };
        let Some(runtime) = runtime_guard.as_ref() else {
            let detail = self
                .manual_probe_runtime_error
                .as_deref()
                .unwrap_or("manual latency probe runtime unavailable");
            snapshots.extend(tasks.into_iter().map(|candidate| {
                manual_probe_unavailable_snapshot(
                    &candidate.link,
                    "native outbound probe runtime unavailable",
                    detail,
                    checked_at,
                    reload_generation,
                )
            }));
            return preferred_latency_snapshots(snapshots);
        };

        let concurrency = self.resource_config.manual_probe_concurrency.value();
        for chunk in tasks.chunks(concurrency) {
            let groups = self.groups.clone();
            let mut chunk_snapshots = runtime.block_on(async {
                let mut handles = Vec::new();
                for candidate in chunk.iter().cloned() {
                    let groups = groups.clone();
                    handles.push(tokio::spawn(async move {
                        probe_resident_candidate_tcp_latency_snapshot(
                            groups,
                            candidate,
                            reload_generation,
                        )
                        .await
                    }));
                }
                let mut values = Vec::new();
                for handle in handles {
                    if let Ok(value) = handle.await {
                        values.push(value);
                    }
                }
                values
            });
            snapshots.append(&mut chunk_snapshots);
        }
        preferred_latency_snapshots(snapshots)
    }
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
        owner.register_thread(
            "test-worker",
            "runtime-lifecycle-test",
            thread::spawn(|| {}),
        );
        let registry = owner.task_registry_value();
        assert_eq!(registry["owner"], "resident-runtime-owner");
        assert_eq!(registry["runtimeHandle"]["owner"], "resident-runtime-owner");
        assert_eq!(registry["runtimeHandle"]["scope"], "manual-latency-probes");

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
        assert_eq!(evidence["manual_probe_runtime_stopped"], true);
    }
}
