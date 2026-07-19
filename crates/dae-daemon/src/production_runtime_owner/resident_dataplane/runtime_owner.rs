use super::*;

mod cleanup_inventory;
mod manual_probe_index;
mod shutdown;
mod task;

use self::cleanup_inventory::*;
pub(crate) use self::manual_probe_index::ResidentManualProbeIndex;
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
    udp_payload_admission: ResidentUdpPayloadAdmission,
    resource_config: ResidentRuntimeResourceConfig,
    event_writer: ResidentEventWriterRuntime,
    cleanup_inventory: ResidentRuntimeCleanupInventory,
    hysteria2_owner_registry: Option<Hysteria2OwnerRegistryHandle>,
    tuic_owner_registry: Option<TuicOwnerRegistryHandle>,
    juicity_owner_registry: Option<JuicityOwnerRegistryHandle>,
    anytls_owner_registry: Option<AnyTlsOwnerRegistryHandle>,
    h2_carrier_generation_owner: Option<H2CarrierGenerationOwnerHandle>,
    meek_transport_generation_owner: Option<MeekTransportGenerationOwnerHandle>,
    vless_mux_generation_owner: Option<VlessMuxGenerationOwnerHandle>,
    xhttp_xmux_generation_owner: Option<tcp::XhttpXmuxGenerationOwnerHandle>,
    xhttp_xmux_owner_thread: Option<JoinHandle<()>>,
}

#[derive(Clone)]
pub(crate) struct ResidentManualProbeHandle {
    groups: Vec<Arc<plan::ResidentProxyGroupPlan>>,
    manual_probe_index: Arc<ResidentManualProbeIndex>,
    reload_generation: u64,
    resource_config: ResidentRuntimeResourceConfig,
    hysteria2_owner_registry: Option<Hysteria2OwnerRegistryHandle>,
    tuic_owner_registry: Option<TuicOwnerRegistryHandle>,
    juicity_owner_registry: Option<JuicityOwnerRegistryHandle>,
    anytls_owner_registry: Option<AnyTlsOwnerRegistryHandle>,
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
        udp_payload_admission: ResidentUdpPayloadAdmission,
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
            udp_payload_admission,
            resource_config,
            event_writer,
            cleanup_inventory: ResidentRuntimeCleanupInventory::default(),
            hysteria2_owner_registry: None,
            tuic_owner_registry: None,
            juicity_owner_registry: None,
            anytls_owner_registry: None,
            h2_carrier_generation_owner: None,
            meek_transport_generation_owner: None,
            vless_mux_generation_owner: None,
            xhttp_xmux_generation_owner: None,
            xhttp_xmux_owner_thread: None,
        }
    }

    pub(crate) fn install_hysteria2_owner_registry(
        &mut self,
        handle: Hysteria2OwnerRegistryHandle,
        thread: JoinHandle<()>,
    ) {
        self.hysteria2_owner_registry = Some(handle);
        self.register_thread(
            "hysteria2-owner-registry",
            "protocol-transport-owner",
            thread,
        );
    }

    pub(crate) fn hysteria2_owner_registry(&self) -> Option<Hysteria2OwnerRegistryHandle> {
        self.hysteria2_owner_registry.clone()
    }

    pub(crate) fn install_tuic_owner_registry(
        &mut self,
        handle: TuicOwnerRegistryHandle,
        thread: JoinHandle<()>,
    ) {
        self.tuic_owner_registry = Some(handle);
        self.register_thread("tuic-owner-registry", "protocol-transport-owner", thread);
    }

    pub(crate) fn tuic_owner_registry(&self) -> Option<TuicOwnerRegistryHandle> {
        self.tuic_owner_registry.clone()
    }

    pub(crate) fn install_juicity_owner_registry(
        &mut self,
        handle: JuicityOwnerRegistryHandle,
        thread: JoinHandle<()>,
    ) {
        self.juicity_owner_registry = Some(handle);
        self.register_thread("juicity-owner-registry", "protocol-transport-owner", thread);
    }

    pub(crate) fn juicity_owner_registry(&self) -> Option<JuicityOwnerRegistryHandle> {
        self.juicity_owner_registry.clone()
    }

    pub(crate) fn install_anytls_owner_registry(
        &mut self,
        handle: AnyTlsOwnerRegistryHandle,
        thread: JoinHandle<()>,
    ) {
        self.anytls_owner_registry = Some(handle);
        self.register_thread("anytls-owner-registry", "protocol-transport-owner", thread);
    }

    pub(crate) fn anytls_owner_registry(&self) -> Option<AnyTlsOwnerRegistryHandle> {
        self.anytls_owner_registry.clone()
    }

    pub(crate) fn install_h2_carrier_generation_owner(
        &mut self,
        handle: H2CarrierGenerationOwnerHandle,
        thread: JoinHandle<()>,
    ) {
        self.h2_carrier_generation_owner = Some(handle);
        self.register_thread("h2-carrier-owner", "protocol-transport-owner", thread);
    }

    pub(crate) fn install_meek_transport_generation_owner(
        &mut self,
        handle: MeekTransportGenerationOwnerHandle,
        thread: JoinHandle<()>,
    ) {
        self.meek_transport_generation_owner = Some(handle);
        self.register_thread("meek-transport-owner", "protocol-transport-owner", thread);
    }

    pub(crate) fn install_vless_mux_generation_owner(
        &mut self,
        handle: VlessMuxGenerationOwnerHandle,
        thread: JoinHandle<()>,
    ) {
        self.vless_mux_generation_owner = Some(handle);
        self.register_thread("vless-mux-owner", "protocol-transport-owner", thread);
    }

    pub(crate) fn install_xhttp_xmux_generation_owner(
        &mut self,
        handle: tcp::XhttpXmuxGenerationOwnerHandle,
        thread: JoinHandle<()>,
    ) {
        self.xhttp_xmux_generation_owner = Some(handle);
        self.xhttp_xmux_owner_thread = Some(thread);
    }

    pub(crate) fn shutdown_xhttp_xmux_generation_owner(
        &mut self,
    ) -> Option<tcp::XhttpXmuxClearReport> {
        let handle = self.xhttp_xmux_generation_owner.take()?;
        let thread = self.xhttp_xmux_owner_thread.take()?;
        Some(tcp::shutdown_xhttp_xmux_generation_owner(
            &handle,
            thread,
            RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE,
        ))
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

    pub(crate) fn cleanup_reporter(&self, owner: &'static str) -> ResidentRuntimeCleanupReporter {
        self.cleanup_inventory.reporter(owner)
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
        manual_probe_index: &Arc<ResidentManualProbeIndex>,
    ) -> ResidentManualProbeHandle {
        ResidentManualProbeHandle {
            groups: groups.to_vec(),
            manual_probe_index: Arc::clone(manual_probe_index),
            reload_generation: self.reload_generation,
            resource_config: self.resource_config.clone(),
            hysteria2_owner_registry: self.hysteria2_owner_registry.clone(),
            tuic_owner_registry: self.tuic_owner_registry.clone(),
            juicity_owner_registry: self.juicity_owner_registry.clone(),
            anytls_owner_registry: self.anytls_owner_registry.clone(),
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
            "hysteria2Owners": self.hysteria2_owner_registry.as_ref().map(Hysteria2OwnerRegistryHandle::metrics_snapshot),
            "tuicOwners": self.tuic_owner_registry.as_ref().map(TuicOwnerRegistryHandle::metrics_snapshot),
            "juicityOwners": self.juicity_owner_registry.as_ref().map(JuicityOwnerRegistryHandle::metrics_snapshot),
            "anytlsOwners": self.anytls_owner_registry.as_ref().map(AnyTlsOwnerRegistryHandle::metrics_snapshot),
            "h2CarrierOwners": self.h2_carrier_generation_owner.as_ref().map(H2CarrierGenerationOwnerHandle::metrics_snapshot),
            "meekTransportOwners": self.meek_transport_generation_owner.as_ref().map(MeekTransportGenerationOwnerHandle::metrics_snapshot),
            "vlessMuxOwners": self.vless_mux_generation_owner.as_ref().map(VlessMuxGenerationOwnerHandle::metrics_snapshot),
            "xhttpXmuxOwner": self.xhttp_xmux_generation_owner.as_ref().map(tcp::XhttpXmuxGenerationOwnerHandle::metrics_snapshot),
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
        snapshot["connectUdpPools"] =
            udp::connect_udp_pool_metrics_snapshot(self.reload_generation);
        snapshot["quicEndpoints"] = tcp::quic_endpoint_metrics_snapshot(self.reload_generation);
        snapshot["hysteria2Owners"] = self
            .hysteria2_owner_registry
            .as_ref()
            .map(Hysteria2OwnerRegistryHandle::metrics_snapshot)
            .unwrap_or(Value::Null);
        snapshot["tuicOwners"] = self
            .tuic_owner_registry
            .as_ref()
            .map(TuicOwnerRegistryHandle::metrics_snapshot)
            .unwrap_or(Value::Null);
        snapshot["juicityOwners"] = self
            .juicity_owner_registry
            .as_ref()
            .map(JuicityOwnerRegistryHandle::metrics_snapshot)
            .unwrap_or(Value::Null);
        snapshot["anytlsOwners"] = self
            .anytls_owner_registry
            .as_ref()
            .map(AnyTlsOwnerRegistryHandle::metrics_snapshot)
            .unwrap_or(Value::Null);
        snapshot["h2CarrierOwners"] = self
            .h2_carrier_generation_owner
            .as_ref()
            .map(H2CarrierGenerationOwnerHandle::metrics_snapshot)
            .unwrap_or(Value::Null);
        snapshot["meekTransportOwners"] = self
            .meek_transport_generation_owner
            .as_ref()
            .map(MeekTransportGenerationOwnerHandle::metrics_snapshot)
            .unwrap_or(Value::Null);
        snapshot["vlessMuxOwners"] = self
            .vless_mux_generation_owner
            .as_ref()
            .map(VlessMuxGenerationOwnerHandle::metrics_snapshot)
            .unwrap_or(Value::Null);
        snapshot["xhttpXmuxOwner"] = self
            .xhttp_xmux_generation_owner
            .as_ref()
            .map(tcp::XhttpXmuxGenerationOwnerHandle::metrics_snapshot)
            .unwrap_or(Value::Null);
        snapshot
    }

    pub(crate) fn prune_event_log(&self) -> std::io::Result<()> {
        self.event_writer.prune()
    }

    pub(crate) fn clear_event_log(&self) -> std::io::Result<()> {
        self.event_writer.clear()
    }

    pub(crate) fn shutdown(&mut self) -> Value {
        let xhttp_xmux = self.shutdown_xhttp_xmux_generation_owner();
        let xhttp_xmux_released = xhttp_xmux.as_ref().is_none_or(|report| {
            !report.cleanup_timed_out
                && report.owner_thread_joined
                && report.h2.locked_managers == 0
                && report.h3.locked_managers == 0
        });
        let mut shutdown = shutdown_resident_runtime_owner(self, RESIDENT_RUNTIME_TASK_JOIN_GRACE);
        shutdown["xhttpXmuxOwnerCleanup"] = xhttp_xmux
            .map(|report| {
                json!({
                    "status": if xhttp_xmux_released { "pass" } else { "fail" },
                    "cleanupTimedOut": report.cleanup_timed_out,
                    "ownerThreadJoined": report.owner_thread_joined,
                    "h2": {
                        "managers": report.h2.managers,
                        "clients": report.h2.clients,
                        "lockedManagers": report.h2.locked_managers,
                    },
                    "h3": {
                        "managers": report.h3.managers,
                        "clients": report.h3.clients,
                        "lockedManagers": report.h3.locked_managers,
                    },
                })
            })
            .unwrap_or(Value::Null);
        if !xhttp_xmux_released {
            shutdown["status"] = json!("fail");
        }
        shutdown
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
            "hysteria2Owners": self.hysteria2_owner_registry.as_ref().map(Hysteria2OwnerRegistryHandle::metrics_snapshot),
            "tuicOwners": self.tuic_owner_registry.as_ref().map(TuicOwnerRegistryHandle::metrics_snapshot),
            "juicityOwners": self.juicity_owner_registry.as_ref().map(JuicityOwnerRegistryHandle::metrics_snapshot),
            "anytlsOwners": self.anytls_owner_registry.as_ref().map(AnyTlsOwnerRegistryHandle::metrics_snapshot),
            "h2CarrierOwners": self.h2_carrier_generation_owner.as_ref().map(H2CarrierGenerationOwnerHandle::metrics_snapshot),
            "meekTransportOwners": self.meek_transport_generation_owner.as_ref().map(MeekTransportGenerationOwnerHandle::metrics_snapshot),
            "vlessMuxOwners": self.vless_mux_generation_owner.as_ref().map(VlessMuxGenerationOwnerHandle::metrics_snapshot),
            "xhttpXmuxOwner": self.xhttp_xmux_generation_owner.as_ref().map(tcp::XhttpXmuxGenerationOwnerHandle::metrics_snapshot),
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
            self.manual_probe_index.plans(),
            links,
            self.reload_generation,
            self.probe_concurrency(),
            ResidentTransportOwnerRegistries::new(
                self.hysteria2_owner_registry.clone(),
                self.tuic_owner_registry.clone(),
                self.juicity_owner_registry.clone(),
            )
            .with_anytls(self.anytls_owner_registry.clone()),
        )
    }

    pub(crate) fn apply_latency_probe_snapshots_to_groups(&self, snapshots: &[Value]) {
        if self.groups.is_empty() || snapshots.is_empty() {
            return;
        }
        for snapshot in snapshots {
            if snapshot.get("admission").is_some() {
                continue;
            }
            if snapshot
                .get("reloadGeneration")
                .and_then(Value::as_u64)
                .is_some_and(|generation| generation != self.reload_generation)
            {
                continue;
            }
            let Some(link_hash) = latency_snapshot_link_hash(snapshot) else {
                continue;
            };
            let Some(links) = self.manual_probe_index.links_for_hash(link_hash) else {
                continue;
            };
            let checked_at = snapshot
                .get("checkedAtUnix")
                .and_then(Value::as_i64)
                .unwrap_or_else(unix_now_secs);
            if let Some(family_results) = snapshot.get("familyResults").and_then(Value::as_array) {
                for family_result in family_results {
                    let Some(network_type) = health_snapshot_network_type(family_result) else {
                        continue;
                    };
                    let Some(health_state) = family_result
                        .get("healthState")
                        .and_then(Value::as_str)
                        .and_then(dae_outbound::HealthState::parse)
                    else {
                        continue;
                    };
                    let latency_ms = family_result.get("latencyMs").and_then(Value::as_i64);
                    for link in links {
                        for group in &self.groups {
                            let _ = group.record_manual_health_state_for_link(
                                link,
                                network_type,
                                health_state,
                                latency_ms,
                                checked_at,
                            );
                        }
                    }
                }
                continue;
            }
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
    health_snapshot_network_type(snapshot)
}

fn health_snapshot_network_type(snapshot: &Value) -> Option<NetworkType> {
    if let Some(dimension) = snapshot.get("networkDimension").and_then(Value::as_str) {
        return NetworkType::from_dimension_name(dimension);
    }
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
    let mut manual_probe_plans = plan::build_resident_manual_probe_plans_for_helper(config, links);
    apply_manual_probe_runtime_generation(&mut manual_probe_plans, reload_generation);
    let requires_tuic_owner = manual_probe_plans
        .values()
        .filter_map(|probe| probe.as_ref().ok())
        .any(plan::ResidentProxyProbePlan::requires_tuic_transport_owner);
    let requires_juicity_owner = manual_probe_plans
        .values()
        .filter_map(|probe| probe.as_ref().ok())
        .any(plan::ResidentProxyProbePlan::requires_juicity_transport_owner);
    let requires_anytls_owner = manual_probe_plans
        .values()
        .filter_map(|probe| probe.as_ref().ok())
        .any(plan::ResidentProxyProbePlan::requires_anytls_transport_owner);
    let requires_h2_carrier_owner = manual_probe_plans
        .values()
        .filter_map(|probe| probe.as_ref().ok())
        .any(plan::ResidentProxyProbePlan::requires_h2_carrier_owner);
    let requires_meek_transport_owner = manual_probe_plans
        .values()
        .filter_map(|probe| probe.as_ref().ok())
        .any(plan::ResidentProxyProbePlan::requires_meek_transport_owner);
    let requires_vless_mux_owner = manual_probe_plans
        .values()
        .filter_map(|probe| probe.as_ref().ok())
        .any(plan::ResidentProxyProbePlan::requires_vless_mux_owner);
    let owner_scope = ManualProbeTransportOwnerScope::start(
        config,
        reload_generation,
        ManualProbeOwnerRequirements {
            tuic: requires_tuic_owner,
            juicity: requires_juicity_owner,
            anytls: requires_anytls_owner,
            h2_carrier: requires_h2_carrier_owner,
            meek: requires_meek_transport_owner,
            vless_mux: requires_vless_mux_owner,
        },
    )
    .ok();
    let snapshots = probe_resident_manual_latency_snapshots(
        &manual_probe_plans,
        links,
        reload_generation,
        concurrency,
        ResidentTransportOwnerRegistries::new(
            owner_scope
                .as_ref()
                .map(|scope| scope.hysteria2_handle.clone()),
            owner_scope
                .as_ref()
                .and_then(|scope| scope.tuic_handle.clone()),
            owner_scope
                .as_ref()
                .and_then(|scope| scope.juicity_handle.clone()),
        )
        .with_anytls(
            owner_scope
                .as_ref()
                .and_then(|scope| scope.anytls_handle.clone()),
        ),
    );
    drop(owner_scope);
    snapshots
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
    let mut manual_probe_plans = plan::build_resident_manual_probe_plans_for_helper(config, links);
    apply_manual_probe_runtime_generation(&mut manual_probe_plans, reload_generation);
    let requires_tuic_owner = manual_probe_plans
        .values()
        .filter_map(|probe| probe.as_ref().ok())
        .any(plan::ResidentProxyProbePlan::requires_tuic_transport_owner);
    let requires_juicity_owner = manual_probe_plans
        .values()
        .filter_map(|probe| probe.as_ref().ok())
        .any(plan::ResidentProxyProbePlan::requires_juicity_transport_owner);
    let requires_anytls_owner = manual_probe_plans
        .values()
        .filter_map(|probe| probe.as_ref().ok())
        .any(plan::ResidentProxyProbePlan::requires_anytls_transport_owner);
    let requires_h2_carrier_owner = manual_probe_plans
        .values()
        .filter_map(|probe| probe.as_ref().ok())
        .any(plan::ResidentProxyProbePlan::requires_h2_carrier_owner);
    let requires_meek_transport_owner = manual_probe_plans
        .values()
        .filter_map(|probe| probe.as_ref().ok())
        .any(plan::ResidentProxyProbePlan::requires_meek_transport_owner);
    let requires_vless_mux_owner = manual_probe_plans
        .values()
        .filter_map(|probe| probe.as_ref().ok())
        .any(plan::ResidentProxyProbePlan::requires_vless_mux_owner);
    let owner_scope = ManualProbeTransportOwnerScope::start(
        config,
        reload_generation,
        ManualProbeOwnerRequirements {
            tuic: requires_tuic_owner,
            juicity: requires_juicity_owner,
            anytls: requires_anytls_owner,
            h2_carrier: requires_h2_carrier_owner,
            meek: requires_meek_transport_owner,
            vless_mux: requires_vless_mux_owner,
        },
    )
    .ok();
    let result = probe_resident_manual_latency_snapshots_streaming(
        &manual_probe_plans,
        links,
        reload_generation,
        concurrency,
        ResidentTransportOwnerRegistries::new(
            owner_scope
                .as_ref()
                .map(|scope| scope.hysteria2_handle.clone()),
            owner_scope
                .as_ref()
                .and_then(|scope| scope.tuic_handle.clone()),
            owner_scope
                .as_ref()
                .and_then(|scope| scope.juicity_handle.clone()),
        )
        .with_anytls(
            owner_scope
                .as_ref()
                .and_then(|scope| scope.anytls_handle.clone()),
        ),
        &mut on_snapshot,
    );
    drop(owner_scope);
    result
}

fn apply_manual_probe_runtime_generation(
    plans: &mut BTreeMap<String, Result<plan::ResidentProxyProbePlan, String>>,
    reload_generation: u64,
) {
    for probe in plans.values_mut().filter_map(|probe| probe.as_mut().ok()) {
        probe.apply_runtime_generation(reload_generation);
    }
}

struct ManualProbeTransportOwnerScope {
    hysteria2_handle: Hysteria2OwnerRegistryHandle,
    tuic_handle: Option<TuicOwnerRegistryHandle>,
    juicity_handle: Option<JuicityOwnerRegistryHandle>,
    anytls_handle: Option<AnyTlsOwnerRegistryHandle>,
    h2_carrier_handle: Option<H2CarrierGenerationOwnerHandle>,
    meek_transport_handle: Option<MeekTransportGenerationOwnerHandle>,
    vless_mux_handle: Option<VlessMuxGenerationOwnerHandle>,
    stop: SharedResidentStopSignal,
    hysteria2_thread: Option<JoinHandle<()>>,
    tuic_thread: Option<JoinHandle<()>>,
    juicity_thread: Option<JoinHandle<()>>,
    anytls_thread: Option<JoinHandle<()>>,
    h2_carrier_thread: Option<JoinHandle<()>>,
    meek_transport_thread: Option<JoinHandle<()>>,
    vless_mux_thread: Option<JoinHandle<()>>,
}

#[derive(Clone, Copy)]
struct ManualProbeOwnerRequirements {
    tuic: bool,
    juicity: bool,
    anytls: bool,
    h2_carrier: bool,
    meek: bool,
    vless_mux: bool,
}

impl ManualProbeTransportOwnerScope {
    fn start(
        config: &Config,
        reload_generation: u64,
        required: ManualProbeOwnerRequirements,
    ) -> Result<Self, String> {
        let resources = ResidentRuntimeResourceConfig::from_config(config);
        let stop = ResidentStopSignal::shared();
        let (handle, thread) = start_hysteria2_owner_registry(
            reload_generation,
            Arc::clone(&stop),
            resources.tcp_flow_stack_bytes.value(),
        )?;
        let (tuic_handle, tuic_thread) = if required.tuic {
            match start_tuic_owner_registry(
                reload_generation,
                Arc::clone(&stop),
                resources.tcp_flow_stack_bytes.value(),
            ) {
                Ok((handle, thread)) => (Some(handle), Some(thread)),
                Err(err) => {
                    stop.store(true, Ordering::Release);
                    let _ = thread.join();
                    return Err(err);
                }
            }
        } else {
            (None, None)
        };
        let (juicity_handle, juicity_thread) = if required.juicity {
            match start_juicity_owner_registry(
                reload_generation,
                Arc::clone(&stop),
                resources.tcp_flow_stack_bytes.value(),
            ) {
                Ok((handle, thread)) => (Some(handle), Some(thread)),
                Err(err) => {
                    stop.store(true, Ordering::Release);
                    if let Some(thread) = tuic_thread {
                        let _ = thread.join();
                    }
                    let _ = thread.join();
                    return Err(err);
                }
            }
        } else {
            (None, None)
        };
        let (anytls_handle, anytls_thread) = if required.anytls {
            match start_anytls_owner_registry(
                reload_generation,
                Arc::clone(&stop),
                resources.tcp_flow_stack_bytes.value(),
            ) {
                Ok((handle, thread)) => (Some(handle), Some(thread)),
                Err(err) => {
                    stop.store(true, Ordering::Release);
                    if let Some(thread) = tuic_thread {
                        let _ = thread.join();
                    }
                    if let Some(thread) = juicity_thread {
                        let _ = thread.join();
                    }
                    let _ = thread.join();
                    return Err(err);
                }
            }
        } else {
            (None, None)
        };
        let (h2_carrier_handle, h2_carrier_thread) = if required.h2_carrier {
            match start_h2_carrier_generation_owner(
                reload_generation,
                Arc::clone(&stop),
                resources.tcp_flow_stack_bytes.value(),
                resources.tcp_runtime_workers.value(),
            ) {
                Ok((handle, thread)) => (Some(handle), Some(thread)),
                Err(err) => {
                    stop.store(true, Ordering::Release);
                    if let Some(thread) = tuic_thread {
                        let _ = thread.join();
                    }
                    if let Some(thread) = juicity_thread {
                        let _ = thread.join();
                    }
                    if let Some(thread) = anytls_thread {
                        let _ = thread.join();
                    }
                    let _ = thread.join();
                    return Err(err);
                }
            }
        } else {
            (None, None)
        };
        let (meek_transport_handle, meek_transport_thread) = if required.meek {
            match start_meek_transport_generation_owner(
                reload_generation,
                Arc::clone(&stop),
                resources.tcp_flow_stack_bytes.value(),
                resources.tcp_runtime_workers.value(),
            ) {
                Ok((handle, thread)) => (Some(handle), Some(thread)),
                Err(err) => {
                    stop.store(true, Ordering::Release);
                    if let Some(thread) = tuic_thread {
                        let _ = thread.join();
                    }
                    if let Some(thread) = juicity_thread {
                        let _ = thread.join();
                    }
                    if let Some(thread) = anytls_thread {
                        let _ = thread.join();
                    }
                    if let Some(thread) = h2_carrier_thread {
                        let _ = thread.join();
                    }
                    let _ = thread.join();
                    return Err(err);
                }
            }
        } else {
            (None, None)
        };
        let (vless_mux_handle, vless_mux_thread) = if required.vless_mux {
            match start_vless_mux_generation_owner(
                reload_generation,
                Arc::clone(&stop),
                resources.tcp_flow_stack_bytes.value(),
                resources.tcp_runtime_workers.value(),
            ) {
                Ok((handle, thread)) => (Some(handle), Some(thread)),
                Err(err) => {
                    stop.store(true, Ordering::Release);
                    if let Some(thread) = tuic_thread {
                        let _ = thread.join();
                    }
                    if let Some(thread) = juicity_thread {
                        let _ = thread.join();
                    }
                    if let Some(thread) = anytls_thread {
                        let _ = thread.join();
                    }
                    if let Some(thread) = h2_carrier_thread {
                        let _ = thread.join();
                    }
                    if let Some(thread) = meek_transport_thread {
                        let _ = thread.join();
                    }
                    let _ = thread.join();
                    return Err(err);
                }
            }
        } else {
            (None, None)
        };
        Ok(Self {
            hysteria2_handle: handle,
            tuic_handle,
            juicity_handle,
            anytls_handle,
            h2_carrier_handle,
            meek_transport_handle,
            vless_mux_handle,
            stop,
            hysteria2_thread: Some(thread),
            tuic_thread,
            juicity_thread,
            anytls_thread,
            h2_carrier_thread,
            meek_transport_thread,
            vless_mux_thread,
        })
    }
}

impl Drop for ManualProbeTransportOwnerScope {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.hysteria2_thread.take() {
            let _ = thread.join();
        }
        if let Some(thread) = self.tuic_thread.take() {
            let _ = thread.join();
        }
        if let Some(thread) = self.juicity_thread.take() {
            let _ = thread.join();
        }
        if let Some(thread) = self.anytls_thread.take() {
            let _ = thread.join();
        }
        if let Some(thread) = self.h2_carrier_thread.take() {
            let _ = thread.join();
        }
        if let Some(thread) = self.meek_transport_thread.take() {
            let _ = thread.join();
        }
        if let Some(thread) = self.vless_mux_thread.take() {
            let _ = thread.join();
        }
        self.h2_carrier_handle = None;
        self.meek_transport_handle = None;
        self.vless_mux_handle = None;
    }
}

fn probe_resident_manual_latency_snapshots(
    manual_probe_plans: &BTreeMap<String, Result<plan::ResidentProxyProbePlan, String>>,
    links: &[String],
    reload_generation: u64,
    concurrency: usize,
    owners: ResidentTransportOwnerRegistries,
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
            owners.clone(),
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
                owners.clone(),
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
    owners: ResidentTransportOwnerRegistries,
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
            owners.clone(),
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
                owners.clone(),
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
    owners: ResidentTransportOwnerRegistries,
) {
    let concurrency = concurrency.max(1);
    while handles.len() < concurrency {
        let Some(candidate) = task_queue.pop_front() else {
            break;
        };
        let owners = owners.clone();
        handles.spawn(async move {
            probe_resident_candidate_manual_latency_snapshot(
                candidate,
                reload_generation,
                owners.hysteria2(),
                owners.tuic(),
                owners.juicity(),
                owners.anytls(),
            )
            .await
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
            ResidentUdpPayloadAdmission::new(9, 1024),
        );
        owner.spawn_thread("test-worker", "runtime-lifecycle-test", || {});
        let registry = owner.task_registry_value();
        assert_eq!(registry["owner"], "resident-runtime-owner");
        assert_eq!(registry["runtimeHandle"]["owner"], "resident-runtime-owner");
        assert_eq!(registry["runtimeHandle"]["scope"], "manual-latency-probes");
        assert_eq!(registry["runtimeHandle"]["persistent"], false);
        assert!(registry["tuicOwners"].is_null());
        assert!(
            registry["tasks"]
                .as_array()
                .unwrap()
                .iter()
                .all(|task| task["name"] != "tuic-owner-registry")
        );

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
            manual_probe_index: Arc::new(ResidentManualProbeIndex::new(
                plan::build_resident_manual_probe_plans(&config),
            )),
            reload_generation: 7,
            resource_config: ResidentRuntimeResourceConfig::from_config(&config),
            hysteria2_owner_registry: None,
            tuic_owner_registry: None,
            juicity_owner_registry: None,
            anytls_owner_registry: None,
        };

        assert_eq!(group.select_proxy_for_tcp().unwrap().node_tag, "node_a");
        handle.apply_latency_probe_snapshots_to_groups(&snapshots);
        assert_eq!(group.select_proxy_for_tcp().unwrap().node_tag, "node_b");
    }

    #[test]
    fn manual_family_results_update_exact_dimensions_and_reject_stale_generation() {
        let config = parse_test_config(
            r#"
            global {
                lan_interface: daerust0
            }
            node {
                node_a: 'socks5://192.0.2.1:1080#node_a'
                node_b: 'socks5://192.0.2.2:1081#node_b'
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
        let candidate = group
            .probe_candidates()
            .into_iter()
            .find(|candidate| candidate.node_tag == "node_b")
            .unwrap();
        let handle = ResidentManualProbeHandle {
            groups: vec![Arc::clone(&group)],
            manual_probe_index: Arc::new(ResidentManualProbeIndex::new(
                plan::build_resident_manual_probe_plans(&config),
            )),
            reload_generation: 7,
            resource_config: ResidentRuntimeResourceConfig::from_config(&config),
            hysteria2_owner_registry: None,
            tuic_owner_registry: None,
            juicity_owner_registry: None,
            anytls_owner_registry: None,
        };
        let snapshot = json!({
            "linkHash": candidate.link_hash,
            "reloadGeneration": 7,
            "checkedAtUnix": 3,
            "familyResults": [
                {
                    "networkType": "tcp4",
                    "networkDimension": "tcp4",
                    "healthState": "alive",
                    "alive": true,
                    "latencyMs": 20,
                },
                {
                    "networkType": "tcp6",
                    "networkDimension": "tcp6",
                    "healthState": "unavailable",
                    "alive": false,
                    "latencyMs": null,
                }
            ],
        });
        handle.apply_latency_probe_snapshots_to_groups(std::slice::from_ref(&snapshot));
        assert_eq!(group.select_proxy_for_tcp().unwrap().node_tag, "node_b");
        let tcp6 = group
            .health_state_snapshots()
            .into_iter()
            .find(|state| state.node_tag == "node_b" && state.network_type == NetworkType::TCP6)
            .unwrap();
        assert_eq!(tcp6.health_state, dae_outbound::HealthState::Unavailable);
        assert_eq!(tcp6.latency_ms, None);

        let mut stale = snapshot;
        stale["reloadGeneration"] = json!(6);
        stale["familyResults"][0]["latencyMs"] = json!(1);
        handle.apply_latency_probe_snapshots_to_groups(std::slice::from_ref(&stale));
        let tcp4 = group
            .health_state_snapshots()
            .into_iter()
            .find(|state| state.node_tag == "node_b" && state.network_type == NetworkType::TCP4)
            .unwrap();
        assert_eq!(tcp4.latency_ms, Some(20));
    }

    fn parse_test_config(input: &str) -> Config {
        let sections = dae_config::parser::parse_config(input).unwrap();
        dae_config::schema::build_config(&sections).unwrap()
    }
}
