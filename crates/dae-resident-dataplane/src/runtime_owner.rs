use super::plan::ResidentProtocolOwnerSpecs;
use super::*;

mod manual_probe_execution;
mod manual_probe_index;
mod shutdown;

use self::manual_probe_execution::{ManualProbeExecution, ManualProbeRuntime};
pub(crate) use self::manual_probe_index::ResidentManualProbeIndex;
pub(crate) use self::shutdown::ResidentRuntimeWorkloadShutdown;
use self::shutdown::shutdown_resident_runtime_owner;
use self::shutdown::shutdown_resident_runtime_workloads;
use dae_resident_runtime::{ResidentRuntimeTask, registered_resident_runtime_task};

const RESIDENT_DATA_RUNTIME_WORKER_STACK_BYTES_MIN: usize = 2 * 1024 * 1024;

fn resident_data_runtime_worker_stack_bytes(configured: usize) -> usize {
    configured.max(RESIDENT_DATA_RUNTIME_WORKER_STACK_BYTES_MIN)
}

#[cfg(test)]
fn spawn_resident_runtime_task<F>(
    name: &'static str,
    kind: &'static str,
    stack_bytes: Option<usize>,
    run: F,
) -> ResidentRuntimeTask
where
    F: FnOnce() + Send + 'static,
{
    dae_resident_runtime::spawn_resident_runtime_thread(
        name,
        kind,
        ResidentRuntimeTaskRole::Workload,
        stack_bytes,
        run,
    )
}

#[derive(Debug)]
struct ResidentAllocatorRuntimeHooksAdapter {
    inner: Arc<dyn ResidentAllocatorRuntimeHooks>,
}

impl dae_resident_runtime::ResidentRuntimeAllocatorHooks for ResidentAllocatorRuntimeHooksAdapter {
    fn thread_start(&self) {
        self.inner.thread_start();
    }

    fn thread_stop(&self) {
        self.inner.thread_stop();
    }

    fn activate(&self, handle: tokio::runtime::Handle) {
        self.inner.activate(handle);
    }

    fn deactivate(&self) {
        self.inner.deactivate();
    }
}

pub(crate) struct ResidentRuntimeOwner {
    workload_stop: SharedResidentStopSignal,
    transport_stop: SharedResidentStopSignal,
    tasks: Vec<ResidentRuntimeTask>,
    async_tasks: Vec<ResidentAsyncRuntimeTask>,
    data_plane_executor: ResidentRuntimeExecutor,
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
    xhttp_xmux_owner_task: Option<ResidentAsyncRuntimeTask>,
}

#[derive(Clone)]
pub struct ResidentManualProbeHandle {
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
            .field(
                "task_count",
                &self
                    .tasks
                    .len()
                    .saturating_add(self.async_tasks.len())
                    .saturating_add(usize::from(self.xhttp_xmux_owner_task.is_some())),
            )
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
    ) -> Result<Self, String> {
        let allocator_reclaim = resident_allocator_runtime_hooks(
            ResidentAllocatorWorkerKind::ResidentData,
            resource_config.tcp_runtime_workers.value(),
        );
        let worker_stack_bytes =
            resident_data_runtime_worker_stack_bytes(resource_config.tcp_flow_stack_bytes.value());
        let data_plane_executor = ResidentRuntimeExecutor::new(
            ResidentRuntimeExecutorConfig::new(
                resource_config.tcp_runtime_workers.value(),
                worker_stack_bytes,
            ),
            Arc::new(ResidentAllocatorRuntimeHooksAdapter {
                inner: allocator_reclaim,
            }),
        )?;
        let event_writer = ResidentEventWriterRuntime::start(
            event_file.clone(),
            Arc::clone(&event_lock),
            resource_config.event_queue_depth.value(),
        );
        Ok(Self {
            workload_stop: ResidentStopSignal::shared(),
            transport_stop: ResidentStopSignal::shared(),
            tasks: Vec::new(),
            async_tasks: Vec::new(),
            data_plane_executor,
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
            xhttp_xmux_owner_task: None,
        })
    }

    pub(crate) fn ensure_protocol_owner_registries(
        &mut self,
        specs: ResidentProtocolOwnerSpecs,
    ) -> Result<(), String> {
        let generation = self.reload_generation;
        let runtime = self.data_plane_handle();
        let stop = self.transport_stop_handle();
        let worker_threads = self.data_plane_worker_threads();
        if specs.hysteria2 && self.hysteria2_owner_registry.is_none() {
            let (registry, task) =
                start_hysteria2_owner_registry_on(&runtime, generation, Arc::clone(&stop));
            self.install_hysteria2_owner_registry_task(registry, task);
        }
        if specs.tuic && self.tuic_owner_registry.is_none() {
            let (registry, task) =
                start_tuic_owner_registry_on(&runtime, generation, Arc::clone(&stop));
            self.install_tuic_owner_registry_task(registry, task);
        }
        if specs.juicity && self.juicity_owner_registry.is_none() {
            let (registry, task) =
                start_juicity_owner_registry_on(&runtime, generation, Arc::clone(&stop));
            self.install_juicity_owner_registry_task(registry, task);
        }
        if specs.anytls && self.anytls_owner_registry.is_none() {
            let (registry, task) =
                start_anytls_owner_registry_on(&runtime, generation, Arc::clone(&stop));
            self.install_anytls_owner_registry_task(registry, task);
        }
        if specs.h2_carrier && self.h2_carrier_generation_owner.is_none() {
            let (owner, task) = start_h2_carrier_generation_owner_on(
                &runtime,
                generation,
                Arc::clone(&stop),
                worker_threads,
            )?;
            self.install_h2_carrier_generation_owner_task(owner, task);
        }
        if specs.meek && self.meek_transport_generation_owner.is_none() {
            let (owner, task) = start_meek_transport_generation_owner_on(
                &runtime,
                generation,
                Arc::clone(&stop),
                worker_threads,
            )?;
            self.install_meek_transport_generation_owner_task(owner, task);
        }
        if specs.vless_mux && self.vless_mux_generation_owner.is_none() {
            let (owner, task) = start_vless_mux_generation_owner_on(
                &runtime,
                generation,
                Arc::clone(&stop),
                worker_threads,
            )?;
            self.install_vless_mux_generation_owner_task(owner, task);
        }
        if specs.xhttp_xmux && self.xhttp_xmux_generation_owner.is_none() {
            let (owner, task) =
                tcp::start_xhttp_xmux_generation_owner_on(&runtime, generation, worker_threads)?;
            self.install_xhttp_xmux_generation_owner_task(owner, task);
        }
        Ok(())
    }

    pub(crate) fn resource_config(&self) -> &ResidentRuntimeResourceConfig {
        &self.resource_config
    }

    pub(crate) const fn physical_generation(&self) -> u64 {
        self.reload_generation
    }

    pub(crate) fn udp_payload_admission(&self) -> ResidentUdpPayloadAdmission {
        self.udp_payload_admission.clone()
    }

    pub(crate) fn install_hysteria2_owner_registry_task(
        &mut self,
        handle: Hysteria2OwnerRegistryHandle,
        task: tokio::task::JoinHandle<()>,
    ) {
        self.hysteria2_owner_registry = Some(handle);
        self.register_transport_task("hysteria2-owner-registry", "protocol-transport-owner", task);
    }

    pub(crate) fn hysteria2_owner_registry(&self) -> Option<Hysteria2OwnerRegistryHandle> {
        self.hysteria2_owner_registry.clone()
    }

    pub(crate) fn install_tuic_owner_registry_task(
        &mut self,
        handle: TuicOwnerRegistryHandle,
        task: tokio::task::JoinHandle<()>,
    ) {
        self.tuic_owner_registry = Some(handle);
        self.register_transport_task("tuic-owner-registry", "protocol-transport-owner", task);
    }

    pub(crate) fn tuic_owner_registry(&self) -> Option<TuicOwnerRegistryHandle> {
        self.tuic_owner_registry.clone()
    }

    pub(crate) fn install_juicity_owner_registry_task(
        &mut self,
        handle: JuicityOwnerRegistryHandle,
        task: tokio::task::JoinHandle<()>,
    ) {
        self.juicity_owner_registry = Some(handle);
        self.register_transport_task("juicity-owner-registry", "protocol-transport-owner", task);
    }

    pub(crate) fn juicity_owner_registry(&self) -> Option<JuicityOwnerRegistryHandle> {
        self.juicity_owner_registry.clone()
    }

    pub(crate) fn install_anytls_owner_registry_task(
        &mut self,
        handle: AnyTlsOwnerRegistryHandle,
        task: tokio::task::JoinHandle<()>,
    ) {
        self.anytls_owner_registry = Some(handle);
        self.register_transport_task("anytls-owner-registry", "protocol-transport-owner", task);
    }

    pub(crate) fn anytls_owner_registry(&self) -> Option<AnyTlsOwnerRegistryHandle> {
        self.anytls_owner_registry.clone()
    }

    pub(crate) fn install_h2_carrier_generation_owner_task(
        &mut self,
        handle: H2CarrierGenerationOwnerHandle,
        task: tokio::task::JoinHandle<()>,
    ) {
        self.h2_carrier_generation_owner = Some(handle);
        self.register_transport_task("h2-carrier-owner", "protocol-transport-owner", task);
    }

    pub(crate) fn install_meek_transport_generation_owner_task(
        &mut self,
        handle: MeekTransportGenerationOwnerHandle,
        task: tokio::task::JoinHandle<()>,
    ) {
        self.meek_transport_generation_owner = Some(handle);
        self.register_transport_task("meek-transport-owner", "protocol-transport-owner", task);
    }

    pub(crate) fn install_vless_mux_generation_owner_task(
        &mut self,
        handle: VlessMuxGenerationOwnerHandle,
        task: tokio::task::JoinHandle<()>,
    ) {
        self.vless_mux_generation_owner = Some(handle);
        self.register_transport_task("vless-mux-owner", "protocol-transport-owner", task);
    }

    pub(crate) fn install_xhttp_xmux_generation_owner_task(
        &mut self,
        handle: tcp::XhttpXmuxGenerationOwnerHandle,
        task: tokio::task::JoinHandle<()>,
    ) {
        self.xhttp_xmux_generation_owner = Some(handle);
        self.xhttp_xmux_owner_task = Some(registered_resident_async_runtime_task(
            "xhttp-xmux-owner",
            "protocol-transport-owner",
            ResidentRuntimeTaskRole::Transport,
            task,
        ));
    }

    pub(crate) fn shutdown_xhttp_xmux_generation_owner(
        &mut self,
    ) -> Option<tcp::XhttpXmuxClearReport> {
        let handle = self.xhttp_xmux_generation_owner.take()?;
        let mut report =
            tcp::stop_xhttp_xmux_generation_owner(&handle, RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE);
        if let Some(task) = self.xhttp_xmux_owner_task.take() {
            let deadline = Instant::now()
                .checked_add(RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE)
                .unwrap_or_else(Instant::now);
            let shutdown = self.data_plane_executor.join_tasks(vec![task], deadline);
            report.owner_thread_joined =
                shutdown.joined == 1 && shutdown.panicked == 0 && shutdown.timed_out == 0;
        }
        Some(report)
    }

    pub(crate) fn stop_handle(&self) -> SharedResidentStopSignal {
        Arc::clone(&self.workload_stop)
    }

    pub(crate) fn transport_stop_handle(&self) -> SharedResidentStopSignal {
        Arc::clone(&self.transport_stop)
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

    pub(crate) fn traffic_counters(&self) -> ResidentTrafficCounters {
        self.metrics.traffic_counters()
    }

    pub(super) fn read_handle(&self) -> ResidentRuntimeOwnerReadHandle {
        let mut resources = self.resource_config.json();
        resources["residentDataWorkerStackBytes"] =
            json!(resident_data_runtime_worker_stack_bytes(
                self.resource_config.tcp_flow_stack_bytes.value(),
            ));
        ResidentRuntimeOwnerReadHandle {
            metrics: Arc::clone(&self.metrics),
            reload_generation: self.reload_generation,
            runtime_owner: Arc::new(self.runtime_owner_value()),
            packet_session_manager: Arc::new(json!({
                "schemaVersion": 1,
                "manager": "resident-udp-session-manager",
                "reloadGeneration": self.reload_generation,
            })),
            resources: Arc::new(resources),
            udp_payload_admission: self.udp_payload_admission.clone(),
            event_writer: self.event_writer.read_handle(),
            hysteria2_owner_registry: self.hysteria2_owner_registry.clone(),
            tuic_owner_registry: self.tuic_owner_registry.clone(),
            juicity_owner_registry: self.juicity_owner_registry.clone(),
            anytls_owner_registry: self.anytls_owner_registry.clone(),
            h2_carrier_generation_owner: self.h2_carrier_generation_owner.clone(),
            meek_transport_generation_owner: self.meek_transport_generation_owner.clone(),
            vless_mux_generation_owner: self.vless_mux_generation_owner.clone(),
            xhttp_xmux_generation_owner: self.xhttp_xmux_generation_owner.clone(),
        }
    }

    pub(crate) fn cleanup_reporter(&self, owner: &'static str) -> ResidentRuntimeCleanupReporter {
        self.cleanup_inventory.reporter(owner)
    }

    pub(crate) fn udp_sessions_active(&self) -> Arc<AtomicUsize> {
        Arc::clone(&self.udp_sessions_active)
    }

    pub(crate) fn manual_probe_handle(
        &self,
        groups: &[Arc<plan::ResidentProxyGroupPlan>],
        manual_probe_index: &Arc<ResidentManualProbeIndex>,
        resource_config: &ResidentRuntimeResourceConfig,
    ) -> ResidentManualProbeHandle {
        ResidentManualProbeHandle {
            groups: groups.to_vec(),
            manual_probe_index: Arc::clone(manual_probe_index),
            reload_generation: self.reload_generation,
            resource_config: resource_config.clone(),
            hysteria2_owner_registry: self.hysteria2_owner_registry.clone(),
            tuic_owner_registry: self.tuic_owner_registry.clone(),
            juicity_owner_registry: self.juicity_owner_registry.clone(),
            anytls_owner_registry: self.anytls_owner_registry.clone(),
        }
    }

    pub(crate) fn register_generation_thread(
        &mut self,
        name: &'static str,
        kind: &'static str,
        handle: JoinHandle<()>,
    ) {
        self.tasks.push(registered_resident_runtime_task(
            name,
            kind,
            ResidentRuntimeTaskRole::Generation,
            handle,
        ));
    }

    pub(crate) fn data_plane_handle(&self) -> tokio::runtime::Handle {
        self.data_plane_executor.handle()
    }

    pub(crate) fn data_plane_worker_threads(&self) -> usize {
        self.data_plane_executor.worker_threads()
    }

    pub(crate) fn register_async_task(
        &mut self,
        name: &'static str,
        kind: &'static str,
        handle: tokio::task::JoinHandle<()>,
    ) {
        self.async_tasks
            .push(registered_resident_async_runtime_task(
                name,
                kind,
                ResidentRuntimeTaskRole::Workload,
                handle,
            ));
    }

    fn register_transport_task(
        &mut self,
        name: &'static str,
        kind: &'static str,
        handle: tokio::task::JoinHandle<()>,
    ) {
        self.async_tasks
            .push(registered_resident_async_runtime_task(
                name,
                kind,
                ResidentRuntimeTaskRole::Transport,
                handle,
            ));
    }

    pub(crate) fn spawn_async_task<F>(&mut self, name: &'static str, kind: &'static str, task: F)
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        let handle = self.data_plane_executor.handle().spawn(task);
        self.register_async_task(name, kind, handle);
    }

    pub(crate) fn spawn_generation_async_task<F>(
        &mut self,
        name: &'static str,
        kind: &'static str,
        task: F,
    ) where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        let handle = self.data_plane_executor.handle().spawn(task);
        self.async_tasks
            .push(registered_resident_async_runtime_task(
                name,
                kind,
                ResidentRuntimeTaskRole::Generation,
                handle,
            ));
    }

    pub(crate) fn reap_finished_generation_tasks(&mut self) {
        let mut pending_threads = Vec::with_capacity(self.tasks.len());
        for mut task in std::mem::take(&mut self.tasks) {
            let finished = task.role == ResidentRuntimeTaskRole::Generation
                && task.handle.as_ref().is_some_and(JoinHandle::is_finished);
            if finished {
                if let Some(handle) = task.handle.take() {
                    let _ = handle.join();
                }
            } else {
                pending_threads.push(task);
            }
        }
        self.tasks = pending_threads;
        self.async_tasks.retain(|task| {
            task.role != ResidentRuntimeTaskRole::Generation || !task.handle.is_finished()
        });
    }

    #[cfg(test)]
    pub(crate) fn spawn_thread<F>(&mut self, name: &'static str, kind: &'static str, run: F)
    where
        F: FnOnce() + Send + 'static,
    {
        self.tasks
            .push(spawn_resident_runtime_task(name, kind, None, run));
    }

    pub(crate) fn task_registry_value(&self) -> Value {
        json!({
            "schemaVersion": 1,
            "owner": "resident-runtime-owner",
            "reloadGeneration": self.reload_generation,
            "taskCount": self.tasks.len().saturating_add(self.async_tasks.len()).saturating_add(usize::from(self.xhttp_xmux_owner_task.is_some())),
            "threadTaskCount": self.tasks.len(),
            "asyncTaskCount": self.async_tasks.len().saturating_add(usize::from(self.xhttp_xmux_owner_task.is_some())),
            "workloadTaskCount": self.async_tasks.iter().filter(|task| task.role != ResidentRuntimeTaskRole::Transport).count(),
            "generationTaskCount": self.async_tasks.iter().filter(|task| task.role == ResidentRuntimeTaskRole::Generation).count(),
            "transportTaskCount": self.async_tasks.iter().filter(|task| task.role == ResidentRuntimeTaskRole::Transport).count().saturating_add(usize::from(self.xhttp_xmux_owner_task.is_some())),
            "shutdownOrder": ["workload", "generation-carriers", "transport", "executor", "event-writer"],
            "dataPlaneExecutor": self.data_plane_executor.json(),
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
                    "role": task.role.name(),
                    "joinPolicy": "bounded-join-on-owner-shutdown",
                })
            }).chain(self.async_tasks.iter().chain(self.xhttp_xmux_owner_task.iter()).map(|task| {
                json!({
                    "name": task.name,
                    "kind": task.kind,
                    "role": task.role.name(),
                    "executor": "process-owned-shared-multi-thread",
                    "joinPolicy": "bounded-join-on-owner-shutdown",
                })
            })).collect::<Vec<_>>(),
        })
    }

    pub(crate) fn prune_event_log(&self) -> std::io::Result<()> {
        self.event_writer.prune()
    }

    pub(crate) fn clear_event_log(&self) -> std::io::Result<()> {
        self.event_writer.clear()
    }

    pub(crate) fn shutdown(&mut self) -> Value {
        let workload = self.shutdown_workloads(RESIDENT_RUNTIME_TASK_JOIN_GRACE);
        let xhttp_xmux = self.shutdown_xhttp_xmux_generation_owner();
        let xhttp_xmux_released = xhttp_xmux.as_ref().is_none_or(|report| {
            !report.cleanup_timed_out
                && report.owner_thread_joined
                && report.h2.locked_managers == 0
                && report.h3.locked_managers == 0
        });
        let mut shutdown =
            shutdown_resident_runtime_owner(self, workload, RESIDENT_RUNTIME_TASK_JOIN_GRACE);
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
            shutdown["safetyStatus"] = json!("fail");
            shutdown["graceful"] = json!(false);
            shutdown["completionMode"] = json!("incomplete");
        }
        shutdown
    }

    #[cfg(test)]
    fn shutdown_with_grace(&mut self, grace: Duration) -> Value {
        let workload = self.shutdown_workloads(grace);
        shutdown_resident_runtime_owner(self, workload, grace)
    }

    pub(crate) fn shutdown_workloads(
        &mut self,
        grace: Duration,
    ) -> ResidentRuntimeWorkloadShutdown {
        shutdown_resident_runtime_workloads(self, grace)
    }

    pub(crate) fn shutdown_after_workloads(
        &mut self,
        workload: ResidentRuntimeWorkloadShutdown,
        grace: Duration,
    ) -> Value {
        shutdown_resident_runtime_owner(self, workload, grace)
    }

    fn runtime_owner_value(&self) -> Value {
        json!({
            "schemaVersion": 1,
            "owner": "resident-runtime-owner",
            "reloadGeneration": self.reload_generation,
            "taskCount": self.tasks.len().saturating_add(self.async_tasks.len()).saturating_add(usize::from(self.xhttp_xmux_owner_task.is_some())),
            "threadTaskCount": self.tasks.len(),
            "asyncTaskCount": self.async_tasks.len().saturating_add(usize::from(self.xhttp_xmux_owner_task.is_some())),
            "workloadTaskCount": self.async_tasks.iter().filter(|task| task.role != ResidentRuntimeTaskRole::Transport).count(),
            "generationTaskCount": self.async_tasks.iter().filter(|task| task.role == ResidentRuntimeTaskRole::Generation).count(),
            "transportTaskCount": self.async_tasks.iter().filter(|task| task.role == ResidentRuntimeTaskRole::Transport).count().saturating_add(usize::from(self.xhttp_xmux_owner_task.is_some())),
            "dataPlaneExecutor": self.data_plane_executor.json(),
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
            "executor": "helper-owned-bounded-tokio-multi-thread",
            "scope": "manual-latency-probes",
            "available": true,
            "persistent": false,
            "lifecycle": "one runtime per bounded helper request; owner and probe tasks share it",
            "error": Value::Null,
        })
    }
}

fn duration_millis(duration: Duration) -> u64 {
    duration.as_millis().min(u128::from(u64::MAX)) as u64
}

impl ResidentManualProbeHandle {
    pub fn reload_generation(&self) -> u64 {
        self.reload_generation
    }

    pub fn probe_concurrency(&self) -> usize {
        self.resource_config.manual_probe_concurrency.value()
    }

    pub fn probe_timeout(&self) -> Duration {
        self.resource_config.tcp_probe_timeout()
    }

    pub fn probe_node_latencies_without_group_update(&self, links: &[String]) -> Vec<Value> {
        let mut runtime =
            match ManualProbeRuntime::start(&self.resource_config, self.probe_concurrency()) {
                Ok(runtime) => runtime,
                Err(detail) => {
                    return manual_probe_setup_failure_snapshots(
                        links,
                        self.reload_generation,
                        &detail,
                    );
                }
            };
        let plans = self.manual_probe_index.plans_for_links(links);
        let snapshots = probe_resident_manual_latency_snapshots(
            runtime.runtime(),
            &plans,
            links,
            self.reload_generation,
            self.probe_concurrency(),
            ResidentTransportOwnerRegistries::new(
                self.hysteria2_owner_registry.clone(),
                self.tuic_owner_registry.clone(),
                self.juicity_owner_registry.clone(),
            )
            .with_anytls(self.anytls_owner_registry.clone()),
        );
        runtime.shutdown();
        snapshots
    }

    pub fn apply_latency_probe_snapshots_to_groups(&self, snapshots: &[Value]) {
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
                        .and_then(dae_outbound_core::HealthState::parse)
                    else {
                        continue;
                    };
                    let latency_ms = family_result.get("latencyMs").and_then(Value::as_i64);
                    for link in &links {
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
            for link in &links {
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

pub fn run_resident_manual_latency_probe_helper(
    config: &Config,
    links: &[String],
    reload_generation: u64,
    concurrency: usize,
) -> Vec<Value> {
    let mut execution =
        match ManualProbeExecution::start(config, links, reload_generation, concurrency) {
            Ok(execution) => execution,
            Err(detail) => {
                return manual_probe_setup_failure_snapshots(links, reload_generation, &detail);
            }
        };
    let snapshots = probe_resident_manual_latency_snapshots(
        execution.runtime(),
        execution.plans(),
        links,
        reload_generation,
        concurrency,
        execution.registries(),
    );
    let _ = execution.shutdown();
    snapshots
}

pub fn run_resident_manual_latency_probe_helper_streaming<F>(
    config: &Config,
    links: &[String],
    reload_generation: u64,
    concurrency: usize,
    mut on_snapshot: F,
) -> Result<(), String>
where
    F: FnMut(Value) -> Result<(), String>,
{
    let mut execution = ManualProbeExecution::start(config, links, reload_generation, concurrency)?;
    let result = probe_resident_manual_latency_snapshots_streaming(
        execution.runtime(),
        execution.plans(),
        links,
        reload_generation,
        concurrency,
        execution.registries(),
        &mut on_snapshot,
    );
    let shutdown = execution.shutdown();
    result.and(shutdown)
}

fn manual_probe_setup_failure_snapshots(
    links: &[String],
    reload_generation: u64,
    detail: &str,
) -> Vec<Value> {
    let checked_at = unix_now_secs();
    preferred_latency_snapshots(links.iter().filter(|link| !link.is_empty()).map(|link| {
        manual_probe_unavailable_snapshot(
            link,
            "native outbound probe runtime unavailable",
            detail,
            checked_at,
            reload_generation,
        )
    }))
}

fn probe_resident_manual_latency_snapshots(
    runtime: &tokio::runtime::Runtime,
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
    preferred_latency_snapshots(snapshots)
}

fn probe_resident_manual_latency_snapshots_streaming<F>(
    runtime: &tokio::runtime::Runtime,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resident_data_runtime_keeps_the_production_stack_safety_floor() {
        assert_eq!(
            resident_data_runtime_worker_stack_bytes(512 * 1024),
            RESIDENT_DATA_RUNTIME_WORKER_STACK_BYTES_MIN
        );
        assert_eq!(
            resident_data_runtime_worker_stack_bytes(4 * 1024 * 1024),
            4 * 1024 * 1024
        );
    }

    #[test]
    fn manual_probe_index_builds_requested_links_lazily_by_execution_identity() {
        let config = Arc::new(parse_test_config(
            r#"
            global {
                lan_interface: daerust0
            }
            routing {
                fallback: direct
            }
            "#,
        ));
        let index = ResidentManualProbeIndex::lazy(config, 7);
        assert_eq!(index.cached_plan_count(), 0);
        let first = "socks5://127.0.0.1:1080#first".to_owned();
        let renamed = "socks5://127.0.0.1:1080#renamed".to_owned();
        assert!(index.plans_for_links(std::slice::from_ref(&first))[&first].is_ok());
        assert_eq!(index.cached_plan_count(), 1);
        assert!(index.plans_for_links(std::slice::from_ref(&renamed))[&renamed].is_ok());
        assert_eq!(index.cached_plan_count(), 1);
    }

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
        )
        .unwrap();
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
            .iter()
            .find(|candidate| candidate.node_tag.as_str() == "node_b")
            .unwrap()
            .link_hash
            .clone();
        let snapshots = [json!({
            "linkHash": node_b_hash.as_str(),
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
            .iter()
            .find(|candidate| candidate.node_tag.as_str() == "node_b")
            .unwrap()
            .clone();
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
            "linkHash": candidate.link_hash.as_str(),
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
