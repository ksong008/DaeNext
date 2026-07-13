use super::*;

mod apply_state;
mod cleanup;
mod instance;
mod process_transition;
mod recovery;
mod startup_recovery;
mod stop;
mod summary;

pub(in crate::daed_product) use apply_state::ProductRuntimeApplySnapshot;
use apply_state::RuntimeApplyState;
use cleanup::{
    cleanup_report_error, cleanup_runtime_instance, cleanup_runtime_instance_with_reclaim,
    cleanup_start_blocker_from_report, ensure_cleanup_allows_start_for_inner,
    spawn_background_cleanup,
};
#[cfg(test)]
pub(super) use instance::resident_dataplane_admission_detail;
pub(super) use instance::{
    preflight_product_runtime_candidate, product_runtime_fake_start_enabled,
    runtime_started_at_after_success, start_product_runtime_instance_with_dns_reload_snapshot,
};
#[cfg(test)]
pub(super) use instance::{
    start_product_runtime_instance, with_product_runtime_fake_start_override,
};
use recovery::ProductRuntimeInterfaceRecoverySupervisor;
#[cfg(test)]
pub(super) use recovery::resident_interface_recovery_request;
use startup_recovery::ProductRuntimeStartupRecoverySupervisor;
use summary::{
    apply_runtime_traffic_metric_carry, runtime_instance_dns_reload_snapshot,
    runtime_instance_node_latencies, runtime_traffic_metric_u64, runtime_traffic_metrics_snapshot,
    successful_latency_seed_snapshots,
};

#[derive(Debug)]
pub(super) struct ProductRuntimeManager {
    coordinator: RuntimeApplyCoordinator,
    lifecycle: Arc<Mutex<()>>,
    pub(super) inner: Arc<Mutex<ProductRuntimeState>>,
    interface_recovery: ProductRuntimeInterfaceRecoverySupervisor,
    startup_recovery: Mutex<ProductRuntimeStartupRecoverySupervisor>,
    process_http_config: Mutex<Option<ProductHttpWorkerConfig>>,
}

#[derive(Debug, Default)]
pub(super) struct ProductRuntimeState {
    pub(super) runtime: Option<ProductRuntimeInstance>,
    pub(super) config: Option<Config>,
    pub(super) config_content: Option<String>,
    pub(super) last_error: Option<String>,
    pub(super) last_transition_at: Option<String>,
    pub(super) runtime_started_at: Option<String>,
    pub(super) last_report: Option<Value>,
    pub(super) reload_count: u64,
    pub(super) stop_count: u64,
    pub(super) lifecycle_epoch: u64,
    pub(super) traffic_carry: RuntimeTrafficCarry,
    pub(super) cleanup: RuntimeCleanupState,
    pub(super) apply: RuntimeApplyState,
    pub(super) active_generation: Option<String>,
    pub(super) pending_process_transition: Option<Value>,
}

#[derive(Debug, Clone, Default)]
pub(super) struct RuntimeCleanupState {
    pub(super) running: bool,
    pub(super) epoch: u64,
    pub(super) mode: Option<String>,
    pub(super) started_at: Option<String>,
    pub(super) finished_at: Option<String>,
    pub(super) last_report: Option<Value>,
    pub(super) last_error: Option<String>,
}

impl RuntimeCleanupState {
    pub(super) fn begin(&mut self, epoch: u64, mode: &str) {
        self.running = true;
        self.epoch = epoch;
        self.mode = Some(mode.to_owned());
        self.started_at = Some(now_text());
        self.finished_at = None;
        self.last_report = None;
        self.last_error = None;
    }

    pub(super) fn finish(&mut self, report: Option<Value>) {
        self.running = false;
        self.finished_at = Some(now_text());
        self.last_error = cleanup_report_error(report.as_ref());
        self.last_report = report;
    }

    fn summary(&self) -> Value {
        json!({
            "running": self.running,
            "state": if self.running {
                "running"
            } else if self.last_error.is_some() {
                "failed"
            } else if self.finished_at.is_some() {
                "done"
            } else {
                "idle"
            },
            "epoch": self.epoch,
            "mode": self.mode,
            "startedAt": self.started_at,
            "finishedAt": self.finished_at,
            "lastError": self.last_error,
            "lastReport": self.last_report,
        })
    }
}

// Runtime ownership keeps the resident instance inline under the manager mutex;
// boxing the large variant would change drop and replacement behavior here.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub(super) enum ProductRuntimeInstance {
    Resident(ResidentProductionRuntime),
    Fake(FakeProductRuntime),
}

#[derive(Debug)]
pub(super) struct FakeProductRuntime {
    pub(super) started_at: String,
    pub(super) tproxy_port: u16,
}

pub(super) enum ProductRuntimeProbeHandle {
    Resident {
        handle: Box<ResidentManualProbeHandle>,
        config_content: Option<String>,
    },
    Fake,
}

impl ProductRuntimeProbeHandle {
    pub(super) fn probe_node_latencies_streaming_without_group_update<F, C>(
        &self,
        links: &[String],
        mut should_cancel: C,
        mut on_snapshots: F,
    ) -> bool
    where
        F: FnMut(&[Value]),
        C: FnMut() -> bool,
    {
        match self {
            Self::Resident {
                handle,
                config_content,
            } => {
                if let Some(config_content) = config_content.as_deref() {
                    match run_latency_probe_helper_streaming(
                        config_content,
                        handle.reload_generation(),
                        handle.probe_concurrency(),
                        handle.probe_timeout(),
                        links,
                        &mut should_cancel,
                        |snapshot| on_snapshots(std::slice::from_ref(snapshot)),
                    ) {
                        Ok(LatencyProbeHelperStreamOutcome::Completed) => false,
                        Ok(LatencyProbeHelperStreamOutcome::Cancelled) => true,
                        Err(err) => {
                            let failures = latency_probe_failure_snapshots_for_unseen_links(
                                links,
                                handle.reload_generation(),
                                "manual latency probe helper failed",
                                &err.message,
                                &err.snapshots,
                            );
                            if !failures.is_empty() {
                                on_snapshots(&failures);
                            }
                            false
                        }
                    }
                } else {
                    if should_cancel() {
                        return true;
                    }
                    let snapshots = handle.probe_node_latencies_without_group_update(links);
                    if should_cancel() {
                        return true;
                    }
                    on_snapshots(&snapshots);
                    false
                }
            }
            Self::Fake => {
                if should_cancel() {
                    return true;
                }
                let snapshots = fake_runtime_probe_node_latencies(links);
                if should_cancel() {
                    return true;
                }
                on_snapshots(&snapshots);
                false
            }
        }
    }

    pub(super) fn apply_latency_probe_snapshots_to_groups(&self, snapshots: &[Value]) {
        if let Self::Resident { handle, .. } = self {
            handle.apply_latency_probe_snapshots_to_groups(snapshots);
        }
    }

    pub(super) fn probe_generation(&self) -> Option<u64> {
        match self {
            Self::Resident { handle, .. } => Some(handle.reload_generation()),
            Self::Fake => None,
        }
    }

    pub(super) fn probe_batch_size(&self, unique_link_count: usize) -> usize {
        match self {
            Self::Resident {
                handle,
                config_content: Some(_),
            } => latency_probe_helper_parent_chunk_size(
                handle.probe_concurrency(),
                unique_link_count,
            ),
            Self::Resident { handle, .. } => handle.probe_concurrency(),
            Self::Fake => 8,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct RuntimeTrafficCarry {
    pub(super) upload_total: u64,
    pub(super) download_total: u64,
}

impl RuntimeTrafficCarry {
    pub(super) fn absorb_runtime(self, runtime: &ProductRuntimeInstance) -> Self {
        let Some(metrics) = runtime_traffic_metrics_snapshot(runtime) else {
            return self;
        };
        self.absorb_metrics(&metrics)
    }

    pub(super) fn absorb_metrics(self, metrics: &Value) -> Self {
        Self {
            upload_total: self
                .upload_total
                .saturating_add(runtime_traffic_metric_u64(metrics, "uploadTotal")),
            download_total: self
                .download_total
                .saturating_add(runtime_traffic_metric_u64(metrics, "downloadTotal")),
        }
    }

    pub(super) fn apply_to_runtime_summary(self, summary: &mut Value) {
        let Some(metrics) = summary.pointer_mut("/residentDataplane/metrics") else {
            return;
        };
        self.apply_to_metrics(metrics);
    }

    pub(super) fn apply_to_metrics(self, metrics: &mut Value) {
        if self.upload_total == 0 && self.download_total == 0 {
            return;
        }
        apply_runtime_traffic_metric_carry(metrics, "uploadTotal", self.upload_total);
        apply_runtime_traffic_metric_carry(metrics, "downloadTotal", self.download_total);
    }
}

#[derive(Debug)]
pub(super) struct RuntimeStartOutcome {
    pub(super) report: Value,
}

#[derive(Debug, Default)]
pub(super) struct RuntimeOverviewDeltaState {
    pub(super) reload_count: u64,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(super) enum ProductRuntimeLifecycleLogMode {
    StartupRestore,
    ReloadLocalControl,
    ReloadSubscriptionRefresh,
}

impl ProductRuntimeLifecycleLogMode {
    pub(super) fn source(self) -> &'static str {
        match self {
            Self::StartupRestore => "startup-restore",
            Self::ReloadLocalControl => "local-control",
            Self::ReloadSubscriptionRefresh => "subscription-refresh",
        }
    }

    pub(super) fn apply_intent(self) -> RuntimeApplyIntent {
        match self {
            Self::StartupRestore => RuntimeApplyIntent::StartupRestore,
            Self::ReloadLocalControl => RuntimeApplyIntent::LocalControlReload,
            Self::ReloadSubscriptionRefresh => RuntimeApplyIntent::SubscriptionRefresh,
        }
    }

    pub(super) fn is_startup(self) -> bool {
        matches!(self, Self::StartupRestore)
    }

    pub(super) fn returns_detailed_report(self) -> bool {
        matches!(self, Self::ReloadSubscriptionRefresh)
    }
}

pub(super) const PRODUCT_RUNTIME_FAKE_START_ENV: &str = "PRODUCT_RUNTIME_FAKE_START";
pub(super) const PRODUCT_RUNTIME_FAKE_START_LEGACY_ENV: &str = "DAED_PRODUCT_RUNTIME_FAKE_START";
const PRODUCT_RUNTIME_CLEANUP_INTERLOCK_WAIT: Duration = Duration::from_secs(5);
const PRODUCT_RUNTIME_INTERFACE_RECOVERY_POLL: Duration = Duration::from_secs(2);
const PRODUCT_RUNTIME_INTERFACE_RECOVERY_RETRY: Duration = Duration::from_secs(30);
const PRODUCT_RUNTIME_INTERFACE_RECOVERY_SOURCE: &str = "interface-monitor";

impl ProductRuntimeManager {
    pub(super) fn new() -> Self {
        let coordinator = RuntimeApplyCoordinator::new();
        let lifecycle = Arc::new(Mutex::new(()));
        let inner = Arc::new(Mutex::new(ProductRuntimeState::default()));
        let interface_recovery = ProductRuntimeInterfaceRecoverySupervisor::start(
            coordinator.clone(),
            Arc::clone(&lifecycle),
            Arc::clone(&inner),
        );
        Self {
            coordinator,
            lifecycle,
            inner,
            interface_recovery,
            startup_recovery: Mutex::new(ProductRuntimeStartupRecoverySupervisor::default()),
            process_http_config: Mutex::new(None),
        }
    }

    pub(super) fn reload_with_config_content(
        &self,
        config: Config,
        config_content: Option<String>,
        source: &str,
        latency_seed: &[Value],
    ) -> Result<RuntimeStartOutcome, String> {
        reload_product_runtime_with_config_content(
            &self.lifecycle,
            &self.inner,
            config,
            config_content,
            source,
            latency_seed,
        )
    }

    pub(super) fn is_running(&self) -> bool {
        self.inner
            .lock()
            .map(|inner| inner.runtime.is_some())
            .unwrap_or(false)
    }

    pub(in crate::daed_product) fn begin_apply(
        &self,
        intent: RuntimeApplyIntent,
    ) -> Result<RuntimeApplyPermit<'_>, String> {
        self.coordinator.begin_apply(intent)
    }
}

impl Drop for ProductRuntimeManager {
    fn drop(&mut self) {
        self.interface_recovery.shutdown();
        if let Ok(supervisor) = self.startup_recovery.get_mut() {
            supervisor.shutdown();
        }
    }
}

fn reload_product_runtime_with_config_content(
    lifecycle: &Arc<Mutex<()>>,
    inner: &Arc<Mutex<ProductRuntimeState>>,
    config: Config,
    config_content: Option<String>,
    source: &str,
    latency_seed: &[Value],
) -> Result<RuntimeStartOutcome, String> {
    let _lifecycle = lifecycle
        .lock()
        .map_err(|_| "product runtime lifecycle lock poisoned".to_owned())?;
    ensure_cleanup_allows_start_for_inner(inner)?;
    let (
        previous_runtime,
        previous_config,
        previous_config_content,
        previous_runtime_started_at,
        previous_runtime_was_running,
        lifecycle_epoch,
    ) = {
        let mut inner = inner
            .lock()
            .map_err(|_| "product runtime manager lock poisoned".to_owned())?;
        inner.lifecycle_epoch = inner.lifecycle_epoch.wrapping_add(1);
        let previous_runtime = inner.runtime.take();
        let previous_config = inner.config.clone();
        let previous_config_content = inner.config_content.clone();
        let previous_runtime_started_at = inner.runtime_started_at.clone();
        let previous_runtime_was_running = previous_runtime.is_some();
        if let Some(runtime) = previous_runtime.as_ref() {
            inner.traffic_carry = inner.traffic_carry.absorb_runtime(runtime);
        }
        if previous_runtime_was_running {
            let cleanup_epoch = inner.lifecycle_epoch;
            inner.cleanup.begin(cleanup_epoch, "reload-replace");
        }
        (
            previous_runtime,
            previous_config,
            previous_config_content,
            previous_runtime_started_at,
            previous_runtime_was_running,
            inner.lifecycle_epoch,
        )
    };

    let live_latency_seed = previous_runtime
        .as_ref()
        .map(runtime_instance_node_latencies)
        .unwrap_or_default();
    let previous_dns_reload_snapshot = previous_runtime
        .as_ref()
        .and_then(|runtime| runtime_instance_dns_reload_snapshot(runtime).ok().flatten())
        .filter(|snapshot| !snapshot.is_empty());
    let dns_config_unchanged = previous_config
        .as_ref()
        .map(|previous| previous.dns == config.dns)
        .unwrap_or(false);
    let dns_reload_plan = dae_runtime_control::ReloadDnsCachePlan::decide(
        dns_config_unchanged,
        previous_dns_reload_snapshot.is_some(),
        previous_dns_reload_snapshot
            .as_ref()
            .map(ResidentDnsReloadSnapshot::entry_count)
            .unwrap_or(0),
    );
    let dns_reload_snapshot = dns_reload_plan
        .restore_cache
        .then(|| previous_dns_reload_snapshot.clone())
        .flatten();
    let latency_seed =
        successful_latency_seed_snapshots(latency_seed.iter().cloned().chain(live_latency_seed));
    let previous_cleanup_report = cleanup_runtime_instance(previous_runtime);
    if previous_runtime_was_running
        && let Ok(mut inner) = inner.lock()
        && inner.lifecycle_epoch == lifecycle_epoch
    {
        inner.cleanup.finish(previous_cleanup_report.clone());
    }
    if previous_runtime_was_running
        && let Some(blocker) = cleanup_start_blocker_from_report(previous_cleanup_report.as_ref())
    {
        let _ = allocator_reclaim(AllocatorReclaimReason::ReloadFailedAfterCleanup);
        return Err(format!(
            "previous product runtime cleanup failed before reload: {blocker}"
        ));
    }
    match start_product_runtime_instance_with_dns_reload_snapshot(
        &config,
        source,
        &latency_seed,
        dns_reload_snapshot.clone(),
    ) {
        Ok((runtime, report)) => {
            let mut inner = inner
                .lock()
                .map_err(|_| "product runtime manager lock poisoned".to_owned())?;
            if inner.lifecycle_epoch != lifecycle_epoch {
                drop(inner);
                drop(runtime);
                if previous_runtime_was_running {
                    let _ = allocator_reclaim(AllocatorReclaimReason::ReloadFailedAfterCleanup);
                }
                return Err(
                    "product runtime reload was superseded by a newer lifecycle operation"
                        .to_owned(),
                );
            }
            let transition_at = now_text();
            inner.runtime = Some(runtime);
            inner.config = Some(config);
            inner.config_content = config_content;
            inner.reload_count += 1;
            inner.last_error = None;
            inner.last_transition_at = Some(transition_at.clone());
            inner.runtime_started_at = Some(runtime_started_at_after_success(
                previous_runtime_was_running,
                previous_runtime_started_at,
                transition_at,
            ));
            inner.last_report = Some(report.clone());
            Ok(RuntimeStartOutcome { report })
        }
        Err(start_err) => {
            let should_restore = inner
                .lock()
                .map(|inner| inner.lifecycle_epoch == lifecycle_epoch)
                .unwrap_or(false);
            let restore_result = if should_restore {
                previous_config.as_ref().map(|previous| {
                    start_product_runtime_instance_with_dns_reload_snapshot(
                        previous,
                        "restore",
                        &latency_seed,
                        previous_dns_reload_snapshot.clone(),
                    )
                })
            } else {
                None
            };
            let mut inner = inner
                .lock()
                .map_err(|_| "product runtime manager lock poisoned".to_owned())?;
            if inner.lifecycle_epoch != lifecycle_epoch {
                let restored_runtime = match restore_result {
                    Some(Ok((runtime, _))) => Some(runtime),
                    _ => None,
                };
                drop(inner);
                drop(restored_runtime);
                if previous_runtime_was_running {
                    let _ = allocator_reclaim(AllocatorReclaimReason::ReloadFailedAfterCleanup);
                }
                return Err(format!(
                    "{start_err}\nrestore skipped because product runtime reload was superseded by a newer lifecycle operation"
                ));
            }
            let restored = restore_result.map(|result| match result {
                    Ok((runtime, report)) => {
                        inner.runtime = Some(runtime);
                        inner.config = previous_config.clone();
                        inner.config_content = previous_config_content.clone();
                        inner.runtime_started_at = previous_runtime_started_at.clone();
                        inner.last_report = Some(report);
                        true
                    }
                    Err(restore_err) => {
                        inner.runtime = None;
                        inner.config = None;
                        inner.config_content = None;
                        inner.runtime_started_at = None;
                        inner.last_error = Some(format!(
                            "{start_err}\nrestore failed while restoring previous product runtime: {restore_err}"
                        ));
                        false
                    }
                });
            let message = match restored {
                Some(true) => {
                    format!("{start_err}\nrestore: restored previous product runtime")
                }
                Some(false) => inner
                    .last_error
                    .clone()
                    .unwrap_or_else(|| start_err.clone()),
                None => start_err,
            };
            inner.last_transition_at = Some(now_text());
            if restored != Some(true) {
                inner.runtime_started_at = None;
            }
            inner.last_error = Some(message.clone());
            drop(inner);
            if previous_runtime_was_running {
                let _ = allocator_reclaim(AllocatorReclaimReason::ReloadFailedAfterCleanup);
            }
            Err(message)
        }
    }
}

impl ProductRuntimeManager {
    #[cfg(test)]
    pub(super) fn wait_for_cleanup_idle(&self, timeout: Duration) -> bool {
        cleanup::wait_for_cleanup_idle_for_inner(&self.inner, timeout)
    }

    #[cfg(test)]
    pub(super) fn ensure_cleanup_allows_start(&self) -> Result<(), String> {
        ensure_cleanup_allows_start_for_inner(&self.inner)
    }

    pub(super) fn summary(&self) -> Value {
        let coordinator = self.coordinator.summary();
        let Ok(inner) = self.inner.lock() else {
            return json!({
                "running": false,
                "state": "error",
                "attachBackend": "unavailable",
                "netnsLinkMode": "unavailable",
                "error": "product runtime manager lock poisoned",
            });
        };
        match inner.runtime.as_ref() {
            Some(ProductRuntimeInstance::Resident(runtime)) => {
                let mut summary = runtime.product_state_summary();
                inner.traffic_carry.apply_to_runtime_summary(&mut summary);
                if let Value::Object(map) = &mut summary {
                    map.insert(
                        "lastTransitionAt".to_owned(),
                        json!(inner.last_transition_at.clone()),
                    );
                    map.insert(
                        "startedAt".to_owned(),
                        json!(inner.runtime_started_at.clone()),
                    );
                    map.insert("lastError".to_owned(), json!(inner.last_error.clone()));
                    map.insert("reloadCount".to_owned(), json!(inner.reload_count));
                    map.insert("stopCount".to_owned(), json!(inner.stop_count));
                    map.insert("lastReport".to_owned(), json!(inner.last_report.clone()));
                    map.insert("cleanup".to_owned(), inner.cleanup.summary());
                    map.insert("apply".to_owned(), inner.apply.summary());
                    map.insert("applyCoordinator".to_owned(), coordinator);
                    map.insert(
                        "activeGeneration".to_owned(),
                        json!(inner.active_generation),
                    );
                    map.insert(
                        "pendingProcessTransition".to_owned(),
                        json!(inner.pending_process_transition),
                    );
                }
                summary
            }
            Some(ProductRuntimeInstance::Fake(fake)) => json!({
                "running": true,
                "state": "running",
                "attachBackend": "fake-resident-runtime-test-only",
                "netnsLinkMode": "fake-test-only",
                "fakeRuntime": true,
                "startedAt": inner.runtime_started_at.clone().unwrap_or_else(|| fake.started_at.clone()),
                "tproxyPort": fake.tproxy_port,
                "lastTransitionAt": inner.last_transition_at,
                "lastError": inner.last_error,
                "reloadCount": inner.reload_count,
                "stopCount": inner.stop_count,
                "lastReport": inner.last_report,
                "cleanup": inner.cleanup.summary(),
                "apply": inner.apply.summary(),
                "applyCoordinator": coordinator,
                "activeGeneration": inner.active_generation,
                "pendingProcessTransition": inner.pending_process_transition,
            }),
            None => json!({
                "running": false,
                "state": if inner.cleanup.running {
                    "stopping"
                } else if inner.last_error.is_some() {
                    "error"
                } else {
                    "stopped"
                },
                "attachBackend": Value::Null,
                "netnsLinkMode": Value::Null,
                "fakeRuntime": product_runtime_fake_start_enabled(),
                "startedAt": Value::Null,
                "lastTransitionAt": inner.last_transition_at,
                "lastError": inner.last_error,
                "reloadCount": inner.reload_count,
                "stopCount": inner.stop_count,
                "lastReport": inner.last_report,
                "cleanup": inner.cleanup.summary(),
                "apply": inner.apply.summary(),
                "applyCoordinator": coordinator,
                "activeGeneration": inner.active_generation,
                "pendingProcessTransition": inner.pending_process_transition,
            }),
        }
    }

    pub(super) fn resident_dataplane_metrics_snapshot(&self) -> Option<Value> {
        let Ok(inner) = self.inner.lock() else {
            return None;
        };
        match inner.runtime.as_ref() {
            Some(ProductRuntimeInstance::Resident(runtime)) => runtime
                .resident_dataplane_metrics_snapshot()
                .map(|mut metrics| {
                    inner.traffic_carry.apply_to_metrics(&mut metrics);
                    metrics
                }),
            Some(ProductRuntimeInstance::Fake(_)) | None => None,
        }
    }

    pub(super) fn runtime_overview_delta_state(&self) -> RuntimeOverviewDeltaState {
        let Ok(inner) = self.inner.lock() else {
            return RuntimeOverviewDeltaState::default();
        };
        RuntimeOverviewDeltaState {
            reload_count: inner.reload_count,
        }
    }

    pub(super) fn group_selector_snapshot_map(&self) -> BTreeMap<String, Value> {
        let Ok(inner) = self.inner.lock() else {
            return BTreeMap::new();
        };
        match inner.runtime.as_ref() {
            Some(ProductRuntimeInstance::Resident(runtime)) => {
                runtime.group_selector_snapshot_map()
            }
            Some(ProductRuntimeInstance::Fake(_)) | None => BTreeMap::new(),
        }
    }

    pub(super) fn current_config(&self) -> Option<Config> {
        self.inner
            .lock()
            .ok()
            .and_then(|inner| inner.config.clone())
    }

    pub(super) fn node_latency_probe_handle(&self) -> Option<ProductRuntimeProbeHandle> {
        let Ok(inner) = self.inner.lock() else {
            return None;
        };
        match inner.runtime.as_ref() {
            Some(ProductRuntimeInstance::Resident(runtime)) => {
                runtime
                    .manual_probe_handle()
                    .map(|handle| ProductRuntimeProbeHandle::Resident {
                        handle: Box::new(handle),
                        config_content: inner.config_content.clone(),
                    })
            }
            Some(ProductRuntimeInstance::Fake(_)) => Some(ProductRuntimeProbeHandle::Fake),
            None if product_runtime_fake_start_enabled() => Some(ProductRuntimeProbeHandle::Fake),
            None => None,
        }
    }

    pub(super) fn current_probe_generation(&self) -> Option<u64> {
        let Ok(inner) = self.inner.lock() else {
            return None;
        };
        match inner.runtime.as_ref() {
            Some(ProductRuntimeInstance::Resident(runtime)) => runtime
                .manual_probe_handle()
                .map(|handle| handle.reload_generation()),
            Some(ProductRuntimeInstance::Fake(_)) | None => None,
        }
    }

    pub(super) fn prune_resident_event_log(&self) -> io::Result<()> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| io::Error::other("product runtime manager lock poisoned"))?;
        if let Some(ProductRuntimeInstance::Resident(runtime)) = inner.runtime.as_ref() {
            runtime.prune_event_log()?;
        }
        Ok(())
    }

    pub(super) fn clear_resident_event_log(&self) -> io::Result<()> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| io::Error::other("product runtime manager lock poisoned"))?;
        if let Some(ProductRuntimeInstance::Resident(runtime)) = inner.runtime.as_ref() {
            runtime.clear_event_log()?;
        }
        Ok(())
    }
}
