use super::*;

mod cleanup;
mod instance;
mod recovery;
mod summary;

use cleanup::{
    cleanup_report_error, cleanup_runtime_instance, cleanup_runtime_instance_with_reclaim,
    cleanup_start_blocker_from_report, ensure_cleanup_allows_start_for_inner,
    spawn_background_cleanup,
};
#[cfg(test)]
pub(super) use instance::resident_dataplane_admission_detail;
pub(super) use instance::{
    product_runtime_fake_start_enabled, runtime_started_at_after_success,
    start_product_runtime_instance,
};
use recovery::ProductRuntimeInterfaceRecoverySupervisor;
#[cfg(test)]
pub(super) use recovery::resident_interface_recovery_request;
use summary::{
    apply_runtime_traffic_metric_carry, runtime_instance_node_latencies,
    runtime_traffic_metric_u64, runtime_traffic_metrics_snapshot,
    successful_latency_seed_snapshots,
};

#[derive(Debug)]
pub(super) struct ProductRuntimeManager {
    lifecycle: Arc<Mutex<()>>,
    pub(super) inner: Arc<Mutex<ProductRuntimeState>>,
    interface_recovery: ProductRuntimeInterfaceRecoverySupervisor,
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
    pub(super) fn probe_node_latencies_streaming_without_group_update<F>(
        &self,
        links: &[String],
        mut on_snapshots: F,
    ) -> Vec<Value>
    where
        F: FnMut(&[Value]),
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
                        links,
                        |snapshot| on_snapshots(std::slice::from_ref(snapshot)),
                    ) {
                        Ok(snapshots) => snapshots,
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
                            let mut snapshots = err.snapshots;
                            snapshots.extend(failures);
                            snapshots
                        }
                    }
                } else {
                    let snapshots = handle.probe_node_latencies_without_group_update(links);
                    on_snapshots(&snapshots);
                    snapshots
                }
            }
            Self::Fake => {
                let snapshots = fake_runtime_probe_node_latencies(links);
                on_snapshots(&snapshots);
                snapshots
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
    pub(super) resident_dataplane_metrics: Option<Value>,
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
        let lifecycle = Arc::new(Mutex::new(()));
        let inner = Arc::new(Mutex::new(ProductRuntimeState::default()));
        let interface_recovery = ProductRuntimeInterfaceRecoverySupervisor::start(
            Arc::clone(&lifecycle),
            Arc::clone(&inner),
        );
        Self {
            lifecycle,
            inner,
            interface_recovery,
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
}

impl Drop for ProductRuntimeManager {
    fn drop(&mut self) {
        self.interface_recovery.shutdown();
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
        return Err(format!(
            "previous product runtime cleanup failed before reload: {blocker}"
        ));
    }
    match start_product_runtime_instance(&config, source, &latency_seed) {
        Ok((runtime, report)) => {
            let mut inner = inner
                .lock()
                .map_err(|_| "product runtime manager lock poisoned".to_owned())?;
            if inner.lifecycle_epoch != lifecycle_epoch {
                drop(inner);
                drop(runtime);
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
                    start_product_runtime_instance(previous, "restore", &latency_seed)
                })
            } else {
                None
            };
            let mut inner = inner
                .lock()
                .map_err(|_| "product runtime manager lock poisoned".to_owned())?;
            if inner.lifecycle_epoch != lifecycle_epoch {
                if let Some(Ok((runtime, _))) = restore_result {
                    drop(inner);
                    drop(runtime);
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
            Err(message)
        }
    }
}

impl ProductRuntimeManager {
    pub(super) fn stop(&self) -> Result<Value, String> {
        let stop_started = Instant::now();
        let _lifecycle = self
            .lifecycle
            .lock()
            .map_err(|_| "product runtime lifecycle lock poisoned".to_owned())?;
        let (stopped_runtime, was_running, cleanup_epoch) = {
            let mut inner = self
                .inner
                .lock()
                .map_err(|_| "product runtime manager lock poisoned".to_owned())?;
            inner.lifecycle_epoch = inner.lifecycle_epoch.wrapping_add(1);
            let was_running = inner.runtime.is_some();
            let stopped_runtime = inner.runtime.take();
            if was_running {
                let cleanup_epoch = inner.lifecycle_epoch;
                inner.cleanup.begin(cleanup_epoch, "background-stop");
            }
            inner.config = None;
            inner.config_content = None;
            inner.traffic_carry = RuntimeTrafficCarry::default();
            inner.runtime_started_at = None;
            inner.stop_count += 1;
            inner.last_transition_at = Some(now_text());
            inner.last_report = None;
            inner.last_error = None;
            (stopped_runtime, was_running, inner.lifecycle_epoch)
        };
        if was_running {
            spawn_background_cleanup(Arc::clone(&self.inner), cleanup_epoch, stopped_runtime);
        } else {
            drop(stopped_runtime);
        }
        let stop_elapsed_ns = stop_started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64;
        Ok(json!({
            "stopped": true,
            "wasRunning": was_running,
            "runtimeControl": "resident-production-runtime-manager",
            "fakeRuntime": product_runtime_fake_start_enabled(),
            "allocatorReclaim": Value::Null,
            "stopElapsedNs": stop_elapsed_ns,
            "stopElapsedMs": stop_elapsed_ns / 1_000_000,
            "cleanupStarted": was_running,
            "cleanupEpoch": if was_running { json!(cleanup_epoch) } else { Value::Null },
            "cleanupMode": if was_running { json!("background-stop") } else { Value::Null },
            "cleanupReport": Value::Null,
        }))
    }

    pub(super) fn stop_and_wait_for_cleanup(&self, cleanup_mode: &str) -> Result<Value, String> {
        let stop_started = Instant::now();
        let _lifecycle = self
            .lifecycle
            .lock()
            .map_err(|_| "product runtime lifecycle lock poisoned".to_owned())?;
        let (stopped_runtime, was_running, cleanup_epoch) = {
            let mut inner = self
                .inner
                .lock()
                .map_err(|_| "product runtime manager lock poisoned".to_owned())?;
            inner.lifecycle_epoch = inner.lifecycle_epoch.wrapping_add(1);
            let was_running = inner.runtime.is_some();
            let stopped_runtime = inner.runtime.take();
            if was_running {
                let cleanup_epoch = inner.lifecycle_epoch;
                inner.cleanup.begin(cleanup_epoch, cleanup_mode);
            }
            inner.config = None;
            inner.config_content = None;
            inner.traffic_carry = RuntimeTrafficCarry::default();
            inner.runtime_started_at = None;
            inner.stop_count += 1;
            inner.last_transition_at = Some(now_text());
            inner.last_report = None;
            inner.last_error = None;
            (stopped_runtime, was_running, inner.lifecycle_epoch)
        };

        let cleanup_report = if was_running {
            let cleanup_report = cleanup_runtime_instance_with_reclaim(
                stopped_runtime,
                AllocatorReclaimReason::StopRuntime,
            );
            let mut inner = self
                .inner
                .lock()
                .map_err(|_| "product runtime manager lock poisoned after cleanup".to_owned())?;
            if inner.cleanup.epoch == cleanup_epoch {
                inner.cleanup.finish(cleanup_report.clone());
            }
            cleanup_report
        } else {
            drop(stopped_runtime);
            None
        };
        let stop_elapsed_ns = stop_started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64;
        Ok(json!({
            "stopped": true,
            "wasRunning": was_running,
            "runtimeControl": "resident-production-runtime-manager",
            "fakeRuntime": product_runtime_fake_start_enabled(),
            "allocatorReclaim": Value::Null,
            "stopElapsedNs": stop_elapsed_ns,
            "stopElapsedMs": stop_elapsed_ns / 1_000_000,
            "cleanupStarted": was_running,
            "cleanupEpoch": if was_running { json!(cleanup_epoch) } else { Value::Null },
            "cleanupMode": if was_running { json!(cleanup_mode) } else { Value::Null },
            "cleanupReport": cleanup_report,
        }))
    }

    #[cfg(test)]
    pub(super) fn wait_for_cleanup_idle(&self, timeout: Duration) -> bool {
        cleanup::wait_for_cleanup_idle_for_inner(&self.inner, timeout)
    }

    #[cfg(test)]
    pub(super) fn ensure_cleanup_allows_start(&self) -> Result<(), String> {
        ensure_cleanup_allows_start_for_inner(&self.inner)
    }

    pub(super) fn summary(&self) -> Value {
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
        let resident_dataplane_metrics = match inner.runtime.as_ref() {
            Some(ProductRuntimeInstance::Resident(runtime)) => runtime
                .resident_dataplane_metrics_snapshot()
                .map(|mut metrics| {
                    inner.traffic_carry.apply_to_metrics(&mut metrics);
                    metrics
                }),
            Some(ProductRuntimeInstance::Fake(_)) | None => None,
        };
        RuntimeOverviewDeltaState {
            reload_count: inner.reload_count,
            resident_dataplane_metrics,
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

    pub(super) fn node_latency_probe_batch_size(&self, unique_link_count: usize) -> Option<usize> {
        self.node_latency_probe_handle()
            .map(|handle| handle.probe_batch_size(unique_link_count))
    }

    pub(super) fn probe_node_latencies_streaming<F>(
        &self,
        links: &[String],
        mut on_snapshots: F,
    ) -> Option<Vec<Value>>
    where
        F: FnMut(&[Value]),
    {
        let handle = self.node_latency_probe_handle()?;
        let generation = handle.probe_generation();
        let mut emitted_snapshots = Vec::<Value>::new();
        let snapshots =
            handle.probe_node_latencies_streaming_without_group_update(links, |snapshots| {
                if let Some(generation) = generation
                    && self.current_probe_generation() != Some(generation)
                {
                    return;
                }
                handle.apply_latency_probe_snapshots_to_groups(snapshots);
                on_snapshots(snapshots);
                emitted_snapshots.extend_from_slice(snapshots);
            });
        if let Some(generation) = generation
            && self.current_probe_generation() != Some(generation)
        {
            let failures = latency_probe_failure_snapshots_for_unseen_links(
                links,
                generation,
                "manual latency probe result discarded",
                "resident runtime generation changed while latency probe was running",
                &emitted_snapshots,
            );
            if !failures.is_empty() {
                on_snapshots(&failures);
                let mut snapshots = snapshots;
                snapshots.extend(failures);
                return Some(snapshots);
            }
        }
        Some(snapshots)
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
