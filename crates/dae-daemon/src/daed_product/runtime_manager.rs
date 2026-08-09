use super::*;

static NEXT_ALLOCATOR_PUBLICATION_ID: AtomicU64 = AtomicU64::new(1);

pub(in crate::daed_product) mod activation_identity;
mod apply_state;
mod cleanup;
pub(in crate::daed_product) mod event_identity;
mod instance;
mod process_transition;
mod read_view;
use self::read_view::ProductRuntimeReadSnapshot;
mod readiness;
mod recovery;
mod startup_recovery;
mod stop;
mod summary;
mod traffic;
use super::runtime_transition::{
    RuntimeTransitionClass, RuntimeTransitionIdentity, classify_runtime_transition,
    process_owned_field_changes,
};
pub(super) use traffic::{RuntimeTrafficAvailability, RuntimeTrafficCarry, RuntimeTrafficRead};

pub(in crate::daed_product) use apply_state::ProductRuntimeApplySnapshot;
use apply_state::RuntimeApplyState;
use cleanup::{
    cleanup_replacement_before_start, cleanup_report_error, cleanup_runtime_instance_with_reclaim,
    cleanup_start_blocker_from_report, ensure_cleanup_allows_start_for_inner,
    spawn_background_cleanup,
};
pub(in crate::daed_product) use instance::PreparedProductRuntime;
#[cfg(test)]
pub(super) use instance::resident_dataplane_admission_detail;
pub(super) use instance::{
    preflight_product_runtime_candidate, prepare_product_runtime_candidate,
    product_runtime_fake_start_enabled, runtime_started_at_after_success,
    start_prepared_product_runtime_instance,
    start_product_runtime_instance_with_dns_reload_snapshot,
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
    runtime_health_seed_snapshots, runtime_instance_dns_reload_snapshot,
    runtime_instance_health_states,
};

#[derive(Debug)]
pub(super) struct ProductRuntimeManager {
    reconciler: RuntimeReconciler,
    lifecycle: Arc<Mutex<()>>,
    pub(super) inner: Arc<Mutex<ProductRuntimeState>>,
    interface_recovery: Mutex<ProductRuntimeInterfaceRecoverySupervisor>,
    startup_recovery: Mutex<ProductRuntimeStartupRecoverySupervisor>,
    process_http_config: Mutex<Option<ProductHttpWorkerConfig>>,
    pprof_runtime: Arc<ProductPprofRuntime>,
    runtime_required_for_readiness: AtomicBool,
    #[cfg(test)]
    summary_render_barrier: Mutex<Option<Arc<std::sync::Barrier>>>,
}

#[derive(Debug, Default)]
pub(super) struct ProductRuntimeState {
    pub(super) runtime: Option<ProductRuntimeInstance>,
    pub(super) config: Option<Arc<Config>>,
    pub(super) config_content: Option<Arc<str>>,
    pub(super) last_error: Option<String>,
    pub(super) last_transition_at: Option<String>,
    pub(super) runtime_started_at: Option<String>,
    pub(super) last_report: Option<Arc<Value>>,
    pub(super) reload_count: u64,
    pub(super) allocator_publication_id: u64,
    pub(super) stop_count: u64,
    pub(super) lifecycle_epoch: u64,
    pub(super) traffic_carry: RuntimeTrafficCarry,
    pub(super) cleanup: RuntimeCleanupState,
    pub(super) apply: RuntimeApplyState,
    pub(super) active_generation: Option<String>,
    pub(super) pending_process_transition: Option<Value>,
    pub(super) transition_identity: Option<RuntimeTransitionIdentity>,
    pub(super) process_baseline_config: Option<Arc<Config>>,
}

#[derive(Debug, Clone, Default)]
pub(super) struct RuntimeCleanupState {
    pub(super) running: bool,
    pub(super) epoch: u64,
    pub(super) mode: Option<String>,
    pub(super) started_at: Option<String>,
    pub(super) finished_at: Option<String>,
    pub(super) last_report: Option<Arc<Value>>,
    pub(super) last_error: Option<String>,
    pub(super) last_start_blocker: Option<String>,
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
        self.last_start_blocker = None;
    }

    pub(super) fn finish(&mut self, report: Option<Value>) {
        self.running = false;
        self.finished_at = Some(now_text());
        self.last_error = cleanup_report_error(report.as_ref());
        self.last_start_blocker = cleanup_start_blocker_from_report(report.as_ref());
        self.last_report = report.map(Arc::new);
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
            "lastStartBlocker": self.last_start_blocker,
            "lastReport": self.last_report.as_deref(),
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
        config_content: Option<Arc<str>>,
    },
    Fake,
}

impl ProductRuntimeProbeHandle {
    pub(super) fn probe_node_latencies_streaming_without_group_update<F, C>(
        &self,
        control_runtime: &ProductControlRuntime,
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
                        LatencyProbeHelperInput::active_runtime(config_content),
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
                                &err.seen_links,
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
                let snapshots = fake_runtime_probe_node_latencies(control_runtime, links);
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
const PRODUCT_RUNTIME_INTERFACE_RECOVERY_POLL: Duration = Duration::from_millis(250);
const PRODUCT_RUNTIME_STARTUP_RECOVERY_POLL: Duration = Duration::from_secs(2);
const PRODUCT_RUNTIME_RECOVERY_STOP_CHECK_INTERVAL: Duration = Duration::from_millis(100);
const PRODUCT_RUNTIME_INTERFACE_RECOVERY_RETRY: Duration = Duration::from_secs(30);
const PRODUCT_RUNTIME_INTERFACE_RECOVERY_SOURCE: &str = "interface-monitor";

impl ProductRuntimeManager {
    #[cfg(test)]
    pub(super) fn new() -> Self {
        Self::new_with_state(None)
    }

    pub(super) fn new_for_state(state: PathBuf) -> Self {
        Self::new_with_state(Some(state))
    }

    fn new_with_state(state: Option<PathBuf>) -> Self {
        let coordinator = RuntimeApplyCoordinator::new();
        let reconciler = RuntimeReconciler::new(coordinator.clone());
        let lifecycle = Arc::new(Mutex::new(()));
        let inner = Arc::new(Mutex::new(ProductRuntimeState::default()));
        let interface_recovery = ProductRuntimeInterfaceRecoverySupervisor::start(
            coordinator.clone(),
            Arc::clone(&lifecycle),
            Arc::clone(&inner),
            state,
        );
        Self {
            reconciler,
            lifecycle,
            inner,
            interface_recovery: Mutex::new(interface_recovery),
            startup_recovery: Mutex::new(ProductRuntimeStartupRecoverySupervisor::default()),
            process_http_config: Mutex::new(None),
            pprof_runtime: Arc::new(ProductPprofRuntime::default()),
            runtime_required_for_readiness: AtomicBool::new(false),
            #[cfg(test)]
            summary_render_barrier: Mutex::new(None),
        }
    }

    #[cfg(test)]
    pub(super) fn reload_with_config_content(
        &self,
        config: impl Into<Arc<Config>>,
        config_content: Option<String>,
        source: &str,
        latency_seed: &[Value],
    ) -> Result<RuntimeStartOutcome, String> {
        let prepared = prepare_product_runtime_candidate(config.into())?;
        self.reload_prepared_with_config_content(prepared, config_content, source, latency_seed)
    }

    pub(super) fn reload_prepared_with_config_content(
        &self,
        prepared: PreparedProductRuntime,
        config_content: Option<String>,
        source: &str,
        latency_seed: &[Value],
    ) -> Result<RuntimeStartOutcome, String> {
        reload_prepared_product_runtime_with_config_content(
            &self.lifecycle,
            &self.inner,
            prepared,
            config_content.map(Arc::<str>::from),
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

    pub(super) fn shutdown_recovery_supervisors(&self) -> Result<(), String> {
        self.interface_recovery
            .lock()
            .map_err(|_| "interface recovery supervisor lock poisoned".to_owned())?
            .shutdown();
        self.startup_recovery
            .lock()
            .map_err(|_| "startup recovery supervisor lock poisoned".to_owned())?
            .shutdown();
        Ok(())
    }

    #[cfg(test)]
    pub(in crate::daed_product) fn begin_apply(
        &self,
        intent: RuntimeApplyIntent,
    ) -> Result<RuntimeApplyPermit<'_>, String> {
        self.reconciler.begin_exclusive(intent)
    }

    pub(in crate::daed_product) fn begin_reconcile(
        &self,
        intent: RuntimeApplyIntent,
    ) -> RuntimeReconcileRequest {
        self.reconciler.begin(intent)
    }
}

impl Drop for ProductRuntimeManager {
    fn drop(&mut self) {
        if let Ok(supervisor) = self.interface_recovery.get_mut() {
            supervisor.shutdown();
        }
        if let Ok(supervisor) = self.startup_recovery.get_mut() {
            supervisor.shutdown();
        }
    }
}

fn reload_prepared_product_runtime_with_config_content(
    lifecycle: &Arc<Mutex<()>>,
    inner: &Arc<Mutex<ProductRuntimeState>>,
    prepared: PreparedProductRuntime,
    config_content: Option<Arc<str>>,
    source: &str,
    latency_seed: &[Value],
) -> Result<RuntimeStartOutcome, String> {
    let config = Arc::clone(prepared.config());
    let desired_identity = prepared.transition_identity();
    let transition = {
        let state = inner
            .lock()
            .map_err(|_| "product runtime manager lock poisoned".to_owned())?;
        match (state.runtime.as_ref(), state.config.as_deref()) {
            (Some(_), Some(active)) => classify_runtime_transition(
                active,
                state.transition_identity,
                &config,
                desired_identity,
            ),
            (None, _) | (Some(_), None) => RuntimeTransitionClass::KernelRebind,
        }
    };
    match transition {
        RuntimeTransitionClass::NoChange | RuntimeTransitionClass::ProcessRestart => {
            publish_runtime_metadata_transition(
                lifecycle,
                inner,
                config,
                config_content,
                desired_identity,
                transition,
                source,
            )
        }
        RuntimeTransitionClass::GenerationSwap if !product_runtime_fake_start_enabled() => {
            publish_resident_runtime_generation(
                lifecycle,
                inner,
                prepared,
                config_content,
                desired_identity,
                source,
                latency_seed,
            )
        }
        RuntimeTransitionClass::GenerationSwap | RuntimeTransitionClass::KernelRebind => {
            replace_prepared_product_runtime_with_config_content(
                lifecycle,
                inner,
                prepared,
                config_content,
                source,
                latency_seed,
                transition,
            )
        }
    }
}

fn process_baseline_after_physical_start(
    previous: Option<&Config>,
    desired: &Config,
) -> Arc<Config> {
    let Some(previous) = previous else {
        return Arc::new(desired.clone());
    };
    let mut baseline = previous.clone();
    baseline.global.resident_tcp_flow_stack_bytes = desired.global.resident_tcp_flow_stack_bytes;
    baseline.global.resident_tcp_runtime_workers = desired.global.resident_tcp_runtime_workers;
    baseline.global.resident_event_queue_depth = desired.global.resident_event_queue_depth;
    Arc::new(baseline)
}

fn record_runtime_publication(state: &mut ProductRuntimeState) {
    state.reload_count = state.reload_count.saturating_add(1);
    state.allocator_publication_id = NEXT_ALLOCATOR_PUBLICATION_ID.fetch_add(1, Ordering::Relaxed);
}

#[allow(clippy::too_many_arguments)]
fn publish_resident_runtime_generation(
    lifecycle: &Arc<Mutex<()>>,
    inner: &Arc<Mutex<ProductRuntimeState>>,
    prepared: PreparedProductRuntime,
    config_content: Option<Arc<str>>,
    desired_identity: Option<RuntimeTransitionIdentity>,
    source: &str,
    latency_seed: &[Value],
) -> Result<RuntimeStartOutcome, String> {
    let config = Arc::clone(prepared.config());
    let resident = prepared.into_resident_generation()?;
    let _lifecycle = lifecycle
        .lock()
        .map_err(|_| "product runtime lifecycle lock poisoned".to_owned())?;
    ensure_cleanup_allows_start_for_inner(inner)?;
    let mut state = inner
        .lock()
        .map_err(|_| "product runtime manager lock poisoned".to_owned())?;
    let preserve_dns_cache = state
        .config
        .as_ref()
        .is_some_and(|active| active.dns == config.dns);
    let live_latency_seed = state
        .runtime
        .as_ref()
        .map(runtime_instance_health_states)
        .unwrap_or_default();
    let latency_seed =
        runtime_health_seed_snapshots(latency_seed.iter().cloned().chain(live_latency_seed));
    let runtime = match state.runtime.as_mut() {
        Some(ProductRuntimeInstance::Resident(runtime)) => runtime,
        Some(ProductRuntimeInstance::Fake(_)) => {
            return Err("cannot publish a resident generation on a fake runtime".to_owned());
        }
        None => return Err("cannot publish a generation without an active runtime".to_owned()),
    };
    let publication =
        runtime.publish_prepared_generation(resident, &latency_seed, preserve_dns_cache)?;
    state.lifecycle_epoch = state.lifecycle_epoch.wrapping_add(1);
    state.config = Some(config);
    state.config_content = config_content;
    state.transition_identity = desired_identity;
    record_runtime_publication(&mut state);
    state.last_error = None;
    state.last_transition_at = Some(now_text());
    let report = json!({
        "status": "pass",
        "runtimeControl": "resident-production-runtime-manager",
        "source": source,
        "transition": RuntimeTransitionClass::GenerationSwap.name(),
        "publication": publication,
        "allocatorPublicationId": state.allocator_publication_id,
    });
    state.last_report = Some(Arc::new(report.clone()));
    Ok(RuntimeStartOutcome { report })
}

#[allow(clippy::too_many_arguments)]
fn publish_runtime_metadata_transition(
    lifecycle: &Arc<Mutex<()>>,
    inner: &Arc<Mutex<ProductRuntimeState>>,
    config: Arc<Config>,
    config_content: Option<Arc<str>>,
    desired_identity: Option<RuntimeTransitionIdentity>,
    transition: RuntimeTransitionClass,
    source: &str,
) -> Result<RuntimeStartOutcome, String> {
    let _lifecycle = lifecycle
        .lock()
        .map_err(|_| "product runtime lifecycle lock poisoned".to_owned())?;
    ensure_cleanup_allows_start_for_inner(inner)?;
    let mut state = inner
        .lock()
        .map_err(|_| "product runtime manager lock poisoned".to_owned())?;
    if state.runtime.is_none() {
        return Err("cannot publish runtime metadata without an active runtime".to_owned());
    }
    state.lifecycle_epoch = state.lifecycle_epoch.wrapping_add(1);
    state.config = Some(config);
    state.config_content = config_content;
    state.transition_identity = desired_identity;
    record_runtime_publication(&mut state);
    state.last_error = None;
    state.last_transition_at = Some(now_text());
    let report = json!({
        "status": "pass",
        "runtimeControl": "resident-production-runtime-manager",
        "source": source,
        "transition": transition.name(),
        "generationPublished": false,
        "physicalRuntimeReused": true,
        "processRestartPending": transition == RuntimeTransitionClass::ProcessRestart,
        "allocatorPublicationId": state.allocator_publication_id,
    });
    state.last_report = Some(Arc::new(report.clone()));
    Ok(RuntimeStartOutcome { report })
}

#[allow(clippy::too_many_arguments)]
fn replace_prepared_product_runtime_with_config_content(
    lifecycle: &Arc<Mutex<()>>,
    inner: &Arc<Mutex<ProductRuntimeState>>,
    prepared: PreparedProductRuntime,
    config_content: Option<Arc<str>>,
    source: &str,
    latency_seed: &[Value],
    transition: RuntimeTransitionClass,
) -> Result<RuntimeStartOutcome, String> {
    let config = Arc::clone(prepared.config());
    let desired_identity = prepared.transition_identity();
    let _lifecycle = lifecycle
        .lock()
        .map_err(|_| "product runtime lifecycle lock poisoned".to_owned())?;
    ensure_cleanup_allows_start_for_inner(inner)?;
    let (
        previous_runtime,
        previous_config,
        previous_config_content,
        previous_transition_identity,
        previous_process_baseline_config,
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
        let previous_transition_identity = inner.transition_identity;
        let previous_process_baseline_config = inner.process_baseline_config.clone();
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
            previous_transition_identity,
            previous_process_baseline_config,
            previous_runtime_started_at,
            previous_runtime_was_running,
            inner.lifecycle_epoch,
        )
    };

    let live_latency_seed = previous_runtime
        .as_ref()
        .map(runtime_instance_health_states)
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
        runtime_health_seed_snapshots(latency_seed.iter().cloned().chain(live_latency_seed));
    let previous_cleanup_report = if previous_runtime_was_running {
        cleanup_replacement_before_start(inner, lifecycle_epoch, previous_runtime)?
    } else {
        drop(previous_runtime);
        None
    };
    let previous_cleanup_error = cleanup_report_error(previous_cleanup_report.as_ref());
    let previous_cleanup_start_blocker =
        cleanup_start_blocker_from_report(previous_cleanup_report.as_ref());
    match start_prepared_product_runtime_instance(
        prepared,
        source,
        &latency_seed,
        dns_reload_snapshot.clone(),
    ) {
        Ok((runtime, mut report)) => {
            if let Value::Object(report) = &mut report {
                report.insert("transition".to_owned(), json!(transition.name()));
                report.insert(
                    "previousRuntimeCleanup".to_owned(),
                    previous_cleanup_report.clone().unwrap_or(Value::Null),
                );
                report.insert(
                    "previousRuntimeCleanupDegraded".to_owned(),
                    json!(previous_cleanup_error.is_some()),
                );
                report.insert(
                    "previousRuntimeCleanupExecution".to_owned(),
                    json!(if previous_runtime_was_running {
                        "synchronous-before-start"
                    } else {
                        "not-applicable"
                    }),
                );
            }
            let mut inner = inner
                .lock()
                .map_err(|_| "product runtime manager lock poisoned".to_owned())?;
            if inner.lifecycle_epoch != lifecycle_epoch {
                drop(inner);
                drop(runtime);
                if previous_runtime_was_running {
                    allocator_request_reclaim(AllocatorReclaimReason::ReloadFailedAfterCleanup);
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
            inner.transition_identity = desired_identity;
            inner.process_baseline_config = Some(process_baseline_after_physical_start(
                previous_process_baseline_config.as_deref(),
                inner
                    .config
                    .as_deref()
                    .expect("committed runtime config is present"),
            ));
            record_runtime_publication(&mut inner);
            if let Value::Object(report) = &mut report {
                report.insert(
                    "allocatorPublicationId".to_owned(),
                    json!(inner.allocator_publication_id),
                );
            }
            inner.last_error = None;
            inner.cleanup.last_start_blocker = None;
            inner.last_transition_at = Some(transition_at.clone());
            inner.runtime_started_at = Some(runtime_started_at_after_success(
                previous_runtime_was_running,
                previous_runtime_started_at,
                transition_at,
            ));
            inner.last_report = Some(Arc::new(report.clone()));
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
                    allocator_request_reclaim(AllocatorReclaimReason::ReloadFailedAfterCleanup);
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
                        inner.transition_identity = previous_transition_identity;
                        inner.process_baseline_config = previous_process_baseline_config.clone();
                        inner.runtime_started_at = previous_runtime_started_at.clone();
                        inner.last_report = Some(Arc::new(report));
                        true
                    }
                    Err(restore_err) => {
                        inner.runtime = None;
                        inner.config = None;
                        inner.config_content = None;
                        inner.transition_identity = None;
                        inner.process_baseline_config = None;
                        inner.runtime_started_at = None;
                        inner.last_error = Some(format!(
                            "{start_err}\nrestore failed while restoring previous product runtime: {restore_err}"
                        ));
                        false
                    }
                });
            let mut message = match restored {
                Some(true) => {
                    format!("{start_err}\nrestore: restored previous product runtime")
                }
                Some(false) => inner
                    .last_error
                    .clone()
                    .unwrap_or_else(|| start_err.clone()),
                None => start_err,
            };
            if let Some(blocker) = previous_cleanup_start_blocker.as_deref() {
                message.push_str("\nprevious runtime conflict cleanup: ");
                message.push_str(blocker);
            } else if let Some(cleanup_error) = previous_cleanup_error.as_deref() {
                message.push_str("\nprevious runtime retirement degraded: ");
                message.push_str(cleanup_error);
            }
            inner.last_transition_at = Some(now_text());
            if restored != Some(true) {
                inner.runtime_started_at = None;
            }
            inner.last_error = Some(message.clone());
            drop(inner);
            if previous_runtime_was_running {
                allocator_request_reclaim(AllocatorReclaimReason::ReloadFailedAfterCleanup);
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
        let coordinator = self.reconciler.summary();
        let fake_runtime_enabled = product_runtime_fake_start_enabled();
        #[cfg(test)]
        let render_barrier = self
            .summary_render_barrier
            .lock()
            .ok()
            .and_then(|barrier| barrier.clone());
        let Ok(inner) = self.inner.lock() else {
            return json!({
                "running": false,
                "state": "error",
                "attachBackend": "unavailable",
                "netnsLinkMode": "unavailable",
                "error": "product runtime manager lock poisoned",
            });
        };
        let snapshot =
            ProductRuntimeReadSnapshot::capture(&inner, coordinator, fake_runtime_enabled);
        drop(inner);
        #[cfg(test)]
        if let Some(barrier) = render_barrier {
            barrier.wait();
            barrier.wait();
        }
        let mut rendered = snapshot.render();
        if let Value::Object(object) = &mut rendered {
            object.insert("pprof".to_owned(), self.pprof_runtime.status());
        }
        rendered
    }

    pub(super) fn configure_pprof_port(&self, port: u16) -> Result<(), String> {
        self.pprof_runtime.apply_port(port)
    }

    pub(super) fn pprof_port(&self) -> u16 {
        self.pprof_runtime.port()
    }

    pub(super) fn runtime_overview_delta_state(&self) -> RuntimeOverviewDeltaState {
        let Ok(inner) = self.inner.lock() else {
            return RuntimeOverviewDeltaState::default();
        };
        RuntimeOverviewDeltaState {
            reload_count: inner.reload_count,
        }
    }

    pub(super) fn allocator_publication_id(&self) -> u64 {
        self.inner
            .lock()
            .map(|inner| inner.allocator_publication_id)
            .unwrap_or(u64::MAX)
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

    pub(super) fn current_config(&self) -> Option<Arc<Config>> {
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

    pub(super) fn latency_probe_lifecycle_epoch(&self) -> u64 {
        self.inner
            .lock()
            .map(|inner| inner.lifecycle_epoch)
            .unwrap_or(u64::MAX)
    }

    pub(super) fn active_generation(&self) -> Option<String> {
        self.inner
            .lock()
            .ok()
            .and_then(|inner| inner.active_generation.clone())
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
