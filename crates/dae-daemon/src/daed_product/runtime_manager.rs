use super::*;
#[derive(Debug)]
pub(super) struct ProductRuntimeManager {
    pub(super) inner: Mutex<ProductRuntimeState>,
}

#[derive(Debug, Default)]
pub(super) struct ProductRuntimeState {
    pub(super) runtime: Option<ProductRuntimeInstance>,
    pub(super) config: Option<Config>,
    pub(super) last_error: Option<String>,
    pub(super) last_transition_at: Option<String>,
    pub(super) runtime_started_at: Option<String>,
    pub(super) last_report: Option<Value>,
    pub(super) reload_count: u64,
    pub(super) stop_count: u64,
    pub(super) lifecycle_epoch: u64,
    pub(super) traffic_carry: RuntimeTrafficCarry,
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
    Resident(Box<ResidentManualProbeHandle>),
    Fake,
}

impl ProductRuntimeProbeHandle {
    pub(super) fn probe_node_latencies(&self, links: &[String]) -> Vec<Value> {
        match self {
            Self::Resident(handle) => handle.probe_node_latencies(links),
            Self::Fake => fake_runtime_probe_node_latencies(links),
        }
    }

    pub(super) fn probe_concurrency(&self) -> usize {
        match self {
            Self::Resident(handle) => handle.probe_concurrency(),
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
    ReloadSignal,
    ReloadSubscriptionRefresh,
}

impl ProductRuntimeLifecycleLogMode {
    pub(super) fn source(self) -> &'static str {
        match self {
            Self::StartupRestore => "startup-restore",
            Self::ReloadSignal => "signal",
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

impl ProductRuntimeManager {
    pub(super) fn new() -> Self {
        Self {
            inner: Mutex::new(ProductRuntimeState::default()),
        }
    }

    pub(super) fn reload(
        &self,
        config: Config,
        source: &str,
    ) -> Result<RuntimeStartOutcome, String> {
        let (
            previous_runtime,
            previous_config,
            previous_runtime_started_at,
            previous_runtime_was_running,
            lifecycle_epoch,
        ) = {
            let mut inner = self
                .inner
                .lock()
                .map_err(|_| "product runtime manager lock poisoned".to_owned())?;
            inner.lifecycle_epoch = inner.lifecycle_epoch.wrapping_add(1);
            let previous_runtime = inner.runtime.take();
            let previous_config = inner.config.clone();
            let previous_runtime_started_at = inner.runtime_started_at.clone();
            let previous_runtime_was_running = previous_runtime.is_some();
            if let Some(runtime) = previous_runtime.as_ref() {
                inner.traffic_carry = inner.traffic_carry.absorb_runtime(runtime);
            }
            (
                previous_runtime,
                previous_config,
                previous_runtime_started_at,
                previous_runtime_was_running,
                inner.lifecycle_epoch,
            )
        };

        drop(previous_runtime);
        match start_product_runtime_instance(&config, source) {
            Ok((runtime, report)) => {
                let mut inner = self
                    .inner
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
                let should_restore = self
                    .inner
                    .lock()
                    .map(|inner| inner.lifecycle_epoch == lifecycle_epoch)
                    .unwrap_or(false);
                let restore_result = if should_restore {
                    previous_config
                        .as_ref()
                        .map(|previous| start_product_runtime_instance(previous, "restore"))
                } else {
                    None
                };
                let mut inner = self
                    .inner
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
                        inner.runtime_started_at = previous_runtime_started_at.clone();
                        inner.last_report = Some(report);
                        true
                    }
                    Err(restore_err) => {
                        inner.runtime = None;
                        inner.config = None;
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

    pub(super) fn stop(&self) -> Result<Value, String> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| "product runtime manager lock poisoned".to_owned())?;
        inner.lifecycle_epoch = inner.lifecycle_epoch.wrapping_add(1);
        let was_running = inner.runtime.is_some();
        inner.runtime.take();
        let reclaim = was_running.then(|| allocator_reclaim(AllocatorReclaimReason::StopRuntime));
        inner.config = None;
        inner.traffic_carry = RuntimeTrafficCarry::default();
        inner.runtime_started_at = None;
        inner.stop_count += 1;
        inner.last_transition_at = Some(now_text());
        inner.last_report = None;
        inner.last_error = None;
        Ok(json!({
            "stopped": true,
            "wasRunning": was_running,
            "runtimeControl": "resident-production-runtime-manager",
            "fakeRuntime": product_runtime_fake_start_enabled(),
            "allocatorReclaim": reclaim,
        }))
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
            }),
            None => json!({
                "running": false,
                "state": if inner.last_error.is_some() { "error" } else { "stopped" },
                "attachBackend": Value::Null,
                "netnsLinkMode": Value::Null,
                "fakeRuntime": product_runtime_fake_start_enabled(),
                "startedAt": Value::Null,
                "lastTransitionAt": inner.last_transition_at,
                "lastError": inner.last_error,
                "reloadCount": inner.reload_count,
                "stopCount": inner.stop_count,
                "lastReport": inner.last_report,
            }),
        }
    }

    pub(super) fn snapshot_node_latencies(&self) -> Vec<Value> {
        let Ok(inner) = self.inner.lock() else {
            return Vec::new();
        };
        match inner.runtime.as_ref() {
            Some(ProductRuntimeInstance::Resident(runtime)) => runtime.snapshot_node_latencies(),
            Some(ProductRuntimeInstance::Fake(_)) | None => Vec::new(),
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
            Some(ProductRuntimeInstance::Resident(runtime)) => runtime
                .manual_probe_handle()
                .map(|handle| ProductRuntimeProbeHandle::Resident(Box::new(handle))),
            Some(ProductRuntimeInstance::Fake(_)) => Some(ProductRuntimeProbeHandle::Fake),
            None if product_runtime_fake_start_enabled() => Some(ProductRuntimeProbeHandle::Fake),
            None => None,
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

fn runtime_traffic_metrics_snapshot(runtime: &ProductRuntimeInstance) -> Option<Value> {
    match runtime {
        ProductRuntimeInstance::Resident(runtime) => runtime.resident_dataplane_metrics_snapshot(),
        ProductRuntimeInstance::Fake(_) => None,
    }
}

fn apply_runtime_traffic_metric_carry(metrics: &mut Value, key: &str, carry: u64) {
    if carry == 0 {
        return;
    }
    metrics[key] = json!(runtime_traffic_metric_u64(metrics, key).saturating_add(carry));
}

fn runtime_traffic_metric_u64(metrics: &Value, key: &str) -> u64 {
    metrics
        .get(key)
        .and_then(|value| {
            value
                .as_u64()
                .or_else(|| value.as_str().and_then(|value| value.parse::<u64>().ok()))
        })
        .unwrap_or(0)
}

pub(super) fn runtime_started_at_after_success(
    previous_runtime_was_running: bool,
    previous_runtime_started_at: Option<String>,
    transition_at: String,
) -> String {
    if previous_runtime_was_running {
        previous_runtime_started_at.unwrap_or(transition_at)
    } else {
        transition_at
    }
}

pub(super) fn start_product_runtime_instance(
    config: &Config,
    source: &str,
) -> Result<(ProductRuntimeInstance, Value), String> {
    if product_runtime_fake_start_enabled() {
        let started_at = now_text();
        let report = json!({
            "status": "pass",
            "runtimeControl": "fake-resident-runtime-test-only",
            "source": source,
            "fakeRuntime": true,
            "startedAt": started_at,
            "tproxyPort": config.global.tproxy_port,
        });
        return Ok((
            ProductRuntimeInstance::Fake(FakeProductRuntime {
                started_at,
                tproxy_port: config.global.tproxy_port,
            }),
            report,
        ));
    }

    crate::service_contract::validate_resident_runtime_reload_config(config)?;

    let mut runtime = start_resident_production_runtime(config)?;
    let state = runtime.product_state_summary();
    let dataplane_enabled = state["residentDataplane"]["enabled"]
        .as_bool()
        .unwrap_or(false);
    let dataplane_status = state["residentDataplane"]["status"].as_str().unwrap_or("");
    if !dataplane_enabled || dataplane_status != "pass" {
        let dataplane_detail = resident_dataplane_admission_detail(&state);
        runtime.cleanup();
        return Err(format!(
            "resident production runtime started without admitted userspace dataplane: {dataplane_detail}; set {}=1 and require resident_dataplane.status=pass before Rust daed can be the production product path",
            crate::service_contract::RESIDENT_DATAPLANE_ENV
        ));
    }
    let report = json!({
        "status": "pass",
        "runtimeControl": "resident-production-runtime-manager",
        "source": source,
        "fakeRuntime": false,
        "tproxyPort": config.global.tproxy_port,
        "residentDataplane": state["residentDataplane"].clone(),
        "residentStartupEvidence": state["startupEvidence"].clone(),
    });
    Ok((ProductRuntimeInstance::Resident(runtime), report))
}

pub(super) fn product_runtime_fake_start_enabled() -> bool {
    std::env::var(PRODUCT_RUNTIME_FAKE_START_ENV)
        .or_else(|_| std::env::var(PRODUCT_RUNTIME_FAKE_START_LEGACY_ENV))
        .map(|value| {
            matches!(
                value.as_str(),
                "1" | "true" | "TRUE" | "on" | "ON" | "yes" | "YES"
            )
        })
        .unwrap_or(false)
}

pub(super) fn resident_dataplane_admission_detail(state: &Value) -> String {
    let dataplane = &state["residentDataplane"];
    for key in ["error", "reason", "message"] {
        if let Some(value) = dataplane
            .get(key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            return value.to_owned();
        }
    }
    let enabled = dataplane.get("enabled").and_then(Value::as_bool);
    let status = dataplane.get("status").and_then(Value::as_str);
    format!(
        "resident_dataplane.enabled={}, resident_dataplane.status={}",
        enabled
            .map(|value| value.to_string())
            .unwrap_or_else(|| "unknown".to_owned()),
        status.unwrap_or("unknown")
    )
}
