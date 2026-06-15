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
    pub(super) traffic_carry: RuntimeTrafficCarry,
}

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

impl FakeProductRuntime {
    pub(super) fn probe_node_latencies(&self, links: &[String]) -> Vec<Value> {
        fake_runtime_probe_node_latencies(links)
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
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| "product runtime manager lock poisoned".to_owned())?;
        let previous_runtime = inner.runtime.take();
        let previous_config = inner.config.clone();
        let previous_runtime_started_at = inner.runtime_started_at.clone();
        let previous_runtime_was_running = previous_runtime.is_some();
        if let Some(runtime) = previous_runtime.as_ref() {
            inner.traffic_carry = inner.traffic_carry.absorb_runtime(runtime);
        }
        drop(previous_runtime);

        match start_product_runtime_instance(&config, source) {
            Ok((runtime, report)) => {
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
                let restored = previous_config
                    .as_ref()
                    .and_then(|previous| match start_product_runtime_instance(previous, "restore")
                    {
                        Ok((runtime, report)) => {
                            inner.runtime = Some(runtime);
                            inner.config = Some(previous.clone());
                            inner.runtime_started_at = previous_runtime_started_at.clone();
                            inner.last_report = Some(report);
                            Some(true)
                        }
                        Err(restore_err) => {
                            inner.runtime = None;
                            inner.config = None;
                            inner.runtime_started_at = None;
                            inner.last_error = Some(format!(
                                "{start_err}\nrestore failed while restoring previous product runtime: {restore_err}"
                            ));
                            Some(false)
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

    pub(super) fn current_config(&self) -> Option<Config> {
        self.inner
            .lock()
            .ok()
            .and_then(|inner| inner.config.clone())
    }

    pub(super) fn probe_node_latencies(&self, links: &[String]) -> Vec<Value> {
        let Ok(inner) = self.inner.lock() else {
            return Vec::new();
        };
        match inner.runtime.as_ref() {
            Some(ProductRuntimeInstance::Resident(runtime)) => runtime.probe_node_latencies(links),
            Some(ProductRuntimeInstance::Fake(fake)) => fake.probe_node_latencies(links),
            None if product_runtime_fake_start_enabled() => {
                fake_runtime_probe_node_latencies(links)
            }
            None => Vec::new(),
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

    let mut runtime = start_resident_production_runtime(config)?;
    let state = runtime.product_state_summary();
    let dataplane_enabled = state["residentDataplane"]["enabled"]
        .as_bool()
        .unwrap_or(false);
    let dataplane_status = state["residentDataplane"]["status"].as_str().unwrap_or("");
    if !dataplane_enabled || dataplane_status != "pass" {
        runtime.cleanup();
        return Err(format!(
            "resident production runtime started without admitted userspace dataplane; set {}=1 and require resident_dataplane.status=pass before Rust daed can be the production product path",
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
