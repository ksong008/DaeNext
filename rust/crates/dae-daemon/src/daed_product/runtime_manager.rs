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
    pub(super) last_report: Option<Value>,
    pub(super) reload_count: u64,
    pub(super) stop_count: u64,
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
}

pub(super) const PRODUCT_RUNTIME_FAKE_START_ENV: &str = "DAED_PRODUCT_RUNTIME_FAKE_START";

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
        let had_previous_runtime = previous_runtime.is_some();
        let previous_config = inner.config.clone();
        drop(previous_runtime);
        let old_owner_reclaim = had_previous_runtime
            .then(|| allocator_reclaim(AllocatorReclaimReason::ReloadOldOwnerClosed));

        match start_product_runtime_instance(&config, source) {
            Ok((runtime, mut report)) => {
                let startup_reclaim =
                    allocator_reclaim(AllocatorReclaimReason::StartupControlBuilt);
                let scoped_reclaim = had_previous_runtime.then(|| {
                    allocator_reclaim(AllocatorReclaimReason::ReloadScopedResourcesFlushed)
                });
                append_runtime_reclaim_report(
                    &mut report,
                    old_owner_reclaim,
                    startup_reclaim,
                    scoped_reclaim,
                );
                inner.runtime = Some(runtime);
                inner.config = Some(config);
                inner.reload_count += 1;
                inner.last_error = None;
                inner.last_transition_at = Some(now_text());
                inner.last_report = Some(report.clone());
                Ok(RuntimeStartOutcome { report })
            }
            Err(start_err) => {
                let restored = previous_config
                    .as_ref()
                    .and_then(|previous| match start_product_runtime_instance(previous, "rollback")
                    {
                        Ok((runtime, report)) => {
                            inner.runtime = Some(runtime);
                            inner.config = Some(previous.clone());
                            inner.last_report = Some(report);
                            Some(true)
                        }
                        Err(rollback_err) => {
                            inner.runtime = None;
                            inner.config = None;
                            inner.last_error = Some(format!(
                                "{start_err}\nrollback failed while restoring previous product runtime: {rollback_err}"
                            ));
                            Some(false)
                        }
                    });
                let message = match restored {
                    Some(true) => {
                        format!("{start_err}\nrollback: restored previous product runtime")
                    }
                    Some(false) => inner
                        .last_error
                        .clone()
                        .unwrap_or_else(|| start_err.clone()),
                    None => start_err,
                };
                inner.last_transition_at = Some(now_text());
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
                if let Value::Object(map) = &mut summary {
                    map.insert(
                        "lastTransitionAt".to_owned(),
                        json!(inner.last_transition_at.clone()),
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
                "startedAt": fake.started_at,
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
            "resident production runtime started without admitted userspace dataplane; set DAE_RUST_RESIDENT_DATAPLANE=1 and require resident_dataplane.status=pass before Rust daed can be the C10 default product path"
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
        .map(|value| {
            matches!(
                value.as_str(),
                "1" | "true" | "TRUE" | "on" | "ON" | "yes" | "YES"
            )
        })
        .unwrap_or(false)
}

pub(super) fn append_runtime_reclaim_report(
    report: &mut Value,
    old_owner_reclaim: Option<Value>,
    startup_reclaim: Value,
    scoped_reclaim: Option<Value>,
) {
    if let Value::Object(map) = report {
        map.insert("allocatorProfile".to_owned(), json!(allocator_profile()));
        map.insert(
            "allocatorReclaim".to_owned(),
            json!({
                "oldOwnerClosed": old_owner_reclaim,
                "startupControlBuilt": startup_reclaim,
                "reloadScopedResourcesFlushed": scoped_reclaim,
            }),
        );
    }
}
