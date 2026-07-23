use super::*;
use std::sync::atomic::{AtomicBool, Ordering};

pub(crate) struct ResidentProductionRuntimeReadHandle {
    pub(super) running: AtomicBool,
    pub(super) runtime_generation: u64,
    pub(super) start_report: Arc<Value>,
    pub(super) binding_registry: Arc<Value>,
    pub(super) native_runtime: NativeEbpfRuntimeReadHandle,
    pub(super) dataplane: Option<ResidentDataplaneReadHandle>,
    pub(super) interface_monitor: Option<ResidentInterfaceMonitorReadHandle>,
}

impl std::fmt::Debug for ResidentProductionRuntimeReadHandle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ResidentProductionRuntimeReadHandle")
            .field("running", &self.running.load(Ordering::Acquire))
            .field("runtime_generation", &self.runtime_generation)
            .finish_non_exhaustive()
    }
}

impl ResidentProductionRuntimeReadHandle {
    pub(super) fn new(
        runtime_generation: u64,
        start_report: Arc<Value>,
        binding_registry: Arc<Value>,
        native_runtime: NativeEbpfRuntimeReadHandle,
        dataplane: Option<ResidentDataplaneReadHandle>,
        interface_monitor: Option<ResidentInterfaceMonitorReadHandle>,
    ) -> Self {
        Self {
            running: AtomicBool::new(true),
            runtime_generation,
            start_report,
            binding_registry,
            native_runtime,
            dataplane,
            interface_monitor,
        }
    }

    pub(super) fn mark_stopped(&self) {
        self.running.store(false, Ordering::Release);
    }

    pub(crate) fn product_state_summary(&self) -> Value {
        let running = self.running.load(Ordering::Acquire);
        let attach_backend = self
            .start_report
            .get("attachBackend")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .or_else(|| actual_resident_attach_backend(&self.start_report))
            .unwrap_or_else(|| {
                self.start_report
                    .pointer("/resident_interface_backend_policy/effective_backend")
                    .and_then(Value::as_str)
                    .unwrap_or("resident-production-runtime")
                    .to_owned()
            });
        let netns_link_mode = self
            .start_report
            .get("netnsLinkMode")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .or_else(|| selected_netns_link_mode(&self.start_report))
            .unwrap_or_else(|| {
                self.start_report
                    .pointer("/topology_values/requested_netns_link_mode")
                    .and_then(Value::as_str)
                    .unwrap_or("production-runtime-owner")
                    .to_owned()
            });
        let mut resident_dataplane = self.start_report["resident_dataplane"].clone();
        if let Some(metrics) = self
            .dataplane
            .as_ref()
            .map(ResidentDataplaneReadHandle::metrics_snapshot)
            && let Value::Object(map) = &mut resident_dataplane
        {
            map.insert("metrics".to_owned(), metrics);
        }
        let resident_interface_state = self
            .interface_monitor
            .as_ref()
            .map(ResidentInterfaceMonitorReadHandle::snapshot)
            .unwrap_or_else(|| self.start_report["resident_interface_monitor"].clone());
        json!({
            "running": running,
            "state": if running { "running" } else { "stopped" },
            "runtimeGeneration": self.runtime_generation,
            "attachBackend": attach_backend,
            "netnsLinkMode": netns_link_mode,
            "fakeRuntime": false,
            "residentRuntimeStarted": self.start_report["resident_runtime_started"].as_bool().unwrap_or(false),
            "residentDataplane": resident_dataplane,
            "residentEbpf": self.native_runtime.runtime_metrics(),
            "residentDatapathBindings": self.binding_registry.as_ref(),
            "residentDatapathBindingPostflight": self.start_report["resident_datapath_binding_postflight"].clone(),
            "residentInterfaceState": resident_interface_state,
            "startupEvidence": self.start_report["startupEvidence"].clone(),
            "artifactDir": self.start_report["artifact_dir"].clone(),
            "startFile": self.start_report["start_file"].clone(),
            "cleanupFile": self.start_report["cleanup_file"].clone(),
        })
    }
}
