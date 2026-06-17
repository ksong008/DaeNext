use super::*;
#[derive(Debug)]
pub struct ResidentProductionRuntime {
    pub(super) live_handoff: Option<LiveLoadedTproxyListenSocketMap>,
    pub(super) native_runtime: NativeEbpfRuntimeState,
    pub(super) dataplane: Option<ResidentDataplaneRuntime>,
    pub(super) interface_monitor: Option<ResidentInterfaceMonitorRuntime>,
    pub(super) start_report: Value,
    pub(super) lan_ifaces: Vec<String>,
    pub(super) native_lan_ifaces: Vec<String>,
    pub(super) cleanup_steps: Vec<Value>,
    pub(super) discovered_map_id: Option<u32>,
    pub(super) discovered_routing_map_ids: Vec<Option<u32>>,
    pub(super) before_pin_snapshot: Vec<String>,
    pub(super) cleanup_file: PathBuf,
    pub(super) cleaned: bool,
}

impl ResidentProductionRuntime {
    pub fn product_state_summary(&self) -> Value {
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
        if let Some(dataplane) = self.dataplane.as_ref()
            && let Value::Object(map) = &mut resident_dataplane
        {
            map.insert("metrics".to_owned(), dataplane.metrics_snapshot());
        }
        json!({
            "running": !self.cleaned,
            "state": if self.cleaned { "stopped" } else { "running" },
            "attachBackend": attach_backend,
            "netnsLinkMode": netns_link_mode,
            "fakeRuntime": false,
            "residentRuntimeStarted": self.start_report["resident_runtime_started"].as_bool().unwrap_or(false),
            "residentDataplane": resident_dataplane,
            "residentInterfaceState": self
                .interface_monitor
                .as_ref()
                .map(ResidentInterfaceMonitorRuntime::snapshot)
                .unwrap_or_else(|| self.start_report["resident_interface_monitor"].clone()),
            "startupEvidence": self.start_report["startupEvidence"].clone(),
            "artifactDir": self.start_report["artifact_dir"].clone(),
            "startFile": self.start_report["start_file"].clone(),
            "cleanupFile": self.start_report["cleanup_file"].clone(),
        })
    }

    pub fn resident_dataplane_metrics_snapshot(&self) -> Option<Value> {
        if self.cleaned {
            return None;
        }
        self.dataplane
            .as_ref()
            .map(ResidentDataplaneRuntime::metrics_snapshot)
    }

    pub fn snapshot_node_latencies(&self) -> Vec<Value> {
        self.dataplane
            .as_ref()
            .map(ResidentDataplaneRuntime::node_latency_snapshots)
            .unwrap_or_default()
    }

    pub fn probe_node_latencies(&self, links: &[String]) -> Vec<Value> {
        self.dataplane
            .as_ref()
            .map(|dataplane| dataplane.probe_node_latencies(links))
            .unwrap_or_default()
    }

    pub fn prune_event_log(&self) -> std::io::Result<()> {
        if let Some(dataplane) = self.dataplane.as_ref() {
            dataplane.prune_event_log()
        } else {
            Ok(())
        }
    }

    pub fn clear_event_log(&self) -> std::io::Result<()> {
        if let Some(dataplane) = self.dataplane.as_ref() {
            dataplane.clear_event_log()
        } else {
            Ok(())
        }
    }

    pub fn cleanup(&mut self) {
        if self.cleaned {
            return;
        }
        if let Some(dataplane) = self.dataplane.as_mut() {
            dataplane.shutdown(&mut self.cleanup_steps);
        }
        self.dataplane = None;
        if let Some(monitor) = self.interface_monitor.as_mut() {
            monitor.shutdown(&mut self.cleanup_steps);
        }
        self.interface_monitor = None;
        self.live_handoff.take();
        let native_peer_attached = self.native_runtime.peer_attached();
        let native_host_attached = self.native_runtime.host_attached();
        self.native_runtime.reset();
        cleanup_resident_lan_programs(
            &mut self.cleanup_steps,
            &self.lan_ifaces,
            &self.native_lan_ifaces,
        );
        cleanup_production_topology(
            &mut self.cleanup_steps,
            native_peer_attached,
            native_host_attached,
        );
        let mut discovered_map_ids = Vec::with_capacity(1 + self.discovered_routing_map_ids.len());
        discovered_map_ids.push(self.discovered_map_id);
        discovered_map_ids.extend(self.discovered_routing_map_ids.iter().copied());
        let (after_map_ids, loaded_map_cleaned) = wait_for_loaded_map_cleanup(&discovered_map_ids);
        let after_pin_snapshot = bpf_dae_snapshot();
        let cleanup_report = json!({
            "status": if loaded_map_cleaned && runtime_resource_leftovers(false).is_empty() && self.before_pin_snapshot == after_pin_snapshot {
                "pass"
            } else {
                "fail"
            },
            "cleanup_steps": self.cleanup_steps,
            "after_map_ids": after_map_ids,
            "loaded_map_cleaned": loaded_map_cleaned,
            "leftovers_after_cleanup": runtime_resource_leftovers(false),
            "sys_fs_bpf_dae_mutated": self.before_pin_snapshot != after_pin_snapshot,
        });
        let _ = write_json_file(
            &self.cleanup_file,
            "resident-production-runtime-cleanup",
            cleanup_report,
        );
        self.cleaned = true;
    }
}

impl Drop for ResidentProductionRuntime {
    fn drop(&mut self) {
        self.cleanup();
    }
}
