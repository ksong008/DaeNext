use super::*;
use std::time::{Duration, Instant};
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
                .resident_interface_state_snapshot(),
            "startupEvidence": self.start_report["startupEvidence"].clone(),
            "artifactDir": self.start_report["artifact_dir"].clone(),
            "startFile": self.start_report["start_file"].clone(),
            "cleanupFile": self.start_report["cleanup_file"].clone(),
        })
    }

    pub(super) fn resident_interface_state_snapshot(&self) -> Value {
        self.interface_monitor
            .as_ref()
            .map(ResidentInterfaceMonitorRuntime::snapshot)
            .unwrap_or_else(|| self.start_report["resident_interface_monitor"].clone())
    }

    pub(crate) fn resident_interface_reattach_ready_snapshot(&self) -> Option<Value> {
        let snapshot = self.resident_interface_state_snapshot();
        if snapshot
            .get("reattachRequired")
            .and_then(Value::as_bool)
            .unwrap_or(false)
            && snapshot
                .get("reattachReady")
                .and_then(Value::as_bool)
                .unwrap_or(false)
        {
            Some(snapshot)
        } else {
            None
        }
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

    pub(crate) fn dns_reload_snapshot(&self) -> Result<ResidentDnsReloadSnapshot, String> {
        self.dataplane
            .as_ref()
            .map(ResidentDataplaneRuntime::dns_reload_snapshot)
            .unwrap_or_else(|| Ok(ResidentDnsReloadSnapshot::default()))
    }

    pub(crate) fn manual_probe_handle(&self) -> Option<ResidentManualProbeHandle> {
        self.dataplane
            .as_ref()
            .map(ResidentDataplaneRuntime::manual_probe_handle)
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

    pub fn cleanup(&mut self) -> Option<Value> {
        if self.cleaned {
            return None;
        }
        let cleanup_started = Instant::now();
        let mut cleanup_phase_timings = Vec::new();

        let phase_started = Instant::now();
        if let Some(dataplane) = self.dataplane.as_mut() {
            dataplane.shutdown(&mut self.cleanup_steps);
            push_cleanup_phase_timing(
                &mut cleanup_phase_timings,
                "dataplane_shutdown",
                "pass",
                phase_started.elapsed(),
            );
        } else {
            push_cleanup_phase_timing(
                &mut cleanup_phase_timings,
                "dataplane_shutdown",
                "skipped",
                phase_started.elapsed(),
            );
        }
        self.dataplane = None;

        let phase_started = Instant::now();
        if let Some(monitor) = self.interface_monitor.as_mut() {
            monitor.shutdown(&mut self.cleanup_steps);
            push_cleanup_phase_timing(
                &mut cleanup_phase_timings,
                "interface_monitor_shutdown",
                "pass",
                phase_started.elapsed(),
            );
        } else {
            push_cleanup_phase_timing(
                &mut cleanup_phase_timings,
                "interface_monitor_shutdown",
                "skipped",
                phase_started.elapsed(),
            );
        }
        self.interface_monitor = None;

        let phase_started = Instant::now();
        self.live_handoff.take();
        push_cleanup_phase_timing(
            &mut cleanup_phase_timings,
            "live_handoff_drop",
            "pass",
            phase_started.elapsed(),
        );

        let native_peer_attached = self.native_runtime.peer_attached();
        let native_host_attached = self.native_runtime.host_attached();
        let phase_started = Instant::now();
        self.native_runtime.reset();
        push_cleanup_phase_timing(
            &mut cleanup_phase_timings,
            "native_ebpf_reset",
            "pass",
            phase_started.elapsed(),
        );

        let phase_started = Instant::now();
        cleanup_resident_lan_programs(
            &mut self.cleanup_steps,
            &self.lan_ifaces,
            &self.native_lan_ifaces,
        );
        push_cleanup_phase_timing(
            &mut cleanup_phase_timings,
            "resident_lan_cleanup",
            "pass",
            phase_started.elapsed(),
        );

        let phase_started = Instant::now();
        cleanup_production_topology(
            &mut self.cleanup_steps,
            native_peer_attached,
            native_host_attached,
        );
        push_cleanup_phase_timing(
            &mut cleanup_phase_timings,
            "production_topology_cleanup",
            "pass",
            phase_started.elapsed(),
        );

        let mut discovered_map_ids = Vec::with_capacity(1 + self.discovered_routing_map_ids.len());
        discovered_map_ids.push(self.discovered_map_id);
        discovered_map_ids.extend(self.discovered_routing_map_ids.iter().copied());
        let phase_started = Instant::now();
        let (after_map_ids, loaded_map_cleaned) = wait_for_loaded_map_cleanup(&discovered_map_ids);
        push_cleanup_phase_timing(
            &mut cleanup_phase_timings,
            "bpf_map_cleanup_wait",
            if loaded_map_cleaned { "pass" } else { "fail" },
            phase_started.elapsed(),
        );

        let phase_started = Instant::now();
        let after_pin_snapshot = bpf_dae_snapshot();
        let leftovers_after_cleanup = runtime_resource_leftovers(false);
        let sys_fs_bpf_dae_mutated = self.before_pin_snapshot != after_pin_snapshot;
        push_cleanup_phase_timing(
            &mut cleanup_phase_timings,
            "leftover_check",
            if leftovers_after_cleanup.is_empty() && !sys_fs_bpf_dae_mutated {
                "pass"
            } else {
                "fail"
            },
            phase_started.elapsed(),
        );

        let cleanup_elapsed_ns = cleanup_started
            .elapsed()
            .as_nanos()
            .min(u128::from(u64::MAX)) as u64;
        let cleanup_command_timed_out = self
            .cleanup_steps
            .iter()
            .any(|step| step["timed_out"].as_bool().unwrap_or(false));
        let mut cleanup_report = json!({
            "status": if loaded_map_cleaned && leftovers_after_cleanup.is_empty() && !sys_fs_bpf_dae_mutated && !cleanup_command_timed_out {
                "pass"
            } else {
                "fail"
            },
            "cleanup_steps": self.cleanup_steps.clone(),
            "cleanup_phase_timings": cleanup_phase_timings.clone(),
            "cleanup_elapsed_ns": cleanup_elapsed_ns,
            "cleanup_elapsed_ms": cleanup_elapsed_ns / 1_000_000,
            "cleanup_command_timed_out": cleanup_command_timed_out,
            "after_map_ids": after_map_ids,
            "loaded_map_cleaned": loaded_map_cleaned,
            "leftovers_after_cleanup": leftovers_after_cleanup,
            "sys_fs_bpf_dae_mutated": sys_fs_bpf_dae_mutated,
        });
        let phase_started = Instant::now();
        let write_status = if write_json_file(
            &self.cleanup_file,
            "resident-production-runtime-cleanup",
            cleanup_report.clone(),
        )
        .is_ok()
        {
            "pass"
        } else {
            "fail"
        };
        push_cleanup_phase_timing(
            &mut cleanup_phase_timings,
            "cleanup_report_write",
            write_status,
            phase_started.elapsed(),
        );
        if let Value::Object(map) = &mut cleanup_report {
            map.insert(
                "cleanup_phase_timings".to_owned(),
                json!(cleanup_phase_timings),
            );
        }
        let _ = write_json_file(
            &self.cleanup_file,
            "resident-production-runtime-cleanup",
            cleanup_report.clone(),
        );
        self.cleaned = true;
        Some(cleanup_report)
    }
}

fn push_cleanup_phase_timing(
    timings: &mut Vec<Value>,
    name: &'static str,
    status: &'static str,
    elapsed: Duration,
) {
    let elapsed_ns = elapsed.as_nanos().min(u128::from(u64::MAX)) as u64;
    timings.push(json!({
        "name": name,
        "status": status,
        "elapsed_ns": elapsed_ns,
        "elapsed_ms": elapsed_ns / 1_000_000,
    }));
}

impl Drop for ResidentProductionRuntime {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}
