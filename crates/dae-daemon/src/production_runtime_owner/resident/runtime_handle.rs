use super::*;
use std::collections::BTreeMap;
use std::time::{Duration, Instant};
#[derive(Debug)]
pub struct ResidentProductionRuntime {
    pub(super) runtime_generation: u64,
    pub(super) binding_registry: ResidentDatapathBindingRegistry,
    pub(super) read_handle: Arc<ResidentProductionRuntimeReadHandle>,
    pub(super) live_handoff: Option<LiveLoadedTproxyListenSocketMap>,
    pub(super) native_runtime: NativeEbpfRuntimeState,
    pub(super) dataplane: Option<ResidentDataplaneRuntime>,
    pub(super) interface_monitor: Option<ResidentInterfaceMonitorRuntime>,
    pub(super) lan_ifaces: Vec<String>,
    pub(super) native_lan_ifaces: Vec<String>,
    pub(super) cleanup_steps: Vec<Value>,
    pub(super) discovered_map_id: Option<u32>,
    pub(super) discovered_routing_map_ids: Vec<Option<u32>>,
    pub(super) before_pin_snapshot: Vec<String>,
    pub(super) cleanup_file: PathBuf,
    pub(super) start_evidence_writer: Option<thread::JoinHandle<Result<(), String>>>,
    pub(super) reload_conflict_cleanup: Option<Value>,
    pub(super) cleaned: bool,
}

#[derive(Clone)]
pub(crate) struct ResidentActiveGenerationSnapshot {
    generation: Arc<ResidentDataplaneGeneration>,
    physical_generation: u64,
}

impl ResidentProductionRuntime {
    pub(crate) fn active_generation_snapshot(&self) -> Option<ResidentActiveGenerationSnapshot> {
        if self.cleaned {
            return None;
        }
        self.dataplane
            .as_ref()
            .map(|dataplane| ResidentActiveGenerationSnapshot {
                generation: dataplane.active_generation_snapshot(),
                physical_generation: self.runtime_generation,
            })
    }

    pub(crate) fn publish_prepared_generation(
        &mut self,
        prepared: ResidentPreparedGeneration,
        latency_seed: &[Value],
        preserve_dns_cache: bool,
    ) -> Result<Value, String> {
        if self.cleaned {
            return Err("cannot publish a generation on a cleaned resident runtime".to_owned());
        }
        let dns_reload_snapshot = preserve_dns_cache
            .then(|| self.dns_reload_snapshot())
            .transpose()?
            .filter(|snapshot| !snapshot.is_empty());
        let ResidentPreparedGeneration {
            config,
            geodata_asset_dirs: _,
            geodata: _,
            dataplane: prepared,
        } = prepared;
        self.dataplane
            .as_mut()
            .ok_or_else(|| "resident dataplane is not active".to_owned())?
            .publish_prepared_generation(
                config,
                prepared,
                latency_seed,
                dns_reload_snapshot.as_ref(),
            )
    }

    pub(crate) fn restore_active_generation(
        &mut self,
        snapshot: &ResidentActiveGenerationSnapshot,
    ) -> Result<Value, String> {
        if self.cleaned || snapshot.physical_generation != self.runtime_generation {
            return Err(
                "resident generation snapshot belongs to a different physical runtime".to_owned(),
            );
        }
        self.dataplane
            .as_mut()
            .ok_or_else(|| "resident dataplane is not active".to_owned())?
            .restore_generation(Arc::clone(&snapshot.generation))
    }

    pub(crate) fn finalize_generation_publication(&self) {
        if let Some(dataplane) = self.dataplane.as_ref() {
            dataplane.finalize_generation_publication();
        }
    }

    pub(crate) fn owns_generation_snapshot(
        &self,
        snapshot: &ResidentActiveGenerationSnapshot,
    ) -> bool {
        !self.cleaned && snapshot.physical_generation == self.runtime_generation
    }

    pub fn product_state_summary(&self) -> Value {
        self.read_handle().product_state_summary()
    }

    pub(crate) fn read_handle(&self) -> Arc<ResidentProductionRuntimeReadHandle> {
        Arc::clone(&self.read_handle)
    }

    pub(crate) fn resident_interface_reattach_ready_snapshot(&self) -> Option<Value> {
        let monitor = self.interface_monitor.as_ref()?;
        let ready_revision = monitor.ready_recovery_revision()?;
        let snapshot = monitor.snapshot();
        if snapshot
            .get("reattachRequired")
            .and_then(Value::as_bool)
            .unwrap_or(false)
            && snapshot
                .get("reattachReady")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            && snapshot
                .pointer("/recoveryDebounce/candidateRevision")
                .and_then(Value::as_u64)
                == Some(ready_revision)
        {
            Some(snapshot)
        } else {
            None
        }
    }

    pub(crate) fn resident_dataplane_traffic_counters(&self) -> Option<ResidentTrafficCounters> {
        if self.cleaned {
            return None;
        }
        self.dataplane
            .as_ref()
            .map(ResidentDataplaneRuntime::traffic_counters)
    }

    pub(crate) fn snapshot_health_states(&self) -> Vec<Value> {
        self.dataplane
            .as_ref()
            .map(ResidentDataplaneRuntime::health_state_snapshots)
            .unwrap_or_default()
    }

    pub fn group_selector_snapshot_map(&self) -> BTreeMap<String, Value> {
        self.dataplane
            .as_ref()
            .map(ResidentDataplaneRuntime::group_selector_snapshot_map)
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

    pub(crate) fn release_reload_conflicts(&mut self) -> Value {
        if let Some(report) = self.reload_conflict_cleanup.as_ref() {
            return report.clone();
        }
        let started = Instant::now();
        let mut phase_timings = Vec::new();

        let phase_started = Instant::now();
        if let Some(monitor) = self.interface_monitor.as_mut() {
            monitor.shutdown(&mut self.cleanup_steps);
            push_cleanup_phase_timing(
                &mut phase_timings,
                "interface_monitor_shutdown",
                "pass",
                phase_started.elapsed(),
            );
        } else {
            push_cleanup_phase_timing(
                &mut phase_timings,
                "interface_monitor_shutdown",
                "skipped",
                phase_started.elapsed(),
            );
        }
        self.interface_monitor = None;

        // Keep the native pin directory as crash-recovery ownership evidence until every
        // fallible runtime wait has completed. A replacement process can then distinguish
        // this topology from a foreign dae0/daens name collision after an abnormal exit.
        let phase_started = Instant::now();
        if let Some(dataplane) = self.dataplane.as_mut() {
            dataplane.quiesce_workloads();
            push_cleanup_phase_timing(
                &mut phase_timings,
                "dataplane_workload_quiesce",
                "pass",
                phase_started.elapsed(),
            );
        } else {
            push_cleanup_phase_timing(
                &mut phase_timings,
                "dataplane_workload_quiesce",
                "skipped",
                phase_started.elapsed(),
            );
        }

        let native_peer_attached = self.native_runtime.peer_attached();
        let native_host_attached = self.native_runtime.host_attached();
        let phase_started = Instant::now();
        self.native_runtime.reset();
        push_cleanup_phase_timing(
            &mut phase_timings,
            "native_ebpf_reset",
            "pass",
            phase_started.elapsed(),
        );

        let phase_started = Instant::now();
        self.live_handoff.take();
        push_cleanup_phase_timing(
            &mut phase_timings,
            "live_handoff_drop",
            "pass",
            phase_started.elapsed(),
        );

        let phase_started = Instant::now();
        let binding_cleanup_postflight = self.binding_registry.cleanup_postflight();
        let binding_cleanup_ok = binding_cleanup_postflight["status"].as_str() == Some("pass");
        self.cleanup_steps.push(json!({
            "name": "resident-datapath-binding-cleanup-postflight",
            "status": if binding_cleanup_ok { "pass" } else { "fail" },
            "report": binding_cleanup_postflight,
        }));
        push_cleanup_phase_timing(
            &mut phase_timings,
            "datapath_binding_cleanup_postflight",
            if binding_cleanup_ok { "pass" } else { "fail" },
            phase_started.elapsed(),
        );

        let phase_started = Instant::now();
        cleanup_resident_lan_programs(
            &mut self.cleanup_steps,
            &self.lan_ifaces,
            &self.native_lan_ifaces,
        );
        push_cleanup_phase_timing(
            &mut phase_timings,
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
            &mut phase_timings,
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
            &mut phase_timings,
            "bpf_map_cleanup_wait",
            if loaded_map_cleaned { "pass" } else { "fail" },
            phase_started.elapsed(),
        );

        let phase_started = Instant::now();
        let after_pin_snapshot = bpf_dae_snapshot();
        let leftovers_after_cleanup = runtime_resource_leftovers(false);
        let sys_fs_bpf_dae_mutated = self.before_pin_snapshot != after_pin_snapshot;
        push_cleanup_phase_timing(
            &mut phase_timings,
            "leftover_check",
            if leftovers_after_cleanup.is_empty() && !sys_fs_bpf_dae_mutated {
                "pass"
            } else {
                "fail"
            },
            phase_started.elapsed(),
        );
        let cleanup_command_timed_out = self
            .cleanup_steps
            .iter()
            .any(|step| step["timed_out"].as_bool().unwrap_or(false));
        let elapsed_ns = started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64;
        let report = json!({
            "status": if binding_cleanup_ok
                && loaded_map_cleaned
                && leftovers_after_cleanup.is_empty()
                && !sys_fs_bpf_dae_mutated
                && !cleanup_command_timed_out
            { "pass" } else { "fail" },
            "binding_cleanup_postflight": binding_cleanup_postflight,
            "after_map_ids": after_map_ids,
            "loaded_map_cleaned": loaded_map_cleaned,
            "leftovers_after_cleanup": leftovers_after_cleanup,
            "sys_fs_bpf_dae_mutated": sys_fs_bpf_dae_mutated,
            "cleanup_command_timed_out": cleanup_command_timed_out,
            "phaseTimings": phase_timings,
            "elapsedNs": elapsed_ns,
            "elapsedMs": elapsed_ns / 1_000_000,
        });
        self.reload_conflict_cleanup = Some(report.clone());
        report
    }

    pub fn cleanup(&mut self) -> Option<Value> {
        if self.cleaned {
            return None;
        }
        let cleanup_started = Instant::now();
        let mut cleanup_phase_timings = Vec::new();

        let conflict_cleanup = self.release_reload_conflicts();
        if let Some(timings) = conflict_cleanup["phaseTimings"].as_array() {
            cleanup_phase_timings.extend(timings.iter().cloned());
        }

        let phase_started = Instant::now();
        let evidence_status = match self.start_evidence_writer.take() {
            Some(writer) => match writer.join() {
                Ok(Ok(())) => "pass",
                Ok(Err(_)) | Err(_) => "fail",
            },
            None => "skipped",
        };
        push_cleanup_phase_timing(
            &mut cleanup_phase_timings,
            "start_evidence_writer_join",
            evidence_status,
            phase_started.elapsed(),
        );

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
        let (process_live_generations, generations_created_total, generations_dropped_total) =
            resident_dataplane_generation_lifetime_counts();

        let binding_cleanup_postflight = conflict_cleanup["binding_cleanup_postflight"].clone();
        let binding_cleanup_ok = binding_cleanup_postflight["status"].as_str() == Some("pass");
        let after_map_ids = conflict_cleanup["after_map_ids"].clone();
        let loaded_map_cleaned = conflict_cleanup["loaded_map_cleaned"]
            .as_bool()
            .unwrap_or(false);
        let leftovers_after_cleanup = conflict_cleanup["leftovers_after_cleanup"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        let sys_fs_bpf_dae_mutated = conflict_cleanup["sys_fs_bpf_dae_mutated"]
            .as_bool()
            .unwrap_or(false);

        let cleanup_elapsed_ns = cleanup_started
            .elapsed()
            .as_nanos()
            .min(u128::from(u64::MAX)) as u64;
        let cleanup_command_timed_out = self
            .cleanup_steps
            .iter()
            .any(|step| step["timed_out"].as_bool().unwrap_or(false));
        let cleanup_step_failed = self.cleanup_steps.iter().any(|step| {
            matches!(
                step["status"].as_str(),
                Some("fail" | "partial" | "timed_out")
            )
        });
        let evidence_ok = evidence_phase_ok(evidence_status);
        let mut cleanup_report = json!({
            "status": if binding_cleanup_ok && loaded_map_cleaned && leftovers_after_cleanup.is_empty() && !sys_fs_bpf_dae_mutated && !cleanup_command_timed_out && !cleanup_step_failed && evidence_ok {
                "pass"
            } else {
                "fail"
            },
            "evidence_writer_status": evidence_status,
            "cleanup_steps": self.cleanup_steps.clone(),
            "cleanup_phase_timings": cleanup_phase_timings.clone(),
            "cleanup_elapsed_ns": cleanup_elapsed_ns,
            "cleanup_elapsed_ms": cleanup_elapsed_ns / 1_000_000,
            "cleanup_command_timed_out": cleanup_command_timed_out,
            "cleanup_step_failed": cleanup_step_failed,
            "binding_cleanup_postflight": binding_cleanup_postflight,
            "after_map_ids": after_map_ids,
            "loaded_map_cleaned": loaded_map_cleaned,
            "leftovers_after_cleanup": leftovers_after_cleanup,
            "sys_fs_bpf_dae_mutated": sys_fs_bpf_dae_mutated,
            "reload_conflict_cleanup": conflict_cleanup,
            "generation_lifetime_after_dataplane_drop": {
                "processLiveGenerations": process_live_generations,
                "generationsCreatedTotal": generations_created_total,
                "generationsDroppedTotal": generations_dropped_total,
            },
        });
        let phase_started = Instant::now();
        let write_status = if write_json_file(
            &self.cleanup_file,
            "resident-production-runtime-cleanup",
            &cleanup_report,
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
            if write_status == "fail" {
                map.insert("status".to_owned(), json!("fail"));
                map.insert("cleanup_report_write_failed".to_owned(), json!(true));
            }
        }
        self.cleaned = true;
        self.read_handle.mark_stopped();
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

fn evidence_phase_ok(status: &str) -> bool {
    matches!(status, "pass" | "skipped")
}

#[cfg(test)]
mod tests {
    use super::evidence_phase_ok;

    #[test]
    fn evidence_phase_ok_accepts_pass_and_skipped() {
        assert!(evidence_phase_ok("pass"));
        assert!(evidence_phase_ok("skipped"));
    }

    #[test]
    fn evidence_phase_ok_rejects_fail() {
        assert!(!evidence_phase_ok("fail"));
    }
}
