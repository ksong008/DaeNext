use super::*;
pub struct ResidentDataplaneRuntime {
    pub(crate) owner: ResidentRuntimeOwner,
    pub(super) read_handle: ResidentDataplaneReadHandle,
    pub(super) active_generation: ActiveGenerationSlot<ResidentDataplaneGeneration>,
    pub(super) generation_drain: ResidentGenerationDrain,
    pub(super) workload_shutdown: Option<ResidentRuntimeWorkloadShutdown>,
    pub(super) routing_tuple_map_id: Option<u32>,
    pub(super) domain_routing_map_id: Option<u32>,
}

impl std::fmt::Debug for ResidentDataplaneRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResidentDataplaneRuntime")
            .field(
                "active_reload_generation",
                &self.active_generation.load().reload_generation,
            )
            .field(
                "workload_shutdown_prepared",
                &self.workload_shutdown.is_some(),
            )
            .field("routing_tuple_map_id", &self.routing_tuple_map_id)
            .field("domain_routing_map_id", &self.domain_routing_map_id)
            .finish_non_exhaustive()
    }
}

impl ResidentDataplaneRuntime {
    pub fn active_generation_snapshot(&self) -> Arc<ResidentDataplaneGeneration> {
        self.active_generation.load()
    }

    pub fn traffic_counters(&self) -> ResidentTrafficCounters {
        self.owner.traffic_counters()
    }

    pub fn read_handle(&self) -> ResidentDataplaneReadHandle {
        self.read_handle.clone()
    }

    pub fn prune_event_log(&self) -> std::io::Result<()> {
        self.owner.prune_event_log()
    }

    pub fn clear_event_log(&self) -> std::io::Result<()> {
        self.owner.clear_event_log()
    }

    pub fn health_state_snapshots(&self) -> Vec<Value> {
        let generation = self.active_generation.load();
        generation
            .groups
            .iter()
            .flat_map(|group| group.health_state_snapshots())
            .map(|snapshot| resident_latency_snapshot_json(snapshot, generation.reload_generation))
            .collect()
    }

    pub fn group_selector_snapshot_map(&self) -> BTreeMap<String, Value> {
        resident_group_selector_snapshot_map(&self.active_generation.load().groups)
    }

    pub fn manual_probe_handle(&self) -> ResidentManualProbeHandle {
        self.active_generation.load().manual_probe_handle.clone()
    }

    pub fn dns_reload_snapshot(&self) -> Result<ResidentDnsReloadSnapshot, String> {
        self.active_generation
            .load()
            .dns_reload_handle
            .snapshot_for_reload()
    }

    pub fn shutdown(&mut self, steps: &mut Vec<Value>) {
        self.quiesce_workloads();
        let generation = self.active_generation.load();
        let reload_generation = generation.reload_generation;
        drop(generation);
        let workload = self
            .workload_shutdown
            .take()
            .expect("resident dataplane workload shutdown was prepared");
        let xmux = self.owner.shutdown_xhttp_xmux_generation_owner();
        steps.push(json!({
            "name": "clear-resident-xhttp-xmux-managers",
            "reloadGeneration": reload_generation,
            "enabled": xmux.is_some(),
            "status": if xmux.as_ref().is_none_or(|report|
                !report.cleanup_timed_out
                    && report.owner_thread_joined
                    && report.h2.locked_managers == 0
                    && report.h3.locked_managers == 0
            ) {
                "pass"
            } else {
                "fail"
            },
            "h2": {
                "managers": xmux.as_ref().map(|report| report.h2.managers).unwrap_or(0),
                "clients": xmux.as_ref().map(|report| report.h2.clients).unwrap_or(0),
                "lockedManagers": xmux.as_ref().map(|report| report.h2.locked_managers).unwrap_or(0),
            },
            "h3": {
                "managers": xmux.as_ref().map(|report| report.h3.managers).unwrap_or(0),
                "clients": xmux.as_ref().map(|report| report.h3.clients).unwrap_or(0),
                "lockedManagers": xmux.as_ref().map(|report| report.h3.locked_managers).unwrap_or(0),
            },
            "cleanupTimedOut": xmux.as_ref().is_some_and(|report| report.cleanup_timed_out),
            "ownerThreadJoined": xmux.as_ref().is_none_or(|report| report.owner_thread_joined),
        }));
        let connect_udp_h2 = udp::clear_connect_udp_h2_pools(reload_generation);
        steps.push(json!({
            "name": "clear-resident-connect-udp-h2-pools",
            "reloadGeneration": reload_generation,
            "status": if !connect_udp_h2.registry_locked && connect_udp_h2.locked_pools == 0 {
                "pass"
            } else {
                "partial"
            },
            "pools": connect_udp_h2.pools,
            "connections": connect_udp_h2.connections,
            "lockedPools": connect_udp_h2.locked_pools,
            "registryLocked": connect_udp_h2.registry_locked,
        }));
        let connect_udp_h3 = udp::clear_connect_udp_h3_pools(reload_generation);
        steps.push(json!({
            "name": "clear-resident-connect-udp-h3-pools",
            "reloadGeneration": reload_generation,
            "status": if !connect_udp_h3.registry_locked && connect_udp_h3.locked_pools == 0 {
                "pass"
            } else {
                "partial"
            },
            "pools": connect_udp_h3.pools,
            "connections": connect_udp_h3.connections,
            "lockedPools": connect_udp_h3.locked_pools,
            "registryLocked": connect_udp_h3.registry_locked,
        }));
        steps.push(
            self.owner
                .shutdown_after_workloads(workload, RESIDENT_RUNTIME_TASK_JOIN_GRACE),
        );
        let active_generation = self.active_generation.clear();
        let external_generation_owners = active_generation
            .as_ref()
            .map(|generation| Arc::strong_count(generation).saturating_sub(1))
            .unwrap_or(0);
        let generation_removed = active_generation.is_some();
        drop(active_generation);
        steps.push(json!({
            "name": "clear-resident-active-generation-slot",
            "status": "pass",
            "generationRemoved": generation_removed,
            "externalGenerationOwnersBeforeRelease": external_generation_owners,
            "ownership": "terminal-runtime-shutdown-after-workload-join",
        }));
        steps.push(json!({
            "name": "clear-resident-udp-reply-socket-cache",
            "status": "pass",
            "sockets": 0,
            "ownership": "udp-session-manager",
            "cleanup": "reply dispatcher stopped and joined with UDP manager",
        }));
        let tls_caches = client::clear_resident_tls_config_caches();
        let boring_io_profile = client::take_boring_tls_io_profile_snapshot();
        steps.push(json!({
            "name": "clear-resident-tls-config-caches",
            "status": "pass",
            "ownership": "process-wide-cache-cleared-after-runtime-quiesce",
            "boringEntries": tls_caches.boring,
            "boringSessions": tls_caches.boring_sessions,
            "boringSessionAttempts": tls_caches.boring_session_attempts,
            "boringSessionReused": tls_caches.boring_session_reused,
            "boringSessionRejected": tls_caches.boring_session_rejected,
            "boringSessionStored": tls_caches.boring_session_stored,
            "boringIoProfile": boring_io_profile,
        }));
    }

    pub fn quiesce_workloads(&mut self) {
        if self.workload_shutdown.is_some() {
            return;
        }
        let generation = self.active_generation.load();
        generation.request_stop();
        self.generation_drain.stop_all();
        self.workload_shutdown = Some(
            self.owner
                .shutdown_workloads(RESIDENT_RUNTIME_TASK_JOIN_GRACE),
        );
    }

    pub fn publish_prepared_generation(
        &mut self,
        config: Arc<Config>,
        prepared: ResidentPreparedDataplane,
        latency_seed: &[Value],
        dns_reload_snapshot: Option<&ResidentDnsReloadSnapshot>,
    ) -> Result<Value, String> {
        let started = Instant::now();
        self.generation_drain.prepare_publication()?;
        let built = build_resident_dataplane_generation(ResidentGenerationBuildContext {
            owner: &mut self.owner,
            config,
            prepared,
            routing_tuple_map_id: self.routing_tuple_map_id,
            domain_routing_map_id: self.domain_routing_map_id,
            latency_seed,
            dns_reload_snapshot,
        })?;
        let next_id = built.generation.id;
        let previous = self.active_generation.publish(built.generation);
        let previous_id = previous.id;
        self.generation_drain.retire(previous);
        Ok(json!({
            "status": "pass",
            "strategy": "process-owned-listeners-runtime-and-generation-slot",
            "previousGeneration": previous_id,
            "activeGeneration": next_id,
            "elapsedNs": started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64,
            "listenerReused": true,
            "sharedRuntimeReused": true,
            "bpfOwnerReused": true,
            "tcpAdmission": "generation-pinned-at-accept",
            "udpAdmission": "generation-pinned-for-session-idle-window",
            "dnsAdmission": "generation-pinned-per-request-or-connection",
        }))
    }

    pub fn restore_generation(
        &mut self,
        generation: Arc<ResidentDataplaneGeneration>,
    ) -> Result<Value, String> {
        let active = self.active_generation.load();
        if Arc::ptr_eq(&active, &generation) {
            return Ok(json!({
                "status": "pass",
                "strategy": "generation-slot-already-restored",
                "activeGeneration": generation.id,
            }));
        }
        if active.reload_generation != generation.reload_generation {
            return Err("resident generation belongs to a different physical runtime".to_owned());
        }
        self.generation_drain.reactivate(generation.id)?;
        let restored_id = generation.id;
        let displaced = self.active_generation.publish(generation);
        let displaced_id = displaced.id;
        self.generation_drain.retire(displaced);
        self.generation_drain.finalize_retirement(displaced_id);
        Ok(json!({
            "status": "pass",
            "strategy": "restore-previous-generation-slot",
            "displacedGeneration": displaced_id,
            "activeGeneration": restored_id,
            "listenerReused": true,
            "sharedRuntimeReused": true,
            "bpfOwnerReused": true,
        }))
    }

    pub fn finalize_generation_publication(&self) {
        self.generation_drain.finalize_retirements();
    }
}
