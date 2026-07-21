use super::*;
#[derive(Debug)]
pub(crate) struct ResidentDataplaneRuntime {
    pub(in crate::production_runtime_owner) owner: ResidentRuntimeOwner,
    pub(in crate::production_runtime_owner) groups: Vec<Arc<plan::ResidentProxyGroupPlan>>,
    pub(in crate::production_runtime_owner) manual_probe_index: Arc<ResidentManualProbeIndex>,
    pub(in crate::production_runtime_owner) dns_reload_handle: dns::ResidentDnsReloadHandle,
    pub(in crate::production_runtime_owner) domain_routing_maintenance:
        Option<dns::ResidentDnsDomainRoutingMaintenanceHandle>,
}

impl ResidentDataplaneRuntime {
    pub(in crate::production_runtime_owner) fn metrics_snapshot(&self) -> Value {
        self.owner.metrics_snapshot()
    }

    pub(in crate::production_runtime_owner) fn prune_event_log(&self) -> std::io::Result<()> {
        self.owner.prune_event_log()
    }

    pub(in crate::production_runtime_owner) fn clear_event_log(&self) -> std::io::Result<()> {
        self.owner.clear_event_log()
    }

    pub(in crate::production_runtime_owner) fn health_state_snapshots(&self) -> Vec<Value> {
        let reload_generation = self.owner.reload_generation();
        self.groups
            .iter()
            .flat_map(|group| group.health_state_snapshots())
            .map(|snapshot| resident_latency_snapshot_json(snapshot, reload_generation))
            .collect()
    }

    pub(in crate::production_runtime_owner) fn group_selector_snapshot_map(
        &self,
    ) -> BTreeMap<String, Value> {
        resident_group_selector_snapshot_map(&self.groups)
    }

    pub(in crate::production_runtime_owner) fn manual_probe_handle(
        &self,
    ) -> ResidentManualProbeHandle {
        self.owner
            .manual_probe_handle(&self.groups, &self.manual_probe_index)
    }

    pub(in crate::production_runtime_owner) fn dns_reload_snapshot(
        &self,
    ) -> Result<ResidentDnsReloadSnapshot, String> {
        self.dns_reload_handle.snapshot_for_reload()
    }

    pub(in crate::production_runtime_owner) fn shutdown(&mut self, steps: &mut Vec<Value>) {
        let reload_generation = self.owner.reload_generation();
        if let Some(maintenance) = self.domain_routing_maintenance.take() {
            maintenance.stop();
        }
        let workload = self
            .owner
            .shutdown_workloads(RESIDENT_RUNTIME_TASK_JOIN_GRACE);
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
        steps.push(json!({
            "name": "clear-resident-udp-reply-socket-cache",
            "status": "pass",
            "sockets": 0,
            "ownership": "udp-session-manager",
            "cleanup": "reply dispatcher stopped and joined with UDP manager",
        }));
        let tls_caches = client::clear_resident_tls_config_caches();
        steps.push(json!({
            "name": "clear-resident-tls-config-caches",
            "status": "pass",
            "rustlsEntries": tls_caches.rustls,
            "boringEntries": tls_caches.boring,
        }));
    }
}
