use super::*;
#[derive(Debug)]
pub(crate) struct ResidentDataplaneRuntime {
    pub(in crate::production_runtime_owner) owner: ResidentRuntimeOwner,
    pub(in crate::production_runtime_owner) groups: Vec<Arc<plan::ResidentProxyGroupPlan>>,
    pub(in crate::production_runtime_owner) manual_probe_plans:
        BTreeMap<String, Result<plan::ResidentProxyProbePlan, String>>,
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
            .manual_probe_handle(&self.groups, &self.manual_probe_plans)
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
        steps.push(self.owner.shutdown());
        let xmux = tcp::clear_xhttp_xmux_managers(reload_generation);
        steps.push(json!({
            "name": "clear-resident-xhttp-xmux-managers",
            "reloadGeneration": reload_generation,
            "status": if xmux.h2.locked_managers == 0 && xmux.h3.locked_managers == 0 {
                "pass"
            } else {
                "partial"
            },
            "h2": {
                "managers": xmux.h2.managers,
                "clients": xmux.h2.clients,
                "lockedManagers": xmux.h2.locked_managers,
            },
            "h3": {
                "managers": xmux.h3.managers,
                "clients": xmux.h3.clients,
                "lockedManagers": xmux.h3.locked_managers,
            },
        }));
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
