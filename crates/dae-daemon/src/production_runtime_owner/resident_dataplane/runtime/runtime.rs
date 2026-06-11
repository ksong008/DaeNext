use super::*;
#[derive(Debug)]
pub(crate) struct ResidentDataplaneRuntime {
    pub(in crate::production_runtime_owner) owner: ResidentRuntimeOwner,
    pub(in crate::production_runtime_owner) groups: Vec<Arc<plan::ResidentProxyGroupPlan>>,
    pub(in crate::production_runtime_owner) manual_probe_plans:
        BTreeMap<String, Result<plan::ResidentProxyProbePlan, String>>,
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

    pub(in crate::production_runtime_owner) fn node_latency_snapshots(&self) -> Vec<Value> {
        let reload_generation = self.owner.reload_generation();
        preferred_latency_snapshots(
            self.groups
                .iter()
                .flat_map(|group| group.latency_snapshots())
                .map(|snapshot| resident_latency_snapshot_json(snapshot, reload_generation)),
        )
    }

    pub(in crate::production_runtime_owner) fn probe_node_latencies(
        &self,
        links: &[String],
    ) -> Vec<Value> {
        self.owner
            .probe_node_latencies(&self.groups, &self.manual_probe_plans, links)
    }

    pub(in crate::production_runtime_owner) fn shutdown(&mut self, steps: &mut Vec<Value>) {
        steps.push(self.owner.shutdown());
    }
}
