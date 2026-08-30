use super::*;
pub(super) use dae_resident_runtime::ResidentGenerationDrainControl;
use dae_resident_runtime::{ResidentGenerationLifetime, resident_generation_lifetime_counts};

pub(super) use dae_resident_runtime::next_resident_generation_id as next_resident_dataplane_generation_id;
pub use dae_resident_runtime::resident_generation_lifetime_counts as resident_dataplane_generation_lifetime_counts;
pub(super) type ResidentDataplaneGenerationLifetime = ResidentGenerationLifetime;

pub struct ResidentDataplaneGeneration {
    pub(crate) id: LogicalGenerationId,
    pub(crate) reload_generation: PhysicalRuntimeId,
    pub(crate) tcp_router: Arc<ResidentTcpRouter>,
    pub(crate) tcp_admission: tcp::ResidentTcpAdmission,
    pub(crate) tcp_runtime_config: ResidentTcpRuntimeConfig,
    pub(crate) dns: Arc<dns::ResidentDnsPlan>,
    pub(crate) udp: udp::ResidentUdpGenerationPlan,
    pub(super) drain_control: Arc<ResidentGenerationDrainControl>,
    pub(crate) metrics: Arc<ResidentDataplaneMetrics>,
    pub(crate) groups: Vec<Arc<plan::ResidentProxyGroupPlan>>,
    pub(crate) manual_probe_handle: ResidentManualProbeHandle,
    pub(crate) dns_reload_handle: dns::ResidentDnsReloadHandle,
    pub(crate) domain_routing_maintenance: Option<dns::ResidentDnsDomainRoutingMaintenanceHandle>,
    pub(super) _lifetime: ResidentDataplaneGenerationLifetime,
}

impl std::fmt::Debug for ResidentDataplaneGeneration {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ResidentDataplaneGeneration")
            .field("id", &self.id)
            .field("reload_generation", &self.reload_generation)
            .field("tcp_runtime_config", &self.tcp_runtime_config)
            .field("group_count", &self.groups.len())
            .finish_non_exhaustive()
    }
}

impl ResidentDataplaneGeneration {
    pub(crate) const fn token(&self) -> GenerationToken {
        GenerationToken::new(self.reload_generation, self.id)
    }

    pub(super) fn activate(&self) -> Result<(), String> {
        self.drain_control.activate()
    }

    pub(super) fn admission_is_open(&self) -> bool {
        self.drain_control.admission_is_open()
    }

    pub(super) fn retire_workloads(&self) {
        self.drain_control.retire_workloads();
        if let Some(maintenance) = self.domain_routing_maintenance.as_ref() {
            maintenance.stop();
        }
    }

    pub(crate) fn request_stop(&self) {
        self.drain_control.request_force_stop();
        if let Some(maintenance) = self.domain_routing_maintenance.as_ref() {
            maintenance.stop();
        }
    }
}

impl ResidentDrainableGeneration for ResidentDataplaneGeneration {
    fn drain_control(&self) -> Arc<dyn ResidentDrainControl> {
        let control: Arc<dyn ResidentDrainControl> = self.drain_control.clone();
        control
    }

    fn retire_workloads(&self) {
        ResidentDataplaneGeneration::retire_workloads(self);
    }

    fn request_force_stop(&self) {
        ResidentDataplaneGeneration::request_stop(self);
    }
}

#[derive(Debug)]
pub(crate) struct ResidentDataplaneGenerationDrainHooks;

impl ResidentGenerationDrainHooks for ResidentDataplaneGenerationDrainHooks {
    fn request_reclaim(&self) {
        resident_allocator_request_reclaim(
            ResidentAllocatorReclaimReason::RetiredGenerationReleased,
        );
    }

    fn lifetime_counts(&self) -> (u64, u64, u64) {
        resident_generation_lifetime_counts()
    }
}
