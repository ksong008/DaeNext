use super::*;
use std::sync::atomic::AtomicBool;

static RESIDENT_DATAPLANE_GENERATION_SEQUENCE: AtomicU64 = AtomicU64::new(1);
static RESIDENT_DATAPLANE_GENERATIONS_LIVE: AtomicU64 = AtomicU64::new(0);
static RESIDENT_DATAPLANE_GENERATIONS_CREATED: AtomicU64 = AtomicU64::new(0);
static RESIDENT_DATAPLANE_GENERATIONS_DROPPED: AtomicU64 = AtomicU64::new(0);

pub(super) fn next_resident_dataplane_generation_id() -> LogicalGenerationId {
    LogicalGenerationId::new(RESIDENT_DATAPLANE_GENERATION_SEQUENCE.fetch_add(1, Ordering::Relaxed))
}

pub fn resident_dataplane_generation_lifetime_counts() -> (u64, u64, u64) {
    (
        RESIDENT_DATAPLANE_GENERATIONS_LIVE.load(Ordering::Acquire),
        RESIDENT_DATAPLANE_GENERATIONS_CREATED.load(Ordering::Relaxed),
        RESIDENT_DATAPLANE_GENERATIONS_DROPPED.load(Ordering::Relaxed),
    )
}

#[derive(Debug)]
pub(super) struct ResidentDataplaneGenerationLifetime;

impl ResidentDataplaneGenerationLifetime {
    pub(super) fn register() -> Self {
        RESIDENT_DATAPLANE_GENERATIONS_CREATED.fetch_add(1, Ordering::Relaxed);
        RESIDENT_DATAPLANE_GENERATIONS_LIVE.fetch_add(1, Ordering::Release);
        Self
    }
}

impl Drop for ResidentDataplaneGenerationLifetime {
    fn drop(&mut self) {
        let previous = RESIDENT_DATAPLANE_GENERATIONS_LIVE.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(
            previous > 0,
            "resident generation lifetime counter underflow"
        );
        RESIDENT_DATAPLANE_GENERATIONS_DROPPED.fetch_add(1, Ordering::Relaxed);
    }
}

pub(crate) struct ResidentGenerationDrainControl {
    id: LogicalGenerationId,
    lifecycle: ResidentGenerationLifecycle,
    workload_stop: SharedResidentStopSignal,
    flow_stop: SharedResidentStopSignal,
    udp_stop: SharedResidentStopSignal,
    udp_router_retained: AtomicBool,
    udp_dns_runtime_retained: AtomicBool,
}

impl std::fmt::Debug for ResidentGenerationDrainControl {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ResidentGenerationDrainControl")
            .field("id", &self.id)
            .field("stop_requested", &self.stop_is_requested())
            .field("flow_stop_requested", &self.flow_stop_is_requested())
            .field("udp_stop_requested", &self.udp_stop_is_requested())
            .field("udp_router_retained", &self.udp_router_is_retained())
            .field(
                "udp_dns_runtime_retained",
                &self.udp_dns_runtime_is_retained(),
            )
            .finish()
    }
}

impl ResidentGenerationDrainControl {
    pub(super) fn new(
        id: LogicalGenerationId,
        workload_stop: SharedResidentStopSignal,
    ) -> Arc<Self> {
        Arc::new(Self {
            id,
            lifecycle: ResidentGenerationLifecycle::default(),
            workload_stop,
            flow_stop: ResidentStopSignal::shared(),
            udp_stop: ResidentStopSignal::shared(),
            udp_router_retained: AtomicBool::new(false),
            udp_dns_runtime_retained: AtomicBool::new(false),
        })
    }

    pub(super) fn id(&self) -> LogicalGenerationId {
        self.id
    }

    pub(super) fn activate(&self) -> Result<(), String> {
        self.lifecycle.activate().map_err(str::to_owned)
    }

    pub(super) fn admission_is_open(&self) -> bool {
        self.lifecycle.admission_is_open()
    }

    pub(super) fn close_admission(&self) {
        self.lifecycle.close_admission();
    }

    pub(super) fn reopen_admission(&self) -> Result<(), String> {
        self.lifecycle.reopen_admission().map_err(str::to_owned)
    }

    pub(super) fn stop_is_requested(&self) -> bool {
        self.lifecycle.stop_is_requested()
    }

    pub(super) fn udp_stop_is_requested(&self) -> bool {
        self.udp_stop.load(Ordering::Acquire)
    }

    pub(super) fn flow_stop_is_requested(&self) -> bool {
        self.flow_stop.load(Ordering::Acquire)
    }

    pub(super) fn flow_stop_handle(&self) -> SharedResidentStopSignal {
        Arc::clone(&self.flow_stop)
    }

    pub(super) fn retire_workloads(&self) {
        self.lifecycle.request_stop();
        self.workload_stop.store(true, Ordering::Release);
    }

    pub(super) fn request_force_stop(&self) {
        self.retire_workloads();
        self.flow_stop.store(true, Ordering::Release);
        self.udp_stop.store(true, Ordering::Release);
        self.lifecycle.stop();
    }

    pub(super) fn register_udp_runtime(&self) {
        self.udp_router_retained.store(true, Ordering::Release);
        self.udp_dns_runtime_retained.store(true, Ordering::Release);
    }

    pub(super) fn release_udp_router(&self) {
        self.udp_router_retained.store(false, Ordering::Release);
    }

    pub(super) fn release_udp_dns_runtime(&self) {
        self.udp_dns_runtime_retained
            .store(false, Ordering::Release);
    }

    pub(super) fn udp_router_is_retained(&self) -> bool {
        self.udp_router_retained.load(Ordering::Acquire)
    }

    pub(super) fn udp_dns_runtime_is_retained(&self) -> bool {
        self.udp_dns_runtime_retained.load(Ordering::Acquire)
    }
}

impl ResidentDrainControl for ResidentGenerationDrainControl {
    fn id(&self) -> LogicalGenerationId {
        ResidentGenerationDrainControl::id(self)
    }

    fn close_admission(&self) {
        ResidentGenerationDrainControl::close_admission(self);
    }

    fn reopen_admission(&self) -> Result<(), String> {
        ResidentGenerationDrainControl::reopen_admission(self)
    }

    fn stop_is_requested(&self) -> bool {
        ResidentGenerationDrainControl::stop_is_requested(self)
    }

    fn flow_stop_is_requested(&self) -> bool {
        ResidentGenerationDrainControl::flow_stop_is_requested(self)
    }

    fn udp_stop_is_requested(&self) -> bool {
        ResidentGenerationDrainControl::udp_stop_is_requested(self)
    }

    fn udp_router_is_retained(&self) -> bool {
        ResidentGenerationDrainControl::udp_router_is_retained(self)
    }

    fn udp_dns_runtime_is_retained(&self) -> bool {
        ResidentGenerationDrainControl::udp_dns_runtime_is_retained(self)
    }

    fn request_force_stop(&self) {
        ResidentGenerationDrainControl::request_force_stop(self);
    }
}

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
    // Keep the lifetime guard last so its drop is observed only after every generation-owned
    // router, protocol plan, scheduler handle, and maintenance owner has been released.
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
        resident_dataplane_generation_lifetime_counts()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn generation_force_stop_wakes_flow_waiters() {
        let control = ResidentGenerationDrainControl::new(
            LogicalGenerationId::new(1),
            ResidentStopSignal::shared(),
        );
        let mut flow_stop = control.flow_stop_handle().listener();

        control.request_force_stop();

        tokio::time::timeout(Duration::from_secs(1), flow_stop.cancelled())
            .await
            .expect("generation stop must wake active flows");
        assert!(control.flow_stop_is_requested());
        assert!(control.udp_stop_is_requested());
    }
}
