use crate::ResidentDrainControl;
use dae_resident_core::{
    LogicalGenerationId, ResidentGenerationLifecycle, ResidentStopSignal, SharedResidentStopSignal,
};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

static RESIDENT_GENERATION_SEQUENCE: AtomicU64 = AtomicU64::new(1);
static RESIDENT_GENERATIONS_LIVE: AtomicU64 = AtomicU64::new(0);
static RESIDENT_GENERATIONS_CREATED: AtomicU64 = AtomicU64::new(0);
static RESIDENT_GENERATIONS_DROPPED: AtomicU64 = AtomicU64::new(0);

pub fn next_resident_generation_id() -> LogicalGenerationId {
    LogicalGenerationId::new(RESIDENT_GENERATION_SEQUENCE.fetch_add(1, Ordering::Relaxed))
}

pub fn resident_generation_lifetime_counts() -> (u64, u64, u64) {
    (
        RESIDENT_GENERATIONS_LIVE.load(Ordering::Acquire),
        RESIDENT_GENERATIONS_CREATED.load(Ordering::Relaxed),
        RESIDENT_GENERATIONS_DROPPED.load(Ordering::Relaxed),
    )
}

#[derive(Debug)]
pub struct ResidentGenerationLifetime;

impl ResidentGenerationLifetime {
    pub fn register() -> Self {
        RESIDENT_GENERATIONS_CREATED.fetch_add(1, Ordering::Relaxed);
        RESIDENT_GENERATIONS_LIVE.fetch_add(1, Ordering::Release);
        Self
    }
}

impl Drop for ResidentGenerationLifetime {
    fn drop(&mut self) {
        let previous = RESIDENT_GENERATIONS_LIVE.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(
            previous > 0,
            "resident generation lifetime counter underflow"
        );
        RESIDENT_GENERATIONS_DROPPED.fetch_add(1, Ordering::Relaxed);
    }
}

pub struct ResidentGenerationDrainControl {
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
    pub fn new(id: LogicalGenerationId, workload_stop: SharedResidentStopSignal) -> Arc<Self> {
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

    #[inline]
    pub fn id(&self) -> LogicalGenerationId {
        self.id
    }

    #[inline]
    pub fn activate(&self) -> Result<(), String> {
        self.lifecycle.activate().map_err(str::to_owned)
    }

    #[inline]
    pub fn admission_is_open(&self) -> bool {
        self.lifecycle.admission_is_open()
    }

    #[inline]
    pub fn close_admission(&self) {
        self.lifecycle.close_admission();
    }

    #[inline]
    pub fn reopen_admission(&self) -> Result<(), String> {
        self.lifecycle.reopen_admission().map_err(str::to_owned)
    }

    #[inline]
    pub fn stop_is_requested(&self) -> bool {
        self.lifecycle.stop_is_requested()
    }

    #[inline]
    pub fn udp_stop_is_requested(&self) -> bool {
        self.udp_stop.load(Ordering::Acquire)
    }

    #[inline]
    pub fn flow_stop_is_requested(&self) -> bool {
        self.flow_stop.load(Ordering::Acquire)
    }

    #[inline]
    pub fn flow_stop_handle(&self) -> SharedResidentStopSignal {
        Arc::clone(&self.flow_stop)
    }

    #[inline]
    pub fn retire_workloads(&self) {
        self.lifecycle.request_stop();
        self.workload_stop.store(true, Ordering::Release);
    }

    #[inline]
    pub fn request_force_stop(&self) {
        self.retire_workloads();
        self.flow_stop.store(true, Ordering::Release);
        self.udp_stop.store(true, Ordering::Release);
        self.lifecycle.stop();
    }

    #[inline]
    pub fn register_udp_runtime(&self) {
        self.udp_router_retained.store(true, Ordering::Release);
        self.udp_dns_runtime_retained.store(true, Ordering::Release);
    }

    #[inline]
    pub fn release_udp_router(&self) {
        self.udp_router_retained.store(false, Ordering::Release);
    }

    #[inline]
    pub fn release_udp_dns_runtime(&self) {
        self.udp_dns_runtime_retained
            .store(false, Ordering::Release);
    }

    #[inline]
    pub fn udp_router_is_retained(&self) -> bool {
        self.udp_router_retained.load(Ordering::Acquire)
    }

    #[inline]
    pub fn udp_dns_runtime_is_retained(&self) -> bool {
        self.udp_dns_runtime_retained.load(Ordering::Acquire)
    }
}

impl ResidentDrainControl for ResidentGenerationDrainControl {
    fn id(&self) -> LogicalGenerationId {
        self.id()
    }

    fn close_admission(&self) {
        self.close_admission();
    }

    fn reopen_admission(&self) -> Result<(), String> {
        self.reopen_admission()
    }

    fn stop_is_requested(&self) -> bool {
        self.stop_is_requested()
    }

    fn flow_stop_is_requested(&self) -> bool {
        self.flow_stop_is_requested()
    }

    fn udp_stop_is_requested(&self) -> bool {
        self.udp_stop_is_requested()
    }

    fn udp_router_is_retained(&self) -> bool {
        self.udp_router_is_retained()
    }

    fn udp_dns_runtime_is_retained(&self) -> bool {
        self.udp_dns_runtime_is_retained()
    }

    fn request_force_stop(&self) {
        self.request_force_stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

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
