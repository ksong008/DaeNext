use super::*;

#[cfg(not(test))]
use crate::allocator::{AllocatorReclaimReason, allocator_request_reclaim};

trait ResidentDrainControl: std::fmt::Debug + Send + Sync {
    fn id(&self) -> u64;
    fn close_admission(&self);
    fn reopen_admission(&self) -> Result<(), String>;
    fn stop_is_requested(&self) -> bool;
    fn udp_stop_is_requested(&self) -> bool;
    fn udp_router_is_retained(&self) -> bool;
    fn udp_dns_runtime_is_retained(&self) -> bool;
    fn request_force_stop(&self);
}

impl ResidentDrainControl for ResidentGenerationDrainControl {
    fn id(&self) -> u64 {
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

trait ResidentDrainableGeneration: std::fmt::Debug + Send + Sync {
    fn drain_control(&self) -> Arc<dyn ResidentDrainControl>;
    fn retire_workloads(&self);
    fn request_force_stop(&self);
}

impl ResidentDrainableGeneration for ResidentDataplaneGeneration {
    fn drain_control(&self) -> Arc<dyn ResidentDrainControl> {
        Arc::clone(&self.drain_control) as Arc<dyn ResidentDrainControl>
    }

    fn retire_workloads(&self) {
        ResidentDataplaneGeneration::retire_workloads(self);
    }

    fn request_force_stop(&self) {
        ResidentDataplaneGeneration::request_stop(self);
    }
}

#[derive(Clone, Debug)]
pub(super) struct ResidentGenerationDrain {
    state: Arc<Mutex<ResidentGenerationDrainState>>,
    policy: ResidentGenerationDrainPolicy,
}

#[derive(Debug, Default)]
struct ResidentGenerationDrainState {
    retired: Vec<RetiredResidentGeneration>,
    retired_total: u64,
    detached_total: u64,
    released_total: u64,
    natural_total: u64,
    deadline_forced_total: u64,
    pressure_forced_total: u64,
    reactivated_total: u64,
    publication_rejected_total: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ResidentGenerationStopReason {
    MaximumAge,
    ResourcePressure,
}

#[derive(Debug)]
struct RetiredResidentGeneration {
    generation: Option<Arc<dyn ResidentDrainableGeneration>>,
    control: Arc<dyn ResidentDrainControl>,
    retired_at: Instant,
    deadline: Instant,
    stop_reason: Option<ResidentGenerationStopReason>,
}

impl RetiredResidentGeneration {
    fn id(&self) -> u64 {
        self.control.id()
    }

    fn detach_heavy_generation_if_unowned(&mut self) -> bool {
        let should_detach = self
            .generation
            .as_ref()
            .is_some_and(|generation| Arc::strong_count(generation) == 1);
        if !should_detach {
            return false;
        }
        if let Some(generation) = self.generation.take() {
            generation.retire_workloads();
        }
        true
    }

    fn ready_to_release(&self) -> bool {
        self.generation.is_none() && Arc::strong_count(&self.control) == 1
    }

    fn force_stop_target(&self) -> ResidentGenerationStopTarget {
        match self.generation.as_ref() {
            Some(generation) => ResidentGenerationStopTarget::Generation(Arc::clone(generation)),
            None => ResidentGenerationStopTarget::Control(Arc::clone(&self.control)),
        }
    }

    fn external_generation_owners(&self) -> usize {
        self.generation
            .as_ref()
            .map(|generation| Arc::strong_count(generation).saturating_sub(1))
            .unwrap_or(0)
    }

    fn external_drain_owners(&self) -> usize {
        Arc::strong_count(&self.control)
            .saturating_sub(1)
            .saturating_sub(usize::from(self.generation.is_some()))
    }
}

enum ResidentGenerationStopTarget {
    Generation(Arc<dyn ResidentDrainableGeneration>),
    Control(Arc<dyn ResidentDrainControl>),
}

impl ResidentGenerationStopTarget {
    fn request_force_stop(self) {
        match self {
            Self::Generation(generation) => generation.request_force_stop(),
            Self::Control(control) => control.request_force_stop(),
        }
    }
}

impl ResidentGenerationDrain {
    pub(super) fn new(policy: ResidentGenerationDrainPolicy) -> Self {
        assert!(policy.maximum_retired > 0);
        Self {
            state: Arc::new(Mutex::new(ResidentGenerationDrainState::default())),
            policy,
        }
    }

    pub(super) fn prepare_publication(&self) -> Result<(), String> {
        self.prepare_publication_at(Instant::now())
    }

    pub(super) fn retire(&self, generation: Arc<ResidentDataplaneGeneration>) {
        self.retire_shared_at(generation, Instant::now());
    }

    pub(super) fn reactivate(&self, generation_id: u64) -> Result<(), String> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let position = state
            .retired
            .iter()
            .position(|retired| retired.id() == generation_id)
            .ok_or_else(|| {
                "resident generation is no longer available for reactivation".to_owned()
            })?;
        let retired = &state.retired[position];
        if retired.generation.is_none() {
            return Err(
                "resident generation heavy state was already detached and cannot be reactivated"
                    .to_owned(),
            );
        }
        if retired.stop_reason.is_some() || retired.control.stop_is_requested() {
            return Err("a stopped resident generation cannot be reactivated".to_owned());
        }
        retired.control.reopen_admission()?;
        if retired.control.stop_is_requested() {
            return Err("resident generation stopped while it was being reactivated".to_owned());
        }
        state.retired.remove(position);
        state.reactivated_total = state.reactivated_total.saturating_add(1);
        Ok(())
    }

    pub(super) async fn run(self, stop: SharedResidentStopSignal) {
        let mut stop_listener = stop.listener();
        loop {
            tokio::select! {
                _ = stop_listener.cancelled() => break,
                _ = tokio::time::sleep(RESIDENT_IDLE_SLEEP) => self.reap(Instant::now()),
            }
        }
        self.stop_all();
    }

    pub(super) fn stop_all(&self) {
        let retired = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            std::mem::take(&mut state.retired)
        };
        for retired in retired {
            retired.force_stop_target().request_force_stop();
        }
    }

    pub(super) fn snapshot(&self) -> Value {
        let now = Instant::now();
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let oldest_age_ms = state
            .retired
            .iter()
            .map(|retired| now.saturating_duration_since(retired.retired_at))
            .max()
            .unwrap_or_default()
            .as_millis();
        let forced_total = state
            .deadline_forced_total
            .saturating_add(state.pressure_forced_total);
        let owner_evidence = state
            .retired
            .iter()
            .map(|retired| {
                let external_generation_owners = retired.external_generation_owners();
                let external_drain_owners = retired.external_drain_owners();
                json!({
                    "generationId": retired.id(),
                    "ageMs": now.saturating_duration_since(retired.retired_at).as_millis(),
                    "heavyGenerationRetained": retired.generation.is_some(),
                    "externalGenerationOwners": external_generation_owners,
                    "externalDrainOwners": external_drain_owners,
                    "externalStrongOwners": external_generation_owners.saturating_add(external_drain_owners),
                    "stopRequested": retired.control.stop_is_requested(),
                    "udpStopRequested": retired.control.udp_stop_is_requested(),
                    "udpRouterRetained": retired.control.udp_router_is_retained(),
                    "udpDnsRuntimeRetained": retired.control.udp_dns_runtime_is_retained(),
                })
            })
            .collect::<Vec<_>>();
        json!({
            "retired": state.retired.len(),
            "retiredTotal": state.retired_total,
            "detachedTotal": state.detached_total,
            "releasedTotal": state.released_total,
            "naturalTotal": state.natural_total,
            "forcedTotal": forced_total,
            "deadlineForcedTotal": state.deadline_forced_total,
            "pressureForcedTotal": state.pressure_forced_total,
            "reactivatedTotal": state.reactivated_total,
            "publicationRejectedTotal": state.publication_rejected_total,
            "maximumRetired": self.policy.maximum_retired,
            "maximumAgeMs": self.policy.maximum_age.as_millis(),
            "oldestAgeMs": oldest_age_ms,
            "policySource": self.policy.source,
            "timeoutMs": self.policy.maximum_age.as_millis(),
            "ownerEvidence": owner_evidence,
        })
    }

    fn prepare_publication_at(&self, now: Instant) -> Result<(), String> {
        self.reap(now);
        let pressure_stop = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if state.retired.len() < self.policy.maximum_retired {
                return Ok(());
            }
            state.publication_rejected_total = state.publication_rejected_total.saturating_add(1);
            let pressure_stop = state.retired.first_mut().and_then(|retired| {
                if retired.stop_reason.is_none() {
                    retired.stop_reason = Some(ResidentGenerationStopReason::ResourcePressure);
                    Some(retired.force_stop_target())
                } else {
                    None
                }
            });
            if pressure_stop.is_some() {
                state.pressure_forced_total = state.pressure_forced_total.saturating_add(1);
            }
            pressure_stop
        };
        if let Some(target) = pressure_stop {
            target.request_force_stop();
        }
        Err("retired resident generations are still draining; retry publication after cleanup progress"
            .to_owned())
    }

    fn retire_shared_at(
        &self,
        generation: Arc<dyn ResidentDrainableGeneration>,
        retired_at: Instant,
    ) {
        let control = generation.drain_control();
        control.close_admission();
        let deadline = retired_at
            .checked_add(self.policy.maximum_age)
            .unwrap_or(retired_at);
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        debug_assert!(state.retired.len() < self.policy.maximum_retired);
        debug_assert!(
            state
                .retired
                .iter()
                .all(|retired| retired.id() != control.id())
        );
        state.retired_total = state.retired_total.saturating_add(1);
        state.retired.push(RetiredResidentGeneration {
            generation: Some(generation),
            control,
            retired_at,
            deadline,
            stop_reason: None,
        });
    }

    fn reap(&self, now: Instant) {
        let mut released = Vec::new();
        let mut forced = Vec::new();
        let detached_any;
        {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut retained = Vec::with_capacity(state.retired.len());
            let mut released_count = 0_u64;
            let mut detached_count = 0_u64;
            let mut natural_count = 0_u64;
            let mut deadline_forced_count = 0_u64;
            for mut retired in state.retired.drain(..) {
                if retired.detach_heavy_generation_if_unowned() {
                    detached_count = detached_count.saturating_add(1);
                }
                if retired.ready_to_release() {
                    released_count = released_count.saturating_add(1);
                    if retired.stop_reason.is_none() {
                        natural_count = natural_count.saturating_add(1);
                    }
                    released.push(retired);
                    continue;
                }
                if now >= retired.deadline && retired.stop_reason.is_none() {
                    retired.stop_reason = Some(ResidentGenerationStopReason::MaximumAge);
                    deadline_forced_count = deadline_forced_count.saturating_add(1);
                    forced.push(retired.force_stop_target());
                }
                retained.push(retired);
            }
            state.retired = retained;
            state.detached_total = state.detached_total.saturating_add(detached_count);
            state.released_total = state.released_total.saturating_add(released_count);
            state.natural_total = state.natural_total.saturating_add(natural_count);
            state.deadline_forced_total = state
                .deadline_forced_total
                .saturating_add(deadline_forced_count);
            detached_any = detached_count > 0;
        }
        for target in forced {
            target.request_force_stop();
        }
        let released_any = !released.is_empty();
        drop(released);
        if detached_any || released_any {
            request_retired_generation_reclaim();
        }
    }
}

#[cfg(not(test))]
fn request_retired_generation_reclaim() {
    allocator_request_reclaim(AllocatorReclaimReason::RetiredGenerationReleased);
}

#[cfg(test)]
fn request_retired_generation_reclaim() {}

#[cfg(test)]
#[path = "generation_drain/tests.rs"]
mod tests;
