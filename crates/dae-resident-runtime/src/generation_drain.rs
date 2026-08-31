use dae_resident_core::{LogicalGenerationId, SharedResidentStopSignal};
use serde_json::{Value, json};
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const LOW_MEMORY_MAXIMUM_RETIRED_GENERATIONS: usize = 1;
const BALANCED_MAXIMUM_RETIRED_GENERATIONS: usize = 2;
const HIGH_PERFORMANCE_MAXIMUM_RETIRED_GENERATIONS: usize = 4;
const LOW_MEMORY_GENERATION_MAXIMUM_AGE_SECONDS: u64 =
    dae_resident_core::RESIDENT_UDP_SESSION_IDLE_TIMEOUT_MAX.as_secs() * 3;
const BALANCED_GENERATION_MAXIMUM_AGE_SECONDS: u64 =
    dae_resident_core::RESIDENT_UDP_SESSION_IDLE_TIMEOUT_MAX.as_secs() * 6;
const HIGH_PERFORMANCE_GENERATION_MAXIMUM_AGE_SECONDS: u64 =
    dae_resident_core::RESIDENT_UDP_SESSION_IDLE_TIMEOUT_MAX.as_secs() * 12;

pub trait ResidentGenerationDrainHooks: fmt::Debug + Send + Sync {
    fn request_reclaim(&self);
    fn lifetime_counts(&self) -> (u64, u64, u64);
}

#[derive(Debug)]
struct NoopResidentGenerationDrainHooks;

impl ResidentGenerationDrainHooks for NoopResidentGenerationDrainHooks {
    fn request_reclaim(&self) {}

    fn lifetime_counts(&self) -> (u64, u64, u64) {
        (0, 0, 0)
    }
}

pub trait ResidentDrainControl: fmt::Debug + Send + Sync {
    fn id(&self) -> LogicalGenerationId;
    fn close_admission(&self);
    fn reopen_admission(&self) -> Result<(), String>;
    fn stop_is_requested(&self) -> bool;
    fn flow_stop_is_requested(&self) -> bool;
    fn udp_stop_is_requested(&self) -> bool;
    fn udp_router_is_retained(&self) -> bool;
    fn udp_dns_runtime_is_retained(&self) -> bool;
    fn request_force_stop(&self);
}

pub trait ResidentDrainableGeneration: fmt::Debug + Send + Sync {
    fn drain_control(&self) -> Arc<dyn ResidentDrainControl>;
    fn retire_workloads(&self);
    fn request_force_stop(&self);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResidentGenerationDrainPolicy {
    pub maximum_age: Duration,
    pub maximum_retired: usize,
    pub source: &'static str,
}

impl ResidentGenerationDrainPolicy {
    pub fn selected() -> Self {
        Self::from_runtime_profile(
            dae_resident_core::ResidentRuntimeProfileSelection::selected().profile,
        )
    }

    pub const fn from_runtime_profile(profile: dae_resident_core::ResidentRuntimeProfile) -> Self {
        let (maximum_age_seconds, maximum_retired) = match profile {
            dae_resident_core::ResidentRuntimeProfile::LowMemory => (
                LOW_MEMORY_GENERATION_MAXIMUM_AGE_SECONDS,
                LOW_MEMORY_MAXIMUM_RETIRED_GENERATIONS,
            ),
            dae_resident_core::ResidentRuntimeProfile::Balanced => (
                BALANCED_GENERATION_MAXIMUM_AGE_SECONDS,
                BALANCED_MAXIMUM_RETIRED_GENERATIONS,
            ),
            dae_resident_core::ResidentRuntimeProfile::HighPerformance => (
                HIGH_PERFORMANCE_GENERATION_MAXIMUM_AGE_SECONDS,
                HIGH_PERFORMANCE_MAXIMUM_RETIRED_GENERATIONS,
            ),
        };
        Self {
            maximum_age: Duration::from_secs(maximum_age_seconds),
            maximum_retired,
            source: "runtime-profile",
        }
    }

    #[cfg(test)]
    const fn for_test(maximum_age: Duration, maximum_retired: usize) -> Self {
        Self {
            maximum_age,
            maximum_retired,
            source: "test",
        }
    }
}

#[derive(Clone, Debug)]
pub struct ResidentGenerationDrain {
    state: Arc<Mutex<ResidentGenerationDrainState>>,
    wake: Arc<tokio::sync::Notify>,
    policy: ResidentGenerationDrainPolicy,
    hooks: Arc<dyn ResidentGenerationDrainHooks>,
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
    finalization_forced_total: u64,
    pressure_evicted_total: u64,
    reactivated_total: u64,
    publication_rejected_total: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ResidentGenerationStopReason {
    Finalized,
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
    fn id(&self) -> LogicalGenerationId {
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
    pub fn new(policy: ResidentGenerationDrainPolicy) -> Self {
        Self::with_hooks(policy, Arc::new(NoopResidentGenerationDrainHooks))
    }

    pub fn with_hooks(
        policy: ResidentGenerationDrainPolicy,
        hooks: Arc<dyn ResidentGenerationDrainHooks>,
    ) -> Self {
        assert!(policy.maximum_retired > 0);
        Self {
            state: Arc::new(Mutex::new(ResidentGenerationDrainState::default())),
            wake: Arc::new(tokio::sync::Notify::new()),
            policy,
            hooks,
        }
    }

    pub fn prepare_publication(&self) -> Result<(), String> {
        self.prepare_publication_at(Instant::now())
    }

    pub fn retire(&self, generation: Arc<dyn ResidentDrainableGeneration>) {
        self.retire_shared_at(generation, Instant::now());
    }

    pub fn finalize_retirement(&self, generation_id: LogicalGenerationId) {
        self.finalize_matching_retirements(Some(generation_id));
    }

    pub fn commit_retirements(&self) {
        self.reap(Instant::now());
    }

    fn finalize_matching_retirements(&self, generation_id: Option<LogicalGenerationId>) {
        let targets = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut targets = Vec::new();
            let mut finalized = 0_u64;
            for retired in &mut state.retired {
                if generation_id.is_none_or(|id| retired.id() == id)
                    && retired.stop_reason.is_none()
                {
                    retired.stop_reason = Some(ResidentGenerationStopReason::Finalized);
                    finalized = finalized.saturating_add(1);
                    targets.push(retired.force_stop_target());
                }
            }
            state.finalization_forced_total =
                state.finalization_forced_total.saturating_add(finalized);
            targets
        };
        for target in targets {
            target.request_force_stop();
        }
        self.reap(Instant::now());
    }

    pub fn reactivate(&self, generation_id: LogicalGenerationId) -> Result<(), String> {
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

    pub async fn run(self, stop: SharedResidentStopSignal) {
        let mut stop_listener = stop.listener();
        loop {
            if self.has_pending_retirements() {
                tokio::select! {
                    _ = stop_listener.cancelled() => break,
                    _ = self.wake.notified() => self.reap(Instant::now()),
                    _ = tokio::time::sleep(dae_resident_core::RESIDENT_IDLE_SLEEP) => self.reap(Instant::now()),
                }
            } else {
                tokio::select! {
                    _ = stop_listener.cancelled() => break,
                    _ = self.wake.notified() => self.reap(Instant::now()),
                }
            }
        }
        self.stop_all();
    }

    pub fn stop_all(&self) {
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

    pub fn snapshot(&self) -> Value {
        let now = Instant::now();
        let (process_live_generations, generations_created_total, generations_dropped_total) =
            self.hooks.lifetime_counts();
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
            .saturating_add(state.pressure_forced_total)
            .saturating_add(state.finalization_forced_total);
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
                    "flowStopRequested": retired.control.flow_stop_is_requested(),
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
            "finalizationForcedTotal": state.finalization_forced_total,
            "pressureEvictedTotal": state.pressure_evicted_total,
            "reactivatedTotal": state.reactivated_total,
            "publicationRejectedTotal": state.publication_rejected_total,
            "processLiveGenerations": process_live_generations,
            "generationsCreatedTotal": generations_created_total,
            "generationsDroppedTotal": generations_dropped_total,
            "maximumRetired": self.policy.maximum_retired,
            "maximumAgeMs": self.policy.maximum_age.as_millis(),
            "oldestAgeMs": oldest_age_ms,
            "policySource": self.policy.source,
            "timeoutMs": self.policy.maximum_age.as_millis(),
            "ownerEvidence": owner_evidence,
        })
    }

    pub fn prepare_publication_at(&self, now: Instant) -> Result<(), String> {
        self.reap(now);
        let pressure_eviction = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if state.retired.len() < self.policy.maximum_retired {
                return Ok(());
            }
            pressure_evict_oldest(&mut state)
        };
        pressure_eviction.0.request_force_stop();
        drop(pressure_eviction.1);
        self.hooks.request_reclaim();
        Ok(())
    }

    pub fn retire_shared_at(
        &self,
        generation: Arc<dyn ResidentDrainableGeneration>,
        retired_at: Instant,
    ) {
        let control = generation.drain_control();
        control.close_admission();
        let deadline = retired_at
            .checked_add(self.policy.maximum_age)
            .unwrap_or(retired_at);
        let pressure_eviction = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let pressure_eviction = (state.retired.len() >= self.policy.maximum_retired)
                .then(|| pressure_evict_oldest(&mut state));
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
            pressure_eviction
        };
        if let Some((target, retired)) = pressure_eviction {
            target.request_force_stop();
            drop(retired);
            self.hooks.request_reclaim();
        }
        self.wake.notify_one();
    }

    fn has_pending_retirements(&self) -> bool {
        !self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retired
            .is_empty()
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
            self.hooks.request_reclaim();
        }
    }
}

fn pressure_evict_oldest(
    state: &mut ResidentGenerationDrainState,
) -> (ResidentGenerationStopTarget, RetiredResidentGeneration) {
    let mut retired = state.retired.remove(0);
    retired.stop_reason = Some(ResidentGenerationStopReason::ResourcePressure);
    let target = retired.force_stop_target();
    state.pressure_forced_total = state.pressure_forced_total.saturating_add(1);
    state.pressure_evicted_total = state.pressure_evicted_total.saturating_add(1);
    (target, retired)
}

#[cfg(test)]
#[path = "generation_drain_tests.rs"]
mod tests;
