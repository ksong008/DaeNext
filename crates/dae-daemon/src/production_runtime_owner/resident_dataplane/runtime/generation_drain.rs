use super::*;

trait ResidentDrainableGeneration: std::fmt::Debug + Send + Sync {
    fn id(&self) -> u64;
    fn close_admission(&self);
    fn reopen_admission(&self) -> Result<(), String>;
    fn stop_is_requested(&self) -> bool;
    fn request_stop(&self);
}

impl ResidentDrainableGeneration for ResidentDataplaneGeneration {
    fn id(&self) -> u64 {
        self.id
    }

    fn close_admission(&self) {
        ResidentDataplaneGeneration::close_admission(self);
    }

    fn reopen_admission(&self) -> Result<(), String> {
        ResidentDataplaneGeneration::reopen_admission(self)
    }

    fn stop_is_requested(&self) -> bool {
        ResidentDataplaneGeneration::stop_is_requested(self)
    }

    fn request_stop(&self) {
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
    generation: Arc<dyn ResidentDrainableGeneration>,
    retired_at: Instant,
    deadline: Instant,
    stop_reason: Option<ResidentGenerationStopReason>,
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
            .position(|retired| retired.generation.id() == generation_id)
            .ok_or_else(|| {
                "resident generation is no longer available for reactivation".to_owned()
            })?;
        let retired = &state.retired[position];
        if retired.stop_reason.is_some() || retired.generation.stop_is_requested() {
            return Err("a stopped resident generation cannot be reactivated".to_owned());
        }
        retired.generation.reopen_admission()?;
        if retired.generation.stop_is_requested() {
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
            retired.generation.request_stop();
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
        json!({
            "retired": state.retired.len(),
            "retiredTotal": state.retired_total,
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
                    Some(Arc::clone(&retired.generation))
                } else {
                    None
                }
            });
            if pressure_stop.is_some() {
                state.pressure_forced_total = state.pressure_forced_total.saturating_add(1);
            }
            pressure_stop
        };
        if let Some(generation) = pressure_stop {
            generation.request_stop();
        }
        Err("retired resident generations are still draining; retry publication after cleanup progress"
            .to_owned())
    }

    fn retire_shared_at(
        &self,
        generation: Arc<dyn ResidentDrainableGeneration>,
        retired_at: Instant,
    ) {
        generation.close_admission();
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
                .all(|retired| retired.generation.id() != generation.id())
        );
        state.retired_total = state.retired_total.saturating_add(1);
        state.retired.push(RetiredResidentGeneration {
            generation,
            retired_at,
            deadline,
            stop_reason: None,
        });
    }

    fn reap(&self, now: Instant) {
        let mut released = Vec::new();
        let mut forced = Vec::new();
        {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut retained = Vec::with_capacity(state.retired.len());
            let mut released_count = 0_u64;
            let mut natural_count = 0_u64;
            let mut deadline_forced_count = 0_u64;
            for mut retired in state.retired.drain(..) {
                if Arc::strong_count(&retired.generation) == 1 {
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
                    forced.push(Arc::clone(&retired.generation));
                }
                retained.push(retired);
            }
            state.retired = retained;
            state.released_total = state.released_total.saturating_add(released_count);
            state.natural_total = state.natural_total.saturating_add(natural_count);
            state.deadline_forced_total = state
                .deadline_forced_total
                .saturating_add(deadline_forced_count);
        }
        for generation in forced {
            generation.request_stop();
        }
        for retired in released {
            retired.generation.request_stop();
        }
    }
}

#[cfg(test)]
#[path = "generation_drain/tests.rs"]
mod tests;
