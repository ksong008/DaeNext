use super::*;

const HEALTH_BOOTSTRAP_NOT_STARTED: &str = "not-started";
const HEALTH_BOOTSTRAP_PENDING: &str = "pending";
const HEALTH_BOOTSTRAP_HAS_ALIVE: &str = "has-alive";
const HEALTH_BOOTSTRAP_COMPLETED_NO_ALIVE: &str = "completed-no-alive";
const HEALTH_BOOTSTRAP_CANCELLED: &str = "cancelled";

#[derive(Clone, Debug)]
pub(in crate::production_runtime_owner::resident_dataplane) struct ResidentGroupHealthBootstrap {
    state: Arc<Mutex<ResidentGroupHealthBootstrapState>>,
}

#[derive(Debug)]
struct ResidentGroupHealthBootstrapState {
    observed_candidates: Vec<bool>,
    alive_candidates: Vec<bool>,
    started_at: Option<Instant>,
    first_alive_elapsed: Option<Duration>,
    completed: bool,
    cancelled: bool,
}

impl ResidentGroupHealthBootstrap {
    pub(super) fn new(candidate_count: usize) -> Self {
        Self {
            state: Arc::new(Mutex::new(ResidentGroupHealthBootstrapState {
                observed_candidates: vec![false; candidate_count],
                alive_candidates: vec![false; candidate_count],
                started_at: None,
                first_alive_elapsed: None,
                completed: false,
                cancelled: false,
            })),
        }
    }

    pub(super) fn begin(&self) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        state.observed_candidates.fill(false);
        state.alive_candidates.fill(false);
        state.started_at = Some(Instant::now());
        state.first_alive_elapsed = None;
        state.completed = false;
        state.cancelled = false;
    }

    pub(super) fn observe(&self, candidate_index: usize, health_state: HealthState) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        let Some(observed) = state.observed_candidates.get_mut(candidate_index) else {
            return;
        };
        *observed = true;
        if health_state == HealthState::Alive {
            if let Some(alive) = state.alive_candidates.get_mut(candidate_index) {
                *alive = true;
            }
            if state.first_alive_elapsed.is_none() {
                state.first_alive_elapsed = state.started_at.map(|started| started.elapsed());
            }
        }
    }

    pub(super) fn complete(&self, cancelled: bool) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        state.completed = !cancelled;
        state.cancelled = cancelled;
    }

    pub(super) fn snapshot_json(&self) -> Value {
        let Ok(state) = self.state.lock() else {
            return json!({"state": "unavailable"});
        };
        let observed = state
            .observed_candidates
            .iter()
            .filter(|observed| **observed)
            .count();
        let alive = state
            .alive_candidates
            .iter()
            .filter(|alive| **alive)
            .count();
        let phase = if state.cancelled {
            HEALTH_BOOTSTRAP_CANCELLED
        } else if state.started_at.is_none() {
            HEALTH_BOOTSTRAP_NOT_STARTED
        } else if alive > 0 {
            HEALTH_BOOTSTRAP_HAS_ALIVE
        } else if state.completed {
            HEALTH_BOOTSTRAP_COMPLETED_NO_ALIVE
        } else {
            HEALTH_BOOTSTRAP_PENDING
        };
        json!({
            "state": phase,
            "completed": state.completed,
            "observedCandidates": observed,
            "totalCandidates": state.observed_candidates.len(),
            "aliveCandidates": alive,
            "firstAliveElapsedMillis": state
                .first_alive_elapsed
                .map(|elapsed| elapsed.as_millis().to_string()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bootstrap_transitions_from_pending_to_first_alive_without_waiting_for_completion() {
        let bootstrap = ResidentGroupHealthBootstrap::new(2);
        bootstrap.begin();
        bootstrap.observe(0, HealthState::Dead);
        assert_eq!(bootstrap.snapshot_json()["state"], json!("pending"));
        bootstrap.observe(1, HealthState::Alive);
        assert_eq!(bootstrap.snapshot_json()["state"], json!("has-alive"));
        assert_eq!(bootstrap.snapshot_json()["aliveCandidates"], json!(1));
        bootstrap.complete(false);
        assert_eq!(bootstrap.snapshot_json()["completed"], json!(true));
    }

    #[test]
    fn bootstrap_reports_completed_no_alive_and_cancelled() {
        let bootstrap = ResidentGroupHealthBootstrap::new(1);
        bootstrap.begin();
        bootstrap.observe(0, HealthState::Dead);
        bootstrap.complete(false);
        assert_eq!(
            bootstrap.snapshot_json()["state"],
            json!("completed-no-alive")
        );

        bootstrap.begin();
        bootstrap.complete(true);
        assert_eq!(bootstrap.snapshot_json()["state"], json!("cancelled"));
    }

    #[test]
    fn bootstrap_begin_does_not_report_a_seed_as_a_current_probe_result() {
        let bootstrap = ResidentGroupHealthBootstrap::new(1);
        bootstrap.observe(0, HealthState::Alive);
        assert_eq!(bootstrap.snapshot_json()["state"], json!("not-started"));

        bootstrap.begin();
        let snapshot = bootstrap.snapshot_json();
        assert_eq!(snapshot["state"], json!("pending"));
        assert_eq!(snapshot["observedCandidates"], json!(0));
        assert_eq!(snapshot["aliveCandidates"], json!(0));
        assert_eq!(snapshot["firstAliveElapsedMillis"], Value::Null);
    }
}
