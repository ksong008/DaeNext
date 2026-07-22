use super::*;

#[derive(Clone, Debug)]
pub(super) struct ResidentGenerationDrain {
    state: Arc<Mutex<ResidentGenerationDrainState>>,
    timeout: Duration,
}

#[derive(Debug, Default)]
struct ResidentGenerationDrainState {
    retired: Vec<RetiredResidentGeneration>,
    retired_total: u64,
    released_total: u64,
    forced_total: u64,
}

#[derive(Debug)]
struct RetiredResidentGeneration {
    generation: Arc<ResidentDataplaneGeneration>,
    deadline: Instant,
    stop_requested: bool,
}

impl ResidentGenerationDrain {
    pub(super) fn new(timeout: Duration) -> Self {
        Self {
            state: Arc::new(Mutex::new(ResidentGenerationDrainState::default())),
            timeout,
        }
    }

    pub(super) fn retire(&self, generation: Arc<ResidentDataplaneGeneration>) {
        let deadline = Instant::now()
            .checked_add(self.timeout)
            .unwrap_or_else(Instant::now);
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.retired_total = state.retired_total.saturating_add(1);
        state.retired.push(RetiredResidentGeneration {
            generation,
            deadline,
            stop_requested: false,
        });
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
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        json!({
            "retired": state.retired.len(),
            "retiredTotal": state.retired_total,
            "releasedTotal": state.released_total,
            "forcedTotal": state.forced_total,
            "timeoutMs": self.timeout.as_millis(),
        })
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
            let mut forced_count = 0_u64;
            for retired in state.retired.drain(..) {
                let naturally_released = Arc::strong_count(&retired.generation) == 1;
                if naturally_released {
                    released_count = released_count.saturating_add(1);
                    released.push(retired);
                } else {
                    let mut retired = retired;
                    if now >= retired.deadline && !retired.stop_requested {
                        retired.stop_requested = true;
                        forced_count = forced_count.saturating_add(1);
                        forced.push(Arc::clone(&retired.generation));
                    }
                    retained.push(retired);
                }
            }
            state.retired = retained;
            state.released_total = state.released_total.saturating_add(released_count);
            state.forced_total = state.forced_total.saturating_add(forced_count);
        }
        for generation in forced {
            generation.request_stop();
        }
        for retired in released {
            retired.generation.request_stop();
        }
    }
}
