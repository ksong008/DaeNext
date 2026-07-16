use std::sync::{Arc, Condvar, Mutex};
use std::time::Instant;

use super::{
    AbsoluteDeadline, OwnerCancellation, OwnerCancellationSignal, OwnerCloseReason,
    OwnerDrainReason, OwnerGeneration, RedactedOwnerIdentity,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GenerationOwnerState {
    Running,
    Draining(OwnerDrainReason),
    Closed(OwnerCloseReason),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OwnerTaskRole {
    CommandLoop,
    TransportDriver,
    Cleanup,
    Metrics,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct OwnerTaskCounts {
    pub command_loops: usize,
    pub transport_drivers: usize,
    pub cleanup_tasks: usize,
    pub metrics_tasks: usize,
}

impl OwnerTaskCounts {
    pub const fn total(self) -> usize {
        self.command_loops + self.transport_drivers + self.cleanup_tasks + self.metrics_tasks
    }

    fn increment(&mut self, role: OwnerTaskRole) {
        let count = self.count_mut(role);
        *count = count.saturating_add(1);
    }

    fn decrement(&mut self, role: OwnerTaskRole) {
        let count = self.count_mut(role);
        *count = count.saturating_sub(1);
    }

    fn count_mut(&mut self, role: OwnerTaskRole) -> &mut usize {
        match role {
            OwnerTaskRole::CommandLoop => &mut self.command_loops,
            OwnerTaskRole::TransportDriver => &mut self.transport_drivers,
            OwnerTaskRole::Cleanup => &mut self.cleanup_tasks,
            OwnerTaskRole::Metrics => &mut self.metrics_tasks,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GenerationOwnerSnapshot {
    pub generation: OwnerGeneration,
    pub redacted_identity: RedactedOwnerIdentity,
    pub state: GenerationOwnerState,
    pub tasks: OwnerTaskCounts,
}

#[derive(Debug)]
struct GenerationOwnerRuntimeState {
    state: GenerationOwnerState,
    tasks: OwnerTaskCounts,
}

#[derive(Debug)]
struct GenerationOwnerInner {
    generation: OwnerGeneration,
    redacted_identity: RedactedOwnerIdentity,
    state: Mutex<GenerationOwnerRuntimeState>,
    joined: Condvar,
    cancellation: OwnerCancellationSignal,
}

#[derive(Debug)]
pub struct GenerationOwnerBoundary {
    inner: Arc<GenerationOwnerInner>,
}

impl GenerationOwnerBoundary {
    pub fn new(generation: OwnerGeneration, redacted_identity: RedactedOwnerIdentity) -> Self {
        Self {
            inner: Arc::new(GenerationOwnerInner {
                generation,
                redacted_identity,
                state: Mutex::new(GenerationOwnerRuntimeState {
                    state: GenerationOwnerState::Running,
                    tasks: OwnerTaskCounts::default(),
                }),
                joined: Condvar::new(),
                cancellation: OwnerCancellationSignal::new(),
            }),
        }
    }

    pub fn snapshot(&self) -> GenerationOwnerSnapshot {
        let state = self.inner.state.lock().unwrap();
        snapshot_from_state(&self.inner, &state)
    }

    pub fn cancellation(&self) -> OwnerCancellationSignal {
        self.inner.cancellation.clone()
    }

    pub fn register_task(
        &self,
        role: OwnerTaskRole,
    ) -> Result<GenerationTaskGuard, OwnerTaskRegistrationError> {
        let mut state = self.inner.state.lock().unwrap();
        match state.state {
            GenerationOwnerState::Running => state.tasks.increment(role),
            GenerationOwnerState::Draining(reason) => {
                return Err(OwnerTaskRegistrationError::Draining(reason));
            }
            GenerationOwnerState::Closed(reason) => {
                return Err(OwnerTaskRegistrationError::Closed(reason));
            }
        }
        Ok(GenerationTaskGuard {
            inner: Some(Arc::clone(&self.inner)),
            role,
        })
    }

    pub fn apply_command(&self, command: GenerationOwnerCommand) -> GenerationOwnerSnapshot {
        let mut state = self.inner.state.lock().unwrap();
        match command {
            GenerationOwnerCommand::BeginDrain(reason) => {
                if matches!(state.state, GenerationOwnerState::Running) {
                    state.state = GenerationOwnerState::Draining(reason);
                    self.inner
                        .cancellation
                        .cancel(OwnerCancellation::GenerationDraining);
                }
            }
            GenerationOwnerCommand::Close(reason)
                if state.tasks.total() == 0
                    && matches!(state.state, GenerationOwnerState::Draining(_)) =>
            {
                state.state = GenerationOwnerState::Closed(reason);
            }
            GenerationOwnerCommand::Close(_) => {}
        }
        snapshot_from_state(&self.inner, &state)
    }

    pub fn wait_joined(
        &self,
        deadline: AbsoluteDeadline,
    ) -> Result<GenerationOwnerSnapshot, OwnerTaskJoinError> {
        let mut state = self.inner.state.lock().unwrap();
        loop {
            if state.tasks.total() == 0 {
                return Ok(snapshot_from_state(&self.inner, &state));
            }
            let Some(remaining) = deadline.remaining_at(Instant::now()) else {
                return Err(OwnerTaskJoinError::DeadlineElapsed(snapshot_from_state(
                    &self.inner,
                    &state,
                )));
            };
            let (next, timeout) = self.inner.joined.wait_timeout(state, remaining).unwrap();
            state = next;
            if timeout.timed_out() && state.tasks.total() != 0 {
                return Err(OwnerTaskJoinError::DeadlineElapsed(snapshot_from_state(
                    &self.inner,
                    &state,
                )));
            }
        }
    }
}

impl Drop for GenerationOwnerBoundary {
    fn drop(&mut self) {
        self.inner
            .cancellation
            .cancel(OwnerCancellation::GenerationDraining);
        let mut state = self.inner.state.lock().unwrap();
        if matches!(state.state, GenerationOwnerState::Running) {
            state.state = GenerationOwnerState::Draining(OwnerDrainReason::Shutdown);
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GenerationOwnerCommand {
    BeginDrain(OwnerDrainReason),
    Close(OwnerCloseReason),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OwnerTaskRegistrationError {
    Draining(OwnerDrainReason),
    Closed(OwnerCloseReason),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OwnerTaskJoinError {
    DeadlineElapsed(GenerationOwnerSnapshot),
}

#[must_use = "the task guard must live inside the generation-owned task"]
#[derive(Debug)]
pub struct GenerationTaskGuard {
    inner: Option<Arc<GenerationOwnerInner>>,
    role: OwnerTaskRole,
}

impl Drop for GenerationTaskGuard {
    fn drop(&mut self) {
        let Some(inner) = self.inner.take() else {
            return;
        };
        let mut state = inner.state.lock().unwrap();
        state.tasks.decrement(self.role);
        let joined = state.tasks.total() == 0;
        drop(state);
        if joined {
            inner.joined.notify_all();
        }
    }
}

fn snapshot_from_state(
    inner: &GenerationOwnerInner,
    state: &GenerationOwnerRuntimeState,
) -> GenerationOwnerSnapshot {
    GenerationOwnerSnapshot {
        generation: inner.generation,
        redacted_identity: inner.redacted_identity.clone(),
        state: state.state,
        tasks: state.tasks,
    }
}
