use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use tokio::sync::watch;
use tokio::task::{JoinError, JoinHandle};

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
    state_changed: watch::Sender<u64>,
    cancellation: OwnerCancellationSignal,
}

#[derive(Debug)]
pub struct GenerationOwnerBoundary {
    inner: Arc<GenerationOwnerInner>,
}

impl GenerationOwnerBoundary {
    pub fn new(generation: OwnerGeneration, redacted_identity: RedactedOwnerIdentity) -> Self {
        let (state_changed, _) = watch::channel(0);
        Self {
            inner: Arc::new(GenerationOwnerInner {
                generation,
                redacted_identity,
                state: Mutex::new(GenerationOwnerRuntimeState {
                    state: GenerationOwnerState::Running,
                    tasks: OwnerTaskCounts::default(),
                }),
                state_changed,
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

    pub fn spawn_task_on<F>(
        &self,
        runtime: &tokio::runtime::Handle,
        role: OwnerTaskRole,
        future: F,
    ) -> Result<GenerationTaskHandle<F::Output>, OwnerTaskRegistrationError>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        let guard = self.reserve_task(role)?;
        let task = runtime.spawn(async move {
            let _guard = guard;
            future.await
        });
        Ok(GenerationTaskHandle::new(task))
    }

    fn reserve_task(
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
        let previous_state = state.state;
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
        let snapshot = snapshot_from_state(&self.inner, &state);
        drop(state);
        if snapshot.state != previous_state {
            notify_state_changed(&self.inner.state_changed);
        }
        snapshot
    }

    pub async fn wait_joined(
        &self,
        deadline: AbsoluteDeadline,
    ) -> Result<GenerationOwnerSnapshot, OwnerTaskJoinError> {
        let mut state_changed = self.inner.state_changed.subscribe();
        loop {
            let snapshot = self.snapshot();
            if matches!(snapshot.state, GenerationOwnerState::Running) {
                return Err(OwnerTaskJoinError::NotDraining(snapshot));
            }
            if snapshot.tasks.total() == 0 {
                return Ok(snapshot);
            }
            if deadline.check_at(Instant::now()).is_err() {
                return Err(OwnerTaskJoinError::DeadlineElapsed(snapshot));
            }

            tokio::select! {
                _ = state_changed.changed() => {}
                _ = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline.instant())) => {
                    let snapshot = self.snapshot();
                    if snapshot.tasks.total() == 0 {
                        return Ok(snapshot);
                    }
                    return Err(OwnerTaskJoinError::DeadlineElapsed(snapshot));
                }
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
        let transitioned = if matches!(state.state, GenerationOwnerState::Running) {
            state.state = GenerationOwnerState::Draining(OwnerDrainReason::Shutdown);
            true
        } else {
            false
        };
        drop(state);
        if transitioned {
            notify_state_changed(&self.inner.state_changed);
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
    NotDraining(GenerationOwnerSnapshot),
    DeadlineElapsed(GenerationOwnerSnapshot),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GenerationTaskJoinError {
    Cancelled,
    Panicked,
    DeadlineElapsed,
}

#[must_use = "generation-owned tasks must be joined or explicitly aborted"]
#[derive(Debug)]
pub struct GenerationTaskHandle<T> {
    task: Option<JoinHandle<T>>,
}

impl<T> GenerationTaskHandle<T> {
    fn new(task: JoinHandle<T>) -> Self {
        Self { task: Some(task) }
    }

    pub fn abort(&self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }

    pub fn is_finished(&self) -> bool {
        self.task.as_ref().is_none_or(JoinHandle::is_finished)
    }

    pub async fn join(mut self) -> Result<T, GenerationTaskJoinError> {
        classify_task_join(self.take_task().await)
    }

    pub async fn join_until(
        mut self,
        deadline: AbsoluteDeadline,
    ) -> Result<T, GenerationTaskJoinError> {
        let mut task = self
            .task
            .take()
            .expect("generation task handle must own its join handle");
        if task.is_finished() {
            return classify_task_join(task.await);
        }
        if deadline.check_at(Instant::now()).is_err() {
            return abort_and_join_at_deadline(task).await;
        }
        tokio::select! {
            result = &mut task => classify_task_join(result),
            _ = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline.instant())) =>
                abort_and_join_at_deadline(task).await,
        }
    }

    async fn take_task(&mut self) -> Result<T, JoinError> {
        self.task
            .take()
            .expect("generation task handle must own its join handle")
            .await
    }
}

impl<T> Drop for GenerationTaskHandle<T> {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

fn classify_task_join<T>(result: Result<T, JoinError>) -> Result<T, GenerationTaskJoinError> {
    result.map_err(|error| {
        if error.is_panic() {
            GenerationTaskJoinError::Panicked
        } else {
            GenerationTaskJoinError::Cancelled
        }
    })
}

async fn abort_and_join_at_deadline<T>(task: JoinHandle<T>) -> Result<T, GenerationTaskJoinError> {
    task.abort();
    match task.await {
        Err(error) if error.is_panic() => Err(GenerationTaskJoinError::Panicked),
        Ok(_) | Err(_) => Err(GenerationTaskJoinError::DeadlineElapsed),
    }
}

#[derive(Debug)]
struct GenerationTaskGuard {
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
        drop(state);
        notify_state_changed(&inner.state_changed);
    }
}

fn notify_state_changed(state_changed: &watch::Sender<u64>) {
    state_changed.send_modify(|revision| *revision = revision.wrapping_add(1));
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
