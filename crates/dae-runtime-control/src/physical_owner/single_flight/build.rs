use std::sync::Arc;
use std::time::Instant;

use tokio::sync::watch;

use super::{SingleFlightInner, SingleFlightOwnerSnapshot};
use crate::physical_owner::{
    AbsoluteDeadline, OwnerCancellation, OwnerDrainReason, OwnerFailureClass, PhysicalOwnerFailure,
    PhysicalOwnerState,
};

#[derive(Debug)]
pub enum SingleFlightDecision<T> {
    Build(SingleFlightBuilder<T>),
    Observe(SingleFlightObserver<T>),
    Ready(Arc<T>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SingleFlightError {
    Cancelled(OwnerCancellation),
    Failed(PhysicalOwnerFailure),
    Draining(OwnerDrainReason),
    Closed,
    Superseded,
    RetryUnavailable(PhysicalOwnerState),
}

#[must_use = "the elected builder must publish success or failure"]
#[derive(Debug)]
pub struct SingleFlightBuilder<T> {
    pub(super) inner: Arc<SingleFlightInner<T>>,
    pub(super) revision: u64,
    pub(super) finished: bool,
}

impl<T> SingleFlightBuilder<T> {
    pub fn publish_ready(mut self, value: T) -> Result<Arc<T>, SingleFlightError> {
        let value = Arc::new(value);
        let mut state = self.inner.state.lock().unwrap();
        if state.snapshot.state != PhysicalOwnerState::Connecting
            || state.snapshot.revision != self.revision
        {
            return Err(SingleFlightError::Superseded);
        }
        state.snapshot.state = PhysicalOwnerState::Ready;
        state.snapshot.revision = state.snapshot.revision.wrapping_add(1);
        state.value = Some(Arc::clone(&value));
        let revision = state.snapshot.revision;
        self.finished = true;
        drop(state);
        self.inner.revision.send_replace(revision);
        Ok(value)
    }

    pub fn publish_failed(mut self, failure: PhysicalOwnerFailure) -> SingleFlightOwnerSnapshot {
        self.finished = true;
        publish_failure(&self.inner, failure, Some(self.revision))
    }
}

impl<T> Drop for SingleFlightBuilder<T> {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        publish_failure(
            &self.inner,
            PhysicalOwnerFailure::new(OwnerFailureClass::BuilderDropped, "owner-construction"),
            Some(self.revision),
        );
    }
}

#[derive(Debug)]
pub struct SingleFlightObserver<T> {
    pub(super) inner: Arc<SingleFlightInner<T>>,
    pub(super) revision: watch::Receiver<u64>,
    pub(super) cancellation: watch::Receiver<Option<OwnerCancellation>>,
    pub(super) deadline: AbsoluteDeadline,
}

impl<T> SingleFlightObserver<T> {
    pub async fn wait(mut self) -> Result<Arc<T>, SingleFlightError> {
        loop {
            if let Some(reason) = *self.cancellation.borrow() {
                return Err(SingleFlightError::Cancelled(reason));
            }
            self.deadline
                .check_at(Instant::now())
                .map_err(SingleFlightError::Cancelled)?;

            {
                let state = self.inner.state.lock().unwrap();
                match state.snapshot.state {
                    PhysicalOwnerState::Ready => return Ok(state.value.as_ref().unwrap().clone()),
                    PhysicalOwnerState::Failed => {
                        return Err(SingleFlightError::Failed(state.snapshot.failure.unwrap()));
                    }
                    PhysicalOwnerState::Draining => {
                        return Err(SingleFlightError::Draining(
                            state
                                .snapshot
                                .drain_reason
                                .unwrap_or(OwnerDrainReason::OperatorRequest),
                        ));
                    }
                    PhysicalOwnerState::Closed => return Err(SingleFlightError::Closed),
                    PhysicalOwnerState::Connecting => {}
                }
            }

            let deadline = tokio::time::Instant::from_std(self.deadline.instant());
            tokio::select! {
                changed = self.revision.changed() => {
                    if changed.is_err() {
                        return Err(SingleFlightError::Closed);
                    }
                }
                changed = self.cancellation.changed() => {
                    if changed.is_err() {
                        return Err(SingleFlightError::Cancelled(OwnerCancellation::DependencyFailed));
                    }
                }
                _ = tokio::time::sleep_until(deadline) => {
                    return Err(SingleFlightError::Cancelled(OwnerCancellation::DeadlineElapsed));
                }
            }
        }
    }
}

pub(super) fn publish_failure<T>(
    inner: &Arc<SingleFlightInner<T>>,
    failure: PhysicalOwnerFailure,
    expected_revision: Option<u64>,
) -> SingleFlightOwnerSnapshot {
    let mut state = inner.state.lock().unwrap();
    if expected_revision.is_none_or(|revision| {
        state.snapshot.state == PhysicalOwnerState::Connecting
            && state.snapshot.revision == revision
    }) {
        state.snapshot.state = PhysicalOwnerState::Failed;
        state.snapshot.failure = Some(failure);
        state.snapshot.revision = state.snapshot.revision.wrapping_add(1);
        state.value = None;
    }
    let snapshot = state.snapshot;
    drop(state);
    inner.revision.send_replace(snapshot.revision);
    snapshot
}
