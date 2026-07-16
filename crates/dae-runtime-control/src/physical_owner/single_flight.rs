use std::sync::{Arc, Mutex};
use std::time::Instant;

use tokio::sync::watch;

use super::{
    AbsoluteDeadline, OwnerCancellationSignal, OwnerDrainReason, PhysicalOwnerFailure,
    PhysicalOwnerState,
};

mod build;
pub use self::build::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SingleFlightOwnerSnapshot {
    pub state: PhysicalOwnerState,
    pub failure: Option<PhysicalOwnerFailure>,
    pub drain_reason: Option<OwnerDrainReason>,
    pub revision: u64,
}

#[derive(Debug)]
pub(super) struct SingleFlightState<T> {
    pub(super) snapshot: SingleFlightOwnerSnapshot,
    pub(super) accepting: bool,
    pub(super) value: Option<Arc<T>>,
}

#[derive(Debug)]
pub(super) struct SingleFlightInner<T> {
    pub(super) state: Mutex<SingleFlightState<T>>,
    pub(super) revision: watch::Sender<u64>,
}

#[derive(Debug)]
pub struct SingleFlightPhysicalOwner<T> {
    inner: Arc<SingleFlightInner<T>>,
}

impl<T> Clone for SingleFlightPhysicalOwner<T> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<T> Default for SingleFlightPhysicalOwner<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> SingleFlightPhysicalOwner<T> {
    pub fn new() -> Self {
        let (revision, _) = watch::channel(0);
        Self {
            inner: Arc::new(SingleFlightInner {
                state: Mutex::new(SingleFlightState {
                    snapshot: SingleFlightOwnerSnapshot {
                        state: PhysicalOwnerState::Closed,
                        failure: None,
                        drain_reason: None,
                        revision: 0,
                    },
                    accepting: true,
                    value: None,
                }),
                revision,
            }),
        }
    }

    pub fn snapshot(&self) -> SingleFlightOwnerSnapshot {
        self.inner.state.lock().unwrap().snapshot
    }

    pub fn begin_or_observe(
        &self,
        deadline: AbsoluteDeadline,
        cancellation: &OwnerCancellationSignal,
    ) -> Result<SingleFlightDecision<T>, SingleFlightError> {
        deadline
            .check_at(Instant::now())
            .map_err(SingleFlightError::Cancelled)?;
        cancellation.check().map_err(SingleFlightError::Cancelled)?;

        let mut state = self.inner.state.lock().unwrap();
        if !state.accepting {
            return match state.snapshot.state {
                PhysicalOwnerState::Draining => Err(SingleFlightError::Draining(
                    state
                        .snapshot
                        .drain_reason
                        .unwrap_or(OwnerDrainReason::OperatorRequest),
                )),
                _ => Err(SingleFlightError::Closed),
            };
        }
        match state.snapshot.state {
            PhysicalOwnerState::Ready => {
                return Ok(SingleFlightDecision::Ready(
                    state.value.as_ref().unwrap().clone(),
                ));
            }
            PhysicalOwnerState::Connecting => {
                return Ok(SingleFlightDecision::Observe(SingleFlightObserver {
                    inner: Arc::clone(&self.inner),
                    revision: self.inner.revision.subscribe(),
                    cancellation: cancellation.subscribe(),
                    deadline,
                }));
            }
            PhysicalOwnerState::Draining => {
                return Err(SingleFlightError::Draining(
                    state
                        .snapshot
                        .drain_reason
                        .unwrap_or(OwnerDrainReason::OperatorRequest),
                ));
            }
            PhysicalOwnerState::Failed => {
                return Err(SingleFlightError::Failed(state.snapshot.failure.unwrap()));
            }
            PhysicalOwnerState::Closed => {}
        }

        state.snapshot.state = PhysicalOwnerState::Connecting;
        state.snapshot.failure = None;
        state.snapshot.drain_reason = None;
        state.snapshot.revision = state.snapshot.revision.wrapping_add(1);
        state.value = None;
        let revision = state.snapshot.revision;
        drop(state);
        self.inner.revision.send_replace(revision);

        Ok(SingleFlightDecision::Build(SingleFlightBuilder {
            inner: Arc::clone(&self.inner),
            revision,
            finished: false,
        }))
    }

    pub fn begin_drain(&self, reason: OwnerDrainReason) -> SingleFlightOwnerSnapshot {
        let mut state = self.inner.state.lock().unwrap();
        if !state.accepting {
            return state.snapshot;
        }
        state.accepting = false;
        state.snapshot.state = PhysicalOwnerState::Draining;
        state.snapshot.drain_reason = Some(reason);
        state.snapshot.revision = state.snapshot.revision.wrapping_add(1);
        state.value = None;
        let snapshot = state.snapshot;
        drop(state);
        self.inner.revision.send_replace(snapshot.revision);
        snapshot
    }

    pub fn prepare_retry(&self) -> Result<SingleFlightOwnerSnapshot, SingleFlightError> {
        let mut state = self.inner.state.lock().unwrap();
        if !state.accepting {
            return Err(SingleFlightError::Closed);
        }
        if state.snapshot.state != PhysicalOwnerState::Failed {
            return Err(SingleFlightError::RetryUnavailable(state.snapshot.state));
        }
        state.snapshot.state = PhysicalOwnerState::Closed;
        state.snapshot.failure = None;
        state.snapshot.revision = state.snapshot.revision.wrapping_add(1);
        let snapshot = state.snapshot;
        drop(state);
        self.inner.revision.send_replace(snapshot.revision);
        Ok(snapshot)
    }

    pub fn close(&self) -> SingleFlightOwnerSnapshot {
        let mut state = self.inner.state.lock().unwrap();
        if !state.accepting && state.snapshot.state == PhysicalOwnerState::Closed {
            return state.snapshot;
        }
        state.accepting = false;
        state.snapshot.state = PhysicalOwnerState::Closed;
        state.snapshot.revision = state.snapshot.revision.wrapping_add(1);
        state.value = None;
        let snapshot = state.snapshot;
        drop(state);
        self.inner.revision.send_replace(snapshot.revision);
        snapshot
    }

    pub fn fail(
        &self,
        expected_revision: u64,
        failure: PhysicalOwnerFailure,
    ) -> Result<SingleFlightOwnerSnapshot, SingleFlightError> {
        let mut state = self.inner.state.lock().unwrap();
        if !state.accepting {
            return match state.snapshot.state {
                PhysicalOwnerState::Draining => Err(SingleFlightError::Draining(
                    state
                        .snapshot
                        .drain_reason
                        .unwrap_or(OwnerDrainReason::OperatorRequest),
                )),
                _ => Err(SingleFlightError::Closed),
            };
        }
        if state.snapshot.revision != expected_revision {
            return Err(SingleFlightError::Superseded);
        }
        if state.snapshot.state == PhysicalOwnerState::Failed {
            return Err(SingleFlightError::Failed(state.snapshot.failure.unwrap()));
        }
        if state.snapshot.state == PhysicalOwnerState::Draining {
            return Err(SingleFlightError::Draining(
                state
                    .snapshot
                    .drain_reason
                    .unwrap_or(OwnerDrainReason::OperatorRequest),
            ));
        }

        state.snapshot.state = PhysicalOwnerState::Failed;
        state.snapshot.failure = Some(failure);
        state.snapshot.drain_reason = None;
        state.snapshot.revision = state.snapshot.revision.wrapping_add(1);
        state.value = None;
        let snapshot = state.snapshot;
        drop(state);
        self.inner.revision.send_replace(snapshot.revision);
        Ok(snapshot)
    }
}
