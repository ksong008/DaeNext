use std::sync::Mutex;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PhysicalOwnerState {
    Connecting,
    Ready,
    Failed,
    Draining,
    Closed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OwnerFailureClass {
    Connect,
    Authentication,
    Transport,
    Resource,
    Cancelled,
    BuilderDropped,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PhysicalOwnerFailure {
    pub class: OwnerFailureClass,
    pub operation: &'static str,
}

impl PhysicalOwnerFailure {
    pub const fn new(class: OwnerFailureClass, operation: &'static str) -> Self {
        Self { class, operation }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OwnerDrainReason {
    Reload,
    Shutdown,
    Fault,
    OperatorRequest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OwnerCloseReason {
    Completed,
    Reload,
    Shutdown,
    Fault,
    Cancelled,
    ImplicitDrop,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OwnerLifecycleSnapshot {
    pub state: PhysicalOwnerState,
    pub failure: Option<PhysicalOwnerFailure>,
    pub drain_reason: Option<OwnerDrainReason>,
    pub close_reason: Option<OwnerCloseReason>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OwnerStateTransitionError {
    pub from: PhysicalOwnerState,
    pub to: PhysicalOwnerState,
}

#[derive(Debug)]
pub struct PhysicalOwnerLifecycle {
    snapshot: Mutex<OwnerLifecycleSnapshot>,
}

impl Default for PhysicalOwnerLifecycle {
    fn default() -> Self {
        Self::connecting()
    }
}

impl PhysicalOwnerLifecycle {
    pub fn connecting() -> Self {
        Self {
            snapshot: Mutex::new(OwnerLifecycleSnapshot {
                state: PhysicalOwnerState::Connecting,
                failure: None,
                drain_reason: None,
                close_reason: None,
            }),
        }
    }

    pub fn snapshot(&self) -> OwnerLifecycleSnapshot {
        *self.snapshot.lock().unwrap()
    }

    pub fn mark_connecting(&self) -> Result<(), OwnerStateTransitionError> {
        self.transition(PhysicalOwnerState::Connecting, None, None, None)
    }

    pub fn mark_ready(&self) -> Result<(), OwnerStateTransitionError> {
        self.transition(PhysicalOwnerState::Ready, None, None, None)
    }

    pub fn mark_failed(
        &self,
        failure: PhysicalOwnerFailure,
    ) -> Result<(), OwnerStateTransitionError> {
        self.transition(PhysicalOwnerState::Failed, Some(failure), None, None)
    }

    pub fn begin_drain(&self, reason: OwnerDrainReason) -> Result<(), OwnerStateTransitionError> {
        self.transition(PhysicalOwnerState::Draining, None, Some(reason), None)
    }

    pub fn mark_closed(&self, reason: OwnerCloseReason) -> Result<(), OwnerStateTransitionError> {
        self.transition(PhysicalOwnerState::Closed, None, None, Some(reason))
    }

    fn transition(
        &self,
        to: PhysicalOwnerState,
        failure: Option<PhysicalOwnerFailure>,
        drain_reason: Option<OwnerDrainReason>,
        close_reason: Option<OwnerCloseReason>,
    ) -> Result<(), OwnerStateTransitionError> {
        let mut current = self.snapshot.lock().unwrap();
        if current.state == to {
            return Ok(());
        }
        if !transition_allowed(current.state, to) {
            return Err(OwnerStateTransitionError {
                from: current.state,
                to,
            });
        }
        current.state = to;
        if let Some(failure) = failure {
            current.failure = Some(failure);
        }
        if let Some(reason) = drain_reason {
            current.drain_reason = Some(reason);
        }
        if let Some(reason) = close_reason {
            current.close_reason = Some(reason);
        }
        Ok(())
    }
}

const fn transition_allowed(from: PhysicalOwnerState, to: PhysicalOwnerState) -> bool {
    use PhysicalOwnerState as State;
    matches!(
        (from, to),
        (State::Connecting, State::Ready)
            | (State::Connecting, State::Failed)
            | (State::Connecting, State::Draining)
            | (State::Connecting, State::Closed)
            | (State::Ready, State::Failed)
            | (State::Ready, State::Draining)
            | (State::Ready, State::Closed)
            | (State::Failed, State::Connecting)
            | (State::Failed, State::Draining)
            | (State::Failed, State::Closed)
            | (State::Draining, State::Closed)
    )
}
