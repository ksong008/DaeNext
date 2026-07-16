use super::*;
use crate::physical_owner::{
    OwnerLifecycleSnapshot, OwnerStateTransitionError, PhysicalOwnerFailure,
    PhysicalOwnerLifecycle, PhysicalOwnerState,
};

#[must_use = "the reservation must remain attached to its physical owner"]
#[derive(Debug)]
pub struct OwnerReservation {
    pub(super) inner: Option<Arc<OwnerAdmissionInner>>,
    pub(super) charged_bytes: ChargedOwnerBytes,
}

impl OwnerReservation {
    pub fn attach<T>(self, owner: T) -> AdmittedPhysicalOwner<T> {
        AdmittedPhysicalOwner {
            owner: Some(owner),
            lifecycle: PhysicalOwnerLifecycle::connecting(),
            reservation: Some(self),
        }
    }
}

impl Drop for OwnerReservation {
    fn drop(&mut self) {
        let Some(inner) = self.inner.take() else {
            return;
        };
        let mut counters = inner.counters.lock().unwrap();
        counters.active_owners = counters.active_owners.saturating_sub(1);
        counters.active_charged_bytes = counters
            .active_charged_bytes
            .saturating_sub(self.charged_bytes.get());
        let drained = counters.active_owners == 0;
        drop(counters);
        if drained {
            inner.drained.notify_all();
        }
    }
}

#[must_use = "the admitted owner retains its resource charge until it is closed and dropped"]
#[derive(Debug)]
pub struct AdmittedPhysicalOwner<T> {
    owner: Option<T>,
    lifecycle: PhysicalOwnerLifecycle,
    reservation: Option<OwnerReservation>,
}

impl<T> AdmittedPhysicalOwner<T> {
    pub fn owner(&self) -> &T {
        self.owner.as_ref().unwrap()
    }

    pub fn owner_mut(&mut self) -> &mut T {
        self.owner.as_mut().unwrap()
    }

    pub fn lifecycle(&self) -> OwnerLifecycleSnapshot {
        self.lifecycle.snapshot()
    }

    pub fn mark_ready(&self) -> Result<(), OwnerStateTransitionError> {
        self.lifecycle.mark_ready()
    }

    pub fn mark_failed(
        &self,
        failure: PhysicalOwnerFailure,
    ) -> Result<(), OwnerStateTransitionError> {
        self.lifecycle.mark_failed(failure)
    }

    pub fn begin_drain(&self, reason: OwnerDrainReason) -> Result<(), OwnerStateTransitionError> {
        self.lifecycle.begin_drain(reason)
    }

    pub fn close(
        mut self,
        reason: OwnerCloseReason,
        close_owner: impl FnOnce(&mut T),
    ) -> Result<(), OwnerStateTransitionError> {
        if self.lifecycle.snapshot().state != PhysicalOwnerState::Draining {
            self.lifecycle.begin_drain(close_reason_as_drain(reason))?;
        }
        close_owner(self.owner.as_mut().unwrap());
        self.lifecycle.mark_closed(reason)?;
        self.drop_owner_then_reservation();
        Ok(())
    }

    fn drop_owner_then_reservation(&mut self) {
        drop(self.owner.take());
        drop(self.reservation.take());
    }
}

impl<T> Drop for AdmittedPhysicalOwner<T> {
    fn drop(&mut self) {
        if self.lifecycle.snapshot().state != PhysicalOwnerState::Closed {
            let _ = self.lifecycle.mark_closed(OwnerCloseReason::ImplicitDrop);
        }
        self.drop_owner_then_reservation();
    }
}

const fn close_reason_as_drain(reason: OwnerCloseReason) -> OwnerDrainReason {
    match reason {
        OwnerCloseReason::Reload => OwnerDrainReason::Reload,
        OwnerCloseReason::Shutdown => OwnerDrainReason::Shutdown,
        OwnerCloseReason::Fault => OwnerDrainReason::Fault,
        OwnerCloseReason::Completed
        | OwnerCloseReason::Cancelled
        | OwnerCloseReason::ImplicitDrop => OwnerDrainReason::OperatorRequest,
    }
}
