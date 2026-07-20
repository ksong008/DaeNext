use std::collections::VecDeque;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use tokio::sync::{Notify, watch};

use super::{
    AbsoluteDeadline, OwnerCancellation, OwnerCancellationSignal, OwnerCloseReason,
    OwnerDrainReason,
};

mod admitted_owner;
pub use self::admitted_owner::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OwnerResourceBudget {
    max_active_owners: NonZeroUsize,
    max_charged_bytes: NonZeroUsize,
}

impl OwnerResourceBudget {
    pub const fn new(max_active_owners: NonZeroUsize, max_charged_bytes: NonZeroUsize) -> Self {
        Self {
            max_active_owners,
            max_charged_bytes,
        }
    }

    pub const fn max_active_owners(self) -> NonZeroUsize {
        self.max_active_owners
    }

    pub const fn max_charged_bytes(self) -> NonZeroUsize {
        self.max_charged_bytes
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChargedOwnerBytes(NonZeroUsize);

impl ChargedOwnerBytes {
    pub const fn new(value: NonZeroUsize) -> Self {
        Self(value)
    }

    pub const fn get(self) -> usize {
        self.0.get()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OwnerAdmissionState {
    Open,
    Draining(OwnerDrainReason),
    Closed(OwnerCloseReason),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OwnerAdmissionMetrics {
    pub state: OwnerAdmissionState,
    pub active_owners: usize,
    pub active_charged_bytes: usize,
    pub high_water_owners: usize,
    pub high_water_charged_bytes: usize,
    pub cumulative_admitted: u64,
    pub rejected_by_count: u64,
    pub rejected_by_charged_bytes: u64,
    pub rejected_while_draining: u64,
    pub budget: OwnerResourceBudget,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OwnerAdmissionRejection {
    Cancelled(OwnerCancellation),
    Draining(OwnerDrainReason),
    Closed(OwnerCloseReason),
    LimitsExceeded { count: bool, charged_bytes: bool },
}

#[derive(Debug)]
struct OwnerAdmissionCounters {
    state: OwnerAdmissionState,
    active_owners: usize,
    active_charged_bytes: usize,
    high_water_owners: usize,
    high_water_charged_bytes: usize,
    cumulative_admitted: u64,
    rejected_by_count: u64,
    rejected_by_charged_bytes: u64,
    rejected_while_draining: u64,
    next_waiter_ticket: u64,
    waiters: VecDeque<OwnerAdmissionWaiter>,
}

#[derive(Debug)]
struct OwnerAdmissionWaiter {
    ticket: u64,
    wake: Arc<Notify>,
}

#[derive(Debug)]
struct OwnerAdmissionInner {
    budget: OwnerResourceBudget,
    counters: Mutex<OwnerAdmissionCounters>,
    state_changed: watch::Sender<u64>,
    admission_state_changed: watch::Sender<u64>,
}

#[derive(Clone, Debug)]
pub struct PhysicalOwnerAdmission {
    inner: Arc<OwnerAdmissionInner>,
}

impl PhysicalOwnerAdmission {
    pub fn new(budget: OwnerResourceBudget) -> Self {
        let (state_changed, _) = watch::channel(0);
        let (admission_state_changed, _) = watch::channel(0);
        Self {
            inner: Arc::new(OwnerAdmissionInner {
                budget,
                counters: Mutex::new(OwnerAdmissionCounters {
                    state: OwnerAdmissionState::Open,
                    active_owners: 0,
                    active_charged_bytes: 0,
                    high_water_owners: 0,
                    high_water_charged_bytes: 0,
                    cumulative_admitted: 0,
                    rejected_by_count: 0,
                    rejected_by_charged_bytes: 0,
                    rejected_while_draining: 0,
                    next_waiter_ticket: 0,
                    waiters: VecDeque::new(),
                }),
                state_changed,
                admission_state_changed,
            }),
        }
    }

    pub fn metrics(&self) -> OwnerAdmissionMetrics {
        let counters = self.inner.counters.lock().unwrap();
        metrics_from_counters(self.inner.budget, &counters)
    }

    pub fn try_reserve(
        &self,
        charged_bytes: ChargedOwnerBytes,
        deadline: AbsoluteDeadline,
        cancellation: &OwnerCancellationSignal,
    ) -> Result<OwnerReservation, OwnerAdmissionRejection> {
        deadline
            .check_at(Instant::now())
            .map_err(OwnerAdmissionRejection::Cancelled)?;
        cancellation
            .check()
            .map_err(OwnerAdmissionRejection::Cancelled)?;

        let mut counters = self.inner.counters.lock().unwrap();
        match counters.state {
            OwnerAdmissionState::Open => {}
            OwnerAdmissionState::Draining(reason) => {
                counters.rejected_while_draining =
                    counters.rejected_while_draining.saturating_add(1);
                return Err(OwnerAdmissionRejection::Draining(reason));
            }
            OwnerAdmissionState::Closed(reason) => {
                return Err(OwnerAdmissionRejection::Closed(reason));
            }
        }

        let count_exceeded = counters.active_owners >= self.inner.budget.max_active_owners.get();
        let next_charged_bytes = counters
            .active_charged_bytes
            .checked_add(charged_bytes.get());
        let charged_bytes_exceeded = next_charged_bytes
            .is_none_or(|value| value > self.inner.budget.max_charged_bytes.get());
        if count_exceeded || charged_bytes_exceeded {
            if count_exceeded {
                counters.rejected_by_count = counters.rejected_by_count.saturating_add(1);
            }
            if charged_bytes_exceeded {
                counters.rejected_by_charged_bytes =
                    counters.rejected_by_charged_bytes.saturating_add(1);
            }
            return Err(OwnerAdmissionRejection::LimitsExceeded {
                count: count_exceeded,
                charged_bytes: charged_bytes_exceeded,
            });
        }

        counters.active_owners += 1;
        counters.active_charged_bytes = next_charged_bytes.unwrap();
        counters.high_water_owners = counters.high_water_owners.max(counters.active_owners);
        counters.high_water_charged_bytes = counters
            .high_water_charged_bytes
            .max(counters.active_charged_bytes);
        counters.cumulative_admitted = counters.cumulative_admitted.saturating_add(1);
        drop(counters);

        Ok(OwnerReservation {
            inner: Some(Arc::clone(&self.inner)),
            charged_bytes,
        })
    }

    pub async fn reserve_until(
        &self,
        charged_bytes: ChargedOwnerBytes,
        deadline: AbsoluteDeadline,
        cancellation: &OwnerCancellationSignal,
    ) -> Result<OwnerReservation, OwnerAdmissionRejection> {
        deadline
            .check_at(Instant::now())
            .map_err(OwnerAdmissionRejection::Cancelled)?;
        cancellation
            .check()
            .map_err(OwnerAdmissionRejection::Cancelled)?;

        let mut registration = {
            let mut counters = self.inner.counters.lock().unwrap();
            match counters.state {
                OwnerAdmissionState::Open => {}
                OwnerAdmissionState::Draining(reason) => {
                    counters.rejected_while_draining =
                        counters.rejected_while_draining.saturating_add(1);
                    return Err(OwnerAdmissionRejection::Draining(reason));
                }
                OwnerAdmissionState::Closed(reason) => {
                    return Err(OwnerAdmissionRejection::Closed(reason));
                }
            }
            if charged_bytes.get() > self.inner.budget.max_charged_bytes.get() {
                counters.rejected_by_charged_bytes =
                    counters.rejected_by_charged_bytes.saturating_add(1);
                return Err(OwnerAdmissionRejection::LimitsExceeded {
                    count: false,
                    charged_bytes: true,
                });
            }
            let ticket = next_waiter_ticket(&mut counters);
            let wake = Arc::new(Notify::new());
            counters.waiters.push_back(OwnerAdmissionWaiter {
                ticket,
                wake: Arc::clone(&wake),
            });
            OwnerAdmissionWaitRegistration::new(Arc::clone(&self.inner), ticket, wake)
        };
        let mut admission_state_changed = self.inner.admission_state_changed.subscribe();
        let mut cancellation_changed = cancellation.subscribe();

        loop {
            deadline
                .check_at(Instant::now())
                .map_err(OwnerAdmissionRejection::Cancelled)?;
            cancellation
                .check()
                .map_err(OwnerAdmissionRejection::Cancelled)?;

            let mut admitted = false;
            let mut rejection = None;
            {
                let mut counters = self.inner.counters.lock().unwrap();
                match counters.state {
                    OwnerAdmissionState::Open => {}
                    OwnerAdmissionState::Draining(reason) => {
                        counters.rejected_while_draining =
                            counters.rejected_while_draining.saturating_add(1);
                        rejection = Some(OwnerAdmissionRejection::Draining(reason));
                    }
                    OwnerAdmissionState::Closed(reason) => {
                        rejection = Some(OwnerAdmissionRejection::Closed(reason));
                    }
                }
                if rejection.is_none()
                    && counters
                        .waiters
                        .front()
                        .is_some_and(|waiter| waiter.ticket == registration.ticket)
                {
                    let count_available =
                        counters.active_owners < self.inner.budget.max_active_owners.get();
                    let next_charged_bytes = counters
                        .active_charged_bytes
                        .checked_add(charged_bytes.get());
                    let charged_bytes_available = next_charged_bytes
                        .is_some_and(|value| value <= self.inner.budget.max_charged_bytes.get());
                    if count_available && charged_bytes_available {
                        counters.waiters.pop_front();
                        counters.active_owners += 1;
                        counters.active_charged_bytes = next_charged_bytes.unwrap();
                        counters.high_water_owners =
                            counters.high_water_owners.max(counters.active_owners);
                        counters.high_water_charged_bytes = counters
                            .high_water_charged_bytes
                            .max(counters.active_charged_bytes);
                        counters.cumulative_admitted =
                            counters.cumulative_admitted.saturating_add(1);
                        admitted = true;
                    }
                }
            }

            if let Some(rejection) = rejection {
                return Err(rejection);
            }
            if admitted {
                registration.complete();
                wake_next_waiter(&self.inner);
                return Ok(OwnerReservation {
                    inner: Some(Arc::clone(&self.inner)),
                    charged_bytes,
                });
            }

            tokio::select! {
                _ = registration.wake.notified() => {}
                changed = admission_state_changed.changed() => {
                    if changed.is_err() {
                        return Err(OwnerAdmissionRejection::Cancelled(
                            OwnerCancellation::DependencyFailed,
                        ));
                    }
                }
                changed = cancellation_changed.changed() => {
                    if changed.is_err() {
                        return Err(OwnerAdmissionRejection::Cancelled(
                            OwnerCancellation::DependencyFailed,
                        ));
                    }
                }
                _ = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline.instant())) => {
                    return Err(OwnerAdmissionRejection::Cancelled(
                        OwnerCancellation::DeadlineElapsed,
                    ));
                }
            }
        }
    }

    pub fn begin_drain(&self, reason: OwnerDrainReason) -> OwnerAdmissionMetrics {
        let mut counters = self.inner.counters.lock().unwrap();
        let transitioned = if matches!(counters.state, OwnerAdmissionState::Open) {
            counters.state = OwnerAdmissionState::Draining(reason);
            true
        } else {
            false
        };
        let metrics = metrics_from_counters(self.inner.budget, &counters);
        drop(counters);
        if transitioned {
            notify_state_changed(&self.inner.state_changed);
            notify_state_changed(&self.inner.admission_state_changed);
        }
        metrics
    }

    pub async fn wait_drained(
        &self,
        deadline: AbsoluteDeadline,
    ) -> Result<OwnerAdmissionMetrics, OwnerDrainWaitError> {
        let mut state_changed = self.inner.state_changed.subscribe();
        loop {
            let metrics = self.metrics();
            if matches!(metrics.state, OwnerAdmissionState::Open) {
                return Err(OwnerDrainWaitError::NotDraining(metrics));
            }
            if metrics.active_owners == 0 {
                return Ok(metrics);
            }
            if deadline.check_at(Instant::now()).is_err() {
                return Err(OwnerDrainWaitError::DeadlineElapsed(metrics));
            }

            tokio::select! {
                _ = state_changed.changed() => {}
                _ = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline.instant())) => {
                    let metrics = self.metrics();
                    if metrics.active_owners == 0 {
                        return Ok(metrics);
                    }
                    return Err(OwnerDrainWaitError::DeadlineElapsed(metrics));
                }
            }
        }
    }

    pub fn mark_closed(
        &self,
        reason: OwnerCloseReason,
    ) -> Result<OwnerAdmissionMetrics, OwnerAdmissionCloseError> {
        let mut counters = self.inner.counters.lock().unwrap();
        if counters.active_owners != 0 {
            return Err(OwnerAdmissionCloseError::OwnersStillActive(
                metrics_from_counters(self.inner.budget, &counters),
            ));
        }
        if !matches!(counters.state, OwnerAdmissionState::Draining(_)) {
            return Err(OwnerAdmissionCloseError::NotDraining(
                metrics_from_counters(self.inner.budget, &counters),
            ));
        }
        counters.state = OwnerAdmissionState::Closed(reason);
        let metrics = metrics_from_counters(self.inner.budget, &counters);
        drop(counters);
        notify_state_changed(&self.inner.state_changed);
        notify_state_changed(&self.inner.admission_state_changed);
        Ok(metrics)
    }
}

struct OwnerAdmissionWaitRegistration {
    inner: Arc<OwnerAdmissionInner>,
    ticket: u64,
    wake: Arc<Notify>,
    registered: bool,
}

impl OwnerAdmissionWaitRegistration {
    fn new(inner: Arc<OwnerAdmissionInner>, ticket: u64, wake: Arc<Notify>) -> Self {
        Self {
            inner,
            ticket,
            wake,
            registered: true,
        }
    }

    fn complete(&mut self) {
        self.registered = false;
    }
}

impl Drop for OwnerAdmissionWaitRegistration {
    fn drop(&mut self) {
        if !self.registered {
            return;
        }
        {
            let mut counters = self.inner.counters.lock().unwrap();
            let Some(position) = counters
                .waiters
                .iter()
                .position(|waiter| waiter.ticket == self.ticket)
            else {
                return;
            };
            counters.waiters.remove(position);
        }
        wake_next_waiter(&self.inner);
    }
}

fn next_waiter_ticket(counters: &mut OwnerAdmissionCounters) -> u64 {
    loop {
        let ticket = counters.next_waiter_ticket;
        counters.next_waiter_ticket = counters.next_waiter_ticket.wrapping_add(1);
        if !counters
            .waiters
            .iter()
            .any(|waiter| waiter.ticket == ticket)
        {
            return ticket;
        }
    }
}

fn wake_next_waiter(inner: &OwnerAdmissionInner) {
    let wake = inner
        .counters
        .lock()
        .unwrap()
        .waiters
        .front()
        .map(|waiter| Arc::clone(&waiter.wake));
    if let Some(wake) = wake {
        wake.notify_one();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OwnerDrainWaitError {
    NotDraining(OwnerAdmissionMetrics),
    DeadlineElapsed(OwnerAdmissionMetrics),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OwnerAdmissionCloseError {
    OwnersStillActive(OwnerAdmissionMetrics),
    NotDraining(OwnerAdmissionMetrics),
}

fn notify_state_changed(state_changed: &watch::Sender<u64>) {
    state_changed.send_modify(|revision| *revision = revision.wrapping_add(1));
}

fn metrics_from_counters(
    budget: OwnerResourceBudget,
    counters: &OwnerAdmissionCounters,
) -> OwnerAdmissionMetrics {
    OwnerAdmissionMetrics {
        state: counters.state,
        active_owners: counters.active_owners,
        active_charged_bytes: counters.active_charged_bytes,
        high_water_owners: counters.high_water_owners,
        high_water_charged_bytes: counters.high_water_charged_bytes,
        cumulative_admitted: counters.cumulative_admitted,
        rejected_by_count: counters.rejected_by_count,
        rejected_by_charged_bytes: counters.rejected_by_charged_bytes,
        rejected_while_draining: counters.rejected_while_draining,
        budget,
    }
}
