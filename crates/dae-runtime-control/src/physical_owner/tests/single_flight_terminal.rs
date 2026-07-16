use super::*;

fn transport_failure(operation: &'static str) -> PhysicalOwnerFailure {
    PhysicalOwnerFailure::new(OwnerFailureClass::Transport, operation)
}

#[test]
fn late_failure_cannot_overwrite_draining_state() {
    let cell = SingleFlightPhysicalOwner::<String>::new();
    let revision = cell.snapshot().revision;
    let draining = cell.begin_drain(OwnerDrainReason::Reload);

    assert_eq!(
        cell.fail(revision, transport_failure("late-driver-failure")),
        Err(SingleFlightError::Draining(OwnerDrainReason::Reload))
    );
    assert_eq!(cell.snapshot(), draining);
}

#[test]
fn late_failure_and_drain_cannot_overwrite_closed_state() {
    let cell = SingleFlightPhysicalOwner::<String>::new();
    let revision = cell.snapshot().revision;
    let closed = cell.close();

    assert_eq!(
        cell.fail(revision, transport_failure("late-close-failure")),
        Err(SingleFlightError::Closed)
    );
    assert_eq!(cell.begin_drain(OwnerDrainReason::Shutdown), closed);
    assert_eq!(cell.snapshot(), closed);
}

#[test]
fn repeated_drain_preserves_the_first_reason_and_revision() {
    let cell = SingleFlightPhysicalOwner::<String>::new();
    let first = cell.begin_drain(OwnerDrainReason::Reload);
    let repeated = cell.begin_drain(OwnerDrainReason::Fault);

    assert_eq!(repeated, first);
    assert_eq!(repeated.drain_reason, Some(OwnerDrainReason::Reload));
}

#[test]
fn failed_state_preserves_the_first_failure_until_explicit_retry() {
    let cell = SingleFlightPhysicalOwner::<String>::new();
    let first_failure = transport_failure("first-failure");
    let first = cell.fail(cell.snapshot().revision, first_failure).unwrap();

    assert_eq!(
        cell.fail(first.revision, transport_failure("second-failure")),
        Err(SingleFlightError::Failed(first_failure))
    );
    assert_eq!(cell.snapshot(), first);
    assert_eq!(
        cell.prepare_retry().unwrap().state,
        PhysicalOwnerState::Closed
    );
}

#[test]
fn stale_failure_cannot_overwrite_an_explicit_retry_boundary() {
    let cell = SingleFlightPhysicalOwner::<String>::new();
    let stale_revision = cell.snapshot().revision;
    cell.fail(stale_revision, transport_failure("first-failure"))
        .unwrap();
    let retry = cell.prepare_retry().unwrap();

    assert_eq!(
        cell.fail(stale_revision, transport_failure("stale-failure")),
        Err(SingleFlightError::Superseded)
    );
    assert_eq!(cell.snapshot(), retry);
}
