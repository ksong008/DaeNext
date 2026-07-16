use super::*;

#[test]
fn physical_owner_state_transitions_are_explicit_and_closed_is_terminal() {
    let lifecycle = PhysicalOwnerLifecycle::connecting();
    lifecycle.mark_ready().unwrap();
    lifecycle.begin_drain(OwnerDrainReason::Reload).unwrap();
    lifecycle.mark_closed(OwnerCloseReason::Reload).unwrap();

    let snapshot = lifecycle.snapshot();
    assert_eq!(snapshot.state, PhysicalOwnerState::Closed);
    assert_eq!(snapshot.drain_reason, Some(OwnerDrainReason::Reload));
    assert_eq!(snapshot.close_reason, Some(OwnerCloseReason::Reload));
    assert_eq!(
        lifecycle.mark_ready(),
        Err(OwnerStateTransitionError {
            from: PhysicalOwnerState::Closed,
            to: PhysicalOwnerState::Ready,
        })
    );
}

#[test]
fn failed_owner_can_begin_one_new_connection_attempt() {
    let lifecycle = PhysicalOwnerLifecycle::connecting();
    lifecycle
        .mark_failed(PhysicalOwnerFailure::new(
            OwnerFailureClass::Connect,
            "connect",
        ))
        .unwrap();
    lifecycle.mark_connecting().unwrap();
    assert_eq!(lifecycle.snapshot().state, PhysicalOwnerState::Connecting);
}
