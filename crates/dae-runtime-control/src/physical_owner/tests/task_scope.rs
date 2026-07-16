use super::fixtures::*;
use super::*;

#[test]
fn generation_boundary_owns_task_registration_drain_and_join() {
    let boundary = GenerationOwnerBoundary::new(TEST_GENERATION, identity(9));
    let driver = boundary
        .register_task(OwnerTaskRole::TransportDriver)
        .unwrap();
    let command = boundary.register_task(OwnerTaskRole::CommandLoop).unwrap();
    assert_eq!(boundary.snapshot().tasks.total(), 2);

    let draining =
        boundary.apply_command(GenerationOwnerCommand::BeginDrain(OwnerDrainReason::Reload));
    assert_eq!(
        draining.state,
        GenerationOwnerState::Draining(OwnerDrainReason::Reload)
    );
    assert_eq!(
        boundary.register_task(OwnerTaskRole::Cleanup).unwrap_err(),
        OwnerTaskRegistrationError::Draining(OwnerDrainReason::Reload)
    );
    assert_eq!(
        boundary.cancellation().reason(),
        Some(OwnerCancellation::GenerationDraining)
    );

    drop(driver);
    drop(command);
    assert_eq!(boundary.wait_joined(deadline()).unwrap().tasks.total(), 0);
    let closed = boundary.apply_command(GenerationOwnerCommand::Close(OwnerCloseReason::Reload));
    assert_eq!(
        closed.state,
        GenerationOwnerState::Closed(OwnerCloseReason::Reload)
    );
}

#[test]
fn close_command_cannot_hide_unjoined_tasks() {
    let boundary = GenerationOwnerBoundary::new(TEST_GENERATION, identity(10));
    let task = boundary
        .register_task(OwnerTaskRole::TransportDriver)
        .unwrap();
    let snapshot =
        boundary.apply_command(GenerationOwnerCommand::Close(OwnerCloseReason::Shutdown));
    assert_eq!(snapshot.state, GenerationOwnerState::Running);
    assert_eq!(snapshot.tasks.transport_drivers, 1);
    drop(task);
}

#[test]
fn close_command_requires_an_explicit_drain_boundary() {
    let boundary = GenerationOwnerBoundary::new(TEST_GENERATION, identity(13));
    let snapshot =
        boundary.apply_command(GenerationOwnerCommand::Close(OwnerCloseReason::Completed));
    assert_eq!(snapshot.state, GenerationOwnerState::Running);
}

#[test]
fn dropping_generation_owner_cancels_registered_persistent_tasks() {
    let boundary = GenerationOwnerBoundary::new(TEST_GENERATION, identity(14));
    let cancellation = boundary.cancellation();
    let task = boundary
        .register_task(OwnerTaskRole::TransportDriver)
        .unwrap();

    drop(boundary);
    assert_eq!(
        cancellation.reason(),
        Some(OwnerCancellation::GenerationDraining)
    );
    drop(task);
}
