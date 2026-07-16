use super::fixtures::*;
use super::*;

#[tokio::test(flavor = "current_thread")]
async fn generation_boundary_owns_task_registration_drain_and_join() {
    let boundary = GenerationOwnerBoundary::new(TEST_GENERATION, identity(9));
    let runtime = tokio::runtime::Handle::current();
    let (release_driver, driver_released) = tokio::sync::oneshot::channel();
    let (release_command, command_released) = tokio::sync::oneshot::channel();
    let driver = boundary
        .spawn_task_on(&runtime, OwnerTaskRole::TransportDriver, async move {
            let _ = driver_released.await;
        })
        .unwrap();
    let command = boundary
        .spawn_task_on(&runtime, OwnerTaskRole::CommandLoop, async move {
            let _ = command_released.await;
        })
        .unwrap();
    assert_eq!(boundary.snapshot().tasks.total(), 2);

    let draining =
        boundary.apply_command(GenerationOwnerCommand::BeginDrain(OwnerDrainReason::Reload));
    assert_eq!(
        draining.state,
        GenerationOwnerState::Draining(OwnerDrainReason::Reload)
    );
    assert_eq!(
        boundary
            .spawn_task_on(&runtime, OwnerTaskRole::Cleanup, async {})
            .unwrap_err(),
        OwnerTaskRegistrationError::Draining(OwnerDrainReason::Reload)
    );
    assert_eq!(
        boundary.cancellation().reason(),
        Some(OwnerCancellation::GenerationDraining)
    );

    let _ = release_driver.send(());
    let _ = release_command.send(());
    driver.join().await.unwrap();
    command.join().await.unwrap();
    assert_eq!(
        boundary
            .wait_joined(deadline())
            .await
            .unwrap()
            .tasks
            .total(),
        0
    );
    let closed = boundary.apply_command(GenerationOwnerCommand::Close(OwnerCloseReason::Reload));
    assert_eq!(
        closed.state,
        GenerationOwnerState::Closed(OwnerCloseReason::Reload)
    );
}

#[tokio::test(flavor = "current_thread")]
async fn close_command_cannot_hide_unjoined_tasks() {
    let boundary = GenerationOwnerBoundary::new(TEST_GENERATION, identity(10));
    let task = boundary
        .spawn_task_on(
            &tokio::runtime::Handle::current(),
            OwnerTaskRole::TransportDriver,
            std::future::pending::<()>(),
        )
        .unwrap();

    let snapshot =
        boundary.apply_command(GenerationOwnerCommand::Close(OwnerCloseReason::Shutdown));
    assert_eq!(snapshot.state, GenerationOwnerState::Running);
    assert_eq!(snapshot.tasks.transport_drivers, 1);

    boundary.apply_command(GenerationOwnerCommand::BeginDrain(
        OwnerDrainReason::Shutdown,
    ));
    task.abort();
    assert_eq!(task.join().await, Err(GenerationTaskJoinError::Cancelled));
    assert_eq!(
        boundary
            .wait_joined(deadline())
            .await
            .unwrap()
            .tasks
            .total(),
        0
    );
}

#[tokio::test(flavor = "current_thread")]
async fn join_wait_requires_an_explicit_drain_boundary() {
    let boundary = GenerationOwnerBoundary::new(TEST_GENERATION, identity(15));

    let OwnerTaskJoinError::NotDraining(snapshot) =
        boundary.wait_joined(deadline()).await.unwrap_err()
    else {
        panic!("a running generation must not report a stable join");
    };
    assert_eq!(snapshot.state, GenerationOwnerState::Running);
    assert_eq!(snapshot.tasks.total(), 0);

    boundary.apply_command(GenerationOwnerCommand::BeginDrain(
        OwnerDrainReason::Shutdown,
    ));
    assert_eq!(
        boundary.wait_joined(deadline()).await.unwrap().state,
        GenerationOwnerState::Draining(OwnerDrainReason::Shutdown)
    );
}

#[test]
fn close_command_requires_an_explicit_drain_boundary() {
    let boundary = GenerationOwnerBoundary::new(TEST_GENERATION, identity(13));
    let snapshot =
        boundary.apply_command(GenerationOwnerCommand::Close(OwnerCloseReason::Completed));
    assert_eq!(snapshot.state, GenerationOwnerState::Running);
}

#[tokio::test(flavor = "current_thread")]
async fn dropping_generation_owner_cancels_owned_persistent_tasks() {
    let boundary = GenerationOwnerBoundary::new(TEST_GENERATION, identity(14));
    let cancellation = boundary.cancellation();
    let mut cancellation_changed = cancellation.subscribe();
    let task = boundary
        .spawn_task_on(
            &tokio::runtime::Handle::current(),
            OwnerTaskRole::TransportDriver,
            async move {
                loop {
                    if let Some(reason) = *cancellation_changed.borrow() {
                        return reason;
                    }
                    cancellation_changed.changed().await.unwrap();
                }
            },
        )
        .unwrap();

    drop(boundary);
    assert_eq!(
        cancellation.reason(),
        Some(OwnerCancellation::GenerationDraining)
    );
    assert_eq!(
        task.join().await.unwrap(),
        OwnerCancellation::GenerationDraining
    );
}
