use std::time::{Duration, Instant};

use super::fixtures::*;
use super::*;

#[tokio::test(flavor = "current_thread")]
async fn task_join_propagates_normal_completion() {
    let boundary = GenerationOwnerBoundary::new(TEST_GENERATION, identity(20));
    let task = boundary
        .spawn_task_on(
            &tokio::runtime::Handle::current(),
            OwnerTaskRole::CommandLoop,
            async { 42_u64 },
        )
        .unwrap();

    assert_eq!(task.join().await.unwrap(), 42);
    assert_eq!(boundary.snapshot().tasks.total(), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn task_join_propagates_panics_without_exposing_the_payload() {
    let boundary = GenerationOwnerBoundary::new(TEST_GENERATION, identity(21));
    let task = boundary
        .spawn_task_on(
            &tokio::runtime::Handle::current(),
            OwnerTaskRole::TransportDriver,
            async { panic!("injected generation task panic") },
        )
        .unwrap();

    assert_eq!(task.join().await, Err(GenerationTaskJoinError::Panicked));
    assert_eq!(boundary.snapshot().tasks.total(), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn task_join_propagates_explicit_cancellation() {
    let boundary = GenerationOwnerBoundary::new(TEST_GENERATION, identity(22));
    let task = boundary
        .spawn_task_on(
            &tokio::runtime::Handle::current(),
            OwnerTaskRole::Cleanup,
            std::future::pending::<()>(),
        )
        .unwrap();

    task.abort();
    assert_eq!(task.join().await, Err(GenerationTaskJoinError::Cancelled));
    assert_eq!(boundary.snapshot().tasks.total(), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn task_deadline_aborts_and_joins_before_returning() {
    let boundary = GenerationOwnerBoundary::new(TEST_GENERATION, identity(23));
    let task = boundary
        .spawn_task_on(
            &tokio::runtime::Handle::current(),
            OwnerTaskRole::Metrics,
            std::future::pending::<()>(),
        )
        .unwrap();
    let deadline = AbsoluteDeadline::from_now(Instant::now(), Duration::from_millis(10));

    assert_eq!(
        task.join_until(deadline).await,
        Err(GenerationTaskJoinError::DeadlineElapsed)
    );
    assert_eq!(
        boundary.snapshot().tasks.total(),
        0,
        "deadline return must follow abort and join"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn expired_task_deadline_aborts_and_joins_before_returning() {
    let boundary = GenerationOwnerBoundary::new(TEST_GENERATION, identity(25));
    let task = boundary
        .spawn_task_on(
            &tokio::runtime::Handle::current(),
            OwnerTaskRole::Metrics,
            std::future::pending::<()>(),
        )
        .unwrap();

    assert_eq!(
        task.join_until(AbsoluteDeadline::at(Instant::now())).await,
        Err(GenerationTaskJoinError::DeadlineElapsed)
    );
    assert_eq!(
        boundary.snapshot().tasks.total(),
        0,
        "an expired deadline must still abort and join the task"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn dropping_a_task_handle_aborts_its_owned_future() {
    let boundary = GenerationOwnerBoundary::new(TEST_GENERATION, identity(24));
    let task = boundary
        .spawn_task_on(
            &tokio::runtime::Handle::current(),
            OwnerTaskRole::TransportDriver,
            std::future::pending::<()>(),
        )
        .unwrap();
    boundary.apply_command(GenerationOwnerCommand::BeginDrain(
        OwnerDrainReason::Shutdown,
    ));
    drop(task);

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
