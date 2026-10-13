use super::*;

#[tokio::test]
async fn poisoned_boundary_drains_and_reaps_tasks_without_resetting_counts() {
    let boundary = GenerationOwnerBoundary::new(
        OwnerGeneration::new(11),
        RedactedOwnerIdentity::new("poison-test", [1; 32]).unwrap(),
    );
    let (release, released) = tokio::sync::oneshot::channel();
    let task = boundary
        .spawn_task_on(
            &tokio::runtime::Handle::current(),
            OwnerTaskRole::TransportDriver,
            async move {
                let _ = released.await;
            },
        )
        .unwrap();
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = boundary.inner.state.lock().unwrap();
        panic!("injected task boundary poison");
    }));
    let snapshot = boundary.snapshot();
    assert_eq!(
        snapshot.state,
        GenerationOwnerState::Draining(OwnerDrainReason::Fault)
    );
    assert_eq!(snapshot.tasks.total(), 1);
    assert!(
        boundary
            .spawn_task_on(
                &tokio::runtime::Handle::current(),
                OwnerTaskRole::Cleanup,
                async {}
            )
            .is_err()
    );
    release.send(()).unwrap();
    task.join().await.unwrap();
    let deadline = AbsoluteDeadline::from_now(Instant::now(), std::time::Duration::from_secs(1));
    assert_eq!(
        boundary.wait_joined(deadline).await.unwrap().tasks.total(),
        0
    );
    drop(boundary);
}
