use super::*;

#[tokio::test]
async fn poison_supersedes_builder_and_wakes_observer_without_accepting_retry() {
    let owner = SingleFlightPhysicalOwner::<u8>::new();
    let deadline = AbsoluteDeadline::from_now(Instant::now(), std::time::Duration::from_secs(2));
    let cancellation = OwnerCancellationSignal::new();
    let SingleFlightDecision::Build(builder) =
        owner.begin_or_observe(deadline, &cancellation).unwrap()
    else {
        panic!("expected builder");
    };
    let SingleFlightDecision::Observe(observer) =
        owner.begin_or_observe(deadline, &cancellation).unwrap()
    else {
        panic!("expected observer");
    };
    let waiter = tokio::spawn(observer.wait());
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = owner.inner.state.lock().unwrap();
        panic!("injected single-flight poison");
    }));
    assert_eq!(owner.snapshot().state, PhysicalOwnerState::Failed);
    assert_eq!(
        builder.publish_ready(1).unwrap_err(),
        SingleFlightError::Superseded
    );
    assert!(matches!(
        tokio::time::timeout(std::time::Duration::from_secs(1), waiter)
            .await
            .unwrap()
            .unwrap(),
        Err(SingleFlightError::Failed(PhysicalOwnerFailure {
            operation: "owner-state-lock-poisoned",
            ..
        }))
    ));
    assert!(owner.prepare_retry().is_err());
    assert!(owner.begin_or_observe(deadline, &cancellation).is_err());
    assert_eq!(owner.close().state, PhysicalOwnerState::Closed);
}
