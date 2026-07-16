use std::time::Instant;

use super::fixtures::*;
use super::*;

#[tokio::test(flavor = "current_thread")]
async fn one_builder_publishes_ready_owner_to_all_observers() {
    let cell = SingleFlightPhysicalOwner::new();
    let cancellation = OwnerCancellationSignal::new();
    let builder = match cell.begin_or_observe(deadline(), &cancellation).unwrap() {
        SingleFlightDecision::Build(builder) => builder,
        _ => panic!("first acquire must build"),
    };
    let observer = match cell.begin_or_observe(deadline(), &cancellation).unwrap() {
        SingleFlightDecision::Observe(observer) => observer,
        _ => panic!("concurrent acquire must observe"),
    };

    let ready = builder.publish_ready(String::from("ready-owner")).unwrap();
    let observed = observer.wait().await.unwrap();
    assert!(std::sync::Arc::ptr_eq(&ready, &observed));
    assert!(matches!(
        cell.begin_or_observe(deadline(), &cancellation).unwrap(),
        SingleFlightDecision::Ready(_)
    ));
}

#[tokio::test(flavor = "current_thread")]
async fn dropped_builder_fans_typed_failure_out_to_observers() {
    let cell = SingleFlightPhysicalOwner::<String>::new();
    let cancellation = OwnerCancellationSignal::new();
    let builder = match cell.begin_or_observe(deadline(), &cancellation).unwrap() {
        SingleFlightDecision::Build(builder) => builder,
        _ => panic!("first acquire must build"),
    };
    let observer = match cell.begin_or_observe(deadline(), &cancellation).unwrap() {
        SingleFlightDecision::Observe(observer) => observer,
        _ => panic!("concurrent acquire must observe"),
    };

    drop(builder);
    assert_eq!(
        observer.wait().await,
        Err(SingleFlightError::Failed(PhysicalOwnerFailure::new(
            OwnerFailureClass::BuilderDropped,
            "owner-construction",
        )))
    );
    assert_eq!(
        cell.begin_or_observe(deadline(), &cancellation)
            .unwrap_err(),
        SingleFlightError::Failed(PhysicalOwnerFailure::new(
            OwnerFailureClass::BuilderDropped,
            "owner-construction",
        ))
    );
    cell.prepare_retry().unwrap();
    assert!(matches!(
        cell.begin_or_observe(deadline(), &cancellation).unwrap(),
        SingleFlightDecision::Build(_)
    ));
}

#[tokio::test(flavor = "current_thread")]
async fn observer_uses_the_original_deadline_and_typed_cancellation() {
    let cell = SingleFlightPhysicalOwner::<String>::new();
    let cancellation = OwnerCancellationSignal::new();
    let builder = match cell.begin_or_observe(deadline(), &cancellation).unwrap() {
        SingleFlightDecision::Build(builder) => builder,
        _ => panic!("first acquire must build"),
    };
    let observer = match cell.begin_or_observe(deadline(), &cancellation).unwrap() {
        SingleFlightDecision::Observe(observer) => observer,
        _ => panic!("concurrent acquire must observe"),
    };
    cancellation.cancel(OwnerCancellation::CallerCancelled);
    assert_eq!(
        observer.wait().await,
        Err(SingleFlightError::Cancelled(
            OwnerCancellation::CallerCancelled
        ))
    );
    drop(builder);

    let expired = AbsoluteDeadline::at(Instant::now());
    assert_eq!(
        cell.begin_or_observe(expired, &OwnerCancellationSignal::new())
            .unwrap_err(),
        SingleFlightError::Cancelled(OwnerCancellation::DeadlineElapsed)
    );
}

#[test]
fn draining_cell_rejects_new_builders() {
    let cell = SingleFlightPhysicalOwner::<String>::new();
    let cancellation = OwnerCancellationSignal::new();
    let builder = match cell.begin_or_observe(deadline(), &cancellation).unwrap() {
        SingleFlightDecision::Build(builder) => builder,
        _ => panic!("first acquire must build"),
    };
    cell.begin_drain(OwnerDrainReason::Shutdown);
    assert_eq!(
        cell.begin_or_observe(deadline(), &cancellation)
            .unwrap_err(),
        SingleFlightError::Draining(OwnerDrainReason::Shutdown)
    );
    drop(builder);
}

#[test]
fn draining_vacant_cell_cannot_create_a_late_owner() {
    let cell = SingleFlightPhysicalOwner::<String>::new();
    let cancellation = OwnerCancellationSignal::new();
    cell.begin_drain(OwnerDrainReason::Reload);

    assert_eq!(
        cell.begin_or_observe(deadline(), &cancellation)
            .unwrap_err(),
        SingleFlightError::Draining(OwnerDrainReason::Reload)
    );
}
