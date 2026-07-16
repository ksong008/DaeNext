use std::time::Duration;

use super::fixtures::*;
use super::*;

#[tokio::test(flavor = "current_thread")]
async fn drain_wait_requires_an_explicit_drain_boundary() {
    let admission = PhysicalOwnerAdmission::new(budget(1, 100));

    let OwnerDrainWaitError::NotDraining(snapshot) =
        admission.wait_drained(deadline()).await.unwrap_err()
    else {
        panic!("an open admission gate must not report a stable drain");
    };
    assert_eq!(snapshot.state, OwnerAdmissionState::Open);
    assert_eq!(snapshot.active_owners, 0);

    admission.begin_drain(OwnerDrainReason::Shutdown);
    assert_eq!(
        admission.wait_drained(deadline()).await.unwrap().state,
        OwnerAdmissionState::Draining(OwnerDrainReason::Shutdown)
    );
}

#[tokio::test(flavor = "current_thread")]
async fn drain_wait_yields_until_the_last_owner_releases() {
    let admission = PhysicalOwnerAdmission::new(budget(1, 100));
    let reservation = admission
        .try_reserve(charge(40), deadline(), &OwnerCancellationSignal::new())
        .unwrap();
    admission.begin_drain(OwnerDrainReason::Shutdown);

    let release = tokio::spawn(async move {
        tokio::task::yield_now().await;
        drop(reservation);
    });
    let drained = tokio::time::timeout(
        Duration::from_millis(100),
        admission.wait_drained(deadline()),
    )
    .await
    .expect("drain wait blocked the current-thread runtime")
    .unwrap();

    release.await.unwrap();
    assert_eq!(drained.active_owners, 0);
    assert_eq!(drained.active_charged_bytes, 0);
}

#[tokio::test(flavor = "current_thread")]
async fn drain_wait_reports_the_balanced_snapshot_at_deadline() {
    let admission = PhysicalOwnerAdmission::new(budget(1, 100));
    let reservation = admission
        .try_reserve(charge(40), deadline(), &OwnerCancellationSignal::new())
        .unwrap();
    admission.begin_drain(OwnerDrainReason::Shutdown);

    let expired = AbsoluteDeadline::at(std::time::Instant::now());
    let OwnerDrainWaitError::DeadlineElapsed(snapshot) =
        admission.wait_drained(expired).await.unwrap_err()
    else {
        panic!("a draining admission with a live owner must report its deadline");
    };
    assert_eq!(snapshot.active_owners, 1);
    assert_eq!(snapshot.active_charged_bytes, 40);

    drop(reservation);
}
