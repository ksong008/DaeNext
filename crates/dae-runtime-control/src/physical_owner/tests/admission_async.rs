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

#[tokio::test(flavor = "current_thread")]
async fn reservation_waits_without_holding_runtime_or_admission_state() {
    let admission = PhysicalOwnerAdmission::new(budget(1, 100));
    let first = admission
        .try_reserve(charge(60), deadline(), &OwnerCancellationSignal::new())
        .unwrap();
    let waiting_admission = admission.clone();
    let waiter = tokio::spawn(async move {
        waiting_admission
            .reserve_until(charge(40), deadline(), &OwnerCancellationSignal::new())
            .await
    });

    tokio::task::yield_now().await;
    assert!(!waiter.is_finished());
    assert_eq!(admission.metrics().active_owners, 1);
    drop(first);

    let second = tokio::time::timeout(Duration::from_millis(100), waiter)
        .await
        .expect("admission waiter blocked the current-thread runtime")
        .unwrap()
        .unwrap();
    assert_eq!(admission.metrics().active_owners, 1);
    drop(second);
    assert_eq!(admission.metrics().active_owners, 0);
}

#[tokio::test(flavor = "current_thread")]
async fn reservation_wait_observes_cancellation_and_deadline() {
    let admission = PhysicalOwnerAdmission::new(budget(1, 100));
    let first = admission
        .try_reserve(charge(60), deadline(), &OwnerCancellationSignal::new())
        .unwrap();
    let cancellation = OwnerCancellationSignal::new();
    let waiting_admission = admission.clone();
    let waiting_cancellation = cancellation.clone();
    let cancelled = tokio::spawn(async move {
        waiting_admission
            .reserve_until(charge(40), deadline(), &waiting_cancellation)
            .await
    });
    tokio::task::yield_now().await;
    cancellation.cancel(OwnerCancellation::CallerCancelled);
    assert!(matches!(
        cancelled.await.unwrap(),
        Err(OwnerAdmissionRejection::Cancelled(
            OwnerCancellation::CallerCancelled
        ))
    ));

    let elapsed = admission
        .reserve_until(
            charge(40),
            AbsoluteDeadline::at(std::time::Instant::now()),
            &OwnerCancellationSignal::new(),
        )
        .await;
    assert!(matches!(
        elapsed,
        Err(OwnerAdmissionRejection::Cancelled(
            OwnerCancellation::DeadlineElapsed
        ))
    ));
    drop(first);
}

#[tokio::test(flavor = "current_thread")]
async fn reservation_wait_stops_when_admission_drains() {
    let admission = PhysicalOwnerAdmission::new(budget(1, 100));
    let first = admission
        .try_reserve(charge(60), deadline(), &OwnerCancellationSignal::new())
        .unwrap();
    let waiting_admission = admission.clone();
    let waiter = tokio::spawn(async move {
        waiting_admission
            .reserve_until(charge(40), deadline(), &OwnerCancellationSignal::new())
            .await
    });
    tokio::task::yield_now().await;
    admission.begin_drain(OwnerDrainReason::Reload);
    assert!(matches!(
        waiter.await.unwrap(),
        Err(OwnerAdmissionRejection::Draining(OwnerDrainReason::Reload))
    ));
    drop(first);
}

#[tokio::test(flavor = "current_thread")]
async fn impossible_byte_charge_is_rejected_without_waiting() {
    let admission = PhysicalOwnerAdmission::new(budget(1, 100));
    let result = admission
        .reserve_until(charge(101), deadline(), &OwnerCancellationSignal::new())
        .await;
    assert!(matches!(
        result,
        Err(OwnerAdmissionRejection::LimitsExceeded {
            count: false,
            charged_bytes: true,
        })
    ));
}
