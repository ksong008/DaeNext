use super::*;

#[tokio::test]
async fn poison_rejects_new_reservations_wakes_waiters_and_keeps_live_charges() {
    let admission = PhysicalOwnerAdmission::new(OwnerResourceBudget::new(
        NonZeroUsize::new(1).unwrap(),
        NonZeroUsize::new(1024).unwrap(),
    ));
    let charge = ChargedOwnerBytes::new(NonZeroUsize::new(64).unwrap());
    let deadline = AbsoluteDeadline::from_now(Instant::now(), std::time::Duration::from_secs(2));
    let cancellation = OwnerCancellationSignal::new();
    let reservation = admission
        .try_reserve(charge, deadline, &cancellation)
        .unwrap();
    let waiter_admission = admission.clone();
    let waiter_cancellation = cancellation.clone();
    let waiter = tokio::spawn(async move {
        waiter_admission
            .reserve_until(charge, deadline, &waiter_cancellation)
            .await
    });
    while admission.inner.counters.lock().unwrap().waiters.is_empty() {
        tokio::task::yield_now().await;
    }
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = admission.inner.counters.lock().unwrap();
        panic!("injected admission poison");
    }));
    assert_eq!(admission.metrics().active_charged_bytes, 64);
    assert_eq!(
        admission
            .try_reserve(charge, deadline, &cancellation)
            .unwrap_err(),
        OwnerAdmissionRejection::Draining(OwnerDrainReason::Fault)
    );
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(1), waiter)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err(),
        OwnerAdmissionRejection::Draining(OwnerDrainReason::Fault)
    );
    drop(reservation);
    let drained = admission.wait_drained(deadline).await.unwrap();
    assert_eq!(drained.active_owners, 0);
    assert_eq!(drained.active_charged_bytes, 0);
    admission.mark_closed(OwnerCloseReason::Fault).unwrap();
    assert!(admission.inner.counters.is_poisoned());
}
