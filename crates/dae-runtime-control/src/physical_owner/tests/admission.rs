use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Instant;

use super::fixtures::*;
use super::*;

#[test]
fn count_and_charged_byte_limits_reject_independently() {
    let cancellation = OwnerCancellationSignal::new();

    let count_limited = PhysicalOwnerAdmission::new(budget(1, 100));
    let count_permit = count_limited
        .try_reserve(charge(60), deadline(), &cancellation)
        .unwrap();
    assert_eq!(
        count_limited
            .try_reserve(charge(10), deadline(), &cancellation)
            .unwrap_err(),
        OwnerAdmissionRejection::LimitsExceeded {
            count: true,
            charged_bytes: false,
        }
    );
    drop(count_permit);

    let byte_limited = PhysicalOwnerAdmission::new(budget(2, 100));
    let byte_permit = byte_limited
        .try_reserve(charge(60), deadline(), &cancellation)
        .unwrap();
    assert_eq!(
        byte_limited
            .try_reserve(charge(50), deadline(), &cancellation)
            .unwrap_err(),
        OwnerAdmissionRejection::LimitsExceeded {
            count: false,
            charged_bytes: true,
        }
    );
    drop(byte_permit);

    assert_eq!(count_limited.metrics().rejected_by_count, 1);
    assert_eq!(count_limited.metrics().rejected_by_charged_bytes, 0);
    assert_eq!(byte_limited.metrics().rejected_by_count, 0);
    assert_eq!(byte_limited.metrics().rejected_by_charged_bytes, 1);
}

#[test]
fn admitted_owner_drops_the_physical_resource_before_releasing_its_charge() {
    struct DropObserver {
        admission: PhysicalOwnerAdmission,
        active_when_dropped: Arc<AtomicUsize>,
    }

    impl Drop for DropObserver {
        fn drop(&mut self) {
            self.active_when_dropped
                .store(self.admission.metrics().active_owners, Ordering::SeqCst);
        }
    }

    let admission = PhysicalOwnerAdmission::new(budget(1, 100));
    let active_when_dropped = Arc::new(AtomicUsize::new(0));
    let reservation = admission
        .try_reserve(charge(80), deadline(), &OwnerCancellationSignal::new())
        .unwrap();
    let owner = reservation.attach(DropObserver {
        admission: admission.clone(),
        active_when_dropped: Arc::clone(&active_when_dropped),
    });

    assert_eq!(admission.metrics().active_owners, 1);
    drop(owner);
    assert_eq!(active_when_dropped.load(Ordering::SeqCst), 1);
    assert_eq!(admission.metrics().active_owners, 0);
    assert_eq!(admission.metrics().active_charged_bytes, 0);
}

#[test]
fn explicit_close_runs_cleanup_before_balancing_the_permit() {
    let admission = PhysicalOwnerAdmission::new(budget(1, 100));
    let closed = Arc::new(AtomicBool::new(false));
    let owner = admission
        .try_reserve(charge(70), deadline(), &OwnerCancellationSignal::new())
        .unwrap()
        .attach(Arc::clone(&closed));
    owner.mark_ready().unwrap();

    owner
        .close(OwnerCloseReason::Shutdown, |closed| {
            closed.store(true, Ordering::SeqCst);
        })
        .unwrap();

    assert!(closed.load(Ordering::SeqCst));
    assert_eq!(admission.metrics().active_owners, 0);
    assert_eq!(admission.metrics().active_charged_bytes, 0);
}

#[test]
fn expired_and_cancelled_work_is_rejected_before_admission() {
    let admission = PhysicalOwnerAdmission::new(budget(1, 100));
    let cancellation = OwnerCancellationSignal::new();

    assert_eq!(
        admission
            .try_reserve(
                charge(10),
                AbsoluteDeadline::at(Instant::now()),
                &cancellation,
            )
            .unwrap_err(),
        OwnerAdmissionRejection::Cancelled(OwnerCancellation::DeadlineElapsed)
    );
    cancellation.cancel(OwnerCancellation::CallerCancelled);
    assert_eq!(
        admission
            .try_reserve(charge(10), deadline(), &cancellation)
            .unwrap_err(),
        OwnerAdmissionRejection::Cancelled(OwnerCancellation::CallerCancelled)
    );
    assert_eq!(admission.metrics().cumulative_admitted, 0);
}

#[tokio::test(flavor = "current_thread")]
async fn deterministic_drain_rejects_new_owners_and_closes_after_balance() {
    let admission = PhysicalOwnerAdmission::new(budget(1, 100));
    let reservation = admission
        .try_reserve(charge(20), deadline(), &OwnerCancellationSignal::new())
        .unwrap();
    admission.begin_drain(OwnerDrainReason::Reload);
    assert_eq!(
        admission
            .try_reserve(charge(20), deadline(), &OwnerCancellationSignal::new(),)
            .unwrap_err(),
        OwnerAdmissionRejection::Draining(OwnerDrainReason::Reload)
    );

    drop(reservation);
    let drained = admission.wait_drained(deadline()).await.unwrap();
    assert_eq!(drained.active_owners, 0);
    let closed = admission.mark_closed(OwnerCloseReason::Reload).unwrap();
    assert_eq!(
        closed.state,
        OwnerAdmissionState::Closed(OwnerCloseReason::Reload)
    );
}
