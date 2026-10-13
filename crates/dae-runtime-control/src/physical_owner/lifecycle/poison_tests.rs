use super::*;

#[test]
fn poisoned_lifecycle_can_close_but_cannot_report_ready() {
    let lifecycle = PhysicalOwnerLifecycle::connecting();
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = lifecycle.snapshot.lock().unwrap();
        panic!("injected lifecycle poison");
    }));
    assert_eq!(lifecycle.snapshot().state, PhysicalOwnerState::Draining);
    assert!(lifecycle.mark_ready().is_err());
    lifecycle.mark_closed(OwnerCloseReason::Fault).unwrap();
    assert_eq!(lifecycle.snapshot().state, PhysicalOwnerState::Closed);
}
