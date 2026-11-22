use super::*;

#[tokio::test]
async fn cleanup_guard_notifies_owner_during_unwind() {
    let (sender, mut receiver) = mpsc::channel(1);
    let metrics = Arc::new(ResidentDataplaneMetrics::default());
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = UdpSessionCleanupGuard::new(7_u64, 11, sender.into(), Arc::clone(&metrics));
        panic!("injected UDP actor panic");
    }));
    assert!(result.is_err());
    assert_eq!(
        receiver.recv().await,
        Some(UdpSessionCleanup {
            key: 7,
            actor_id: 11,
        })
    );
    assert_eq!(metrics.snapshot()["udpSessionCleanupNotificationFailed"], 0);
}

#[tokio::test]
async fn cleanup_falls_back_to_bounded_overflow_then_arms_reconciliation() {
    let (primary, mut primary_rx) = mpsc::channel(1);
    let (overflow, mut overflow_rx) = mpsc::channel(1);
    let (scan_needed, scan_state) = watch::channel(false);
    let sender = UdpSessionCleanupSender::with_overflow(primary, overflow, scan_needed);
    let metrics = Arc::new(ResidentDataplaneMetrics::default());
    let cleanup = |actor_id| {
        UdpSessionCleanupGuard::new(7_u64, actor_id, sender.clone(), Arc::clone(&metrics))
    };

    drop(cleanup(1));
    let guard = cleanup(2);
    let task = tokio::spawn(async move {
        let _cleanup = guard;
        std::future::pending::<()>().await;
    });
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert!(!*scan_state.borrow());
    drop(cleanup(3));
    assert!(*scan_state.borrow());
    assert_eq!(primary_rx.try_recv().unwrap().actor_id, 1);
    assert_eq!(overflow_rx.try_recv().unwrap().actor_id, 2);

    drop(cleanup(4));
    assert_eq!(primary_rx.try_recv().unwrap().actor_id, 4);
    assert_eq!(metrics.snapshot()["udpSessionCleanupNotificationFailed"], 1);
}
