use super::*;

#[tokio::test]
async fn lowering_tcp_limit_keeps_existing_reservations_and_grants_fifo_after_returns() {
    let admission = ResidentTcpAdmission::new(3, Arc::new(ResidentDataplaneMetrics::default()));
    let first = admission.acquire().await.unwrap();
    let second = admission.acquire().await.unwrap();
    let third = admission.acquire().await.unwrap();
    let mut wait1 = Box::pin(admission.acquire());
    let mut wait2 = Box::pin(admission.acquire());
    assert!(futures_util::poll!(wait1.as_mut()).is_pending());
    assert!(futures_util::poll!(wait2.as_mut()).is_pending());
    admission.set_limit(1);
    drop(first);
    assert!(futures_util::poll!(wait1.as_mut()).is_pending());
    drop(second);
    assert!(futures_util::poll!(wait1.as_mut()).is_pending());
    assert_eq!(admission.snapshot()["used"], 1);
    drop(third);
    let granted1 = wait1.await.unwrap();
    assert!(futures_util::poll!(wait2.as_mut()).is_pending());
    drop(granted1);
    drop(wait2.await.unwrap());
    assert_eq!(admission.snapshot()["used"], 0);
    assert_eq!(admission.snapshot()["waiters"], 0);
}

#[tokio::test]
async fn tcp_waiter_cancellation_before_and_after_grant_releases_exactly_once() {
    let admission = ResidentTcpAdmission::new(3, Arc::new(ResidentDataplaneMetrics::default()));
    let held = (
        admission.acquire().await.unwrap(),
        admission.acquire().await.unwrap(),
        admission.acquire().await.unwrap(),
    );
    let mut first = Box::pin(admission.acquire());
    let mut middle = Box::pin(admission.acquire());
    let mut last = Box::pin(admission.acquire());
    for wait in [&mut first, &mut middle, &mut last] {
        assert!(futures_util::poll!(wait.as_mut()).is_pending());
    }
    assert!(
        admission.acquire().await.is_err(),
        "waiter queue must be bounded"
    );
    drop(middle);
    drop(first);
    drop(held.0); // Grant last but do not poll its receiver.
    assert_eq!(admission.snapshot()["used"], 3);
    drop(last);
    assert_eq!(admission.snapshot()["used"], 2);
    drop((held.1, held.2));
    assert_eq!(admission.snapshot()["used"], 0);
    assert_eq!(admission.snapshot()["waiters"], 0);
}

#[tokio::test]
async fn tcp_limit_updates_are_shared_and_close_wakes_all_waiters() {
    let admission = ResidentTcpAdmission::new(1, Arc::new(ResidentDataplaneMetrics::default()));
    let next_generation = admission.clone();
    let held = admission.acquire().await.unwrap();
    let mut wait = Box::pin(next_generation.acquire());
    assert!(futures_util::poll!(wait.as_mut()).is_pending());
    next_generation.set_limit(2);
    let granted = wait.await.unwrap();
    assert_eq!(admission.snapshot()["used"], 2);
    let mut wait = Box::pin(admission.acquire());
    assert!(futures_util::poll!(wait.as_mut()).is_pending());
    next_generation.close();
    assert!(wait.await.is_err());
    assert!(admission.acquire().await.is_err());
    drop((held, granted));
    assert_eq!(admission.snapshot()["used"], 0);
}
