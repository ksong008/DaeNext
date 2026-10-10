use super::*;

#[test]
fn queue_capacity_and_close_are_bounded() {
    let queue = ProductLogQueue::new(1);
    queue
        .submit(test_command(), Duration::from_millis(10))
        .unwrap();
    let started = Instant::now();
    let error = queue
        .submit(test_command(), Duration::from_millis(20))
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert!(started.elapsed() < Duration::from_secs(1));
    assert!(queue.receive().is_some());
    queue.close();
    assert!(queue.receive().is_none());
    assert_eq!(
        queue
            .submit(test_command(), Duration::from_millis(10))
            .unwrap_err()
            .kind(),
        io::ErrorKind::BrokenPipe
    );
}

#[test]
fn zero_timeout_submission_never_waits_for_capacity() {
    let queue = ProductLogQueue::new(1);
    queue
        .submit(test_command(), Duration::ZERO)
        .expect("first detached command must fit");
    let started = Instant::now();
    let error = queue
        .submit(test_command(), Duration::ZERO)
        .expect_err("full detached queue must reject");
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert!(started.elapsed() < Duration::from_millis(10));
}

fn test_command() -> ProductLogCommand {
    let (completion, _) = mpsc::sync_channel(1);
    ProductLogCommand {
        action: ProductLogAction::Clear,
        completion,
    }
}
