use super::*;

fn poison(queue: &ProductLogQueue) {
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = queue.state.lock().unwrap();
        panic!("injected queue poison");
    }));
}

#[test]
fn poisoned_close_wakes_a_sleeping_receiver() {
    let queue = Arc::new(ProductLogQueue::new(1));
    let (done, receiver) = mpsc::channel();
    let worker = Arc::clone(&queue);
    let thread = thread::spawn(move || {
        done.send(worker.receive().is_none()).unwrap();
    });
    poison(&queue);
    queue.close();
    assert!(receiver.recv_timeout(Duration::from_secs(1)).unwrap());
    thread.join().unwrap();
    assert!(queue.submit(test_command(), Duration::ZERO).is_err());
}

#[test]
fn poisoned_submission_wakes_the_worker_without_an_explicit_close() {
    let queue = Arc::new(ProductLogQueue::new(1));
    let (done, receiver) = mpsc::channel();
    let worker = Arc::clone(&queue);
    let thread = thread::spawn(move || {
        done.send(worker.receive().is_none()).unwrap();
    });
    poison(&queue);
    assert!(queue.submit(test_command(), Duration::ZERO).is_err());
    assert!(receiver.recv_timeout(Duration::from_secs(1)).unwrap());
    thread.join().unwrap();
}

#[test]
fn poisoned_close_fails_queued_completions_and_blocked_producers() {
    let queue = Arc::new(ProductLogQueue::new(1));
    let (completion, waiting) = mpsc::sync_channel(1);
    queue
        .submit(
            ProductLogCommand {
                action: ProductLogAction::Clear,
                completion,
            },
            Duration::ZERO,
        )
        .unwrap();
    let (done, receiver) = mpsc::channel();
    let producer = Arc::clone(&queue);
    let thread = thread::spawn(move || {
        done.send(
            producer
                .submit(test_command(), Duration::from_secs(10))
                .is_err(),
        )
        .unwrap();
    });
    poison(&queue);
    queue.close();
    assert!(receiver.recv_timeout(Duration::from_secs(1)).unwrap());
    assert!(matches!(
        waiting.recv_timeout(Duration::from_secs(1)),
        Err(mpsc::RecvTimeoutError::Disconnected)
    ));
    thread.join().unwrap();
    assert!(queue.receive().is_none());
}

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
