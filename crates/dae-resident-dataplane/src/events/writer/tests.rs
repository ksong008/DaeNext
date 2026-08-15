use super::*;
use serde_json::json;
use std::sync::mpsc;

#[test]
fn resident_event_writer_drops_datapath_errors_when_queue_is_full() {
    let (sender, receiver) = mpsc::sync_channel(1);
    sender
        .send(ResidentEventWriterCommand::Event(ResidentEvent::new(
            json!({"event": "tcp_worker_started"}),
        )))
        .unwrap();
    let metrics = Arc::new(ResidentEventWriterMetrics::new(1));
    let handle = ResidentEventWriterHandle {
        inner: Arc::new(ResidentEventWriterInner {
            path: std::env::temp_dir().join(format!(
                "resident-event-writer-drop-test-{}",
                std::process::id()
            )),
            lock: Arc::new(Mutex::new(())),
            sender,
            metrics: Arc::clone(&metrics),
        }),
    };

    handle.submit(ResidentEvent::new(json!({
        "event": "udp_exchange_failed",
        "error": "sample",
    })));

    drop(receiver);
    let snapshot = metrics.snapshot();
    assert_eq!(snapshot["droppedCount"], json!(1));
    assert_eq!(snapshot["droppedByClass"]["error"], json!(1));
    assert_eq!(snapshot["lastWriteError"], Value::Null);
}

#[test]
fn resident_event_full_queue_blocking_policy_is_lifecycle_only() {
    assert!(ResidentEvent::new(json!({"event": "tcp_worker_started"})).block_on_full_queue());
    assert!(ResidentEvent::new(json!({"event": "runtime_reload_finished"})).block_on_full_queue());
    assert!(ResidentEvent::new(json!({"event": "resident_fatal_error"})).block_on_full_queue());
    assert!(!ResidentEvent::new(json!({"event": "tcp_connection_failed"})).block_on_full_queue());
    assert!(!ResidentEvent::new(json!({"event": "udp_exchange_failed"})).block_on_full_queue());
}

#[test]
fn resident_event_writer_control_send_obeys_timeout_when_queue_is_full() {
    let (sender, _receiver) = mpsc::sync_channel(1);
    sender
        .send(ResidentEventWriterCommand::Event(ResidentEvent::new(
            json!({"event": "tcp_worker_started"}),
        )))
        .unwrap();
    let handle = ResidentEventWriterHandle {
        inner: Arc::new(ResidentEventWriterInner {
            path: std::env::temp_dir().join(format!(
                "resident-event-writer-control-timeout-test-{}",
                std::process::id()
            )),
            lock: Arc::new(Mutex::new(())),
            sender,
            metrics: Arc::new(ResidentEventWriterMetrics::new(1)),
        }),
    };

    let started = Instant::now();
    let timeout = Duration::from_millis(25);
    let result = handle.control_with_timeout(ResidentEventWriterCommand::Prune, timeout);

    assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::TimedOut);
    assert!(started.elapsed() < timeout * 4);
}

#[test]
fn resident_event_writer_control_ack_obeys_the_same_deadline() {
    let (sender, receiver) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    let worker = thread::spawn(move || {
        let command = receiver.recv().unwrap();
        release_rx.recv().unwrap();
        drop(command);
    });
    let handle = ResidentEventWriterHandle {
        inner: Arc::new(ResidentEventWriterInner {
            path: std::env::temp_dir().join(format!(
                "resident-event-writer-ack-timeout-test-{}",
                std::process::id()
            )),
            lock: Arc::new(Mutex::new(())),
            sender,
            metrics: Arc::new(ResidentEventWriterMetrics::new(1)),
        }),
    };

    let timeout = Duration::from_millis(25);
    let started = Instant::now();
    let result = handle.control_with_timeout(ResidentEventWriterCommand::Prune, timeout);
    release_tx.send(()).unwrap();
    worker.join().unwrap();

    assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::TimedOut);
    assert!(started.elapsed() < timeout * 4);
}

#[test]
fn resident_event_writer_shutdown_does_not_join_a_blocked_writer_past_deadline() {
    let path = std::env::temp_dir().join(format!(
        "resident-event-writer-shutdown-deadline-test-{}",
        std::process::id()
    ));
    let (sender, _receiver) = mpsc::sync_channel(1);
    let metrics = Arc::new(ResidentEventWriterMetrics::new(1));
    let handle = ResidentEventWriterHandle {
        inner: Arc::new(ResidentEventWriterInner {
            path,
            lock: Arc::new(Mutex::new(())),
            sender,
            metrics,
        }),
    };
    let (completion_tx, completion_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    let thread = thread::spawn(move || {
        release_rx.recv().unwrap();
        let _ = completion_tx.send(ResidentEventWriterExit::Completed);
    });
    let mut runtime = ResidentEventWriterRuntime {
        handle,
        thread: Some(thread),
        completion: Some(completion_rx),
    };

    let timeout = Duration::from_millis(25);
    let started = Instant::now();
    let shutdown = runtime.shutdown_until(deadline_after(timeout));

    assert_eq!(shutdown["status"], "fail");
    assert_eq!(shutdown["threadJoined"], false);
    assert_eq!(shutdown["threadTimedOut"], true);
    assert!(started.elapsed() < timeout * 4);

    release_tx.send(()).unwrap();
    assert_eq!(
        runtime.wait_for_completion_until(deadline_after(Duration::from_secs(1))),
        Some(ResidentEventWriterExit::Completed)
    );
}
