use super::*;
use serde_json::json;
use std::sync::atomic::{AtomicBool, Ordering};
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
fn resident_event_full_queue_critical_policy_is_lifecycle_only() {
    assert!(ResidentEvent::new(json!({"event": "tcp_worker_started"})).is_critical());
    assert!(ResidentEvent::new(json!({"event": "runtime_reload_finished"})).is_critical());
    assert!(ResidentEvent::new(json!({"event": "resident_fatal_error"})).is_critical());
    assert!(!ResidentEvent::new(json!({"event": "tcp_connection_failed"})).is_critical());
    assert!(!ResidentEvent::new(json!({"event": "udp_exchange_failed"})).is_critical());
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

#[test]
fn resident_event_writer_critical_drop_does_not_block_when_queue_is_full() {
    let (sender, _receiver) = mpsc::sync_channel(1);
    sender
        .send(ResidentEventWriterCommand::Event(ResidentEvent::new(
            json!({"event": "tcp_worker_started"}),
        )))
        .unwrap();
    let metrics = Arc::new(ResidentEventWriterMetrics::new(1));
    let handle = ResidentEventWriterHandle {
        inner: Arc::new(ResidentEventWriterInner {
            path: std::env::temp_dir().join(format!(
                "resident-event-writer-critical-drop-test-{}",
                std::process::id()
            )),
            lock: Arc::new(Mutex::new(())),
            sender,
            metrics: Arc::clone(&metrics),
        }),
    };

    // A Startup-class (critical) event with a full queue used to block the
    // caller for up to the 5s control timeout; the async hot path must never
    // block on event submission.
    let started = Instant::now();
    handle.submit(ResidentEvent::new(json!({"event": "tcp_worker_started"})));
    let elapsed = started.elapsed();

    assert!(
        elapsed < Duration::from_secs(2),
        "critical event submit blocked for {elapsed:?}; async hot path must be non-blocking"
    );
    let snapshot = metrics.snapshot();
    assert_eq!(snapshot["droppedCount"], json!(1));
    assert_eq!(snapshot["droppedByClass"]["startup"], json!(1));
    assert!(
        snapshot["lastWriteError"].is_string(),
        "dropping a critical event must be surfaced in the writer error metrics"
    );
}

#[test]
fn resident_event_writer_panic_clears_active_writer_and_events_are_delivered_directly() {
    let _guard = super::super::tests::event_test_guard();
    let dir = std::env::temp_dir().join(format!(
        "resident-event-writer-panic-test-{}-{}",
        std::process::id(),
        super::super::current_unix()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("events.jsonl");
    let fallback_lock = Arc::new(Mutex::new(()));
    let captured = Arc::new(Mutex::new(Vec::<Value>::new()));
    let sink_panics = Arc::new(AtomicBool::new(true));
    let sink_panics_captured = Arc::clone(&sink_panics);
    let captured_sink = Arc::clone(&captured);
    super::super::set_event_log_sink(Some(Arc::new(move |event| {
        if sink_panics_captured.swap(false, Ordering::Relaxed) {
            panic!("injected sink panic");
        }
        captured_sink.lock().unwrap().push(event.clone());
    })));
    super::super::set_event_log_policies(None, None);
    let mut writer = ResidentEventWriterRuntime::start(path.clone(), Arc::clone(&fallback_lock), 2);

    // Event 1 is processed by the writer thread, whose sink dispatch panics.
    super::super::append_event(
        &path,
        &fallback_lock,
        json!({"event": "tcp_worker_started"}),
    );

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if writer
            .thread
            .as_ref()
            .is_some_and(|thread| thread.is_finished())
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "writer thread did not exit after injected sink panic"
        );
        thread::sleep(Duration::from_millis(10));
    }

    // The panicked writer must no longer be the active writer, otherwise
    // submissions would hit the disconnected channel and be lost forever.
    let slot = ACTIVE_EVENT_WRITER.get();
    assert!(
        slot.is_none_or(|slot| slot.load().is_none()),
        "panicked writer must be cleared from ACTIVE_EVENT_WRITER"
    );

    // Event 2 falls back to direct sink dispatch and must still be delivered.
    super::super::append_event(
        &path,
        &fallback_lock,
        json!({"event": "tcp_worker_started"}),
    );

    let events = captured.lock().unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["event"], json!("tcp_worker_started"));
    drop(events);

    writer.shutdown();
    super::super::set_event_log_sink(None);
    std::fs::remove_dir_all(dir).unwrap();
}
