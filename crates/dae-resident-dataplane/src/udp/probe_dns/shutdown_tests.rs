use super::*;

use std::future::pending;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE;

const SHUTDOWN_COMPLETION_DELAY: Duration = Duration::from_millis(20);

#[tokio::test]
async fn bridge_shutdown_waits_for_the_executor_task_to_finish() {
    let (shutdown, stopped) = tokio::sync::oneshot::channel();
    let completed = Arc::new(AtomicBool::new(false));
    let task_completed = Arc::clone(&completed);
    let task = tokio::spawn(async move {
        let _ = stopped.await;
        time::sleep(SHUTDOWN_COMPLETION_DELAY).await;
        task_completed.store(true, Ordering::Release);
    });
    let bridge = ResidentProxyUdpBridge {
        local_addr: "127.0.0.1:1".parse().unwrap(),
        shutdown: Some(shutdown),
        task: Some(task),
        last_error: Arc::new(Mutex::new(None)),
    };

    bridge.shutdown_and_join().await.unwrap();

    assert!(completed.load(Ordering::Acquire));
}

#[tokio::test]
async fn bridge_shutdown_reports_executor_task_failure() {
    let (shutdown, stopped) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        let _ = stopped.await;
        panic!("injected bridge task failure");
    });
    let bridge = ResidentProxyUdpBridge {
        local_addr: "127.0.0.1:1".parse().unwrap(),
        shutdown: Some(shutdown),
        task: Some(task),
        last_error: Arc::new(Mutex::new(None)),
    };

    let error = bridge.shutdown_and_join().await.unwrap_err();

    assert!(error.contains("join resident proxy UDP bridge task"));
    assert!(error.contains("panicked"));
}

#[tokio::test]
async fn deadline_shutdown_joins_a_graceful_executor_task() {
    let (shutdown, stopped) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        let _ = stopped.await;
    });
    let bridge = ResidentProxyUdpBridge {
        local_addr: "127.0.0.1:1".parse().unwrap(),
        shutdown: Some(shutdown),
        task: Some(task),
        last_error: Arc::new(Mutex::new(None)),
    };

    let completion = bridge
        .shutdown_and_join_until(time::Instant::now() + RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE)
        .await
        .unwrap();

    assert_eq!(completion, ResidentOwnedTaskShutdownCompletion::Joined);
}

#[tokio::test]
async fn deadline_shutdown_aborts_and_joins_a_stalled_executor_task() {
    struct TaskDropMarker(Arc<AtomicBool>);

    impl Drop for TaskDropMarker {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }

    let (shutdown, stopped) = tokio::sync::oneshot::channel();
    let (started, task_started) = tokio::sync::oneshot::channel();
    let dropped = Arc::new(AtomicBool::new(false));
    let task_dropped = Arc::clone(&dropped);
    let task = tokio::spawn(async move {
        let _marker = TaskDropMarker(task_dropped);
        let _ = started.send(());
        let _ = stopped.await;
        pending::<()>().await;
    });
    task_started.await.unwrap();
    let bridge = ResidentProxyUdpBridge {
        local_addr: "127.0.0.1:1".parse().unwrap(),
        shutdown: Some(shutdown),
        task: Some(task),
        last_error: Arc::new(Mutex::new(None)),
    };

    let completion = bridge
        .shutdown_and_join_until(time::Instant::now() + RESIDENT_IDLE_SLEEP)
        .await
        .unwrap();

    assert_eq!(completion, ResidentOwnedTaskShutdownCompletion::Aborted);
    assert!(dropped.load(Ordering::Acquire));
}
