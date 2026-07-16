use super::*;

use std::sync::atomic::{AtomicBool, Ordering};

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
