use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;

use super::abort_and_reap_xhttp_task;

struct ActiveTaskGuard(Arc<AtomicUsize>);

impl Drop for ActiveTaskGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn abort_reaper_awaits_nested_task_cancellation() {
    let active_tasks = Arc::new(AtomicUsize::new(0));
    let task_active_tasks = Arc::clone(&active_tasks);
    let task = tokio::spawn(async move {
        task_active_tasks.fetch_add(1, Ordering::AcqRel);
        let _active = ActiveTaskGuard(task_active_tasks);
        std::future::pending::<()>().await;
    });

    tokio::time::timeout(Duration::from_secs(1), async {
        while active_tasks.load(Ordering::Acquire) != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("nested xHTTP task startup timeout");

    abort_and_reap_xhttp_task(task);

    tokio::time::timeout(Duration::from_secs(1), async {
        while active_tasks.load(Ordering::Acquire) != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("nested xHTTP task cancellation timeout");
}
