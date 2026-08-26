use super::*;
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender};

#[derive(Debug)]
pub(crate) struct SubscriptionSchedulerHandle {
    stop: Option<Sender<()>>,
    thread: Option<thread::JoinHandle<()>>,
}

impl SubscriptionSchedulerHandle {
    pub(crate) fn shutdown(mut self) -> io::Result<()> {
        self.stop_and_join()
    }

    fn stop_and_join(&mut self) -> io::Result<()> {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        let Some(thread) = self.thread.take() else {
            return Ok(());
        };
        thread
            .join()
            .map_err(|_| io::Error::other("subscription scheduler thread panicked"))
    }
}

impl Drop for SubscriptionSchedulerHandle {
    fn drop(&mut self) {
        let _ = self.stop_and_join();
    }
}

pub(super) fn start_subscription_scheduler(
    state: PathBuf,
    config_dir: PathBuf,
    runtime: Arc<ProductRuntimeManager>,
    control_runtime: Arc<ProductControlRuntime>,
) -> io::Result<SubscriptionSchedulerHandle> {
    let (stop, receiver) = std::sync::mpsc::channel();
    let thread = thread::Builder::new()
        .name("daed-subscription-scheduler".to_owned())
        .spawn(move || {
            run_subscription_scheduler(state, config_dir, runtime, control_runtime, receiver)
        })?;
    Ok(SubscriptionSchedulerHandle {
        stop: Some(stop),
        thread: Some(thread),
    })
}

fn run_subscription_scheduler(
    state: PathBuf,
    config_dir: PathBuf,
    runtime: Arc<ProductRuntimeManager>,
    control_runtime: Arc<ProductControlRuntime>,
    stop: Receiver<()>,
) {
    let _ = ensure_state_schema(&state);
    let _ = set_metadata(&state, "subscription_scheduler_started_at", &now_text());
    let _ = append_log_for_config(
        &config_dir,
        &state,
        "info",
        "subscription scheduler started by Rust daed",
    );
    let mut invalid_cron = InvalidCronLogTracker::default();
    loop {
        match stop.try_recv() {
            Ok(()) | Err(std::sync::mpsc::TryRecvError::Disconnected) => break,
            Err(std::sync::mpsc::TryRecvError::Empty) => {}
        }
        if let Err(err) = refresh_due_subscriptions_for_scheduler_with_tracker(
            &control_runtime,
            &state,
            &config_dir,
            &runtime,
            unix_now(),
            &mut invalid_cron,
        ) {
            let _ = append_log_for_config(
                &config_dir,
                &state,
                "error",
                &format!("subscription scheduler tick failed: {err}"),
            );
        }
        match stop.recv_timeout(SUBSCRIPTION_SCHEDULER_TICK) {
            Ok(()) | Err(RecvTimeoutError::Disconnected) => break,
            Err(RecvTimeoutError::Timeout) => {}
        }
    }
    let _ = set_metadata(&state, "subscription_scheduler_stopped_at", &now_text());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scheduler_shutdown_interrupts_the_tick_wait_and_joins() {
        let dir = std::env::temp_dir().join(format!(
            "daed-product-scheduler-lifecycle-{}",
            fastrand::u64(..)
        ));
        let state = dir.join("daed.db");
        ensure_state_schema(&state).unwrap();
        let started = Instant::now();
        let scheduler = start_subscription_scheduler(
            state.clone(),
            dir.clone(),
            Arc::new(ProductRuntimeManager::new()),
            product_test_control_runtime(),
        )
        .unwrap();
        scheduler.shutdown().unwrap();
        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(
            get_metadata(&state, "subscription_scheduler_stopped_at")
                .unwrap()
                .is_some()
        );
        fs::remove_dir_all(dir).unwrap();
    }
}
