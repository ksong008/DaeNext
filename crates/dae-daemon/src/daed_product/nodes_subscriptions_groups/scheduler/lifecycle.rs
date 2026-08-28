use super::*;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender};

#[derive(Debug)]
enum SchedulerCommand {
    Stop,
    Wake,
}

type SchedulerWakeRegistry = Mutex<Option<(u64, Sender<SchedulerCommand>)>>;

static NEXT_SCHEDULER_ID: AtomicU64 = AtomicU64::new(1);
static SCHEDULER_WAKE: OnceLock<SchedulerWakeRegistry> = OnceLock::new();

#[derive(Debug)]
pub(crate) struct SubscriptionSchedulerHandle {
    id: u64,
    stop: Option<Sender<SchedulerCommand>>,
    thread: Option<thread::JoinHandle<()>>,
}

impl SubscriptionSchedulerHandle {
    pub(crate) fn shutdown(mut self) -> io::Result<()> {
        self.stop_and_join()
    }

    fn stop_and_join(&mut self) -> io::Result<()> {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(SchedulerCommand::Stop);
        }
        let Some(thread) = self.thread.take() else {
            unregister_scheduler(self.id);
            return Ok(());
        };
        let result = thread
            .join()
            .map_err(|_| io::Error::other("subscription scheduler thread panicked"));
        unregister_scheduler(self.id);
        result
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
    let id = NEXT_SCHEDULER_ID.fetch_add(1, Ordering::Relaxed);
    register_scheduler(id, stop.clone())?;
    let thread = thread::Builder::new()
        .name("daed-subscription-scheduler".to_owned())
        .spawn(move || {
            run_subscription_scheduler(state, config_dir, runtime, control_runtime, receiver)
        });
    let thread = match thread {
        Ok(thread) => thread,
        Err(err) => {
            unregister_scheduler(id);
            return Err(err);
        }
    };
    Ok(SubscriptionSchedulerHandle {
        id,
        stop: Some(stop),
        thread: Some(thread),
    })
}

pub(super) fn notify_subscription_scheduler() {
    let Some(registry) = SCHEDULER_WAKE.get() else {
        return;
    };
    let Ok(registry) = registry.lock() else {
        return;
    };
    if let Some((_, sender)) = registry.as_ref() {
        let _ = sender.send(SchedulerCommand::Wake);
    }
}

fn register_scheduler(id: u64, sender: Sender<SchedulerCommand>) -> io::Result<()> {
    let registry = SCHEDULER_WAKE.get_or_init(|| Mutex::new(None));
    let mut registry = registry
        .lock()
        .map_err(|_| io::Error::other("subscription scheduler registry lock poisoned"))?;
    if registry.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "subscription scheduler is already running",
        ));
    }
    *registry = Some((id, sender));
    Ok(())
}

fn unregister_scheduler(id: u64) {
    let Some(registry) = SCHEDULER_WAKE.get() else {
        return;
    };
    let Ok(mut registry) = registry.lock() else {
        return;
    };
    if registry.as_ref().is_some_and(|(current, _)| *current == id) {
        *registry = None;
    }
}

fn run_subscription_scheduler(
    state: PathBuf,
    config_dir: PathBuf,
    runtime: Arc<ProductRuntimeManager>,
    control_runtime: Arc<ProductControlRuntime>,
    stop: Receiver<SchedulerCommand>,
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
        let wait = match subscription_scheduler_wait(&state, unix_now()) {
            Ok(Some(wait)) => Some(wait),
            Ok(None) => None,
            Err(_) => Some(SUBSCRIPTION_SCHEDULER_RETRY),
        };
        let command = match wait {
            Some(wait) => match stop.recv_timeout(wait) {
                Ok(command) => Some(command),
                Err(RecvTimeoutError::Disconnected) => Some(SchedulerCommand::Stop),
                Err(RecvTimeoutError::Timeout) => None,
            },
            None => match stop.recv() {
                Ok(command) => Some(command),
                Err(_) => Some(SchedulerCommand::Stop),
            },
        };
        match command {
            Some(SchedulerCommand::Stop) => break,
            Some(SchedulerCommand::Wake) => loop {
                match stop.try_recv() {
                    Ok(SchedulerCommand::Wake) => {}
                    Ok(SchedulerCommand::Stop)
                    | Err(std::sync::mpsc::TryRecvError::Disconnected) => return,
                    Err(std::sync::mpsc::TryRecvError::Empty) => break,
                }
            },
            None => {}
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
