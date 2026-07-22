use super::*;

pub(super) async fn run_product_control_task_supervisor(
    mut receiver: tokio::sync::mpsc::Receiver<ProductControlTaskCommand>,
    stop: ProductControlCancellation,
    metrics: Arc<ProductControlRuntimeMetrics>,
    shutdown_timeout: Duration,
) -> ProductControlTaskShutdown {
    let mut tasks = tokio::task::JoinSet::new();
    let mut shutdown = ProductControlTaskShutdown::default();

    loop {
        tokio::select! {
            _ = stop.cancelled() => break,
            command = receiver.recv() => match command {
                Some(command) => spawn_control_task(&mut tasks, command, &stop, &metrics),
                None => break,
            },
            completed = tasks.join_next(), if !tasks.is_empty() => {
                record_control_task_completion(&mut shutdown, completed, &metrics, false);
            }
        }
    }

    receiver.close();
    while let Ok(command) = receiver.try_recv() {
        command.cancellation.request();
        spawn_control_task(&mut tasks, command, &stop, &metrics);
    }

    let deadline = tokio::time::Instant::now() + shutdown_timeout;
    while !tasks.is_empty() {
        match tokio::time::timeout_at(deadline, tasks.join_next()).await {
            Ok(Some(completed)) => {
                record_control_task_completion(&mut shutdown, Some(completed), &metrics, false);
            }
            Ok(None) => break,
            Err(_) => {
                let forced = tasks.len();
                shutdown.forced = shutdown.forced.saturating_add(forced);
                metrics.forced(forced);
                tasks.abort_all();
                while let Some(completed) = tasks.join_next().await {
                    record_control_task_completion(&mut shutdown, Some(completed), &metrics, true);
                }
                break;
            }
        }
    }
    shutdown
}

fn spawn_control_task(
    tasks: &mut tokio::task::JoinSet<()>,
    command: ProductControlTaskCommand,
    stop: &ProductControlCancellation,
    metrics: &Arc<ProductControlRuntimeMetrics>,
) {
    metrics.dequeued();
    let stop = stop.clone();
    let metrics = Arc::clone(metrics);
    tasks.spawn(async move {
        let _active = metrics.active();
        let mut future = command.future;
        tokio::select! {
            _ = stop.cancelled() => {
                command.cancellation.request();
                future.await;
            }
            _ = &mut future => {}
        }
    });
}

fn record_control_task_completion(
    shutdown: &mut ProductControlTaskShutdown,
    completed: Option<Result<(), tokio::task::JoinError>>,
    metrics: &ProductControlRuntimeMetrics,
    forced: bool,
) {
    let Some(completed) = completed else {
        return;
    };
    match completed {
        Ok(()) => shutdown.joined = shutdown.joined.saturating_add(1),
        Err(error) if error.is_cancelled() => {
            shutdown.cancelled = shutdown.cancelled.saturating_add(1);
            metrics.cancelled();
            if !forced {
                debug_assert!(
                    false,
                    "product control task was cancelled before forced shutdown"
                );
            }
        }
        Err(_) => {
            shutdown.panicked = shutdown.panicked.saturating_add(1);
            metrics.panicked();
        }
    }
}
