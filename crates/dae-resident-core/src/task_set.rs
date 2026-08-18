use std::time::Duration;

#[derive(Default)]
pub struct ResidentTaskSetShutdown {
    pub joined: usize,
    pub cancelled: usize,
    pub panicked: usize,
    pub forced: usize,
}

pub async fn shutdown_resident_task_set<T: 'static>(
    tasks: &mut tokio::task::JoinSet<T>,
    grace: Duration,
) -> ResidentTaskSetShutdown {
    let mut shutdown = ResidentTaskSetShutdown::default();
    let deadline = tokio::time::Instant::now() + grace;
    while !tasks.is_empty() {
        match tokio::time::timeout_at(deadline, tasks.join_next()).await {
            Ok(Some(completed)) => record_resident_task_completion(&mut shutdown, completed),
            Ok(None) => break,
            Err(_) => {
                shutdown.forced = shutdown.forced.saturating_add(tasks.len());
                tasks.abort_all();
                while let Some(completed) = tasks.join_next().await {
                    record_resident_task_completion(&mut shutdown, completed);
                }
                break;
            }
        }
    }
    shutdown
}

pub fn record_resident_task_completion<T>(
    shutdown: &mut ResidentTaskSetShutdown,
    completed: Result<T, tokio::task::JoinError>,
) {
    match completed {
        Ok(_) => shutdown.joined = shutdown.joined.saturating_add(1),
        Err(error) if error.is_cancelled() => {
            shutdown.cancelled = shutdown.cancelled.saturating_add(1);
        }
        Err(_) => shutdown.panicked = shutdown.panicked.saturating_add(1),
    }
}
