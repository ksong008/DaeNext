use super::*;

pub(super) async fn join_bridge_task_until(
    mut task: tokio::task::JoinHandle<()>,
    deadline: time::Instant,
) -> Result<ResidentOwnedTaskShutdownCompletion, String> {
    match time::timeout_at(deadline, &mut task).await {
        Ok(Ok(())) => Ok(ResidentOwnedTaskShutdownCompletion::Joined),
        Ok(Err(error)) => Err(format!("join resident proxy UDP bridge task: {error}")),
        Err(_) => {
            task.abort();
            match task.await {
                Ok(()) => Ok(ResidentOwnedTaskShutdownCompletion::Joined),
                Err(error) if error.is_cancelled() => {
                    Ok(ResidentOwnedTaskShutdownCompletion::Aborted)
                }
                Err(error) => Err(format!(
                    "abort and join resident proxy UDP bridge task: {error}"
                )),
            }
        }
    }
}
