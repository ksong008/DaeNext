use super::*;

pub(super) async fn join_bridge_task_until(
    mut task: tokio::task::JoinHandle<()>,
    deadline: time::Instant,
) -> Result<ResidentProxyUdpBridgeShutdownCompletion, String> {
    match time::timeout_at(deadline, &mut task).await {
        Ok(Ok(())) => Ok(ResidentProxyUdpBridgeShutdownCompletion::Joined),
        Ok(Err(error)) => Err(format!("join resident proxy UDP bridge task: {error}")),
        Err(_) => {
            task.abort();
            match task.await {
                Ok(()) => Ok(ResidentProxyUdpBridgeShutdownCompletion::Joined),
                Err(error) if error.is_cancelled() => {
                    Ok(ResidentProxyUdpBridgeShutdownCompletion::Aborted)
                }
                Err(error) => Err(format!(
                    "abort and join resident proxy UDP bridge task: {error}"
                )),
            }
        }
    }
}
